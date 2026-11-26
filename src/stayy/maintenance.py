"""Periodic safe cache cleanup and model quota failover management."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_FALLBACK_MODELS: tuple[str, ...] = (
    "claude-sonnet-5-5-medium",
    "claude-sonnet-5-5-low",
    "gemini-4-neon-medium",
    "gemini-4-carbon-medium",
    "gemini-3.8-flash-high",
    "gpt-oss-120b-medium",
)

QUOTA_ERROR_KEYWORDS: tuple[str, ...] = (
    "resource_exhausted",
    "quota",
    "rate limit",
    "rate_limit",
    "ratelimit",
    "too many requests",
    "429",
    "usage limit",
    "limit reached",
    "limit exceeded",
    "daily limit",
    "exhausted",
    "no capacity",
    "overloaded",
    "model is overloaded",
    "service unavailable",
    "503",
    "model unavailable",
    "model not available",
    "额度",
    "配额",
    "次数已达上限",
    "请求过多",
    "容量不足",
)

NON_QUOTA_EXCLUSIONS: tuple[str, ...] = (
    "这一步跑了超过",
    "执行超时",
    "timed out",
)

# Directories whose names must NEVER be touched by cache cleanup (protect login & configs)
PROTECTED_DIR_NAMES = frozenset({"config", "data", "memory", "prompts", "src", "tests", ".venv", "assets"})


def is_quota_or_capacity_error(error_text: str, stderr_text: str = "") -> bool:
    """Return True if an agy turn failure was caused by model quota, rate-limit, or capacity exhaustion."""
    combined = f"{error_text}\n{stderr_text}".strip().lower()
    if not combined:
        return False
    if any(excl in combined for excl in NON_QUOTA_EXCLUSIONS):
        return False
    return any(kw in combined for kw in QUOTA_ERROR_KEYWORDS)


class ModelFailoverPool:
    """Tracks preferred + fallback models with temporary cooldowns when a model runs out of quota."""

    def __init__(
        self,
        primary_model: str,
        fallback_models: tuple[str, ...] = DEFAULT_FALLBACK_MODELS,
        cooldown_seconds: float = 3600.0,
    ) -> None:
        ordered: list[str] = []
        for m in (primary_model, *fallback_models):
            clean = m.strip()
            if clean and clean not in ordered:
                ordered.append(clean)
        self.models: list[str] = ordered
        self.cooldown_seconds = max(30.0, cooldown_seconds)
        self._cooldown_until: dict[str, float] = {}
        self._manual_override: str = ""

    @property
    def primary_model(self) -> str:
        return self._manual_override or (self.models[0] if self.models else "")

    def set_manual_primary(self, model_name: str) -> None:
        clean = model_name.strip()
        self._manual_override = clean
        if clean:
            self._cooldown_until.pop(clean, None)
            if clean not in self.models:
                self.models.insert(0, clean)

    def mark_exhausted(self, model_name: str) -> None:
        clean = model_name.strip()
        if not clean:
            return
        until = time.monotonic() + self.cooldown_seconds
        self._cooldown_until[clean] = until
        logger.warning(
            "Model %s marked quota-exhausted (cooling down for %.0f min)",
            clean,
            self.cooldown_seconds / 60.0,
        )

    def _prune_expired(self) -> None:
        now = time.monotonic()
        expired = [m for m, ts in self._cooldown_until.items() if ts <= now]
        for m in expired:
            del self._cooldown_until[m]
            logger.info("Model %s quota cooldown expired; restored to available pool", m)

    def pick_best_available(self) -> str:
        """Return the highest-priority non-cooling model (or primary if all are cooling)."""
        self._prune_expired()
        candidates = list(self.models)
        if self._manual_override:
            candidates = [self._manual_override] + [m for m in candidates if m != self._manual_override]

        for m in candidates:
            if m not in self._cooldown_until:
                return m

        if self._cooldown_until:
            soonest = min(self._cooldown_until.items(), key=lambda kv: kv[1])[0]
            return soonest
        return self.primary_model

    def next_after(self, failed_model: str, tried: set[str]) -> str | None:
        """Mark failed_model exhausted and return the next untried available model, or None."""
        self.mark_exhausted(failed_model)
        self._prune_expired()
        candidates = list(self.models)
        if self._manual_override:
            candidates = [self._manual_override] + [m for m in candidates if m != self._manual_override]

        for m in candidates:
            if m not in tried and m not in self._cooldown_until:
                return m
        return None

    def cooldown_summary(self) -> list[tuple[str, int]]:
        """Return [(model_name, remaining_minutes), ...] for models currently cooling down."""
        self._prune_expired()
        now = time.monotonic()
        out: list[tuple[str, int]] = []
        for m, until in self._cooldown_until.items():
            rem_min = max(1, int((until - now + 59) // 60))
            out.append((m, rem_min))
        return out


@dataclass
class CleanupReport:
    deleted_files: int = 0
    freed_bytes: int = 0
    scanned_dirs: list[str] = field(default_factory=list)

    @property
    def freed_mb(self) -> float:
        return self.freed_bytes / (1024.0 * 1024.0)

    def format_human(self) -> str:
        if self.deleted_files == 0:
            return "缓存很干净，暂时没有需要清理的过期文件。"
        if self.freed_mb >= 1.0:
            return f"已清理 {self.deleted_files} 个过期缓存文件，释放了 {self.freed_mb:.2f} MB 空间。"
        kb = self.freed_bytes / 1024.0
        return f"已清理 {self.deleted_files} 个过期缓存文件（约 {kb:.1f} KB）。"


def discover_default_cache_targets(project_dir: Path) -> list[tuple[Path, float, int]]:
    """Return list of (directory_path, max_age_hours, max_keep_files) safe to clean periodically."""
    return [
        (project_dir / "inbox", 24.0, 40),
    ]


def run_safe_cache_cleanup(
    targets: list[tuple[Path, float, int]],
    *,
    force_all_expired_zero: bool = False,
) -> CleanupReport:
    """Clean expired / excess files inside safe cache directories without touching protected dirs."""
    report = CleanupReport()
    now = time.time()

    for directory, max_age_hours, max_keep_files in targets:
        try:
            if not directory.is_dir():
                continue
            resolved_dir = directory.resolve()
            if resolved_dir.name.lower() in PROTECTED_DIR_NAMES:
                logger.warning("Refusing to clean protected directory: %s", resolved_dir)
                continue

            report.scanned_dirs.append(str(resolved_dir))
            age_cutoff = now if force_all_expired_zero else (now - max_age_hours * 3600.0)

            all_files: list[tuple[float, int, Path]] = []
            for item in resolved_dir.rglob("*"):
                if not item.is_file():
                    continue
                rel_parts = {p.lower() for p in item.relative_to(resolved_dir).parts[:-1]}
                if rel_parts & PROTECTED_DIR_NAMES:
                    continue
                st = item.stat()
                all_files.append((st.st_mtime, st.st_size, item))

            all_files.sort(key=lambda t: t[0], reverse=True)

            for idx, (mtime, size, fpath) in enumerate(all_files):
                should_delete = (mtime < age_cutoff) or (max_keep_files > 0 and idx >= max_keep_files)
                if should_delete:
                    try:
                        fpath.unlink()
                        report.deleted_files += 1
                        report.freed_bytes += size
                    except OSError:
                        pass

            for sub in sorted(
                (p for p in resolved_dir.rglob("*") if p.is_dir()),
                key=lambda p: len(p.parts),
                reverse=True,
            ):
                try:
                    if not any(sub.iterdir()):
                        sub.rmdir()
                except OSError:
                    pass
        except Exception as exc:
            logger.warning("Cache cleanup skipped %s due to error: %s", directory, exc)

    return report
