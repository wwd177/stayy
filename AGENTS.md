# AGENTS.md

When deploying or maintaining **Stayy**:

1. For fresh installation on a user machine, read and execute `INSTALL_FOR_AI.md`.
2. Key modules under `src/stayy/`:
   - `auth.py`: Per-host `host_id` binding, `AuthManager` with `auth_epoch`, 5-minute one-time pairing codes, epoch-bound HMAC session cookies & media tickets, atomic `.env` token rotation (`atomic_write_env_token`), and ACL-restricted loopback `.runtime/admin.json`.
   - `approvals.py`: Branch-B read-only approval context extractor & tracker (`ApprovalReadonlyTracker`, `deny_auto_invoke`, `inspect_ide_actions_readonly`) — never auto-clicks desktop approval prompts; guides users into the mobile `3.2×` optical magnifier screen.
   - `desktop_tools.py`: Live Windows UIA prompt delivery & new-conversation creation (`_DESKTOP_UIA_LOCK` + foreground/clipboard sequence verification), read-only bounded context inspection (`inspect_antigravity_ide_actions`, hard-rejected `invoke_antigravity_ide_action`), DPI-accurate remote touch/key input, bidirectional PC clipboard sync, PC system/dev-port telemetry, workspace file explorer, and `git status` / `git diff` inspector.
   - `beacon.py`: Zero-trust PBKDF2 + HMAC-SHA256 encrypted tunnel beacon (`STAYY-BEACON-V1` + `host_id` & `nonce` verification) & static iOS Standalone PWA publisher (`beacon_enabled=False` default, explicit opt-in only, upstream-protected).
   - `notifier.py`: HTTPS + SSRF-hardened (`validate_bark_url`, redirects disabled) Bark push notifier sending fixed generic copy (`SAFE_NOTIFY_TITLE` / `SAFE_NOTIFY_BODY`) with 6h TTL and 30s cooldown coalescing.
   - `web_pwa.py` + `static/index.html`: Single-port (`8766` default) HTTP + WebSocket Mobile/iOS Standalone PWA server + loopback-only admin API, CSWSH & epoch-revocation defense, single-producer shared `_LiveScreenHub`, race-free IDE watcher, and `3.2×` optical loupe remote desktop.
   - `launcher.py`: Windows 11 DWM translucent glassmorphic desktop hub (`Local\StayyLauncherSingleton_v1` mutex, `Stayy LAN` firewall rule, `probe_stayy_gateway_identity`), tunnel auto-heal watchdog, one-time pairing QR, and instant remote revocation (`🔒 踢出并换密`).
   - `conversations.py`: Discovers & parses local PC conversations across Antigravity IDE (`~/.gemini/antigravity`), OpenAI Codex Desktop (`~/.codex`), DeepSeek Harness (`~/.dsh`), WorkBuddy (`~/.workbuddy`), GitHub Copilot (`~/.copilot`), API sessions (`.runtime/api_sessions/`), and Remote CLI (`~/.gemini/antigravity-cli`).
   - `agents/` (`base.py`, `local_config.py`, `cli_adapters.py`, `openai_compat.py`, `desktop_apps.py`, `registry.py`): Plugin ecosystem routing with strict read-only CLI defaults (`STAYY_ALLOW_AGENT_WRITE=false`), endpoint-pinned SSRF-guarded OpenAI-compat SSE client, and zero-trust PE-verified/non-elevated desktop AI app launching.
   - `agy_session.py`: Persistent `agy` stream-json session manager with generation-safe cancellation and model quota failover (`agy_dangerously_skip_permissions=False`, `agy_prewarm=False` by default).
   - `setup_wizard.py`: Non-interactive bootstrapper, `Stayy.lnk` shortcut creator (never overwrites `Antigravity.lnk` or `反重力助手.lnk`), and secret-redacted `--doctor --json` diagnostics (including sanitized `ecosystem` counts).
3. Never commit `.env`, `.runtime/`, `agents.local.json`, `memory/user_profile.md`, `.continuation_map.json`, `.gh_pages_stage/`, `inbox/`, or `bin/` to Git.
