# INSTALL_FOR_AI.md — AI Agent Automated Setup Guide for Stayy

If you are an AI coding agent deploying **Stayy** on a user's **Windows** workstation, follow these deterministic steps.

> **Platform Scope**: Stayy's full feature set (Antigravity IDE UIA inspection, 3.2× fast screen capture & input, desktop Glassmorphic launcher, and `.lnk` shortcut creation) is built for **Windows 10 / 11**. macOS and Linux are not currently supported for desktop host hosting.

---

## Step 1: Verify At Least One Local AI Backend Exists

Stayy requires at least one of the following installed on Windows (the setup doctor verifies this automatically):
- **Google Antigravity IDE** (`%LOCALAPPDATA%\Programs\Antigravity\Antigravity.exe` or `~/.gemini/antigravity`)
- **OpenAI Codex Desktop / CLI** (`codex` or `~/.codex`)
- **Antigravity CLI** (`agy`)

## Step 2: Create Isolated Virtual Environment & Install Dependencies

**Option A (`uv` locked install — recommended):**
```powershell
uv sync --locked
```

**Option B (`venv` + `pip` editable install):**
```powershell
uv venv --python 3.12 .venv
uv pip install --python .\.venv\Scripts\python.exe -e ".[dev]"
```

*(Fallback without `uv`: `python -m venv .venv` and `.\.venv\Scripts\pip install -e ".[dev]"`)*

## Step 3: Initialize `.env`, Optional Tunnel Binary & `Stayy.lnk` Desktop Shortcut

```powershell
.\.venv\Scripts\python.exe -X utf8 -m stayy.setup_wizard --non-interactive --with-tunnel --create-shortcut --doctor --json
```

Notes:
- Default port is **`8766`** (kept isolated from any other local bridge on `:8765`).
- Safe-by-default permissions: `AGY_DANGEROUSLY_SKIP_PERMISSIONS=false`, `REMOTE_DESKTOP_ENABLED=false`, and `REMOTE_CLIPBOARD_ENABLED=false` (you can toggle desktop touch/clipboard live from the **Stayy** window header).
- `BEACON_ENABLED` defaults to **`false`** — you do NOT need GitHub Pages credentials or upstream push access to use Stayy via LAN, Tailscale (`PUBLIC_BASE_URL`), or Quick Tunnel.
- Upgrading from an older `.env`? Missing toggles safely default to `false`; compare against [`.env.example`](.env.example) or toggle capabilities directly in the launcher UI.
- The JSON output intentionally **redacts all tokens and push URLs**. Confirm `"ok": true` in the JSON output.

## Step 4: Verify Security Gates & Test Suite

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Step 5: Launch Stayy

- **Windows Desktop Hub (Recommended)**:
  ```powershell
  Start-Process -FilePath ".\.venv\Scripts\pythonw.exe" -ArgumentList "-X utf8 -m stayy.launcher" -WorkingDirectory (Get-Location)
  ```
- **Headless Gateway**:
  ```powershell
  .\.venv\Scripts\python.exe -X utf8 -u -m stayy.main
  ```

Tell the user to scan the **one-time pairing QR code** displayed in the **Stayy** window with their iPhone.
