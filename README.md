# Stayy

[English](README.md) · [简体中文](README.zh-CN.md)

> **Stay connected to your local AI coding sessions and Windows desktop from your iPhone — securely, accurately, and without handing over your workstation to third-party cloud bots.**

**Stayy** is a hardened, **local-first Windows mobile hub** for developers running **Google Antigravity IDE**, **OpenAI Codex Desktop**, or **`agy` CLI** on their PC. When you step away from your desk, Stayy lets you inspect what your coding agent is doing, read Git diffs at the hunk level, receive privacy-sanitized lock-screen alerts via Bark, and intervene safely using a **3.2× Optical Touch Magnifier Loupe** and **Virtual Trackpad**.

---

## Why Stayy?

- **Precision Mobile Remote Control (`3.2×` Loupe + Virtual Trackpad)**
  - Desktop screens on phones are notoriously hard to tap accurately. Stayy gives you a touch-hold **`3.2×` optical loupe with smart edge-flipping**, drag-out-to-cancel safety, a **ballistic Virtual Trackpad** (1-finger slide, 1-finger tap left click, 2-finger tap right click, 2-finger scroll), **`1×–5×` pinch zoom**, and **direct Unicode text input**.
- **Anti-TOCTOU Safe Approval Inspection (No Blind Auto-Click)**
  - Instead of letting a stale mobile notification blindly click whatever confirmation dialog happened to replace an older one on your PC, Stayy scans pending confirmation cards **read-only**, displays a bounded context summary, and jumps straight to the **`3.2×` optical screen view** so you see and click the exact dialog yourself.
- **Hardened Single-Host Multi-Device Auth & 1-Click Revocation**
  - Runs on an isolated port (`8766` by default) with **epoch-bound session cookies & media tickets** and **short-lived one-time pairing codes (`?pair=`)**.
  - Clicking **「🔒 踢出并换密」** on the Windows console calls an **isolated loopback-only admin port** (never exposed through public tunnels), atomically rotates `WEB_ACCESS_TOKEN` in `.env`, increments `auth_epoch`, purges media/approval caches, and disconnects all active phones with `4001`.
- **Reuses Your Local Tools & Multi-Agent Ecosystem (v0.2)**
  - Supports **Antigravity IDE**, **Codex Desktop**, **`agy` CLI**, **DeepSeek Harness (`dsh`)**, **Tencent WorkBuddy (`workbuddy`)**, and **GitHub Copilot CLI (`copilot`)** via a modular adapter layer (`src/stayy/agents/`), plus OpenAI-compatible cloud/local endpoints (**Doubao Ark**, **DeepSeek API**, **Ollama**, and custom entries via `agents.local.json`).
  - **Read-Only First Safety**: External CLI adapters default strictly to read-only flags (`STAYY_ALLOW_AGENT_WRITE=false`, `AGY_DANGEROUSLY_SKIP_PERMISSIONS=false`, no `-y` or `--allow-all` bypasses).
  - **Zero-Trust Desktop AI Launch + `3.2×` Loupe**: Launch or focus local desktop AI clients (**Doubao Desktop**, **TRAE CN**, **DeepSeek Harness**, **WorkBuddy**, **Copilot**, **Gemini**, **Grok Bot**, etc.) with strict reparse/junction-free PE validation, non-elevated UAC check, and zero CLI arguments, then operate their PC windows cleanly through Stayy's `3.2×` optical loupe.
- **Native Mobile App & Permanent App Closed-Loop**
  - One-tap mobile PWA install banner (`beforeinstallprompt` + iOS 2-step home-screen guide) with complete offline shell (`manifest.json` `id`/`scope`/maskable icons + Service Worker).
  - Windows console **「📲 永久 App」** tab offers an explicit opt-in setup for user-owned GitHub repositories (blocking upstream author repos and blocking `#key=` QR emission on HTTP 404 or stale CDN caches until `host_id` + `nonce` live verification succeeds).
- **Privacy-Preserving Bark Notifications (Opt-In)**
  - Set `BARK_PUSH_URL` to receive generic lock-screen reminders when a prompt awaits attention — zero commands, file paths, screenshots, or tokens ever leave your machine in push notifications, protected by strict HTTPS/non-private SSRF and no-redirect checks.

---

## Platform & Network Support

| Component | Current Status |
| :--- | :--- |
| **Desktop Host OS** | **Windows 10 / 11** (Full IDE window sync, read-only approval inspection, 3.2× remote screen & system telemetry) |
| **Mobile Client** | **iOS Safari / Chrome PWA** (OLED dark mobile UI with Home Screen Web Clip support) |
| **Connection Modes** | **Same Wi-Fi LAN (default)** · **Tailscale / Custom HTTPS (`PUBLIC_BASE_URL`)** · **Cloudflare Quick Tunnel (optional)** · Self-hosted GitHub Pages beacon (`BEACON_ENABLED=false` by default) |

---

## Quick Start (Windows)

```powershell
git clone https://github.com/wwd177/stayy.git
cd stayy
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```

Then double-click **`Stayy.lnk`** on your Desktop (or run `.\.venv\Scripts\pythonw.exe -X utf8 -m stayy.launcher`) and scan the **one-time pairing QR code** from your phone.

> For automated AI-assisted setup, see [INSTALL_FOR_AI.md](INSTALL_FOR_AI.md).

---

## Security Architecture Highlights

1. **Separated Control Plane**: `/admin/pair` and `/admin/revoke` bind exclusively to an ephemeral `127.0.0.1` loopback port with current-user-only `.runtime/admin.json` ACLs — unreachable from Cloudflare Tunnels or LAN.
2. **Closed Media & WebSocket Authorization**: `/dl/<id>` never falls back to open CORS (`*`), requires a valid epoch-bound session cookie or short-lived ticket, and returns `0` bytes on `401`.
3. **Zero Plaintext Secret Leakage**: `python -m stayy.setup_wizard --doctor --json` redacts tokens and push URLs across stdout, stderr, and JSON outputs.
4. **Upstream Beacon Protection**: `BEACON_ENABLED=false` by default so cloned setups never push to upstream repositories or display unverified third-party QR URLs.
5. **Endpoint-Pinned SSRF Defense**: OpenAI-compatible API calls disallow unencrypted public URLs, block HTTP redirects, deny private/link-local IPs, and restrict loopback traffic solely to explicit `STAYY_ALLOW_LOCAL_LLM_PORTS` (default Ollama `11434` / LM Studio `1234`).
6. **Composite Concurrency Isolation**: Multi-agent CLI/API turns serialize per `(store, workspace, session_id)` and cancel/launch barriers serialize with `auth_epoch` revocation under `_revoke_exec_lock`.

> See `agents.local.example.json` and `.env.example` for optional DeepSeek, Doubao Ark, Ollama, and custom desktop AI configuration.

---

## Verification

Run the security gates and bridge test suite locally:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

---

## License

[MIT License](LICENSE)
