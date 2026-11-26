# Stayy

[English](README.md) · [简体中文](README.zh-CN.md)

> **人离开 Windows 电脑时，用 iPhone 看懂 AI 编程工具卡在哪里、安全精准处理一次并确认任务继续。**

**Stayy** 是一套面向 **Windows** 开发者打造的**本地优先（Local-First）移动 AI 编程与高精度电脑远控中枢**：无缝同步本机 **Google Antigravity IDE**、**OpenAI Codex Desktop** 与 **`agy` CLI** 会话（安装任一即可运行），并配备 **`3.2×` 实时触摸放大镜 + 虚拟触控板**、**抗替身安全审批**、**本机隔离管理面一键撤销** 以及 **可选脱敏 Bark 锁屏提醒**。

---

## 核心特性

1. **小屏高精度电脑操控（`3.2×` 光学放大镜 + 虚拟触控板）**
   - **触摸放大直触**：按住电脑画面弹出 `3.2×` 高清十字准星放大镜，贴边缘自动翻转避让，移出边界松手自动取消防误触；
   - **虚拟触控板**：支持非线性指针加速度、轻点左键、双指轻点右键、双指滑动滚轮、`1×–5×` 双指捏合缩放、直接向电脑焦点输入 Unicode 中英文。
2. **安全第一的抗 TOCTOU 审批模型（Branch B）**
   - 坚决拒绝无实例 ID 保证的盲点一键自动放行（杜绝同文连续弹窗 A→B 替身误操作）；
   - 手机端只读提取并展示确认卡片上下文摘要，点击直达 **`3.2×` 放大镜看屏亲自确认**；CLI 路径默认 `AGY_DANGEROUSLY_SKIP_PERMISSIONS=false`。
3. **独立隔离端口 & 本机一键全端撤销**
   - 默认运行在独立端口 `8766`；管理控制面（`/admin/pair`、`/admin/revoke`）绑定仅限本机回环的独立随机端口（`.runtime/admin.json` 严格收缩当前用户 ACL，不暴露给公网隧道）。
   - 点击启动器 **「🔒 踢出并换密」** 立即原子写入新密钥到 `.env`、递增会话代次 `auth_epoch`、清空缓存，并秒级断连全部在线旧手机（`4001`）。
4. **多用户友好与三连接通道**
   - **默认零第三方账号写入权限即可使用**：原生支持 **同 Wi-Fi 局域网直连**、**Tailscale / 自有域名（`PUBLIC_BASE_URL`）**、**Cloudflare Quick Tunnel**；仅在显式配置 `BEACON_ENABLED=true` 与 `BEACON_GIT_REMOTE` 并通过 HTTPS 读回验真后才开启自托管加密信标。
5. **单渠道强脱敏 Bark 提醒（可选，默认关闭）**
   - 配置 `BARK_PUSH_URL` 后仅发送通用脱敏提醒文案（不含任何命令、路径、截图与密钥），强制 HTTPS + 防内网 SSRF + 禁止重定向，并按事件实例有界去重与 30s 冷却合并。

---

## 快速安装（Windows 10 / 11）

```powershell
git clone https://github.com/wwd177/stayy.git
cd stayy
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```

安装完成后，双击桌面上的 **`Stayy.lnk`**（与原程序完全独立互不干扰），使用手机扫描右侧**一次性配对二维码**即可开始使用。

AI 智能体全自动安装指引请见：[INSTALL_FOR_AI.md](INSTALL_FOR_AI.md)。

---

## 运行全量测试与安全门禁

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## 开源协议

[MIT License](LICENSE)
