param(
    [switch]$NoTunnel,
    [switch]$NoShortcut,
    [switch]$LaunchNow
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

Write-Host "==> [1/3] 正在准备 Stayy 隔离 Python 环境与依赖..." -ForegroundColor Cyan
if (Get-Command uv -ErrorAction SilentlyContinue) {
    uv sync --python 3.12
} else {
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        python -m venv .venv
    }
    & ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
    & ".\.venv\Scripts\python.exe" -m pip install -e .
}

$venvPy = Join-Path $repoRoot ".venv\Scripts\python.exe"
$venvPyw = Join-Path $repoRoot ".venv\Scripts\pythonw.exe"

Write-Host "==> [2/3] 正在初始化配置、加密隧道与 Stayy 桌面快捷方式..." -ForegroundColor Cyan
$wizArgs = @("-X", "utf8", "-m", "stayy.setup_wizard", "--non-interactive", "--doctor")
if (-not $NoTunnel) { $wizArgs += "--with-tunnel" }
if (-not $NoShortcut) { $wizArgs += "--create-shortcut" }

& $venvPy @wizArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "请根据上方自检提示确认本机至少安装了 Antigravity IDE、Codex Desktop 或 agy CLI 之一。" -ForegroundColor Yellow
    exit $LASTEXITCODE
}

Write-Host "==> [3/3] Stayy 部署完成！" -ForegroundColor Green
if ($LaunchNow) {
    Write-Host "正在启动 Stayy 桌面控制台..." -ForegroundColor Cyan
    Start-Process -FilePath $venvPyw -ArgumentList "-X","utf8","-m","stayy.launcher" -WorkingDirectory $repoRoot
} else {
    Write-Host "双击桌面上的『Stayy』图标（或加 -LaunchNow 参数）即可一键启动！" -ForegroundColor Green
}
