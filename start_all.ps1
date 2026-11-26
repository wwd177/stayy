$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$projectDir = $PSScriptRoot
Set-Location $projectDir

foreach ($cand in @(
    (Join-Path $env:LOCALAPPDATA "agy\bin"),
    (Join-Path $env:LOCALAPPDATA "Programs\Antigravity\bin")
)) {
    if ($cand -and (Test-Path $cand)) {
        $env:PATH = "$cand;$env:PATH"
    }
}

if (-not (Test-Path (Join-Path $projectDir ".env"))) {
    $venvPyInit = Join-Path $projectDir ".venv\Scripts\python.exe"
    if (Test-Path $venvPyInit) {
        & $venvPyInit -X utf8 -m stayy.setup_wizard --non-interactive
    }
}

Write-Host "正在启动 Stayy..." -ForegroundColor Cyan
$venvPy = Join-Path $projectDir ".venv\Scripts\python.exe"
if (Test-Path $venvPy) {
    & $venvPy -X utf8 -u -m stayy.main
} else {
    uv run --python 3.12 stayy
}
