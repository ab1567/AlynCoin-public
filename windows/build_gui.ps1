$ErrorActionPreference = "Stop"

$Root    = (Resolve-Path "$PSScriptRoot\..").Path
$AppDir  = Join-Path $Root "application"
$Venv    = Join-Path $AppDir ".venv"
$CliExe  = Join-Path $Root "dist\cli\Release\alyncoin.exe"
$AppCli  = Join-Path $AppDir "alyncoin.exe"
$OutBase = Join-Path $Root "dist\gui"
$OutDir  = Join-Path $OutBase "AlynCoin Wallet"

# --- Venv + deps ---
python -m venv "$Venv"
& "$Venv\Scripts\pip.exe" install --upgrade pip
& "$Venv\Scripts\pip.exe" install PyInstaller PyQt5 requests dnspython

# --- Build GUI via spec file ---
Copy-Item "$CliExe" "$AppCli" -Force
Push-Location $AppDir
& "$Venv\Scripts\pyinstaller.exe" "main.spec"
Pop-Location
Remove-Item "$AppCli" -Force

# --- Copy GUI to dist folder ---
New-Item -ItemType Directory -Force -Path "$OutDir" | Out-Null
robocopy "$AppDir\dist\AlynCoin Wallet" "$OutDir" /E /NFL /NDL /NJH /NJS /NP | Out-Null

Write-Host "✅ GUI ready at $OutDir\AlynCoin Wallet.exe"
