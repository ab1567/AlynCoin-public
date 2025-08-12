$ErrorActionPreference = "Stop"

$Root   = (Resolve-Path "$PSScriptRoot\..").Path
$AppDir = Join-Path $Root "application"
$Venv   = Join-Path $AppDir ".venv"
$OutDir = Join-Path $Root "dist\gui\AlynCoinGUI"
$CliExe = Join-Path $Root "dist\cli\Release\alyncoin.exe"

# --- Venv + deps ---
python -m venv "$Venv"
& "$Venv\Scripts\pip.exe" install --upgrade pip
& "$Venv\Scripts\pip.exe" install PyInstaller PyQt5 requests dnspython

# --- Build GUI (use arg array, no CMD carets) ---
Push-Location $AppDir
& "$Venv\Scripts\pyinstaller.exe" @(
  "--noconfirm", "--windowed", "--onedir",
  "--icon", "logo.ico",
  "--name", "AlynCoinGUI",
  "main.py"
)
Pop-Location

# --- Copy GUI + drop CLI beside it ---
New-Item -ItemType Directory -Force -Path "$OutDir" | Out-Null
robocopy "$AppDir\dist\AlynCoinGUI" "$OutDir" /E /NFL /NDL /NJH /NJS /NP | Out-Null
Copy-Item "$CliExe" (Join-Path "$OutDir" "alyncoin.exe") -Force

Write-Host "✅ GUI ready at $OutDir\AlynCoinGUI.exe"
