@echo off
REM Simple helper to install WSL and Visual C++ runtime

echo Installing Windows Subsystem for Linux...
wsl --install -d Ubuntu

REM Install the Visual C++ runtime (required by some binaries)
set "VC_REDIST=%TEMP%\vc_redist.x64.exe"
if not exist %VC_REDIST% (
    powershell -Command "Invoke-WebRequest -Uri https://aka.ms/vs/17/release/vc_redist.x64.exe -OutFile '%VC_REDIST%'"
)
start /wait %VC_REDIST% /quiet /norestart

echo Installation complete. Please reboot if this is the first time installing WSL.