#define MyAppName "AlynCoin"
#define MyAppVersion "0.9.0"
#define MyAppExeName "AlynCoinGUI.exe"

[Setup]
AppId={{ED3A9F3E-1E8B-4B31-9D8A-7C8C1E8D80B7}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={pf}\AlynCoin
DefaultGroupName=AlynCoin
OutputDir=..\dist\installer
OutputBaseFilename=AlynCoinSetup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=lowest

[Files]
Source: "..\dist\gui\AlynCoinGUI\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\AlynCoin"; Filename: "{app}\{#MyAppExeName}"
Name: "{commondesktop}\AlynCoin"; Filename: "{app}\{#MyAppExeName}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Flags: nowait postinstall skipifsilent
