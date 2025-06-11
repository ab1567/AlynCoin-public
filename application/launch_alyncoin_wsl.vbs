Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
' Convert Windows path like C:\Foo\Bar to /mnt/c/Foo/Bar for WSL
letter = LCase(Left(scriptDir, 1))
rest = Mid(scriptDir, 3)
rest = Replace(rest, "\", "/")
wslDir = "/mnt/" & letter & rest
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "wsl -d Ubuntu --cd """ & wslDir & """ -- ./alyncoin", 0, False