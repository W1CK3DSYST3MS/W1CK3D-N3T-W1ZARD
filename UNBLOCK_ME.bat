@echo off
echo Unblocking W1CK3D_NET_WIZARD scripts...
powershell -NoProfile -Command "Get-ChildItem '%~dp0' -Recurse -Include *.py,*.pyw,*.ps1,*.bat | Unblock-File; Write-Host 'Done.'"
echo.
echo All script files unblocked. You can now run launch.pyw
echo.
pause
