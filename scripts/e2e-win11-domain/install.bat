@echo off
rem dockurr/windows runs C:\OEM\install.bat once, as the local administrator, after setup.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\OEM\setup.ps1 > C:\OEM\setup.log 2>&1
