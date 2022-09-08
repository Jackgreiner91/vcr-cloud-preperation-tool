@echo off

cd "C:\Hovercast\apps\"
SetVol.exe unmute
SetVol.exe 100

cd "C:\Hovercast\Apps\nginx"
start nginx.exe