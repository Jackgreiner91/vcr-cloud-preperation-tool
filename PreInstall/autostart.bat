@echo off

cd "C:\Hovercast\apps\SetVol.exe"
SetVol unmute
SetVol 100

cd "C:\Hovercast\Apps\nginx"
start nginx.exe