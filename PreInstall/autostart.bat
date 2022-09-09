@echo off

cd "C:\Hovercast\apps\"
SetVol unmute
SetVol 100
SetVol makedefault 

cd "C:\Hovercast\Apps\nginx"
start nginx.exe