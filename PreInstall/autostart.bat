@echo off

cd "C:\Hovercast\apps\"
SetVol makeDefault device  CABLE Input (VB-Audio Virtual Cable)
SetVol 100 device  CABLE Input (VB-Audio Virtual Cable)
SetVol unmute device  CABLE Input (VB-Audio Virtual Cable)
SetVol 100 device CABLE-A Input (VB-Audio Cable A)
SetVol 100 device CABLE-B Input (VB-Audio Cable B)
SetVol 100 device CABLE-C Input (VB-Audio Cable C)
SetVol 100 device CABLE-D Input (VB-Audio Cable D)
SetVol unmute device CABLE-A Input (VB-Audio Cable A)
SetVol unmute device CABLE-B Input (VB-Audio Cable B)
SetVol unmute device CABLE-C Input (VB-Audio Cable C)
SetVol unmute device CABLE-D Input (VB-Audio Cable D)
QRes /x:1920 /y:1080 

cd "C:\Hovercast\Apps\nginx"
start nginx.exe