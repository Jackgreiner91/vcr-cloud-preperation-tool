$basePath = "C:\Hovercast\temp\"
$latestRelease = Invoke-WebRequest https://github.com/obsproject/obs-studio/releases/latest -Headers @{"Accept"="application/json"}
# The releases are returned in the format {"id":3622206,"tag_name":"hello-1.0.0.11",...}, we have to extract the tag_name.
$json = $latestRelease.Content | ConvertFrom-Json
$latestVersion = $json.tag_name
$fileName = "OBS-Studio-$latestVersion-Full-Installer-x64.exe"
$Path = "$basePath$fileName"

$url = "https://github.com/obsproject/obs-studio/releases/latest/download/$fileName"

Write-Output $Path

$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -URI $URL -OutFile $Path





$privacyRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\"
Set-ItemProperty "$privacyRegPath\microphone" "value" -Value "Allow" -type String
Set-ItemProperty "$privacyRegPath\webcam" "value" -Value "Allow" -type String
$authRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
Set-ItemProperty $authRegPath "AutoAdminLogon" -Value "1" -type String
Set-ItemProperty $authRegPath "DefaultPassword" -Value "ControlRoom!" -type String
Set-ItemProperty $authRegPath "DefaultUsername" -Value "hovercast" -type String




#Stop ServerManager from Launching on Startup 
Set-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -Value 1




$authRegPath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if((Test-Path -Path $authRegPath\DefaultPassword) -eq $true) {Set-ItemProperty -path "$authRegPath" -name "DefaultPassword" -Value "ControlRoom!" -type String} Else {New-Item -path "$authRegPath" -name "DefaultPassword" -Value "ControlRoom!"}

New-Item -path "$authRegPath" -name "DefaultPassword" -Value "ControlRoom!" -type String
Set-ItemProperty "$authRegPath" "DefaultUsername" -Value "hovercast" -type String
Set-ItemProperty "$authRegPath" "AutoAdminLogon" -Value "1" -type String
add-newitem



vMix Config
Default Audio Inputs Skype + Zoom
Template Files On desktop


Install NDI tools last because it stops all other processes. 