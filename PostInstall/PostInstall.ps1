$host.ui.RawUI.WindowTitle = "VCR Cloud Preparation Tool"

[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

Function ProgressWriter {
    param (
    [int]$percentcomplete,
    [string]$status
    )
    Write-Progress -Activity "Setting Up Your Machine" -Status $status -PercentComplete $PercentComplete
    }

$path = [Environment]::GetFolderPath("Desktop")


$secure = ConvertTo-SecureString "ControlRoom!" -AsPlainText -force
Set-LocalUser -Name "hovercast" -Password $secure

$privacyRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\"
Set-ItemProperty "$privacyRegPath\microphone" "value" -Value "Allow" -type String
Set-ItemProperty "$privacyRegPath\webcam" "value" -Value "Allow" -type String

$authRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
Set-ItemProperty $authRegPath "AutoAdminLogon" -Value "1" -type String
Set-ItemProperty $authRegPath "DefaultPassword" -Value "ControlRoom!" -type String
Set-ItemProperty $authRegPath "DefaultUsername" -Value "hovercast" -type String


#Creating Folders and moving script files into System directories
function setupEnvironment {
    ProgressWriter -Status "Moving files and folders into place" -PercentComplete $PercentComplete
    if((Test-Path -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Startup) -eq $true) {} Else {New-Item -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Startup -ItemType directory | Out-Null}
    if((Test-Path -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown) -eq $true) {} Else {New-Item -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown -ItemType directory | Out-Null}
    if((Test-Path -Path $env:ProgramData\ParsecLoader) -eq $true) {} Else {New-Item -Path $env:ProgramData\ParsecLoader -ItemType directory | Out-Null}
    if((Test-Path C:\Windows\system32\GroupPolicy\Machine\Scripts\psscripts.ini) -eq $true) {} Else {Move-Item -Path $path\HovercastTemp\PreInstall\psscripts.ini -Destination C:\Windows\system32\GroupPolicy\Machine\Scripts}
    if((Test-Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown\NetworkRestore.ps1) -eq $true) {} Else {Move-Item -Path $path\HovercastTemp\PreInstall\NetworkRestore.ps1 -Destination C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown} 
    if((Test-Path $env:ProgramData\ParsecLoader\clear-proxy.ps1) -eq $true) {} Else {Move-Item -Path $path\HovercastTemp\PreInstall\clear-proxy.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\CreateClearProxyScheduledTask.ps1) -eq $true) {} Else {Move-Item -Path $path\HovercastTemp\PreInstall\CreateClearProxyScheduledTask.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\parsecpublic.cer) -eq $true) {} Else {Move-Item -Path $path\HovercastTemp\PreInstall\parsecpublic.cer -Destination $env:ProgramData\ParsecLoader}
    }

function cloudprovider { 
    #finds the cloud provider that this VM is hosted by
    $gcp = $(
                try {
                    (Invoke-WebRequest -uri http://metadata.google.internal/computeMetadata/v1/ -Method GET -header @{'metadata-flavor'='Google'} -TimeoutSec 5)
                    }
                catch {
                    }
             )

    $aws = $(
                Try {
                    (Invoke-WebRequest -uri http://169.254.169.254/latest/meta-data/ -TimeoutSec 5)
                    }
                catch {
                    }
             )

    $paperspace = $(
                        Try {
                            (Invoke-WebRequest -uri http://metadata.paperspace.com/meta-data/machine -TimeoutSec 5)
                            }
                        catch {
                            }
                    )

    $azure = $(
                  Try {(Invoke-Webrequest -Headers @{"Metadata"="true"} -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text" -TimeoutSec 5)}
                  catch {}              
               )


    if ($GCP.StatusCode -eq 200) {
        "Google Cloud Instance"
        } 
    Elseif ($AWS.StatusCode -eq 200) {
        "Amazon AWS Instance"
        } 
    Elseif ($paperspace.StatusCode -eq 200) {
        "Paperspace Instance"
        }
    Elseif ($azure.StatusCode -eq 200) {
        "Microsoft Azure Instance"
        }
    Else {
        "Generic Instance"
        }
}


add-type  @"
        using System;
        using System.Collections.Generic;
        using System.Text;
        using System.Runtime.InteropServices;
 
        namespace ComputerSystem
        {
            public class LSAutil
            {
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_UNICODE_STRING
                {
                    public UInt16 Length;
                    public UInt16 MaximumLength;
                    public IntPtr Buffer;
                }
 
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_OBJECT_ATTRIBUTES
                {
                    public int Length;
                    public IntPtr RootDirectory;
                    public LSA_UNICODE_STRING ObjectName;
                    public uint Attributes;
                    public IntPtr SecurityDescriptor;
                    public IntPtr SecurityQualityOfService;
                }
 
                private enum LSA_AccessPolicy : long
                {
                    POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
                    POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
                    POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
                    POLICY_TRUST_ADMIN = 0x00000008L,
                    POLICY_CREATE_ACCOUNT = 0x00000010L,
                    POLICY_CREATE_SECRET = 0x00000020L,
                    POLICY_CREATE_PRIVILEGE = 0x00000040L,
                    POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
                    POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
                    POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
                    POLICY_SERVER_ADMIN = 0x00000400L,
                    POLICY_LOOKUP_NAMES = 0x00000800L,
                    POLICY_NOTIFICATION = 0x00001000L
                }
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaRetrievePrivateData(
                            IntPtr PolicyHandle,
                            ref LSA_UNICODE_STRING KeyName,
                            out IntPtr PrivateData
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaStorePrivateData(
                        IntPtr policyHandle,
                        ref LSA_UNICODE_STRING KeyName,
                        ref LSA_UNICODE_STRING PrivateData
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaOpenPolicy(
                    ref LSA_UNICODE_STRING SystemName,
                    ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                    uint DesiredAccess,
                    out IntPtr PolicyHandle
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaNtStatusToWinError(
                    uint status
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaClose(
                    IntPtr policyHandle
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaFreeMemory(
                    IntPtr buffer
                );
 
                private LSA_OBJECT_ATTRIBUTES objectAttributes;
                private LSA_UNICODE_STRING localsystem;
                private LSA_UNICODE_STRING secretName;
 
                public LSAutil(string key)
                {
                    if (key.Length == 0)
                    {
                        throw new Exception("Key lenght zero");
                    }
 
                    objectAttributes = new LSA_OBJECT_ATTRIBUTES();
                    objectAttributes.Length = 0;
                    objectAttributes.RootDirectory = IntPtr.Zero;
                    objectAttributes.Attributes = 0;
                    objectAttributes.SecurityDescriptor = IntPtr.Zero;
                    objectAttributes.SecurityQualityOfService = IntPtr.Zero;
 
                    localsystem = new LSA_UNICODE_STRING();
                    localsystem.Buffer = IntPtr.Zero;
                    localsystem.Length = 0;
                    localsystem.MaximumLength = 0;
 
                    secretName = new LSA_UNICODE_STRING();
                    secretName.Buffer = Marshal.StringToHGlobalUni(key);
                    secretName.Length = (UInt16)(key.Length * UnicodeEncoding.CharSize);
                    secretName.MaximumLength = (UInt16)((key.Length + 1) * UnicodeEncoding.CharSize);
                }
 
                private IntPtr GetLsaPolicy(LSA_AccessPolicy access)
                {
                    IntPtr LsaPolicyHandle;
 
                    uint ntsResult = LsaOpenPolicy(ref this.localsystem, ref this.objectAttributes, (uint)access, out LsaPolicyHandle);
 
                    uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                    if (winErrorCode != 0)
                    {
                        throw new Exception("LsaOpenPolicy failed: " + winErrorCode);
                    }
 
                    return LsaPolicyHandle;
                }
 
                private static void ReleaseLsaPolicy(IntPtr LsaPolicyHandle)
                {
                    uint ntsResult = LsaClose(LsaPolicyHandle);
                    uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                    if (winErrorCode != 0)
                    {
                        throw new Exception("LsaClose failed: " + winErrorCode);
                    }
                }
 
                public void SetSecret(string value)
                {
                    LSA_UNICODE_STRING lusSecretData = new LSA_UNICODE_STRING();
 
                    if (value.Length > 0)
                    {
                        //Create data and key
                        lusSecretData.Buffer = Marshal.StringToHGlobalUni(value);
                        lusSecretData.Length = (UInt16)(value.Length * UnicodeEncoding.CharSize);
                        lusSecretData.MaximumLength = (UInt16)((value.Length + 1) * UnicodeEncoding.CharSize);
                    }
                    else
                    {
                        //Delete data and key
                        lusSecretData.Buffer = IntPtr.Zero;
                        lusSecretData.Length = 0;
                        lusSecretData.MaximumLength = 0;
                    }
 
                    IntPtr LsaPolicyHandle = GetLsaPolicy(LSA_AccessPolicy.POLICY_CREATE_SECRET);
                    uint result = LsaStorePrivateData(LsaPolicyHandle, ref secretName, ref lusSecretData);
                    ReleaseLsaPolicy(LsaPolicyHandle);
 
                    uint winErrorCode = LsaNtStatusToWinError(result);
                    if (winErrorCode != 0)
                    {
                        throw new Exception("StorePrivateData failed: " + winErrorCode);
                    }
                }
            }
        }
"@

#Modifies Local Group Policy to enable Shutdown scrips items
function add-gpo-modifications {
    $querygpt = Get-content C:\Windows\System32\GroupPolicy\gpt.ini
    $matchgpt = $querygpt -match '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}'
    if ($matchgpt -contains "*0000F87571E3*" -eq $false) {
        $gptstring = get-content C:\Windows\System32\GroupPolicy\gpt.ini
        $gpoversion = $gptstring -match "Version"
        $GPO = $gptstring -match "gPCMachineExtensionNames"
        $add = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
        $replace = "$GPO" + "$add"
        (Get-Content "C:\Windows\System32\GroupPolicy\gpt.ini").Replace("$GPO","$replace") | Set-Content "C:\Windows\System32\GroupPolicy\gpt.ini"
        [int]$i = $gpoversion.trim("Version=") 
        [int]$n = $gpoversion.trim("Version=")
        $n +=2
        (Get-Content C:\Windows\System32\GroupPolicy\gpt.ini) -replace "Version=$i", "Version=$n" | Set-Content C:\Windows\System32\GroupPolicy\gpt.ini
        }
    else{
        write-output "Not Required"
        }
    }


#Adds Premade Group Policu Item if existing configuration doesn't exist
function addRegItems{
    ProgressWriter -Status "Adding Registry Items and Group Policy" -PercentComplete $PercentComplete
    if (Test-Path ("C:\Windows\system32\GroupPolicy" + "\gpt.ini")) {
        add-gpo-modifications
        }
    Else {
        Move-Item -Path $path\HovercastTemp\PreInstall\gpt.ini -Destination C:\Windows\system32\GroupPolicy -Force | Out-Null
        }
    regedit /s $path\HovercastTemp\PreInstall\NetworkRestore.reg
    regedit /s $path\HovercastTemp\PreInstall\ForceCloseShutDown.reg
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
    }

function Test-RegistryValue {
    # https://www.jonathanmedd.net/2014/02/testing-for-the-presence-of-a-registry-key-and-value.html
    param (

     [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Path,

    [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Value
    )

    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
        }
    catch {
        return $false
        }

}


#Create ParsecTemp folder in C Drive
function create-directories {
    ProgressWriter -Status "Creating Directories (C:\ParsecTemp)" -PercentComplete $PercentComplete
    if((Test-Path -Path C:\Hovercast) -eq $true) {} Else {New-Item -Path C:\Hovercast -ItemType directory | Out-Null}
    if((Test-Path -Path C:\Hovercast\Apps) -eq $true) {} Else {New-Item -Path C:\Hovercast\Apps -ItemType directory | Out-Null}
    if((Test-Path -Path C:\Hovercast\DirectX) -eq $true) {} Else {New-Item -Path C:\Hovercast\DirectX -ItemType directory | Out-Null}
    if((Test-Path -Path C:\Hovercast\Drivers) -eq $true) {} Else {New-Item -Path C:\Hovercast\Drivers -ItemType Directory | Out-Null}
    }

#disable IE security
function disable-iesecurity {
    ProgressWriter -Status "Disabling Internet Explorer security to enable web browsing" -PercentComplete $PercentComplete
    Set-Itemproperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -name IsInstalled -value 0 -force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name IsInstalled -Value 0 -Force | Out-Null
    Stop-Process -Name Explorer -Force
    }

#download-files-S3
function download-resources {
    ProgressWriter -Status "Downloading DirectX June 2010 Redist" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe", "C:\Hovercast\Apps\directx_Jun2010_redist.exe") 
    ProgressWriter -Status "Downloading Parsec" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsecgaming.com/package/parsec-windows.exe", "C:\Hovercast\Apps\parsec-windows.exe")
    ProgressWriter -Status "Downloading Parsec Virtual Display Driver" -percentcomplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsec.app/vdd/parsec-vdd-0.37.0.0.exe", "C:\Hovercast\Apps\parsec-vdd.exe")
    ProgressWriter -Status "Downloading GPU Updater" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://firebasestorage.googleapis.com/v0/b/controlroom-live.appspot.com/o/app-uploads%2Fwallpaper_5b52c7d7-43a3-410f-b91c-6fe966ed3339.jpg?alt=media&token=907a55b1-60c4-4deb-a88d-056edbfb5849", "C:\Hovercast\hovercastWallpaper.jpg")
    ProgressWriter -Status "Downloading Google Chrome" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi", "C:\Hovercast\Apps\googlechromestandaloneenterprise64.msi")
    ProgressWriter -Status "Downloading vMix25" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://cdn.vmix.com/download/vmix25.exe", "C:\Hovercast\Apps\vmix25.exe") 
    ProgressWriter -Status "Downloading Zoom" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://zoom.us/client/latest/ZoomInstallerFull.msi", "C:\Hovercast\Apps\ZoomInstallerFull.msi") 
    ProgressWriter -Status "Downloading Skype" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://go.skype.com/msi-download", "C:\Hovercast\Apps\skype.msi") 
    ProgressWriter -Status "Downloading NDI5 Tools" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://downloads.ndi.tv/Tools/NDI%205%20Tools.exe", "C:\Hovercast\Apps\NDI5.exe") 
    ProgressWriter -Status "Downloading VideoCom Zoom NDI Bridge" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://videocom.at/downloads/VideoCom%20-%20Zoom%20Bridge%20for%20NDI-1.4.2%20Setup.exe", "C:\Hovercast\Apps\VideoCom.NDI.Bridge.exe") 
    ProgressWriter -Status "Moving Files from TEMP" -PercentComplete $PercentComplete
    Move-Item -path "$path\HovercastTemp\PreInstall\VBCable_CD_PackSetup.exe" -Destination "c:\hovercast\apps\VBCable_CD_PackSetup.exe"
    Move-Item -path "$path\HovercastTemp\PreInstall\autostart.bat" -Destination "c:\hovercast\apps\autostart.bat"
    Move-Item -path "$path\HovercastTemp\PreInstall\SetVol.exe" -Destination "c:\hovercast\apps\SetVol.exe"
    Move-Item -path "$path\HovercastTemp\PreInstall\template assets" -Destination "c:\users\hovercast\documents"
    Move-Item -path "$path\HovercastTemp\PreInstall\admin" -Destination "c:\users\hovercast\desktop"
    ProgressWriter -Status "Downloading OBS" -PercentComplete $PercentComplete
    $latestRelease = Invoke-WebRequest https://api.github.com/repos/obsproject/obs-studio/releases/latest -Headers @{"Accept"="application/json"}
    # The releases are returned in the format {"id":3622206,"tag_name":"hello-1.0.0.11",...}, we have to extract the tag_name.
    $json = $latestRelease.Content | ConvertFrom-Json
    $fileName = $json.assets.name[0]
    $url = "https://github.com/obsproject/obs-studio/releases/latest/download/$fileName"
    (New-Object System.Net.WebClient).DownloadFile("$URL", "C:\Hovercast\Apps\OBS.exe") 
    }

#install-base-files-silently
function install-windows-features {
    ProgressWriter -Status "Installing Chrome" -PercentComplete $PercentComplete
    start-process -filepath "C:\Windows\System32\msiexec.exe" -ArgumentList '/qn /i "C:\Hovercast\Apps\googlechromestandaloneenterprise64.msi"' -Wait
    ProgressWriter -Status "Installing DirectX June 2010 Redist" -PercentComplete $PercentComplete
    Start-Process -FilePath "C:\Hovercast\Apps\directx_jun2010_redist.exe" -ArgumentList '/T:C:\Hovercast\DirectX /Q'-wait
    ProgressWriter -Status "Installing DirectX" -PercentComplete $PercentComplete
    Start-Process -FilePath "C:\Hovercast\DirectX\DXSETUP.EXE" -ArgumentList '/silent' -wait
    ProgressWriter -Status "Installing Direct Play" -PercentComplete $PercentComplete
    Install-WindowsFeature Direct-Play | Out-Null
    ProgressWriter -Status "Installing .net 3.5" -PercentComplete $PercentComplete
    Install-WindowsFeature Net-Framework-Core | Out-Null
    ProgressWriter -Status "Installing Skype" -PercentComplete $PercentComplete
    start-process -filepath "C:\Windows\System32\msiexec.exe" -ArgumentList '/qn /i "C:\Hovercast\Apps\skype.msi"' -Wait
    ProgressWriter -Status "Installing Zoom" -PercentComplete $PercentComplete
    start-process -filepath "C:\Windows\System32\msiexec.exe" -ArgumentList '/qn /i "C:\Hovercast\Apps\ZoomInstallerFull.msi"' -Wait
    ProgressWriter -Status "Installing vMix25" -PercentComplete $PercentComplete
    Start-Process -FilePath "C:\Hovercast\Apps\vmix25.exe" -ArgumentList '/verysilent' -wait
    ProgressWriter -Status "Installing NDI Tools" -PercentComplete $PercentComplete
    ProgressWriter -Status "Cleaning up" -PercentComplete $PercentComplete
    Remove-Item -Path C:\Hovercast\DirectX -force -Recurse 
    }


#set update policy
function set-update-policy {
    ProgressWriter -Status "Disabling Windows Update" -PercentComplete $PercentComplete
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'UpdateServiceURLAlternative') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUSatusServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null}
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -value 'UseWUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null} else {new-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null}
    }

#set automatic time and timezone
function set-time {
    ProgressWriter -Status "Setting computer time to automatic" -PercentComplete $PercentComplete
    Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name Type -Value NTP | Out-Null
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name Start -Value 00000003 | Out-Null
    }

#disable new network window
function disable-network-window {
    ProgressWriter -Status "Disabling New Network Window" -PercentComplete $PercentComplete
    if((Test-RegistryValue -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value NewNetworkWindowOff)-eq $true) {} Else {new-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null}
    }

#Enable Pointer Precision 
function enhance-pointer-precision {
    ProgressWriter -Status "Enabling enchanced pointer precision" -PercentComplete $PercentComplete
    Set-Itemproperty -Path 'HKCU:\Control Panel\Mouse' -Name MouseSpeed -Value 1 | Out-Null
    }

#enable Mouse Keys
function enable-mousekeys {
    ProgressWriter -Status "Enabling mouse keys to assist with mouse cursor" -PercentComplete $PercentComplete
    set-Itemproperty -Path 'HKCU:\Control Panel\Accessibility\MouseKeys' -Name Flags -Value 63 | Out-Null
    }


#Sets all applications to force close on shutdown
function force-close-apps {
    ProgressWriter -Status "Setting Windows not to stop shutdown if there are unsaved apps" -PercentComplete $PercentComplete
    if (((Get-Item -Path "HKCU:\Control Panel\Desktop").GetValue("AutoEndTasks") -ne $null) -eq $true) {
        Set-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
        }
    Else {
        New-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
        }
    }

#show hidden items
function show-hidden-items {
    ProgressWriter -Status "Showing hidden files in Windows Explorer" -PercentComplete $PercentComplete
    set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1 | Out-Null
    }

#show file extensions
function show-file-extensions {
    ProgressWriter -Status "Showing file extensions in Windows Explorer" -PercentComplete $PercentComplete
    Set-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name HideFileExt -Value 0 | Out-Null
    }

#disable logout start menu
function disable-logout {
    ProgressWriter -Status "Disabling log out button on start menu" -PercentComplete $PercentComplete
    if((Test-RegistryValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Value StartMenuLogOff )-eq $true) {Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null} Else {New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null}
    }

#disable lock start menu
function disable-lock {
    ProgressWriter -Status "Disabling option to lock your Windows user profile" -PercentComplete $PercentComplete
    if((Test-Path -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null}
    if((Test-RegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Value DisableLockWorkstation) -eq $true) {Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null } Else {New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null}
    }

#set wallpaper
function set-wallpaper {
    ProgressWriter -Status "Setting the Parsec logo ass the computer wallpaper" -PercentComplete $PercentComplete
    if((Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name "System" | Out-Null}
    if((Test-RegistryValue -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -value Wallpaper) -eq $true) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name Wallpaper -value "C:\Hovercast\hovercastWallpaper.jpg" | Out-Null} Else {New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name Wallpaper -PropertyType String -value "C:\Hovercast\hovercastWallpaper.jpg" | Out-Null}
    if((Test-RegistryValue -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -value WallpaperStyle) -eq $true) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name WallpaperStyle -value 2 | Out-Null} Else {New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name WallpaperStyle -PropertyType String -value 2 | Out-Null}
    Stop-Process -ProcessName explorer
    }

#disable recent start menu items
function disable-recent-start-menu {
    New-Item -path HKLM:\SOFTWARE\Policies\Microsoft\Windows -name Explorer
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -PropertyType DWORD -Name HideRecentlyAddedApps -Value 1
    }


#Disables Server Manager opening on Startup
function disable-server-manager {
    ProgressWriter -Status "Disabling Windows Server Manager from starting at startup" -PercentComplete $PercentComplete
    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
    }

#AWS Clean up Desktop Items
function clean-aws {
    remove-item -path "$path\EC2 Feedback.Website"
    Remove-Item -Path "$path\EC2 Microsoft Windows Guide.website"
    }

function nginx {
    New-Item -Path "C:\Hovercast\Apps\nginx" -ItemType Directory| Out-Null
    Expand-Archive -Path "C:\Users\hovercast\Desktop\HovercastTemp\PreInstall\nginx.zip" -DestinationPath "C:\Hovercast\Apps\nginx"
    cmd.exe /c  "C:\Hovercast\Apps\nginx\windows firewall\open.firewall.ports_run.as.admin.bat"
    cmd.exe /c  "C:\Hovercast\Apps\autostart.bat"
    $action = New-ScheduledTaskAction -Execute 'C:\Hovercast\Apps\autostart.bat'
    $trigger =  New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME 
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "startNginX" -RunLevel Highest
    Write-Output "Successfully Created"
}


function AudioInstall0 {
    New-Item -Path "C:\Hovercast\Apps\VBCable0" -ItemType Directory| Out-Null
    Expand-Archive -Path "$path\HovercastTemp\PreInstall\VBCABLE_Driver_Pack43.zip" -DestinationPath "C:\Hovercast\Apps\VBCable0"
    $pathToCatFile = "C:\Hovercast\Apps\VBCable0\vbaudio_cable64_win7.cat"
    $FullCertificateExportPath = "C:\Hovercast\Apps\VBCable0\VBCert.cer"
    $VB = @{}
    $VB.DriverFile = $pathToCatFile;
    $VB.CertName = $FullCertificateExportPath;
    $VB.ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
    $VB.Cert = (Get-AuthenticodeSignature -filepath $VB.DriverFile).SignerCertificate;
    [System.IO.File]::WriteAllBytes($VB.CertName, $VB.Cert.Export($VB.ExportType))
    Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -FilePath $VB.CertName | Out-Null
    Start-Process -FilePath "C:\Hovercast\Apps\VBCable0\VBCABLE_Setup_x64.exe" -ArgumentList '-i','-h' -wait
    Set-Service -Name audiosrv -StartupType Automatic
    Start-Service -Name audiosrv
    }

function AudioInstall1 {
    New-Item -Path "C:\Hovercast\Apps\VBCable1" -ItemType Directory| Out-Null
    Expand-Archive -Path "$path\HovercastTemp\PreInstall\VBCABLE_A_Driver_Pack43.zip" -DestinationPath "C:\Hovercast\Apps\VBCable1"
    $pathToCatFile = "C:\Hovercast\Apps\VBCable1\vbaudio_cablea_win7.cat"
    $FullCertificateExportPath = "C:\Hovercast\Apps\VBCable1\VBCert.cer"
    $VB = @{}
    $VB.DriverFile = $pathToCatFile;
    $VB.CertName = $FullCertificateExportPath;
    $VB.ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
    $VB.Cert = (Get-AuthenticodeSignature -filepath $VB.DriverFile).SignerCertificate;
    [System.IO.File]::WriteAllBytes($VB.CertName, $VB.Cert.Export($VB.ExportType))
    Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -FilePath $VB.CertName | Out-Null
    Start-Process -FilePath "C:\Hovercast\Apps\VBCable1\VBCABLE_Setup_x64.exe" -ArgumentList '-i','-h' -wait
    Set-Service -Name audiosrv -StartupType Automatic
    Start-Service -Name audiosrv
}

function AudioInstall2 {
    New-Item -Path "C:\Hovercast\Apps\VBCable2" -ItemType Directory| Out-Null
    Expand-Archive -Path "$path\HovercastTemp\PreInstall\VBCABLE_B_Driver_Pack43.zip" -DestinationPath "C:\Hovercast\Apps\VBCable2"
    $pathToCatFile = "C:\Hovercast\Apps\VBCable2\vbaudio_cableb_win7.cat"
    $FullCertificateExportPath = "C:\Hovercast\Apps\VBCable2\VBCert.cer"
    $VB = @{}
    $VB.DriverFile = $pathToCatFile;
    $VB.CertName = $FullCertificateExportPath;
    $VB.ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
    $VB.Cert = (Get-AuthenticodeSignature -filepath $VB.DriverFile).SignerCertificate;
    [System.IO.File]::WriteAllBytes($VB.CertName, $VB.Cert.Export($VB.ExportType))
    Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -FilePath $VB.CertName | Out-Null
    Start-Process -FilePath "C:\Hovercast\Apps\VBCable2\VBCABLE_Setup_x64.exe" -ArgumentList '-i','-h' -wait
    Set-Service -Name audiosrv -StartupType Automatic
    Start-Service -Name audiosrv
}

function AudioInstall3 {
    Start-Process -FilePath "C:\Hovercast\Apps\VBCable2\VBCABLE_Setup_x64.exe" -ArgumentList '/S', '-i','-h' -wait
    Set-Service -Name audiosrv -StartupType Automatic
    Start-Service -Name audiosrv
}



#7Zip is required to extract the Parsec-Windows.exe File
function Install7Zip {
    $url = Invoke-WebRequest -Uri https://www.7-zip.org/download.html
    (New-Object System.Net.WebClient).DownloadFile("https://www.7-zip.org/$($($($url.Links | Where-Object outertext -Like "Download")[1]).OuterHTML.split('"')[1])" ,"C:\Hovercast\Apps\7zip.exe")
    Start-Process C:\Hovercast\Apps\7zip.exe -ArgumentList '/S /D="C:\Program Files\7-Zip"' -Wait
    }

Function Server2019Controller {
    ProgressWriter -Status "Adding Xbox 360 Controller driver to Windows Server 2019" -PercentComplete $PercentComplete
    if ((gwmi win32_operatingsystem | % caption) -like '*Windows Server 2019*') {
        (New-Object System.Net.WebClient).DownloadFile("http://www.download.windowsupdate.com/msdownload/update/v3-19990518/cabpool/2060_8edb3031ef495d4e4247e51dcb11bef24d2c4da7.cab", "C:\Hovercast\Drivers\Xbox360_64Eng.cab")
        if((Test-Path -Path C:\Hovercast\Drivers\Xbox360_64Eng) -eq $true) {} Else {New-Item -Path C:\Hovercast\Drivers\Xbox360_64Eng -ItemType directory | Out-Null}
        cmd.exe /c "C:\Windows\System32\expand.exe C:\Hovercast\Drivers\Xbox360_64Eng.cab -F:* C:\Hovercast\Drivers\Xbox360_64Eng" | Out-Null
        cmd.exe /c '"C:\Program Files\Parsec\vigem\10\x64\devcon.exe" dp_add "C:\Hovercast\Drivers\Xbox360_64Eng\xusb21.inf"' | Out-Null
        }
    }

Function InstallParsec {
    Start-Process "C:\Hovercast\Apps\parsec-windows.exe" -ArgumentList "/silent", "/shared" -wait
    }

Function InstallParsecVDD {
    ProgressWriter -Status "Installing Parsec Virtual Display Driver" -PercentComplete $PercentComplete
    Import-Certificate -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" -FilePath "$env:ProgramData\ParsecLoader\parsecpublic.cer" | Out-Null
    Start-Process "C:\Hovercast\Apps\parsec-vdd.exe" -ArgumentList "/silent" 
    $iterator = 0    
    do {
        Start-Sleep -s 2
        $iterator++
        }
    Until (($null -ne ((Get-PnpDevice | Where-Object {$_.Name -eq "Parsec Virtual Display Adapter"}).DeviceID)) -or ($iterator -gt 7))
    if (Get-process -name parsec-vdd -ErrorAction SilentlyContinue) {
        Stop-Process -name parsec-vdd -Force
        }
    $configfile = Get-Content C:\ProgramData\Parsec\config.txt
    $configfile += "host_virtual_monitors = 1"
    $configfile += "host_privacy_mode = 1"
    $configfile | Out-File C:\ProgramData\Parsec\config.txt -Encoding ascii
}

#Apps that require human intervention
function Install-Gaming-Apps {
    ProgressWriter -Status "Installing Parsec, ViGEm https://github.com/ViGEm/ViGEmBus and 7Zip" -PercentComplete $PercentComplete
    Install7Zip
    InstallParsec
    #if((Test-RegistryValue -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -value "Parsec.App.0") -eq $true) {Set-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name "Parsec.App.0" -Value "C:\Program Files\Parsec\parsecd.exe" | Out-Null} Else {New-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name "Parsec.App.0" -Value "C:\Program Files\Parsec\parsecd.exe" | Out-Null}
    Start-Process -FilePath "C:\Program Files\Parsec\parsecd.exe"
    Start-Sleep -s 1
    }

#Disable Devices
function disable-devices {
    ProgressWriter -Status "Disabling Microsoft Basic Display Adapter, Generic Non PNP Monitor and other devices" -PercentComplete $PercentComplete
    Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "HDAUDIO\FUNC_01&VEN_10DE&DEV_0083&SUBSYS_10DE11A3*"'
    Get-PnpDevice | where {$_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Get-PnpDevice | where {$_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Get-PnpDevice | where {$_.friendlyname -like "Google Graphics Array (GGA)" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Get-PnpDevice | where {$_.friendlyname -like "Microsoft Hyper-V Video" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1013&DEV_00B8*"'
    Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1D0F&DEV_1111*"'
    Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1AE0&DEV_A002*"'
    }

#Cleanup
function clean-up {
    ProgressWriter -Status "Deleting temporary files from C:\ParsecTemp" -PercentComplete $PercentComplete
    Remove-Item -Path C:\Hovercast\Drivers -force -Recurse
    Remove-Item -Path $path\ParsecTemp -force -Recurse
    }


#cleanup recent files
function clean-up-recent {
    ProgressWriter -Status "Delete recently accessed files list from Windows Explorer" -PercentComplete $PercentComplete
    remove-item "$env:AppData\Microsoft\Windows\Recent\*" -Recurse -Force | Out-Null
    }


function Install-NDI-Tools {
    Start-Job -FilePath "$path\HovercastTemp\preinstall\ndi-tools-install.ps1"
}
 


function Install-OBS-with-NDI {
    New-Item "C:\Program Files\obs-studio" -ItemType directory
    Copy-Item -path "$path\HovercastTemp\PreInstall\obs-studio\" -Destination "C:\Program Files" -Force -recurse
    Start-Process -FilePath "C:\Hovercast\Apps\OBS.exe" -ArgumentList '/S' -wait
    }
    






    Write-Host -foregroundcolor red " ,,,                                      
                                ,,,,,,,,,,,,,,,,,                               
                           ,,,,,,,,,,,,,,,,,,,,,,,,,,                           
                       ,,,,,,,,,,,,           ,,,,,,,,,,,,                      
                   ,,,,,,,,,,,                    ,,,,,,,,,,,,                  
              .,,,,,,,,,,,                            .,,,,,,,,,,,              
          ,,,,,,,,,,,,               ,,,,,,                ,,,,,,,,,,,,         
      ,,,,,,,,,,,,               ,,,,,,,,,,,,,,,               ,,,,,,,,,,,,     
  ,,,,,,,,,,,                ,,,,,,,,,,,,,,,,,,,,,,,               .,,,,,,,,,,, 
 ,,,,,,,,               ,,,,,,,,,,,,         ,,,,,,,,,,,                ,,,,,,,,
,,,,,,              ,,,,,,,,,,,,,,,              ,,,,,,,,,,,,             ,,,,,,
 ,,,,,,,,,.     ,,,,,,,,,,,,,,,,,,,,,,,              ,,,,,,,,,,,,     ,,,,,,,,,,
   ,,,,,,,,,,,,,,,,,,,,      ,,,,,,,,.                    ,,,,,,,,,,,,,,,,,,,,  
       (,,,,,,,,,,,                            ,              ,,,,,,,,,,,(      
   ,,(((((((,,,,,,,,,,,,                   ,,,,,,,,,     .,,,,,,,,,,,((((((/,,  
 ,,,,,,,,*      ,,,,,,,,,,,,              ,,,,,,,,,,,,,,,,,,,,,,,     ,,,,,,,,,,
,,,,,,               ,,,,,,,,,,,              ,,,,,,,,,,,,,,               ,,,,,
 ,,,,,,,,                ,,,,,,,,,,,.       .,,,,,,,,,,,                ,,,,,,,,
  ,,,,,,,,,,,,               ,,,,,,,,,,,,,,,,,,,,,,,               ,,,,,,,,,,,. 
      ,,,,,,,,,,,,               .,,,,,,,,,,,,,.               ,,,,,,,,,,,,     
           ,,,,,,,,,,,                ,,,,,                ,,,,,,,,,,,          
               ,,,,,,,,,,,.                           ,,,,,,,,,,,,              
                   ,,,,,,,,,,,,                   ,,,,,,,,,,,,                  
                        ,,,,,,,,,,,           ,,,,,,,,,,,                       
                            ,,,,,,,,,,,,,,,,,,,,,,,,,                           
                                ,,,,,,,,,,,,,,,,,                               
                                       ,,,  

                           ~Hovercast VCR Cloud Prep Tool~

                    This script sets up your cloud computer
                    with a bunch of settings and drivers
                    to make your life easier.  
                    
                    It's provided with no warranty, 
                    so use it at your own risk.
                    
                    Check out the README.md for more
                    information.

"   
$ScripttaskList = @(
"setupEnvironment";
"addRegItems";
"create-directories";
"disable-iesecurity";
"download-resources";
"Install-NDI-Tools";
"install-windows-features";
"Install-OBS-with-NDI"
"force-close-apps";
"disable-network-window";
"disable-logout";
"disable-lock";
'nginx';
"show-hidden-items";
"show-file-extensions";
"enhance-pointer-precision";
"enable-mousekeys";
"set-time";
"set-wallpaper";
"disable-server-manager";
"Install-Gaming-Apps";
"disable-devices";
"InstallParsecVDD";
"AudioInstall0";
"AudioInstall1";
"AudioInstall2";
"AudioInstall3";
"Server2019Controller";
)

foreach ($func in $ScripttaskList) {
    $PercentComplete =$($ScriptTaskList.IndexOf($func) / $ScripttaskList.Count * 100)
    & $func $PercentComplete
    }

ProgressWriter -status "Done" -percentcomplete 100


Write-host "DONE!" -ForegroundColor black -BackgroundColor Green
if ($DontPromptPasswordUpdateGPU) {} 
Else {pause}