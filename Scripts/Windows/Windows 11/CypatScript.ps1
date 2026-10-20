# CYPat Enforcer - Full Security & Audit Script (Success-only audit for Logon/Logoff + Credential Validation Failures + Remote Assistance disabled + Defender enabled + FTP disabled + classic Windows Update + LimitBlankPasswordUse)
# Made by Sheeshkidayyy github.com/sheeshkidayyy Also know as Sheesh
$Apply = $true
$AutoYes = $true
$VerbosePreference = "Continue"

function Check-Admin {
    $isAdmin = ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
    if (-not $isAdmin -and $Apply) {
        Write-Error "This script must be run as Administrator to apply changes. Re-run in elevated session."
        exit 1
    }
}

function Force-Action {
    param($Description, [scriptblock]$Action)
    Write-Host "[APPLY ] $Description" -ForegroundColor Green
    if ($Apply) {
        Try { & $Action; Write-Host "Success: $Description" -ForegroundColor Green } 
        Catch { Write-Warning "Failed to apply $Description : $_" }
    }
}

Check-Admin
Write-Host "CYPat Enforcer - APPLY mode active"

# --- 1) Account Lockout Policy ---
Force-Action "Configure Account Lockout Policy" {
    net accounts /lockoutduration:60 /lockoutwindow:60 /lockoutthreshold:5
}

# --- 2) Password Policy ---
Force-Action "Set minimum password length = 10" { net accounts /minpwlen:10 }
Force-Action "Set minimum password age = 5, maximum = 30, enforce history = 20" {
    net accounts /minpwage:5 /maxpwage:30 /uniquepw:20
}
Force-Action "Enable password complexity & disable reversible encryption" {
    $inf = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 10
PasswordHistorySize = 20
MaximumPasswordAge = 30
MinimumPasswordAge = 5
PasswordComplexity = 1
ClearTextPassword = 0
"@
    $infPath = Join-Path -Path $env:TEMP -ChildPath "cypat_password.inf"
    $inf | Out-File -FilePath $infPath -Encoding ASCII
    secedit /configure /db secedit.sdb /cfg $infPath /areas SECURITYPOLICY | Out-Null
}

# --- 3) Set all local users to require password expiration ---
Force-Action "Set all local users to require password expiration" {
    Get-LocalUser | ForEach-Object { Try { Set-LocalUser -Name $_.Name -PasswordExpires $true } Catch {} }
}

# --- 4) Disable anonymous enumeration of SAM accounts ---
Force-Action "Disable anonymous enumeration of SAM accounts" {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -PropertyType DWord -Value 1 -Force
}

# --- 5) Limit local use of blank passwords to console only ---
Force-Action "Limit local use of blank passwords to console only" {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LimitBlankPasswordUse" -PropertyType DWord -Value 1 -Force
}

# --- 6) Disable Autorun for USB drives ---
Force-Action "Disable Autorun for USB drives" {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWord -Force
}

# --- 7) Enable Windows Firewall ---
Force-Action "Enable Windows Firewall for all profiles" {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
}

# --- 8) Windows Update service ---
Force-Action "Set Windows Update service (wuauserv) to Automatic and start" {
    Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
}
Force-Action "Trigger Windows Update scan / download / install (classic wuauclt method)" {
    Try {
        Start-Process "wuauclt.exe" -ArgumentList "/detectnow" -NoNewWindow -Wait
        Start-Process "wuauclt.exe" -ArgumentList "/updatenow" -NoNewWindow -Wait
    } Catch {
        Write-Warning "Failed to trigger Windows Update via wuauclt: $_"
    }
}

# --- 9) Audit Logon/Logoff Events (Success only) + Credential Validation Failures ---
Force-Action "Enable auditing for Logon/Logoff (success only) and Credential Validation (failure only)" {
    $auditSubcatsSuccess = @("Logon","Logoff","Account Lockout","Special Logon","Other Logon/Logoff Events")
    foreach ($sub in $auditSubcatsSuccess) {
        Try { auditpol /set /subcategory:"$sub" /success:enable /failure:disable | Out-Null } 
        Catch { Write-Warning "Failed to set audit for $sub : $_" }
    }

    Try { auditpol /set /subcategory:"Credential Validation" /success:disable /failure:enable | Out-Null } 
    Catch { Write-Warning "Failed to set audit for Credential Validation : $_" }

    Write-Host "Current audit policies:"
    foreach ($sub in $auditSubcatsSuccess + "Credential Validation") {
        Write-Host "`n${sub}:"
        auditpol /get /subcategory:"$sub"
    }
}

# --- 10) Disable Remote Assistance connections ---
Force-Action "Disable Remote Assistance connections" {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Force
}

# --- 11) Enable Windows Defender Real-time Protection ---
Force-Action "Enable Windows Defender Virus & Threat Protection" {
    Try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-Host "Success: Windows Defender real-time protection enabled."
    } Catch {
        Write-Warning "Failed to enable Windows Defender real-time protection: $_"
    }
}

# --- 12) Disable FTP (like Control Panel 'Turn Windows Features on or off') ---
Force-Action "Disable FTP Windows Feature" {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer -ErrorAction SilentlyContinue
    if ($feature -and $feature.State -ne "Disabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer -NoRestart -ErrorAction Stop
        Write-Host "IIS FTP Server disabled (Control Panel style)."
    } else {
        Write-Host "FTP feature already disabled or not present."
    }
}

Write-Host "CYPat Enforcer finished. Security policies applied. FTP disabled. Windows Updates triggered. Media files like .MP3, .MP4, .MP5, .JPEG, .GIF, .TXT were not removed."
