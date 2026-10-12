# CYPat Enforcer - Windows Server 2019 Full Security & All-Audit Policies [V3] BIG BOY
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
Write-Host "CYPat Enforcer - APPLY mode active on Windows Server 2019"

# --- 1) Account Lockout Policy ---
Force-Action "Configure Account Lockout Policy" {
    net accounts /lockoutduration:60 /lockoutwindow:60 /lockoutthreshold:10
}

# --- 2) Password Policy ---
Force-Action "Set minimum password length = 10" {
    net accounts /minpwlen:10
}

Force-Action "Set minimum password age = 5, maximum = 30, enforce history = 20" {
    net accounts /minpwage:5 /maxpwage:30 /uniquepw:20
}

Force-Action "Disable storing passwords using reversible encryption (local only)" {
    $inf = @"
[Unicode]
Unicode=yes
[System Access]
ClearTextPassword = 0
"@

    $infPath    = Join-Path -Path $env:TEMP -ChildPath "cypat_password_cleartext.inf"
    $dbPath     = Join-Path -Path $env:TEMP -ChildPath "cypat_secedit.sdb"
    $exportPath = Join-Path -Path $env:TEMP -ChildPath "cypat_secpol_export.inf"

    try {
        $inf | Out-File -FilePath $infPath -Encoding ASCII -Force

        # Apply the INF to the local security policy
        secedit /configure /db $dbPath /cfg $infPath /areas SECURITYPOLICY | Out-Null

        Start-Sleep -Seconds 2

        # Export the effective local policy and verify ClearTextPassword
        secedit /export /cfg $exportPath 2>$null

        $match = Select-String -Path $exportPath -Pattern "ClearTextPassword" -SimpleMatch -ErrorAction SilentlyContinue
        if ($match -and $match.Line -match "ClearTextPassword\s*=\s*0") {
            Write-Host "Verified: 'Store passwords using reversible encryption' is DISABLED (ClearTextPassword = 0)." -ForegroundColor Green
        } else {
            Write-Warning "Verification: 'ClearTextPassword' is not 0 in exported local policy. A Group Policy may be overriding this setting."
            Write-Host "Exported policy saved at: $exportPath"
        }
    } catch {
        Write-Warning "Failed to apply/verify reversible password setting: $_"
    }
}

# --- 3) Require password expiration for all local users ---
Force-Action "Set all local users to require password expiration" {
    Get-LocalUser | ForEach-Object { Try { Set-LocalUser -Name $_.Name -PasswordExpires $true } Catch {} }
}

# --- 4) Disable anonymous enumeration of SAM accounts ---
Force-Action "Disable anonymous enumeration of SAM accounts" {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -PropertyType DWord -Value 1 -Force | Out-Null
}




# --- 5) Disable Autorun for USB drives ---
Force-Action "Disable Autorun for USB drives" {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" -Name "Explorer" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWord -Force | Out-Null
}


# --- 6) Windows Update service (handled in section 11) ---

# --- 7) ADVANCED AUDIT POLICY: dynamic enumeration + apply Success & Failure ---
Write-Host "Capturing existing advanced audit settings (before)..." -ForegroundColor Cyan
$beforeFile = Join-Path $env:TEMP "cypat_audit_before.txt"
& auditpol /get /subcategory:* > $beforeFile 2>&1

Write-Host "Detecting available advanced audit subcategories..." -ForegroundColor Cyan
$rawList = (& auditpol /list /subcategory:* ) 2>&1

# --- 8) Trim and filter likely empty/header lines; we'll attempt to set each trimmed line and ignore failures.
# Filter out category-level items (which cause 0x57 errors) — only keep true subcategories
$categories = @("Account Logon", "Account Management", "Category/Subcategory", "Detailed Tracking", "DS Access", "Logon/Logoff", "Object Access", "Policy Change", "Privilege Use", "System")
$subcategories = $rawList | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -ne " ") -and ($categories -notcontains $_) } | Sort-Object -Unique

Write-Host "Found $($subcategories.Count) entries to attempt." -ForegroundColor Cyan

foreach ($subcategory in $subcategories) {
    try {
        Write-Host "Enabling advanced audit on: $subcategory (Success & Failure)"
        # Some lines may not be valid subcategory names; auditpol will error — catch suppresses that.
        auditpol /set /subcategory:"$subcategory" /success:enable /failure:enable | Out-Null
    }
    catch {
        Write-Warning "Error applying advanced audit policy to: $subcategory — $_"
    }
}

Write-Host "Capturing advanced audit settings (after)..." -ForegroundColor Cyan
$afterFile = Join-Path $env:TEMP "cypat_audit_after.txt"
& auditpol /get /subcategory:* > $afterFile 2>&1

# --- 9) Save gpresult to help identify GPO overrides
Write-Host "Capturing Group Policy result (gpresult)..." -ForegroundColor Cyan
$gpFile = Join-Path $env:TEMP "cypat_gpresult.txt"
Try {
    gpresult /r > $gpFile 2>&1
} Catch {
    Write-Warning "Failed to run gpresult: $_"
}

Write-Host "Advanced audit apply step completed. Before/After saved to:" -ForegroundColor Green
Write-Host "  $beforeFile"
Write-Host "  $afterFile"
Write-Host "  $gpFile"

# --- 9.1) Verification: report subcategories still set to No Auditing and show gpresult ---
$reportFile = Join-Path $env:TEMP "cypat_audit_verify.txt"
Add-Content -Path $reportFile -Value ("Audit verification report - {0}" -f (Get-Date -Format o))

# --- 9.2) Show any subcategories still No Auditing
Add-Content -Path $reportFile -Value "== Subcategories with 'No Auditing' =="
$auditNo = Get-Content -Path $afterFile | Select-String -Pattern "No Auditing" -Context 1,0
if ($auditNo) {
    # write the matched lines and the preceding name line to report
    $auditNo | ForEach-Object {
        Add-Content -Path $reportFile -Value ($_.Context.PreContext + $_.Line)
        Add-Content -Path $reportFile -Value "----"
    }
    Write-Host "Some subcategories remain set to 'No Auditing'. See $reportFile" -ForegroundColor Yellow
} else {
    Add-Content -Path $reportFile -Value "All available subcategories show auditing configured (no 'No Auditing' matches)."
    Write-Host "All available advanced subcategories appear configured." -ForegroundColor Green
}

# --- 9.3) Save a small summary of gpresult (look for GPOs configuring Advanced Audit Policy)
Add-Content -Path $reportFile -Value "`n== Group Policy Summary (gpresult excerpt) =="
try {
    # show only lines mentioning Advanced Audit Policy or Security Settings to keep summary short
    Select-String -Path $gpFile -Pattern "Advanced Audit Policy|Security Settings|Audit" -SimpleMatch -Context 0,1 | ForEach-Object {
        Add-Content -Path $reportFile -Value ($_.Line)
    }
    Add-Content -Path $reportFile -Value "`nFull gpresult saved at: $gpFile"
} catch {
    Add-Content -Path $reportFile -Value "Failed to process gpresult: $_"
}

# --- 9.4) Optional: open the report automatically if running interactively
if (-not $DryRun) {
    Write-Host "Audit verification saved to: $reportFile"
    # Uncomment the following line to auto-open the report in Notepad (interactive sessions only)
    # Start-Process notepad.exe -ArgumentList $reportFile
}

# --- 10) Enable Windows Defender Real-time Protection ---
Force-Action "Enable Windows Defender Virus & Threat Protection" {
    Try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-Host "Success: Windows Defender real-time protection enabled."
    } Catch {
        Write-Warning "Failed to enable Windows Defender real-time protection: $_"
    }
}

# --- 11) Automatic Windows Updates ---
Force-Action "Enable Automatic Windows Updates" {
    Try {
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction Stop

        $AUKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
        If (-Not (Test-Path $AUKey)) { New-Item -Path $AUKey -Force | Out-Null }
        Set-ItemProperty -Path $AUKey -Name "AUOptions" -Value 4 -Force
        # Trigger an immediate scan/install attempt (best-effort)
        Try {
            Start-Process "wuauclt.exe" -ArgumentList "/detectnow" -NoNewWindow -Wait -ErrorAction Stop
            Start-Process "wuauclt.exe" -ArgumentList "/updatenow" -NoNewWindow -Wait -ErrorAction Stop
        } Catch {
            Write-Warning "Failed to trigger Windows Update via wuauclt: $_"
        }

        Write-Host "Automatic Windows Updates enabled and configured." -ForegroundColor Green
    } Catch {
        Write-Warning "Failed to enable/configure automatic updates: $_"
    }
}

# --- 12) Disable Microsoft FTP Server Service ---
Force-Action "Disable Microsoft FTP Server Service" {
    Try {
        $ftpService = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
        if ($ftpService -and $ftpService.Status -ne 'Stopped') {
            Stop-Service -Name FTPSVC -Force -ErrorAction Stop
            Write-Host "Microsoft FTP Server service stopped." -ForegroundColor Green
        }

        if ($ftpService) {
            Set-Service -Name FTPSVC -StartupType Disabled -ErrorAction Stop
            Write-Host "Microsoft FTP Server service disabled." -ForegroundColor Green
        } else {
            Write-Host "Microsoft FTP Server service not installed, nothing to disable." -ForegroundColor Yellow
        }
    } Catch {
        Write-Warning "Failed to stop/disable Microsoft FTP Server service: $_"
    }
}

# --- 13) Disable & Stop Simple Mail Transfer Protocol (SMTP) Service ---
Force-Action "Disable Simple Mail Transfer Protocol (SMTP) Service" {
    Try {
        # Common SMTP service name for the built-in IIS SMTP service
        $smtpService = Get-Service -Name SMTPSVC -ErrorAction SilentlyContinue

        if ($smtpService) {
            if ($smtpService.Status -ne 'Stopped') {
                Stop-Service -Name SMTPSVC -Force -ErrorAction Stop
                Write-Host "SMTP service stopped." -ForegroundColor Green
            }
            Set-Service -Name SMTPSVC -StartupType Disabled -ErrorAction Stop
            Write-Host "SMTP service disabled." -ForegroundColor Green
        } else {
            Write-Host "SMTP service (SMTPSVC) not installed on this server." -ForegroundColor Yellow
        }

        # Optional: remove the Windows feature if present (Server Manager)
        $smtpFeature = Get-WindowsFeature -Name SMTP-Server -ErrorAction SilentlyContinue
        if ($smtpFeature -and $smtpFeature.Installed) {
            Uninstall-WindowsFeature -Name SMTP-Server -ErrorAction Stop
            Write-Host "SMTP Server Windows feature removed." -ForegroundColor Green
        }
    } Catch {
        Write-Warning "Failed to stop/disable/remove SMTP service/feature: $_"
    }
}

# --- 14) Limit local use of blank passwords to console only ---
Force-Action "Limit local use of blank passwords to console only" {
    Try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -PropertyType DWord -Value 1 -Force | Out-Null
        Write-Host "Configured: LimitBlankPasswordUse = 1" -ForegroundColor Green
    } Catch {
        Write-Warning "Failed to set LimitBlankPasswordUse: $_"
    }
}

# --- 14.5) Require Ctrl+Alt+Delete for login (Secure Attention Sequence) ---
Force-Action "Enable Ctrl+Alt+Delete requirement for login" {
    Try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -PropertyType DWord -Value 0 -Force | Out-Null
        Write-Host "Configured: Ctrl+Alt+Delete logon requirement ENABLED (SAS protected)" -ForegroundColor Green
    } Catch {
        Write-Warning "Failed to enable Ctrl+Alt+Delete requirement: $_"
    }
}

# --- 15) Enable 'Microsoft network server: Digitally sign communications (always)' ---
Force-Action "Enable Microsoft network server: Digitally sign communications (always)" {
    Try {
        # Enable SMB signing on the server (enforce signing)
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -PropertyType DWord -Value 1 -Force | Out-Null
        Write-Host "Configured: RequireSecuritySignature = 1 and EnableSecuritySignature = 1" -ForegroundColor Green

        # Try to restart the Server service to apply immediately (may disrupt SMB sessions)
        Try {
            Restart-Service -Name LanmanServer -Force -ErrorAction Stop
            Write-Host "Server service restarted to apply SMB signing settings." -ForegroundColor Green
        } Catch {
            Write-Warning "Could not restart LanmanServer service automatically: $_. A reboot may be required to apply the setting."
        }
    } Catch {
        Write-Warning "Failed to enable SMB server signing: $_"
    }
}

# --- 16) Disable SMB v1 (legacy insecure protocol) ---
Force-Action "Disable SMB v1 protocol" {
    Try {
        # Disable SMB v1 via registry (applies to both server and client)
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -PropertyType DWord -Value 0 -Force | Out-Null
        Write-Host "Configured: SMB v1 disabled (SMB1 = 0)" -ForegroundColor Green

        # Optional: remove the SMB 1.0/CIFS feature on Server 2019 (if installed)
        $smbv1Feature = Get-WindowsFeature -Name FS-SMB1 -ErrorAction SilentlyContinue
        if ($smbv1Feature -and $smbv1Feature.Installed) {
            Try {
                Uninstall-WindowsFeature -Name FS-SMB1 -ErrorAction Stop
                Write-Host "SMB 1.0/CIFS Windows feature removed." -ForegroundColor Green
            } Catch {
                Write-Warning "Could not uninstall FS-SMB1 feature: $_"
            }
        } else {
            Write-Host "SMB 1.0/CIFS feature not installed (nothing to remove)." -ForegroundColor Yellow
        }
    } Catch {
        Write-Warning "Failed to disable SMB v1: $_"
    }
}

# --- 17) Browser Security (Firefox & Chrome) ---
Force-Action "Harden Browsers (Disable Password Saving)" {
    # 1. Firefox Hardening via Registry
    $ffPath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
    if (-not (Test-Path $ffPath)) { New-Item -Path $ffPath -Force | Out-Null }
    
    # Disable Password Manager and the 'Offer to Save' prompt
    New-ItemProperty -Path $ffPath -Name "PasswordManagerEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ffPath -Name "OfferToSaveLogins" -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $ffPath -Name "OfferToSaveLoginsDefault" -PropertyType DWord -Value 0 -Force | Out-Null
    Write-Host "Firefox: Password Manager DISABLED." -ForegroundColor Green

    # 19.5. Chrome Hardening (Just in case they switch browsers)
    $chromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    if (-not (Test-Path $chromePath)) { New-Item -Path $chromePath -Force | Out-Null }
    New-ItemProperty -Path $chromePath -Name "PasswordManagerEnabled" -PropertyType DWord -Value 0 -Force | Out-Null
    Write-Host "Chrome: Password Manager DISABLED." -ForegroundColor Green
}

# --- 17.5) Browser Extension Audit (Firefox & Chrome) ---
Write-Host "`n--- BROWSER EXTENSION AUDIT ---" -ForegroundColor Cyan
$extensionReport = Join-Path $env:TEMP "cypat_browser_extensions.txt"
Add-Content -Path $extensionReport -Value ("Browser Extension Audit Report - {0}" -f (Get-Date -Format o))

# Firefox Extensions Check
Add-Content -Path $extensionReport -Value "`n== FIREFOX EXTENSIONS =="
$firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $firefoxProfilePath) {
    $extensionsFound = $false
    Get-ChildItem -Path $firefoxProfilePath -Directory | ForEach-Object {
        $extensionsJsonPath = Join-Path $_.FullName "extensions.json"
        if (Test-Path $extensionsJsonPath) {
            Try {
                $extensionsJson = Get-Content $extensionsJsonPath | ConvertFrom-Json
                if ($extensionsJson.addons -and $extensionsJson.addons.Count -gt 0) {
                    $extensionsFound = $true
                    Add-Content -Path $extensionReport -Value "Profile: $($_.Name)"
                    $extensionsJson.addons | ForEach-Object {
                        Add-Content -Path $extensionReport -Value "  - $($_.name) (ID: $($_.id))"
                    }
                }
            } Catch {
                Write-Warning "Could not parse Firefox extensions.json: $_"
            }
        }
    }
    if (-not $extensionsFound) {
        Add-Content -Path $extensionReport -Value "No extensions found."
    }
} else {
    Add-Content -Path $extensionReport -Value "Firefox profiles not found."
}

# Chrome Extensions Check
Add-Content -Path $extensionReport -Value "`n== CHROME/EDGE EXTENSIONS =="
$chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
$edgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"

$extensionsFound = $false
foreach ($extPath in @($chromeExtPath, $edgeExtPath)) {
    if (Test-Path $extPath) {
        $browserName = if ($extPath -match "Chrome") { "Chrome" } else { "Edge" }
        Add-Content -Path $extensionReport -Value "`n$browserName Extensions:"
        
        Get-ChildItem -Path $extPath -Directory | ForEach-Object {
            $manifestPath = Join-Path $_.FullName "*/manifest.json" | Get-Item -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($manifestPath) {
                Try {
                    $manifest = Get-Content $manifestPath.FullName | ConvertFrom-Json
                    Add-Content -Path $extensionReport -Value "  - $($manifest.name) (ID: $($_.Name))"
                    $extensionsFound = $true
                } Catch {
                    Add-Content -Path $extensionReport -Value "  - Extension ID: $($_.Name) (unable to read name)"
                }
            }
        }
    }
}

if (-not $extensionsFound) {
    Add-Content -Path $extensionReport -Value "No Chrome/Edge extensions found."
}

Write-Host "Browser extension audit saved to: $extensionReport" -ForegroundColor Green
Write-Host "REMINDER: Review extensions for unauthorized or suspicious add-ons." -ForegroundColor Yellow

# --- 18) File Sharing Audit (Disable Unauthorized Shares) ---
Force-Action "Audit and Disable Non-Administrative Shares" {
    # Get all shares that are NOT default administrative shares (C$, ADMIN$, IPC$, etc.)
    # System shares end with $ and cannot be removed — filter them out explicitly
    $unauthorizedShares = Get-SmbShare | Where-Object { -not $_.IsSpecial -and $_.Name -notlike '*$' }

    if ($unauthorizedShares) {
        foreach ($share in $unauthorizedShares) {
            Write-Host "FOUND UNAUTHORIZED SHARE: $($share.Name) at $($share.Path)" -ForegroundColor Yellow
            # Stop the share (Matches the 'Stop Sharing' action in the key)
            Remove-SmbShare -Name $share.Name -Force
            Write-Host "SUCCESS: Share '$($share.Name)' has been removed." -ForegroundColor Green
        }
    } else {
        Write-Host "No unauthorized non-admin shares found." -ForegroundColor Green
    }
}


# --- 19) Local Security & LSA ---

# --- 20) FIREWALL HARDENING (ADVANCED) ---
Force-Action "Reset and Harden Windows Firewall" {
    # Wipe any malicious rules added by a hacker
    netsh advfirewall reset
    # Enable and Block all incoming by default
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
    # Ensure RDP is still allowed since it is a Critical Service
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
}

Force-Action "Disable Prohibited Services (Xbox, RetailDemo)" {
    $badSvc = @("XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc", "RetailDemo")
    foreach ($srv in $badSvc) {
        if (Get-Service -Name $srv -ErrorAction SilentlyContinue) {
            Stop-Service -Name $srv -Force -ErrorAction SilentlyContinue
            Set-Service -Name $srv -StartupType Disabled
        }
    }
}

Force-Action "Disable Legacy & P2P Services (Telnet, Routing, Peer-to-Peer)" {
    $legacySvc = @("TlntSvr", "Rasman", "p2psvc", "PNRPsvc", "p2pimsvc")
    foreach ($srv in $legacySvc) {
        $service = Get-Service -Name $srv -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne 'Stopped') {
                Stop-Service -Name $srv -Force -ErrorAction SilentlyContinue
            }
            Set-Service -Name $srv -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "$srv disabled." -ForegroundColor Green
        }
    }
}

# --- 21-23) Advanced Audit / SMB / File-sharing deduplicated above

# --- 24) ADVANCED NETWORKING HARDENING ---
Force-Action "Disable Insecure Protocols (LLMNR & NetBIOS)" {
    # Disable LLMNR
    $dnscPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dnscPath)) { New-Item -Path $dnscPath -Force | Out-Null }
    New-ItemProperty -Path $dnscPath -Name "EnableMulticast" -Value 0 -Force | Out-Null

    # Disable NetBIOS over TCP/IP
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
    Get-ChildItem $regPath | ForEach-Object { Set-ItemProperty -Path "HKLM:\$($_.Name)" -Name "NetbiosOptions" -Value 2 -Force | Out-Null }
}

Force-Action "Cleanse Hosts File & Disable Remote Assistance" {
    #  26.33)Reset Hosts file to default (removes redirects)
    $hosts = "127.0.0.1 localhost`n::1 localhost"
    $hosts | Out-File -FilePath "$env:SystemRoot\System32\drivers\etc\hosts" -Encoding ASCII -Force | Out-Null
    # 26.66) Disable Remote Assistance (but keep RDP)
    $raPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    if (Test-Path $raPath) {
        Set-ItemProperty -Path $raPath -Name "fAllowToGetHelp" -Value 0 -Force
    } else {
        Write-Host "Remote Assistance registry path not found; skipping." -ForegroundColor Yellow
    }
}

# --- 25) BITLOCKER CHECK & REMINDER ---
Write-Host "`n--- BITLOCKER STATUS CHECK ---" -ForegroundColor Cyan
Try {
    $bitlockerFeature = Get-WindowsFeature -Name BitLocker -ErrorAction SilentlyContinue
    if ($bitlockerFeature -and $bitlockerFeature.Installed) {
        Write-Host "BitLocker feature: INSTALLED" -ForegroundColor Green
        
        $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($bitlockerStatus) {
            if ($bitlockerStatus.ProtectionStatus -eq "On") {
                Write-Host "BitLocker C: drive: ENABLED ✓" -ForegroundColor Green
                Write-Host "Encryption method: $($bitlockerStatus.EncryptionMethod)" -ForegroundColor Green
            } else {
                Write-Host "BitLocker C: drive: DISABLED (not encrypted)" -ForegroundColor Yellow
                Write-Host "REMINDER: To enable BitLocker, run as admin:" -ForegroundColor Yellow
                Write-Host "  Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly" -ForegroundColor Cyan
            }
        }
    } else {
        Write-Host "BitLocker feature: NOT INSTALLED" -ForegroundColor Yellow
        Write-Host "REMINDER: To install and enable BitLocker, run as admin:" -ForegroundColor Yellow
        Write-Host "  Install-WindowsFeature -Name BitLocker -IncludeManagementTools" -ForegroundColor Cyan
        Write-Host "  Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly" -ForegroundColor Cyan
    }
} Catch {
    Write-Warning "Unable to check BitLocker status: $_"
}

# --- 26) Event Viewer Hardening ---
Force-Action "Harden Event Log Policies (Size & Retention)" {
    $logs = @("Security", "Application", "System")
    foreach ($log in $logs) {
        # Set max size to 1GB (1024MB) and ensure it doesn't drop events
        Limit-EventLog -LogName $log -MaximumSize 1024MB -OverflowAction OverWriteAsNeeded
        Write-Host "Configured $log Log: 1GB Size, Overwrite as Needed." -ForegroundColor Green
    }
}

# --- 27) Disable NTLMv1 and Force NTLMv2 ---
Force-Action "Disable NTLMv1 and Force NTLMv2" {
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    
    # LmCompatibilityLevel = 5 (Send NTLMv2 response only. Refuse LM & NTLM)
    New-ItemProperty -Path $lsaKey -Name "LmCompatibilityLevel" -PropertyType DWord -Value 5 -Force | Out-Null
    
    # Disable LM on the network
    New-ItemProperty -Path $lsaKey -Name "NoLMHash" -PropertyType DWord -Value 1 -Force | Out-Null
    
    # NTLM MinClientSec (Require 128-bit encryption)
    $msvKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    if (-not (Test-Path $msvKey)) { New-Item -Path $msvKey -Force | Out-Null }
    New-ItemProperty -Path $msvKey -Name "NtlmMinClientSec" -PropertyType DWord -Value 537395200 -Force | Out-Null
    New-ItemProperty -Path $msvKey -Name "NtlmMinServerSec" -PropertyType DWord -Value 537395200 -Force | Out-Null
    
    Write-Host "NTLMv1 Disabled. NTLMv2 Enforced (128-bit)." -ForegroundColor Green
}

# --- 28) Certificate Security (Audit Rogue, Find Expired, Update Roots) ---
Force-Action "Certificate Security Audit" {
    $certReport = Join-Path $env:TEMP "cypat_cert_report.txt"
    "--- CERTIFICATE REPORT ---" | Out-File $certReport
    
    # A. Audit Rogue Root Certificates (Non-Microsoft)
    Write-Host "Scanning for Rogue Root Certificates..." -ForegroundColor Cyan
    $rogueCerts = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { 
        $_.Issuer -notmatch "Microsoft" -and $_.Subject -notmatch "Microsoft" 
    }
    if ($rogueCerts) {
        Write-Host "WARNING: Potential Rogue Root Certificates found!" -ForegroundColor Red
        "Rogue Roots Found:" | Add-Content $certReport
        $rogueCerts | Format-Table Thumbprint, Subject, Issuer | Out-String | Add-Content $certReport
    } else {
        Write-Host "No obvious rogue root certificates found." -ForegroundColor Green
    }

    # B. Find Expired Certificates (Web Server/IIS)
    Write-Host "Scanning for Expired Certificates..." -ForegroundColor Cyan
    $expiredCerts = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.NotAfter -lt (Get-Date) }
    if ($expiredCerts) {
        Write-Host "WARNING: Expired Certificates Found!" -ForegroundColor Red
        "Expired Certs (Needs Renewal):" | Add-Content $certReport
        $expiredCerts | Format-Table Subject, NotAfter, Thumbprint | Out-String | Add-Content $certReport
        Write-Host "ACTION: Check IIS Manager to manually renew these certificates." -ForegroundColor Yellow
    } else {
        Write-Host "No expired local certificates found." -ForegroundColor Green
    }

    # C. Update Trusted Root Certificates (Requires Internet)
    Write-Host "Attempting to update Trusted Root Certificate List..." -ForegroundColor Cyan
    Try {
        # Trigger standard Windows Update certificate sync
        certutil -trigger sync | Out-Null
        Write-Host "Triggered Root Certificate Sync." -ForegroundColor Green
    } Catch {
        Write-Warning "Could not trigger certificate sync (Internet may be blocked)."
    }

    Write-Host "Certificate Report saved to: $certReport" -ForegroundColor White
}

# --- 30) Disable Extended Weak Services (FINAL SWEEP) ---
Force-Action "Disable Extended Weak Services (Spooler, SNMP, RemoteReg)" {
    $weakServices = @(
        "Spooler",          # Print Spooler (Critical Vuln risk - Check README if Print Server!)
        "RemoteRegistry",   # Remote Registry Access
        "MapsBroker",       # Downloaded Maps Manager
        "Fax",              # Fax Service
        "TapiSrv",          # Telephony
        "SNMP",             # Simple Network Management Protocol (Info Leak)
        "SNMPTrap",         # SNMP Trap
        "upnphost",         # UPnP Device Host
        "SSDPSRV",          # SSDP Discovery (Network Chatter)
        "W3SVC",            # IIS World Wide Web Publishing (Disable ONLY if NOT a Web Server)
        "SessionEnv"        # Remote Desktop Configuration (Careful - related to RDP)
    )

    foreach ($svcName in $weakServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        # Only stop if it is currently running or not disabled
        if ($svc -and ($svc.Status -ne 'Stopped' -or $svc.StartType -ne 'Disabled')) {
            # Check for critical exemptions (e.g., if README says "Print Server", skip Spooler)
            # This is a safety check you should do manually, but the script will enforce the disable.
            
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "Disabled Service: $svcName" -ForegroundColor Green
        }
    }
}

# --- 31) RDP Hardening (NLA & High Encryption) ---
Force-Action "Harden Remote Desktop Settings" {
    $rdpKey = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    # Enforce NLA (1)
    New-ItemProperty -Path $rdpKey -Name "UserAuthentication" -PropertyType DWord -Value 1 -Force | Out-Null
    # Set Encryption Level to 3 (High - 128 bit)
    New-ItemProperty -Path $rdpKey -Name "MinEncryptionLevel" -PropertyType DWord -Value 3 -Force | Out-Null
    Write-Host "RDP Hardened: NLA Enforced and High Encryption Set." -ForegroundColor Green
}

# --- 32) Disable LLMNR and NetBIOS ---
Force-Action "Disable LLMNR & NetBIOS" {
    # Disable LLMNR via Registry
    $dnscKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dnscKey)) { New-Item -Path $dnscKey -Force | Out-Null }
    New-ItemProperty -Path $dnscKey -Name "EnableMulticast" -PropertyType DWord -Value 0 -Force | Out-Null

    # Disable NetBIOS on all network adapters
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(2) | Out-Null # 2 = Disable NetBIOS over TCP/IP
    }
    Write-Host "LLMNR and NetBIOS disabled across all adapters." -ForegroundColor Green
}

# --- 33) Disable Legacy Name Resolution (LLMNR & NetBIOS) ---
Force-Action "Disable LLMNR & NetBIOS" {
    # Disable LLMNR
    $dnsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $dnsKey)) { New-Item -Path $dnsKey -Force | Out-Null }
    New-ItemProperty -Path $dnsKey -Name "EnableMulticast" -PropertyType DWord -Value 0 -Force | Out-Null

    # Disable NetBIOS on all active network adapters
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(2) | Out-Null # 2 = Disable
    }
    Write-Host "Network Protocols Hardened: LLMNR/NetBIOS Disabled." -ForegroundColor Green
}

# --- 34) Secure Required RDP (Enforce NLA) ---
Force-Action "Secure RDP with NLA" {
    $rdpPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    New-ItemProperty -Path $rdpPath -Name "UserAuthentication" -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Host "RDP Security: Network Level Authentication (NLA) Enforced." -ForegroundColor Green
}

# --- 35) Disable Sticky Keys (Prevent Login Backdoors) ---
Force-Action "Disable Sticky Keys Shortcuts" {
    # Set the 'Flags' registry key for Sticky Keys to '506' (Disabled) for the current user (and default user if possible)
    $stickyPath = "HKCU:\Control Panel\Accessibility\StickyKeys"
    if (Test-Path $stickyPath) {
        Set-ItemProperty -Path $stickyPath -Name "Flags" -Value "506" -Force
    }
    Write-Host "Sticky Keys shortcut disabled for current user." -ForegroundColor Green
}

# --- 36) Remove Malicious WSUS/Update Blocks ---
Force-Action "Remove WSUS Restrictions (Fix Update Blocking)" {
    $auKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    
    # Remove 'UseWUServer' which forces the PC to look at a fake update server
    if (Get-ItemProperty -Path $auKey -Name "UseWUServer" -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $auKey -Name "UseWUServer" -Force
        Write-Host "REMOVED 'UseWUServer' restriction. Updates will now come from Microsoft." -ForegroundColor Green
    }
    
    # Ensure we aren't blocking updates via 'NoAutoUpdate'
    Set-ItemProperty -Path $auKey -Name "NoAutoUpdate" -Value 0 -Force -ErrorAction SilentlyContinue
}

# --- 37) Disable Windows Update Delivery Optimization (P2P Updates) ---
Force-Action "Disable WUDO (Peer-to-Peer Update Sharing)" {
    $doKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    if (-not (Test-Path $doKey)) { New-Item -Path $doKey -Force | Out-Null }
    
    # DODownloadMode = 0 (HTTP only, no Peer-to-Peer)
    New-ItemProperty -Path $doKey -Name "DODownloadMode" -PropertyType DWord -Value 0 -Force | Out-Null
    Write-Host "Delivery Optimization (P2P) Disabled." -ForegroundColor Green
}

Write-Host "CYPat Enforcer finished. All security policies and advanced audit policies attempted." -ForegroundColor Green