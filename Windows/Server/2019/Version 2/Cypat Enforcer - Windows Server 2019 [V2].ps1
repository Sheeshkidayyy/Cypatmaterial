# CYPat Enforcer - Windows Server 2019 Full Security & All-Audit Policies
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
    net accounts /lockoutduration:60 /lockoutwindow:60 /lockoutthreshold:5
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
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -PropertyType DWord -Value 1 -Force
}

# --- 5) Limit blank password use to console only ---
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
Force-Action "Trigger Windows Update scan / download / install" {
    Try {
        Start-Process "wuauclt.exe" -ArgumentList "/detectnow" -NoNewWindow -Wait
        Start-Process "wuauclt.exe" -ArgumentList "/updatenow" -NoNewWindow -Wait
    } Catch {
        Write-Warning "Failed to trigger Windows Update via wuauclt: $_"
    }
}

# ---  9) ADVANCED AUDIT POLICY: dynamic enumeration + apply Success & Failure ---
Write-Host "Capturing existing advanced audit settings (before)..." -ForegroundColor Cyan
$beforeFile = Join-Path $env:TEMP "cypat_audit_before.txt"
& auditpol /get /subcategory:* > $beforeFile 2>&1

Write-Host "Detecting available advanced audit subcategories..." -ForegroundColor Cyan
$rawList = (& auditpol /list /subcategory:* ) 2>&1

# --- 10) Trim and filter likely empty/header lines; we'll attempt to set each trimmed line and ignore failures.
$subcategories = $rawList | ForEach-Object { $_.Trim() } | Where-Object { $_ -and ($_ -ne " ") } | Sort-Object -Unique

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

# --- 11) Save gpresult to help identify GPO overrides
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

# --- 11.25) Verification: report subcategories still set to No Auditing and show gpresult ---
$reportFile = Join-Path $env:TEMP "cypat_audit_verify.txt"
Add-Content -Path $reportFile -Value ("Audit verification report - {0}" -f (Get-Date -Format o))

# --- 11.50) Show any subcategories still No Auditing
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

# --- 11.75) Save a small summary of gpresult (look for GPOs configuring Advanced Audit Policy)
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

# --- 11.99) Optional: open the report automatically if running interactively
if (-not $DryRun) {
    Write-Host "Audit verification saved to: $reportFile"
    # Uncomment the following line to auto-open the report in Notepad (interactive sessions only)
    # Start-Process notepad.exe -ArgumentList $reportFile
}

# --- 12) Enable Windows Defender Real-time Protection ---
Force-Action "Enable Windows Defender Virus & Threat Protection" {
    Try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-Host "Success: Windows Defender real-time protection enabled."
    } Catch {
        Write-Warning "Failed to enable Windows Defender real-time protection: $_"
    }
}

# --- 13) Automatic Windows Updates ---
Force-Action "Enable Automatic Windows Updates" {
    Try {
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
        Start-Service -Name wuauserv -ErrorAction Stop

        $AUKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
        If (-Not (Test-Path $AUKey)) { New-Item -Path $AUKey -Force | Out-Null }
        Set-ItemProperty -Path $AUKey -Name "AUOptions" -Value 4 -Force

        Write-Host "Automatic Windows Updates enabled and configured." -ForegroundColor Green
    } Catch {
        Write-Warning "Failed to enable/configure automatic updates: $_"
    }
}

# --- 14) Disable Microsoft FTP Server Service ---
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

# --- 15) Disable & Stop Simple Mail Transfer Protocol (SMTP) Service ---
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

# --- 16) Limit local use of blank passwords to console only ---
Force-Action "Limit local use of blank passwords to console only" {
    Try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -PropertyType DWord -Value 1 -Force
        Write-Host "Configured: LimitBlankPasswordUse = 1" -ForegroundColor Green
    } Catch {
        Write-Warning "Failed to set LimitBlankPasswordUse: $_"
    }
}

# --- 17) Enable 'Microsoft network server: Digitally sign communications (always)' ---
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

# --- 18) Disable SMB v1 (legacy insecure protocol) ---
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


Write-Host "CYPat Enforcer finished. All security policies and advanced audit policies attempted." -ForegroundColor Green
