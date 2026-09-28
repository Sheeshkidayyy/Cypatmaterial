# CYPat Enforcer - Windows Server 2019 Security Hardening Script

**Author:** Sheeshkidayyy (GitHub: github.com/sheeshkidayyy)  
**Purpose:** Comprehensive security hardening and audit policy enforcement for Windows Server 2019 in competitive/work environments  
**Platform:** Windows Server 2019 (PowerShell 5.1+)

---

## Quick Start

### Step 1: Open PowerShell as Administrator
- Right-click **PowerShell** or **Windows Terminal**
- Select **"Run as Administrator"**
- You will see `Administrator:` in the title bar

### Step 2: Paste the Script
- Copy the entire script contents
- Paste into the PowerShell console

### Step 3: Press Enter and Watch the Points Rain In!
- Script will execute automatically
- Output shows real-time progress with color-coded messages:
  - **Green:** Successful actions
  - **Yellow:** Warnings or non-critical issues
  - **Red:** Critical findings
  - **Cyan:** Information/progress indicators

### Step 4: Critical Verification Step
**⚠️ IMPORTANT:** Verify that passwords are NOT stored with reversible encryption
- Look for message: `Verified: 'Store passwords using reversible encryption' is DISABLED (ClearTextPassword = 0).` ✓
- If you see: `Verification: 'ClearTextPassword' is not 0...` - A Group Policy override exists
- Check `C:\Users\[Username]\AppData\Local\Temp\cypat_secpol_export.inf` and verify the setting
- **Do NOT allow reversible encryption** - it defeats password security entirely

---

## What This Script Does - Complete Breakdown

### SECTION 1: Account Lockout Policy
**Command:** `net accounts /lockoutduration:60 /lockoutwindow:60 /lockoutthreshold:10`

**Effect:**
- Accounts lock after **10 failed login attempts**
- Lock persists for **60 minutes**
- Failed attempts reset after **60 minutes**
- Prevents brute-force password attacks (e.g., dictionary attacks)

**Why it matters:** Attackers cannot endlessly guess passwords; they're limited to 10 attempts per hour.

---

### SECTION 2: Password Policy
Three password rules enforced:

#### 2a) Minimum Password Length = 10 Characters
- Users cannot set passwords shorter than 10 characters
- Longer passwords are exponentially harder to crack
- Entropy increases: 8-char vs 10-char = 100x stronger

#### 2b) Password Age Requirements
- **Minimum age:** 5 days (users cannot change password more than once per 5 days)
- **Maximum age:** 30 days (forces password changes monthly)
- **History:** 20 previous passwords remembered (prevents cycling back to old passwords)

#### 2c) Disable Reversible Encryption
- Uses `secedit` to set `ClearTextPassword = 0`
- **Reversible encryption** = passwords stored almost as plaintext (defeats encryption)
- Verification exports policy and confirms setting applied
- **Warns if Group Policy overrides exist** (may need domain admin to fix)

**Why it matters:** 
- 10 chars + monthly changes + history enforcement = strong password hygiene
- No reversible encryption = passwords cannot be easily extracted from system

---

### SECTION 3: Password Expiration Enforcement
**Target:** All local user accounts

**Effect:**
- Each user account gets `PasswordExpires = $true`
- Users must change password at next logon
- Ensures stale/compromised passwords are updated

**Why it matters:** Expired passwords force regular updates, reducing risk of long-term credential compromise.

---

### SECTION 4: Disable Anonymous SAM Enumeration
**Registry Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM = 1`

**Effect:**
- Prevents anonymous users from enumerating local user accounts via SAMRPC
- Attackers cannot remotely list all users without credentials

**Why it matters:** Reconnaissance becomes harder; attackers cannot build target list of users.

---

### SECTION 5: Disable USB Autorun
**Registry Key:** `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun = 255`

**Effect:**
- Disables autorun for **all drive types** (USB, CD, external drives, network drives)
- Value `255` = disable all; prevents `.exe` auto-execution from removable media

**Why it matters:** Prevents "Conficker" and similar malware that spreads via USB drives with autorun.inf.

---

### SECTION 6: Windows Update Service Reference
- Placeholder comment (actual implementation in Section 11)

---

### SECTIONS 7-9: Advanced Audit Policy (59 Subcategories)

#### Section 7: Capture Before State
- Runs: `auditpol /get /subcategory:* > cypat_audit_before.txt`
- Saves baseline audit configuration

#### Section 8: Dynamic Enumeration & Enable All Subcategories
1. **Enumerate:** Runs `auditpol /list /subcategory:*` (lists all available subcategories)
2. **Filter:** Removes category-level items that cause "0x57 (parameter incorrect)" errors
   - **Excluded categories:** Account Logon, Account Management, Detailed Tracking, DS Access, Logon/Logoff, Object Access, Policy Change, Privilege Use, System
   - **Result:** 59 valid subcategories on Server 2019
3. **Enable:** For each subcategory, runs:
   ```
   auditpol /set /subcategory:"[name]" /success:enable /failure:enable
   ```
   - Success: Logs when users/processes perform actions (login, file access, etc.)
   - Failure: Logs when users/processes are denied (failed login, access denied, etc.)

#### Section 9: Capture After State & GPO Report
- Runs: `auditpol /get /subcategory:* > cypat_audit_after.txt` (audit settings after changes)
- Runs: `gpresult /r > cypat_gpresult.txt` (Group Policy report - shows what GPOs are applied)

#### Sections 9.1-9.4: Verification & Reporting
- Searches `cypat_audit_after.txt` for any subcategories still set to "No Auditing"
- Extracts relevant audit-related lines from gpresult
- Generates `cypat_audit_verify.txt` with findings and warnings
- **Success message:** "All available advanced subcategories appear configured." ✓

**Why it matters:**
- **59 audit subcategories = complete visibility** into user actions, system changes, security events
- **Success & Failure logging = forensic trail** for incident investigation
- **Before/After reports = verification** that audit policies applied correctly
- **Catches GPO conflicts** that may override local settings

---

### SECTION 10: Windows Defender Real-Time Protection
**Command:** `Set-MpPreference -DisableRealtimeMonitoring $false`

**Effect:**
- Enables Windows Defender real-time file scanning
- Scans files as they are accessed/created
- Prevents known malware from executing

**Why it matters:** Active malware detection layer; prevents many commodity malware variants.

---

### SECTION 11: Automatic Windows Updates
Multiple steps:

1. **Set Service to Automatic:**
   - `Set-Service -Name wuauserv -StartupType Automatic`
   - Ensures Windows Update service starts on every reboot

2. **Start Service Immediately:**
   - `Start-Service -Name wuauserv`

3. **Configure Auto-Install:**
   - Sets registry: `AUOptions = 4`
   - Meaning: Auto-download updates AND auto-install them

4. **Trigger Immediate Detection & Installation:**
   - Runs: `wuauclt.exe /detectnow` (scan for available updates)
   - Runs: `wuauclt.exe /updatenow` (download and install immediately)

**Effect:**
- Windows patches are installed automatically without user action
- Reduces window of exposure to known vulnerabilities

**Why it matters:** Patches critical security vulnerabilities; most ransomware exploits known CVEs that patches would have blocked.

---

### SECTION 12: Disable Microsoft FTP Server Service
**Service:** `FTPSVC` (File Transfer Protocol service)

**Actions:**
- Stops the service (if running)
- Sets `StartupType = Disabled` (won't restart on reboot)
- Gracefully handles if service not installed

**Effect:**
- FTP is deprecated and insecure (credentials transmitted in plaintext)
- Removes attack surface

**Why it matters:** FTP has been obsolete for 20+ years; SFTP/HTTPS are secure alternatives. No legitimate use case in modern server.

---

### SECTION 13: Disable SMTP Service
**Service:** `SMTPSVC` (IIS Simple Mail Transfer Protocol service)  
**Feature:** `SMTP-Server` (Windows feature)

**Actions:**
- Stops `SMTPSVC` service (if running)
- Sets `StartupType = Disabled`
- Uninstalls `SMTP-Server` Windows feature (if installed)

**Effect:**
- Removes email relay attack surface
- Prevents open relay attacks (malicious email distribution)

**Why it matters:** SMTP services are common targets for spam/phishing distribution. If not needed, eliminate it.

---

### SECTION 14: Limit Blank Passwords to Console Only
**Registry Key:** `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse = 1`

**Effect:**
- Blank passwords can only be used for **local console logon**
- Blank passwords **cannot be used for network access** (SMB, RDP, SSH, etc.)

**Why it matters:** Prevents local accounts with no password from being exploited over the network.

---

### SECTION 14.5: Require Ctrl+Alt+Delete for Login (Secure Attention Sequence)
**Registry Key:** `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD = 0`

**Effect:**
- Users **must press Ctrl+Alt+Delete** before the logon screen appears
- Creates a hardware interrupt (SAS - Secure Attention Sequence)
- Prevents malware from spoofing the logon screen

**Why it matters:**
- Keyloggers and fake logon screens cannot intercept SAS
- Windows OS takes control when SAS is pressed, bypassing malware
- Guarantees users are typing credentials to legitimate system logon

---

### SECTION 15: Enable SMB Signing (Server-Side)
**Registry Keys:** 
- `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature = 1`
- `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature = 1`

**Effect:**
- All SMB file shares must be digitally signed
- Prevents man-in-the-middle (MITM) attacks on network shares
- Server restarted to apply immediately (may briefly disrupt SMB connections)

**Why it matters:**
- Without signing, attacker on network can intercept SMB traffic and inject malicious commands
- Signing validates traffic authenticity
- Prevents "Eternal Blue" and similar SMB-based exploits

---

### SECTION 16: Disable SMB v1 Protocol
**Registry Key:** `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0`  
**Feature:** `FS-SMB1` (Windows feature removal)

**Effect:**
- SMB v1 (20+ years old) is completely disabled
- Only SMB v2/v3 (modern, secure) are available
- Windows feature `FS-SMB1` is uninstalled (if present)

**Why it matters:**
- SMB v1 has **numerous critical vulnerabilities** (WannaCry, NotPetya exploited SMB v1)
- No modern system needs SMB v1
- Disabling eliminates entire attack surface

---

### SECTION 17: Browser Password Manager Hardening

#### Firefox
**Registry Path:** `HKLM:\SOFTWARE\Policies\Mozilla\Firefox`

**Policies Set:**
- `PasswordManagerEnabled = 0` (disable password storage)
- `OfferToSaveLogins = 0` (don't prompt to save passwords)
- `OfferToSaveLoginsDefault = 0` (disable by default)

#### Chrome
**Registry Path:** `HKLM:\SOFTWARE\Policies\Google\Chrome`

**Policy Set:**
- `PasswordManagerEnabled = 0` (disable password storage)

**Effect:**
- Browsers cannot store/save passwords
- Prevents local credential theft if device is compromised

**Why it matters:**
- Browser password stores are common malware targets
- Local attacker can extract stored passwords from browser database
- Forces users to use password managers (which encrypt better) or enter passwords manually

---

### SECTION 17.5: Browser Extension Audit (Security Review)

**Firefox Extensions:**
- Scans: `$env:APPDATA\Mozilla\Firefox\Profiles\*/extensions.json`
- Parses JSON and extracts extension names and IDs
- Lists all extensions by profile

**Chrome & Edge Extensions:**
- Scans: `$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions`
- Scans: `$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions`
- Reads `manifest.json` from each extension directory
- Lists extension names and IDs

**Output:** Generates `cypat_browser_extensions.txt` in temp folder

**Why it matters:**
- **Browser extensions are privilege-escalated code** - they run with full browser access
- **Malicious extensions can:**
  - Steal passwords/credentials (keylogging, form capture)
  - Hijack searches and modify web pages
  - Inject ads or redirect to phishing sites
  - Exfiltrate data and cookies
  - Monitor browsing history
- **Legitimate review:** User must manually verify each extension is authorized/expected
- **Removes unauthorized extensions:** Eliminates attack vector

---

### SECTION 18: File Sharing Audit (Remove Unauthorized Shares)
**Command:** `Get-SmbShare | Where-Object { -not $_.IsSpecial -and $_.Name -notlike '*$' }`

**Logic:**
1. Enumerates all SMB shares
2. Filters out:
   - **Administrative shares:** C$, ADMIN$, IPC$, PRINT$ (marked `IsSpecial = $true`)
   - **System shares:** Any ending with `$` (cannot be safely removed)
3. For each **unauthorized user-created share:**
   - Logs the share name and path
   - Removes it with `Remove-SmbShare -Force`

**Effect:**
- Only intentional administrator-configured shares remain
- Removes accidental or malicious shares

**Why it matters:**
- Unauthorized shares expose files to network attacks
- Malware often creates shares to exfiltrate data or propagate
- Removes C2 communication channels

---

### SECTION 19: Local Security & LSA
- **Currently:** Empty placeholder (reserved for future LSA hardening enhancements)

---

### SECTION 20: Firewall Hardening (Advanced)

#### Subsection A: Reset and Harden Windows Firewall
**Commands:**
1. `netsh advfirewall reset` - Wipes all firewall rules (removes malicious rules added by attackers)
2. `Set-NetFirewallProfile -Enabled True -DefaultInboundAction Block` - All profiles (Domain, Private, Public)
3. `Enable-NetFirewallRule -DisplayGroup "Remote Desktop"` - Allows RDP so server remains accessible

**Effect:**
- Firewall starts from clean slate (no malicious rules)
- **Default-deny inbound:** All incoming traffic blocked except explicitly allowed
- **RDP still works:** Remote Desktop access maintained

**Why it matters:**
- Removes backdoors/C2 rules added by malware
- Default-deny prevents unauthorized inbound access
- Principle of least privilege: only allow necessary services

#### Subsection B: Disable Prohibited Services (Xbox, RetailDemo)
**Services Disabled:**
- `XblAuthManager` - Xbox Live authentication
- `XblGameSave` - Xbox game save sync
- `XboxNetApiSvc` - Xbox network API
- `XboxGipSvc` - Xbox input (gamepad) service
- `RetailDemo` - Retail demo mode

**Effect:**
- Removes gaming/demo features (not needed on server)
- Reduces attack surface

#### Subsection C: Disable Legacy & P2P Services
**Services Disabled:**
- `TlntSvr` - Telnet Server (insecure remote access; use RDP instead)
- `Rasman` - Remote Access Service (legacy VPN, obsolete)
- `p2psvc` - Peer-to-Peer Networking service
- `PNRPsvc` - Peer Name Resolution Protocol service
- `p2pimsvc` - Peer-to-Peer Infrastructure Manager service

**Effect:**
- Removes 20+ year old insecure protocols
- Eliminates P2P attack surface (used by malware for C2)

**Why it matters:**
- Telnet credentials sent in plaintext (anyone on network can capture password)
- P2P services enable distributed malware networks
- No legitimate use cases in enterprise environment

---

### SECTION 21-23: Deduplicated Notes
- Comment noting that Advanced Audit, SMB hardening, and File-sharing are already consolidated above
- No duplicate code

---

### SECTION 24: Advanced Networking Hardening

#### Subsection A: Disable Insecure Name Resolution Protocols

**LLMNR (Link-Local Multicast Name Resolution) Disabled:**
- Registry: `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast = 0`
- Prevents LLMNR broadcast queries
- **Why?** LLMNR is exploited via:
  - **LLMNR Poisoning:** Attacker responds to LLMNR queries with their IP
  - **Responder attacks:** Attacker captures hashed credentials from LLMNR traffic
  - No legitimate need; DNS is standard

**NetBIOS over TCP/IP Disabled:**
- Iterates through all network interfaces: `HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\[GUID]`
- Sets `NetbiosOptions = 2` for each (disabled)
- **Why?** NetBIOS is legacy 1980s protocol:
  - Used for broadcast name resolution (inefficient)
  - Can be exploited for enumeration and MITM attacks
  - Replaced by DNS in modern networks

**Effect:** Only modern DNS-based name resolution remains

#### Subsection B: Cleanse Hosts File & Disable Remote Assistance

**Reset Hosts File:**
- Overwrites `C:\Windows\System32\drivers\etc\hosts` with only:
  ```
  127.0.0.1 localhost
  ::1 localhost
  ```
- **Why?** Hosts file can be poisoned by malware:
  - `127.0.0.1 google.com` redirects Google requests to attacker
  - Malware often redirects security sites to prevent updates
  - Resetting ensures no malicious redirects

**Disable Remote Assistance:**
- Registry: `HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance\fAllowToGetHelp = 0`
- Disables "Windows Remote Assistance" (allow someone to remote into your PC)
- **Keeps RDP enabled** (administrators can still RDP in)
- **Why?** Remote Assistance:
  - Allows untrusted users to remotely control PC
  - Can be exploited to gain admin access
  - Not needed in enterprise environment

**Effect:** Removes remote assistance attack surface; RDP (more controlled) still available

---

### SECTION 25: Massive Prohibited File Hunter (C:\Users Only)

**Scan Location:** `C:\Users` (recursively searches Desktop, Downloads, Documents, Pictures, etc.)

**File Categories Detected:**

1. **Video Files (RED):**
   - `.mp4, .avi, .mov, .mkv, .wmv, .flv, .mpg, .mpeg`
   - Flagged as `[POTENTIAL HACK TOOL/SCRIPT]` if script extension detected

2. **Audio Files (YELLOW):**
   - `.mp3, .wav, .m4a, .flac, .aac, .ogg`
   - Flagged as `[PROHIBITED MEDIA FOUND]`

3. **Script Files (RED):**
   - `.ps1, .bat, .vbs, .py, .sh, .pl, .js, .php`
   - Flagged as `[POTENTIAL HACK TOOL/SCRIPT]`

4. **Image Files (CYAN):**
   - `.jpg, .jpeg, .png, .gif, .bmp, .tiff`
   - Flagged as `[IMAGE/PHOTO DETECTED]`

**Output:**
- Lists each file with full path
- Color-coded by severity (Red > Yellow > Cyan)
- **Does NOT automatically delete** - requires manual confirmation
- Final message: "CRITICAL: Do NOT delete files unless you are 100% sure they are prohibited."

**Why it matters:**
- In competition environments, contraband files (games, media, hack tools) are not allowed
- Automated detection without auto-deletion prevents accidental data loss
- Manual review allows legitimate files to be kept

---

### BITLOCKER STATUS CHECK & REMINDER

**Checks:**
1. **BitLocker Feature Installed?**
   - Query: `Get-WindowsFeature -Name BitLocker`

2. **If Installed - Is C: Drive Encrypted?**
   - Query: `Get-BitLockerVolume -MountPoint "C:"`
   - If **ProtectionStatus = "On":** Display `ENABLED ✓` with encryption method (AES256, etc.)
   - If **ProtectionStatus = "Off":** Display `DISABLED` and provide enable command

3. **If Not Installed - Provide Install Command:**
   - Suggests: `Install-WindowsFeature -Name BitLocker -IncludeManagementTools`

**Enable Command Provided (if needed):**
```powershell
Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -UsedSpaceOnly
```

**Why Intentionally NOT Auto-Enabled:**
- **BitLocker requires recovery key backup** (critical - losing key = data loss)
- **User decision required:** Server owner must decide to enable and save recovery key
- **Not automatic:** Prevents accidental encryption without proper planning

**Why BitLocker Matters:**
- **Full disk encryption** protects data if drive is stolen/removed
- **At-rest protection:** Even if attacker has physical access, data is encrypted
- **Common compliance requirement:** HIPAA, PCI-DSS, SOC2 require encryption

---

## FINAL OUTPUT & VERIFICATION

### Success Message
```
CYPat Enforcer finished. All security policies and advanced audit policies attempted.
```

### Temporary Reports Generated
All reports saved to: `$env:TEMP` (usually `C:\Users\[USERNAME]\AppData\Local\Temp\`)

| Report File | Purpose |
|------------|---------|
| `cypat_audit_before.txt` | Audit settings before script ran |
| `cypat_audit_after.txt` | Audit settings after script ran |
| `cypat_gpresult.txt` | Group Policy summary (shows all applied GPOs) |
| `cypat_audit_verify.txt` | Verification report (highlights any failures) |
| `cypat_browser_extensions.txt` | List of installed browser extensions |
| `cypat_password_cleartext.inf` | Password policy INF file (temp) |
| `cypat_secpol_export.inf` | Exported security policy (for verification) |

---

## Security Summary: What's Protected

| Category | Controls Implemented |
|----------|---------------------|
| **Access Control** | Account lockout (10 tries/60 min), Ctrl+Alt+Delete logon requirement, blank password restriction |
| **Password Security** | Minimum 10 characters, 30-day expiration, 20 password history, reversible encryption disabled |
| **Audit & Logging** | 59 advanced audit subcategories enabled (Success & Failure) |
| **Network Security** | SMB signing enforced, SMB v1 disabled, LLMNR/NetBIOS disabled |
| **Services Hardening** | FTP, SMTP, Telnet, P2P, Xbox, RetailDemo disabled |
| **Firewall** | Default-deny inbound rules, malicious rules wiped, RDP maintained |
| **Endpoint Protection** | Windows Defender real-time enabled, automatic Windows Updates |
| **Data Protection** | Unauthorized shares removed, hosts file reset, BitLocker status checked |
| **Browser Security** | Password managers disabled, extensions audited |
| **File Integrity** | Prohibited files flagged and logged |

---

## Important Notes & Warnings

### ⚠️ CRITICAL: Reversible Password Encryption Verification
- **Step 4 of quick start:** MUST verify reversible encryption is disabled
- Look for: `Verified: 'Store passwords using reversible encryption' is DISABLED (ClearTextPassword = 0).`
- If you see a warning about Group Policy override: Check temp folder INF file and escalate to domain admin
- **Do NOT ignore this** - reversible encryption is a critical security flaw

### Administrator Privileges Required
- Script will exit with error if not run as Administrator
- Right-click PowerShell → "Run as Administrator"

### Firewall Rules Reset
- `netsh advfirewall reset` **removes all custom firewall rules**
- Only removes rules if you had malicious/outdated ones
- RDP is automatically re-enabled (so you don't lose access)

### LanmanServer Service Restart
- SMB signing changes trigger service restart
- May briefly disrupt SMB connections
- Reconnection is automatic; users see temporary pause

### Group Policy Overrides
- Local settings may be overridden by domain Group Policy
- If on domain, check `gpresult /h gpresult_report.html` to see effective policies
- Some settings may require domain admin to override GPO

### BitLocker Not Auto-Enabled
- Script only checks status and suggests commands
- **You must manually enable and save recovery key**
- Losing recovery key = potential data loss

---

## What to Expect During Execution

### Estimated Runtime
- **2-5 minutes** (depending on system speed and file scan size)

### Output Flow
1. **Admin check** → Verifies administrator privileges
2. **Account lockout** → Applies net accounts policy
3. **Password policies** → Sets min length, age, history
4. **Reversible encryption** → Uses secedit, exports for verification
5. **User expiration** → Iterates local users
6. **Audit policy** → Enumerates, filters, enables 59 subcategories (may see many "[VERBOSE]" lines)
7. **Defender & Updates** → Enables real-time protection, configures auto-update
8. **Services** → Disables FTP, SMTP, Xbox, P2P, Telnet, routing
9. **Firewall** → Resets and hardens
10. **File scan** → Recursively scans C:\Users (slowest part if many files)
11. **BitLocker check** → Queries encryption status
12. **Completion** → Displays success message

### Color-Coded Progress Indicators
- **Green `[APPLY]`** = Action starting
- **Green `Success:`** = Action completed
- **Yellow `WARNING:`** = Non-critical issue (e.g., service not installed)
- **Cyan** = Informational messages (progress updates)
- **Red `[POTENTIAL HACK TOOL/SCRIPT]`** = Suspicious file found

---

## Post-Execution Checklist

- [ ] Script completed with "CYPat Enforcer finished" message
- [ ] No `[APPLY] Failed to apply` messages (warnings are OK, failures are not)
- [ ] Verified reversible encryption is disabled (Step 4)
- [ ] Checked audit verification report for unexpected "No Auditing" entries
- [ ] Reviewed browser extension audit report for suspicious extensions
- [ ] Reviewed file scan results and deleted/quarantined prohibited files as needed
- [ ] Confirmed firewall is enabled and RDP works
- [ ] BitLocker status checked (enable and backup recovery key if needed)

---

## Troubleshooting

### Script Says "Not Administrator"
- Close PowerShell
- Right-click PowerShell → **"Run as Administrator"**
- Paste and run script again

### Some Policy Changes Show Warnings
- This is normal (e.g., "SMTP service not installed" = not a failure)
- Warnings ≠ Failures; script continues successfully

### Reversible Encryption Warning about Group Policy Override
- Domain Group Policy is overriding local setting
- Contact domain admin to modify GPO
- May be intended security configuration

### File Scan Is Very Slow
- C:\Users has many files
- Script will complete; this is normal for large systems

### BitLocker Feature Not Installed
- This is OK; script will suggest install command
- Run suggested command if you need encryption

### Services Already Disabled
- Shows as "not found" or "already disabled"
- This is expected; script skips gracefully

---

## Security Posture After Running

Your Windows Server 2019 is now hardened with:
- ✅ Strong password policies (10 chars, 30-day expiration, 20 history)
- ✅ Account lockout protection (10 attempts/60 minutes)
- ✅ Secure logon (Ctrl+Alt+Delete requirement)
- ✅ Complete audit logging (59 subcategories)
- ✅ Disabled legacy insecure protocols (SMB v1, Telnet, LLMNR, NetBIOS)
- ✅ SMB signing enforced (prevents MITM attacks)
- ✅ Firewall hardened (default-deny inbound)
- ✅ Windows Defender active (real-time protection)
- ✅ Automatic security updates (patches applied immediately)
- ✅ Prohibited files identified and flagged
- ✅ Browser extensions audited
- ✅ Unauthorized shares removed
- ✅ BitLocker encryption status checked

---

## Additional Hardening (Not in Script)

Consider also:
- **Domain-level policies:** Apply security GPOs at domain level (overrides local settings)
- **MFA:** Enable multi-factor authentication for remote access
- **Backup:** Implement automated backups (daily minimum)
- **Antivirus:** Consider third-party antivirus beyond Windows Defender
- **Web filtering:** Block malicious websites at network level
- **Endpoint detection:** Deploy EDR (Endpoint Detection & Response) for advanced threats

---

## Support & Questions

- **Script Author:** Sheeshkidayyy
- **GitHub:** github.com/sheeshkidayyy
- **License:** Use freely; credit author if redistributing

---

**Last Updated:** January 15, 2026  
**Platform Tested:** Windows Server 2019 (Build 17763+)
