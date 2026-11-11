# Cypat Server 2022 Enforcer V2

Windows Server 2022 baseline, audit, and guarded hardening script. This version adds
passwordless-account reset, enforced Success+Failure auditing, Administrators-only
sensitive rights, a Y/N netcat quarantine decision, a full SmartScreen baseline, and a
private **plain-text** run folder.

> **Status: untested on a VM.** The script was statically reviewed, but it has not been
> executed on Windows yet. Run `-AuditOnly` in a snapshot first, read the report, then
> test `-Apply`.

---

## Requirements

- Windows Server 2022.
- Elevated 64-bit Windows PowerShell 5.1.
- The image README and forensics questions completed first.
- A local writable folder for the script.

Running the script **without** `-AuditOnly` applies changes. Always audit first.

---

## Quick start

```powershell
# 1. Read-only. No security changes, no passwords, no deletion.
.\Cypat Server 2022 Enforcer v2.ps1 -AuditOnly

# 2. Apply the baseline after reading the report.
.\Cypat Server 2022 Enforcer v2.ps1 -Apply

# 3. Keep documented service accounts out of the password reset.
.\Cypat Server 2022 Enforcer v2.ps1 -Apply `
    -PasswordExemptUsers 'svc_sql','svc_backup'

# 4. Custom private run folder and a plain-text report copy.
.\Cypat Server 2022 Enforcer v2.ps1 -Apply `
    -RunRoot 'D:\CYPat' `
    -ReportPath 'C:\cypat-v2.txt'
```

`-ReportPath` writes plain text. If you pass a `.json` or `.csv` name, V2 renames it to
`.txt` and warns. There is no JSON or CSV output anywhere.

---

## What V2 does for the checklist

| # | Checklist item | V2 behavior |
|---|----------------|-------------|
| 5 | Passwordless account gets a password | Every **enabled** local account with `PasswordRequired = false` **or** no `PasswordLastSet` gets a unique 18-character password. The password is applied, read back, printed once, and saved in `Changed-Passwords.txt`. Built-in Administrator is included if blank. Guest, DefaultAccount, and WDAGUtilityAccount are excluded. `-PasswordExemptUsers` is the only opt-out. |
| 11 | Password history 5 | `secedit` baseline sets history to 5 and never lowers a stronger value. |
| 12 | Password complexity | Enabled through the same account-policy baseline. |
| 13 | Lockout threshold 5 | 5 attempts, 60-minute duration and reset. |
| 14 | Audit Credential Validation [Success] | `auditpol /set /category:* /success:enable /failure:enable`; every subcategory is then read back by GUID and reported. `SCENoApplyLegacyAuditPolicy=1` and command-line process auditing are set. Security log grows to 192 MB; Application and System to 32 MB. |
| 15 | Only administrators manage auditing/security log | `SeSecurityPrivilege` is rewritten to `*S-1-5-32-544` (BUILTIN\Administrators) only. Every named user, including wyatt or darius, is removed. Prior principals are written to `Ledger.txt`. |
| 16 | Only administrators take ownership | `SeTakeOwnershipPrivilege` is rewritten the same way. Prior principals are written to `Ledger.txt`. |
| 17 | Blank passwords console-only | `LimitBlankPasswordUse = 1`. |
| 18 | Don't display last signed-in | `DontDisplayLastUserName = 1`. |
| 19 | Firewall enabled | All three profiles enabled, inbound default Block. |
| 31 | Netcat backdoor removed | Detects `nc.exe`, `ncat.exe`, `netcat.exe`, `mfc.exe`, `nc64.exe`, and `cryptcat.exe` that are running or present in `System32`/`SysWOW64`. Shows PID, path, listening ports, and signature. **Y** stops the process, copies the file to `Quarantine\`, verifies SHA-256, and deletes the original. **N** leaves it unchanged. |
| 32 | SmartScreen warn/block | Windows System policy: `EnableSmartScreen=1`, `ShellSmartScreenLevel=Block`, `SmartScreenPuaEnabled=1`. IE: `PhishingFilter\PreventOverride=1`. Edge: SmartScreen, PUA, site and download override prevention, DNS reputation checks. Chrome/Chromium: site and download override prevention. Windows 11 22H2+ also gets Enhanced Phishing Protection; Server 2022 records it as SKIPPED. |

### Also retained from the base script

- Disable built-in Guest.
- Disable password expiration for accounts that should expire, and audit account policy.
- Network logon right review. Removing Everyone is opt-in with
  `-RemoveEveryoneNetworkLogonRight`; without it V2 only reports whether Everyone is
  present.
- RDP, service, and SMB share decisions with required-service protection. The Server
  service is started temporarily for share review and restored to its prior state.
- SMB signing, SMB1 disablement, Defender, firewall.
- Registry baselines for UAC, autorun, NTLM, LDAP signing, LLMNR, blank-password limits,
  last-user display, and related settings.
- Browser machine policies for Chrome, Chromium, Edge, and Firefox.
- Process, listener, software, task, hotfix, certificate, and BitLocker inventory.

---

## Private plain-text run folder

Default location:

```
C:\ProgramData\CYPatV2\Runs\<timestamp>-<random>\
```

Override with `-RunRoot`. The folder ACL allows only SYSTEM and BUILTIN\Administrators.
Its records are plain text; the `Quarantine\` subfolder can also hold copied binary
files:

| File | Contents |
|------|----------|
| `Report.txt` | Findings, summary, accounts, groups, processes, listeners, applications, tasks, shares, roles, browsers, Defender, hotfixes, backdoor candidates, security policy/user rights, and BitLocker. |
| `Changed-Passwords.txt` | Timestamp, account, and generated password for every password reset. |
| `Ledger.txt` | Every change, in order: settings, audit, user rights, passwords, quarantine. |
| `Quarantine.txt` | Each stopped/removed file with original path, SHA-256, PID, listeners, signature. |
| `Quarantine\` | Copies of removed files; these can be binary. |
| `README.txt` | Short explanation of the folder. |

The folder is required before any password reset. If it cannot be created, V2 refuses
to generate passwords rather than leave them unrecorded. Under `-WhatIf` the folder is
not created and no passwords are reset.

During the run V2 may start the Server (`LanmanServer`) service so Windows can enumerate
SMB shares. It restores the prior running/stopped state and start mode afterward unless
SMB is a required service.

---

## How the sensitive decisions work

### Network logon right (opt-in)

`SeNetworkLogonRight` normally includes Everyone. V2 does **not** change it unless you
pass `-RemoveEveryoneNetworkLogonRight`. Without the switch, V2 reports PASS if Everyone
is already absent, or SKIPPED with a recommendation if Everyone is present. With the
switch, V2 removes only Everyone and refuses the change if it would also remove
Administrators or Users/Authenticated Users.

### Passwordless detection

An account is treated as passwordless when either fact is true:

- `PasswordRequired` is `false`, or
- `PasswordLastSet` is empty/null.

This avoids guessing or attempting a blank logon. V2 generates a complex password with
the Windows cryptographic RNG, sets it, verifies `PasswordRequired` and
`PasswordLastSet`, and only then writes it to the private file.

### Administrators-only rights

The only accepted principal is:

```
*S-1-5-32-544
```

That is BUILTIN\Administrators. Domain Admins and Enterprise Admins keep access through
their normal membership in the local Administrators group. Named users are never kept.
If a domain GPO overrides the local right, the report records the readback and you must
check `gpresult /r`.

### Netcat / backdoor Y/N

The decision is interactive and per candidate:

- `-AuditOnly` lists candidates and changes nothing.
- `-NonInteractive` lists candidates and changes nothing.
- `-WhatIf` lists candidates and changes nothing.
- Interactive `-Apply` asks **Y/N** for each candidate.
- Valid Microsoft-signed binaries are never touched.
- A file is deleted only after a quarantine copy and matching SHA-256.
- If the copy or hash check fails, the original is left in place and the result is FAILED.
- An invalid answer (not Y or N) records REVIEW; only an explicit N records SKIPPED.

### SmartScreen

SmartScreen is configured as a Windows machine policy, not only a browser policy:

| Scope | Values |
|-------|--------|
| Windows System | `EnableSmartScreen=1`, `ShellSmartScreenLevel=Block`, `SmartScreenPuaEnabled=1` |
| Internet Explorer | `PhishingFilter\PreventOverride=1` |
| Edge | `SmartScreenEnabled=1`, `SmartScreenPuaEnabled=1`, `PreventSmartScreenPromptOverride=1`, `PreventSmartScreenPromptOverrideForFiles=1`, `SmartScreenDnsRequestsEnabled=1` |
| Chrome / Chromium | `PreventSmartScreenPromptOverride=1`, `PreventSmartScreenPromptOverrideForFiles=1` |
| Windows 11 22H2+ | `WTDS\Components`: `ServiceEnabled=1`, `NotifyMalicious=1`, `NotifyPasswordReuse=1`, `NotifyUnsafeApp=1` |

Enhanced Phishing Protection is Windows 11 22H2+ only. Server 2022 records it as
SKIPPED rather than writing a policy that does nothing.

---

## Safety and limits

- **Read the README.** Do not remove users, shares, or software that the scenario requires.
- **Password reset is broad.** Every enabled blank account is reset unless you name it in
  `-PasswordExemptUsers`. The console prints each new password once; keep
  `Changed-Passwords.txt` private.
- **Domain controllers are not locally reset.** On a DC, local account commands do not
  describe domain accounts; AD changes remain manual.
- **GPO can override local settings.** Audit policy and user rights may be controlled by
  a domain GPO. Verify with `gpresult /r` and re-run `-AuditOnly`.
- **No software removal or updates.** V2 does not uninstall WildTangent, WinDirStat, or
  Wireshark, does not install Notepad++, and does not download Windows updates. Use the
  image README for those items.
- **No group creation or demotion.** V2 does not create SpiderVerse, add members to it, or
  demote tina/peterson. Those remain manual.
- **Netcat scope.** V2 checks running netcat-family processes and the same names in
  `System32`/`SysWOW64`. A renamed binary in another folder needs manual review.
- **Untested.** Verify in a VM snapshot before using it in a scored round.

---

## Verify after a run

```powershell
# Audit policy: both Success and Failure should appear for every subcategory.
auditpol /get /category:*

# Passwordless accounts: none should have PasswordRequired=False.
Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet

# Sensitive rights: only *S-1-5-32-544.
secedit /export /cfg $env:TEMP\secpol-v2.inf /areas USER_RIGHTS
Get-Content $env:TEMP\secpol-v2.inf |
    Select-String 'SeSecurityPrivilege|SeTakeOwnershipPrivilege'

# SmartScreen.
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' |
    Select-Object EnableSmartScreen,ShellSmartScreenLevel,SmartScreenPuaEnabled

# Private run folder.
Get-ChildItem 'C:\ProgramData\CYPatV2\Runs'
```

---

## Parameters added in V2

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `-RunRoot` | `C:\ProgramData\CYPatV2\Runs` | Parent folder for the private run folder. |
| `-PasswordExemptUsers` | empty | Exact account names to leave out of the passwordless reset. |
| `-SecurityLogSizeKB` | `196608` | Security log maximum size in KB (192 MB). |
| `-ApplicationLogSizeKB` | `32768` | Application log maximum size in KB (32 MB). |
| `-SystemLogSizeKB` | `32768` | System log maximum size in KB (32 MB). |

`-RemoveEveryoneNetworkLogonRight` is unchanged but intentionally opt-in: pass it only
when the scenario does not require Everyone to access the server over the network.

Existing parameters such as `-Apply`, `-AuditOnly`, `-NonInteractive`,
`-SkipKnownPasswordCheck`, `-RemoveEveryoneNetworkLogonRight`, `-RequiredServices`,
`-RequiredShares`, `-KeepShares`, `-RemoveShares`, `-AuditCoverage`, the
password/lockout values, `-AuthorizedUsers`, `-AuthorizedAdministrators`,
`-ReportPath`, `-Detailed`, and `-PassThru` are unchanged.

---

## Notes on the audit baseline

- `AuditCoverage=All` is the default and enables every subcategory Windows reports.
- `AuditCoverage=Core` limits the list to the high-value subcategories.
- The Security log is enlarged so all-failure auditing does not roll over immediately.
- `SCENoApplyLegacyAuditPolicy=1` stops legacy category auditing from overriding the
  subcategory settings.
- `ProcessCreationIncludeCmdLine_Enabled=1` records command lines in process-creation
  events.

If a subcategory refuses both bits, the report marks it FAILED with the readback mask.
That is normally a governing GPO or a subcategory that does not accept both settings.

---

## File

```
Scripts/Windows/Server/2022/Cypat Server 2022 Enforcer v2.ps1
```
