#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CYPat Enforcer V6 - Windows 11 / Windows Server baseline, audit, and guarded hardening.
.DESCRIPTION
    HOW TO RUN (no parameters are needed):
      * Paste: open Windows PowerShell with Run as administrator, copy this whole
        file (for example from the Raw view on GitHub), paste it into the window
        with a right-click or Ctrl+V, and press Enter if the last line has not
        started on its own. Nothing has to be saved or unblocked first.
      * File: save it, open an elevated Windows PowerShell window in its folder,
        and run these two lines (the name has spaces, so it needs the quotes):
          Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
          & '.\Cypat Server 2022 Enforcer v6.ps1'
    Windows 11 and Windows Server hardening helper. Without -AuditOnly the script applies
    its baseline; with -AuditOnly it only reports. Read the image README and complete the
    forensics questions first. Nothing in the script is tied to a specific image, user,
    or domain; every account, share, service, and path is discovered at run time.

    V6 behavior (the reason this version exists):
      * Origin, not folder name, decides trust. V5 trusted any path under Program
        Files, so an unsigned impostor sitting in a real vendor folder was never
        reported. V6 classifies every executable it meets as OS component
        (hardlinked into WinSxS), Microsoft signed, installed product (valid signer
        whose install folder is registered in Uninstall), unregistered signed,
        impersonation, publisher mismatch, or unknown. A file that claims a vendor
        in its version resource but cannot prove that vendor is a high-signal
        finding even inside C:\Program Files.
      * Autoruns are resolved, not just listed. Every Run, RunOnce, and
        Policies\Explorer\Run value under HKLM/HKCU and WOW6432Node is expanded to
        its executable and given the same provenance check. V5 printed the value
        name and never looked at the target.
      * Installed software is evaluated. A registered product whose own binary
        cannot prove its publisher, an install root that no longer exists, a
        writable install root, a publisher that disagrees with the signature, and
        uninstall entries with no display name are each reported.
      * Defender is actually exercised. Detection history (Get-MpThreatDetection)
        is read as forensic evidence, signature and scan age are checked, CFAs and
        ASR rules are reported, and -QuickScan adds an opt-in on-demand scan of the
        flagged folders or the whole system.
      * Scheduled tasks, services, drivers, and startup folders all escalate on
        provenance, not on path.
      * IIS is hardened when present: directory browsing, WebDAV, TRACE/TRACK/DEBUG,
        version headers, W3C logging, pool identity, bindings, TLS posture,
        webshell-shaped files in writable folders, global modules outside
        System32\inetsrv, and allowed ISAPI/CGI paths outside inetsrv.
      * A retained SMB share is attested, not assumed: signing, SMB1, guest
        logons, null sessions, ABE, and the share/NTFS ACE set are read back in one
        block. SMB encryption is reported and only applied with
        -EncryptKeptShares.
      * A HIGH-SIGNAL INDICATORS block in Report.txt and on the console lists every
        object that could not prove its origin. Interactive Apply mode can
        quarantine one at a time (hash-verified copy first, never a silent delete)
        and refuses C:\CyberPatriot, C:\AFA, %SystemRoot%, and service images.
      * -SelfTest proves the classifier on the running host before you rely on it.

    V6.1/V6.2 behavior (persistence and forensics):
      * Defender exclusions are audited and a whole-root, user-writable,
        executable-type, or unverifiable-process exclusion is high-signal.
      * DLL search-order hijacks: a well-known hijackable DLL name planted beside
        a running application or service binary is detected and hashed.
      * Winlogon (Shell/Userinit/Notify/AppSetup/GinaDll), AppInit_DLLs,
        LSA packages, BootExecute, netsh helpers, print monitors, time providers,
        Winsock providers, IFEO debuggers, and SilentProcessExit are read.
      * Offline per-user hives are loaded read-only so another account's Run keys
        are visible, not just the current administrator's HKCU.
      * Trusted roots holding a private key, unrecognised self-signed roots,
        AlwaysInstallElevated, stored Winlogon passwords, PowerShell profiles, and
        unattend answer files are reported.
      * Event log forensics: 1102/104 log clears, 7045 service installs,
        7040 start-type changes, 4698 task creation, and 4720 account creation.
      * Execution history: Prefetch, RunMRU, UserAssist, BAM, and Amcache.
      * Network pivots: netsh portproxy, persistent routes, hosts overrides,
        WinINET proxy settings, and trusted-site entries.
      * Listening-port attribution: every TCP/UDP listener is tied to its process,
        owning service, and provenance, and named from a port catalog (SSH on 22,
        Telnet on 23, RDP on 3389, VNC, common backdoor ports, and so on). A named
        service that nothing in -RequiredServices, the service Y/N answers, or
        -AllowedPorts says is needed is reported as UNEXPECTED, for example SSH
        listening when SSH should not be there. Interactive Apply mode asks Y
        (keep and record) or N (close) per port. Closing never stops a service
        that shares its process, a core Windows service, or a required program,
        and a service is disabled only after its port is proven closed.
      * A Windows catalog signature is verified through the catalog API, so an
        inbox or MSI-installed file that has no embedded signature is not reported
        as an impostor.

    V6.3 behavior (README-driven checks; each one acts only on names you pass):
      * -RequiredSoftware confirms each README program is installed machine-wide at
        its default location and keeps its folder out of quarantine and port closing.
      * -RemoveUsers removes the README's unauthorized accounts one Y/N at a time and
        proves the profile folder was kept.
      * -ResetPasswords sets a new generated password on the README's insecure-password
        accounts.
      * -RemovePackages uninstalls the README's prohibited programs one Y/N at a time.
      * -ProhibitedExtensions finds files of those types under user folders, inetpub,
        Temp, and ProgramData and offers each one for quarantine.
      * The run reports Windows update and browser freshness.

    Round 3 behavior:
      * The firewall is always on and enforced with no question: every profile on,
        outbound Allow, and a policy value that turned a profile off is corrected.
        It blocks only risky inbound traffic: Telnet, FTP, SSH, TFTP, rsh, VNC,
        Radmin, TeamViewer, DameWare, and well-known backdoor ports get Block rules
        unless the README needs them, and SMB, RDP, WinRM, and SNMP are blocked
        only after an N answer. A Y answer keeps the service's port open: a rule
        that blocks it is switched off and its built-in Allow rule switched on
        (RDP Y keeps 3389 open). Windows' own setting for other traffic is left as
        found and reported. Local rule merging stays at the Windows default (on).
      * RDP is one Y/N question. Y keeps Remote Desktop on port 3389 (a moved port
        is put back) with its service running and its built-in firewall rules on
        3389. N turns RDP off: connections denied, its firewall rules disabled,
        and TermService, SessionEnv, and UmRdpService stopped and disabled.
      * The whole-disk malware file search is a separate script, Deep File Hunter
        v2 (cp 19\Deep File Hunter v2), so this script stays focused on settings.
      * Scheduled tasks: every task outside \Microsoft\ and every high-risk task
        gets a Y/N question, does it belong? Y keeps it; N removes it after its
        XML is saved.
      * Deep hardening: the full User Rights Assignment table (no-one rights,
        Administrators-only rights, Everyone/Guests removed, Guests denied), about
        60 more Security Options and policy values (WDigest, CredSSP, SMB
        signing, NTLM fallback, UAC, logon banner, IP source routing, WinRM Basic
        and unencrypted traffic, RDP drive redirection and saved passwords, print
        driver restrictions, script block logging), anonymous SID translation
        off, Group Policy values that switch Defender off are reset, and
        potentially unwanted app blocking, cloud protection, and network
        protection are turned on. Automatic logon with a stored password and the
        PowerShell 2.0 engine each get a Y/N question, as do the UPnP, SSDP, and
        sharing services.

    V3 behavior (retained):
      * Passwordless accounts are found two ways: the PasswordRequired/PasswordLastSet
        flags, and one empty-password local logon per eligible account. The logon
        test temporarily sets LimitBlankPasswordUse to 0, because that restriction
        rejects an empty password even when the account is blank. A rejected empty
        logon is not treated as proof of a password while that restriction is active.
        Every account with a null/never-set password date or a not-required flag gets
        a generated password, and an inconclusive probe never blocks the reset. Only a
        policy-lifted rejection plus a real password date keeps an existing password.
        The restriction is restored immediately after each probe and again by the
        registry audit.
        Built-in Administrator and disabled accounts are included; disabled accounts
        are never enabled by this script. Use -PasswordExemptUsers for documented
        exceptions. -ResetAllUserPasswords adds an interactive all-account reset.
      * Persistence and anomaly review covers service binary paths, unquoted service
        paths, unsigned service binaries, masquerading and unsigned processes,
        startup folders, WMI event subscriptions, LOLBin command-line arguments, and
        a driver signature baseline. Every finding is REVIEW-only; nothing is
        deleted.
      * Every audit subcategory is enabled for Success and Failure and read back by
        GUID. Event log sizes are enlarged and the Windows Event Log service is kept
        Automatic and Running.
      * SMB shares are audited for share-level and NTFS permissions. Everyone,
        ANONYMOUS LOGON, and Guests are flagged; risky shares get a separate
        keep/remove decision and a permission-hardening decision.
      * SeSecurityPrivilege and SeTakeOwnershipPrivilege are restricted to
        *S-1-5-32-544 (BUILTIN\Administrators) only.
      * Netcat-family binaries are detected and handled with an interactive Y/N
        decision; Y stops the process, quarantines a hash-verified copy, and deletes
        the original.
      * OpenSSH is inventoried across service, capability, binary, listener, firewall,
        configuration, host-key, and authorized-key evidence. If it is present and
        active, the operator is asked whether to turn it off.
      * Scheduled tasks are checked for irregular persistence, including the known
        backup_plan pattern, hidden tasks, user-writable executables, encoded commands,
        and suspicious principals. In interactive Apply mode each non-Microsoft or
        high-risk task gets a Y/N belongs question; N removes it after an XML export.
      * SmartScreen is enforced for Windows, Internet Explorer, Edge, and
        Chrome/Chromium, with Enhanced Phishing Protection on Windows 11 22H2+.
        Chrome, Edge, and Firefox machine policies cover daily update checks,
        pop-up blocking, third-party cookie blocking, and Firefox add-on warnings.
      * Windows Defender Firewall profiles are always enabled with outbound Allow
        and blocked-packet logging; only risky inbound ports are blocked, and the
        allow rules for required services are preserved.
      * Every finding is written as plain text under C:\findings, one
        Enforcer-<date-time> folder per run (Report.txt, Changed-Passwords.txt,
        Ledger.txt, Quarantine.txt, Quarantine\, README.txt), unless -RunRoot is
        supplied. The folder is limited to SYSTEM, Administrators, and the account
        that ran the script, so that account can open everything in Notepad.
      * Removing Everyone from SeNetworkLogonRight is the default. Use
        -KeepEveryoneNetworkLogonRight only when the README explicitly requires
        Everyone network access.
.PARAMETER Apply
    Apply the baseline. This is the default when -AuditOnly is not supplied.
.PARAMETER AuditOnly
    Report only. No security setting, password, share, service, or file changes.
.PARAMETER RemoveEveryoneNetworkLogonRight
    Retained for compatibility. Everyone is removed from SeNetworkLogonRight by
    default. Administrators and Users/Authenticated Users are preserved.
.PARAMETER KeepEveryoneNetworkLogonRight
    Opt out of the default removal of Everyone from SeNetworkLogonRight. Use only
    when the README explicitly requires Everyone to access this computer over the
    network.
.PARAMETER PasswordExemptUsers
    Exact account names that are excluded from password resets. Applies to both
    passwordless-account resets and -ResetAllUserPasswords.
.PARAMETER ResetAllUserPasswords
    Add an interactive full reset of every enabled local account, including the
    built-in Administrator (RID 500). Guest, DefaultAccount, and WDAGUtilityAccount
    are always excluded. Domain controllers are skipped. Each new password is
    printed once and recorded in Changed-Passwords.txt.
.PARAMETER AuditCoverage
    Retained for compatibility. All audit subcategories are always checked and
    enabled with Success and Failure auditing.
.PARAMETER ProtectedShareNames
    Share names that the scenario requires the script to keep (never offered for
    removal). Defaults to AFA, AFA$, CyberPatriot, and CyberPatriot$. Override this
    list for other images.
.PARAMETER ProtectedSharePaths
    Folder paths whose shares the scenario requires the script to keep. Defaults to
    C:\AFA and C:\CyberPatriot. Override this list for other images.
.PARAMETER RunRoot
    Parent folder for the findings. Default: C:\findings. Each run gets its own
    Enforcer-<date-time> folder inside it.
.PARAMETER QuickScan
    Opt-in. In interactive Apply mode, ask for one Y/N confirmation and then run a
    Defender custom scan of the folders named by the audits, or a quick scan of the
    whole system when nothing was flagged. A quick scan costs several minutes of a
    short round, so it is never automatic.
.PARAMETER HuntVendorFolders
    Opt-in. Walk three levels of Program Files, Program Files (x86), and ProgramData
    and provenance-check every .exe found (bounded at 1500 files). Use this when you
    suspect a dropped binary that is not running yet.
.PARAMETER EncryptKeptShares
    Opt-in. Require SMB encryption on every retained ordinary share. Leave it off
    when an old client cannot negotiate SMB 3.x encryption; the current state is
    reported as REVIEW either way.
.PARAMETER SelfTest
    Run only the provenance classifier self-test and exit. Creates the private run
    folder and a temporary folder under %TEMP%, and changes no image setting. Exit
    code 0 means every assertion passed.
.PARAMETER AllowedPorts
    Ports the README requires, as '80' or 'tcp/80'. They are reported as declared
    instead of unexpected.
.PARAMETER RequiredSoftware
    Optional. Program names from this round's README (as shown in Apps & Features,
    for example 'GIMP' or 'Firefox'), typed on the command line for that run;
    nothing is saved in the script. Each must be installed at its default
    location; its folder is never quarantined, closed, or uninstalled. Leave it out
    and the script says nothing about it.
.PARAMETER RemoveUsers
    Exact local account names the README says must go. Each is removed only after a
    Y answer; the profile folder is always kept and checked afterwards.
.PARAMETER ResetPasswords
    Exact local account names whose README-given passwords are insecure. After one Y
    confirmation each gets a generated password, recorded in Changed-Passwords.txt.
.PARAMETER RemovePackages
    Program names the README prohibits. Each match is uninstalled only after a Y
    answer, through its own uninstall entry. Names that match -RequiredSoftware are
    refused.
.PARAMETER ProhibitedExtensions
    File types the README prohibits, for example 'mp3','mp4'. Off by default. Matches
    under user folders, inetpub, Temp, and ProgramData are listed and offered for
    quarantine one at a time.
.PARAMETER ReportPath
    Extra plain-text report copy. A .json or .csv name is renamed to .txt.
.EXAMPLE
    & '.\Cypat Server 2022 Enforcer v6.ps1' -AuditOnly
    Runs the read-only review and writes the private plain-text run folder.
.EXAMPLE
    & '.\Cypat Server 2022 Enforcer v6.ps1' -Apply -PasswordExemptUsers 'svc_sql'
    Applies the baseline, resetting blank account passwords except svc_sql.
.EXAMPLE
    & '.\Cypat Server 2022 Enforcer v6.ps1' -Apply -ResetAllUserPasswords
    Applies the baseline and, after a Y confirmation, resets every enabled local
    account password and records each generated password in the private run folder.
.EXAMPLE
    & '.\Cypat Server 2022 Enforcer v6.ps1' -Apply -RequiredSoftware 'GIMP','Firefox' -RemoveUsers 'olduser' -ResetPasswords 'bob','alice' -RemovePackages 'Wireshark' -ProhibitedExtensions 'mp3','mp4'
    Applies the baseline, checks the README programs, and asks Y/N for each named
    account, package, and prohibited file.
.EXAMPLE
    & '.\Cypat Server 2022 Enforcer v6.ps1' -Apply -AllowedPorts '80','443','8080'
    Treats those ports as declared so they are not prompted as undeclared.
#>
# CYPat Enforcer V6 2022 - Full Security & Audit Script
# CYPat Enforcer V6 - Windows 11 / Windows Server baseline, audit and guarded hardening.
# V6 adds: provenance-based identity classification (hardlink, Authenticode,
# installed-product registry), resolved autorun and installed-software audits,
# Defender detection history plus opt-in -QuickScan, IIS hardening, kept-share
# attestation, and a high-signal quarantine list.
# V3 adds: empty-password logon probe (LimitBlankPasswordUse lifted only for that
# test, then restored), post-reset verification, enforced
# Success+Failure auditing, admin-only
# sensitive rights, Netcat-family Y/N quarantine, full SmartScreen baseline,
# scheduled-task persistence review (including backup_plan), Event Log service
# verification, and a private plain-text run folder. Read the image README and
# complete forensics first.
# The script discovers every account, share, service, and path at run time, so it
# works on any Windows 11 or Windows Server image.
# Made by Sheeshkidayyy github.com/sheeshkidayyy Also know as Sheesh


function Add-Result {
    param([string]$Category, [string]$Item,
        [ValidateSet('PASS','CHANGED','REVIEW','FAILED','SKIPPED')][string]$Status,
        [string]$Evidence, [string]$Recommendation)
    $script:Results.Add([pscustomobject]@{Category=$Category;Item=$Item;Status=$Status;Evidence=$Evidence;Recommendation=$Recommendation})
}

function Initialize-PrivateRun {
    # Every finding goes under C:\findings (or -RunRoot), one Enforcer-<date-time>
    # folder per run, all plain text. The folder is limited to SYSTEM,
    # Administrators, and the account that ran the script, so that account can open
    # the files in Notepad without elevating while standard users cannot.
    param([string]$Root='')
    if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Join-Path ($env:SystemDrive + '\') 'findings' }
    $Root = [Environment]::ExpandEnvironmentVariables($Root)
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $operatorSid = $null
    try { $operatorSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User } catch { $operatorSid = $null }
    foreach ($principal in @($systemSid,$adminSid,$operatorSid)) {
        if ($null -eq $principal) { continue }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($principal,'FullControl',$inheritance,$propagation,'Allow')
        $acl.AddAccessRule($rule)
    }
    if (-not (Test-Path -LiteralPath $Root)) {
        New-Item -Path $Root -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Set-Acl -LiteralPath $Root -AclObject $acl -ErrorAction Stop
    }
    $stamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
    $run = Join-Path $Root "Enforcer-$stamp"
    if (Test-Path -LiteralPath $run) { $run = "$run-$([guid]::NewGuid().ToString('N').Substring(0,4))" }
    New-Item -Path $run -ItemType Directory -Force -ErrorAction Stop | Out-Null
    New-Item -Path (Join-Path $run 'Quarantine') -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Set-Acl -LiteralPath $run -AclObject $acl -ErrorAction Stop
    Set-Acl -LiteralPath (Join-Path $run 'Quarantine') -AclObject $acl -ErrorAction Stop
    $script:RunDirectory = $run
    $header = @(
        "$($script:ProductTitle) - findings folder",
        "Created : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "Computer: $env:COMPUTERNAME",
        ''
    )
    Set-Content -LiteralPath (Join-Path $run 'Changed-Passwords.txt') -Value ($header + @('Format: timestamp | account | new password')) -Encoding UTF8 -ErrorAction Stop
    Set-Content -LiteralPath (Join-Path $run 'Ledger.txt') -Value ($header + @('Format: timestamp | action | target | detail')) -Encoding UTF8 -ErrorAction Stop
    Set-Content -LiteralPath (Join-Path $run 'Quarantine.txt') -Value ($header + @('Format: timestamp | action | file | original path | SHA256 | notes')) -Encoding UTF8 -ErrorAction Stop
    Set-Content -LiteralPath (Join-Path $run 'Password-Help.txt') -Value @(
        "$($script:ProductTitle) - manual password reference",
        '',
        'Use these commands from an elevated PowerShell or Command Prompt when the',
        'script could not set or verify an account password.',
        '',
        '  net user "<account>" "<new-password>"     set a new password',
        '  net user "<account>" /passwordreq:yes     require a password',
        '  net user "<account>" /expires:never       only when policy allows it',
        '  net user "<account>"                      read back the account state',
        '  lusrmgr.msc                               GUI: Users > right-click > Set Password',
        '',
        'Disabled accounts stay disabled. Add /active:yes only when the README says so.',
        'The new password must meet the configured length and complexity policy.',
        'Record each password before closing the window; this file never stores them.'
    ) -Encoding UTF8 -ErrorAction Stop
    Set-Content -LiteralPath (Join-Path $run 'README.txt') -Value @(
        "$($script:ProductTitle) - plain-text findings folder",
        '',
        'Report.txt              Full findings, inventory detail, security policy, and user rights.',
        'Changed-Passwords.txt   Passwords generated by this run. Keep private.',
        'Ledger.txt              Every change made by this run, in order.',
        'Quarantine.txt          Files stopped, copied, or removed, with SHA-256.',
        'Password-Help.txt       Manual password commands for any account the script could not fix.',
        'Quarantine\             Copies of removed files, renamed to end in .quarantine so they cannot run.',
        '',
        'Every file here except the quarantine copies opens in Notepad.',
        'This folder is restricted to SYSTEM, BUILTIN\Administrators, and the account that ran the script.',
        'Report, password, ledger, and quarantine records are plain text; no JSON or CSV.',
        'The Server service may be started temporarily to review SMB shares, then restored.'
    ) -Encoding UTF8 -ErrorAction Stop
    return $run
}
function Write-PrivateLine {
    param([string]$FileName,[string]$Line)
    if ([string]::IsNullOrWhiteSpace($script:RunDirectory)) { return }
    $path = Join-Path $script:RunDirectory $FileName
    Add-Content -LiteralPath $path -Value $Line -Encoding UTF8 -ErrorAction Stop
}
function Add-Ledger {
    param([string]$Action,[string]$Target,[string]$Detail='')
    try {
        $line = '{0} | {1} | {2} | {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Action, $Target, ([string]$Detail -replace '[\r\n]+',' ')
        Write-PrivateLine 'Ledger.txt' $line
    } catch { Write-Warning "Ledger write failed: $($_.Exception.Message)" }
}
function Invoke-Check {
    param([string]$Name, [scriptblock]$Action)
    try { & $Action }
    catch { Add-Result 'Check' $Name 'FAILED' $_.Exception.Message 'Review the error and retry this check.' }
}

function Invoke-Setting {
    param([string]$Category, [string]$Item, [scriptblock]$Test,
        [scriptblock]$Action, [string]$Evidence, [string]$Recommendation, [switch]$Manual)
    try {
        if (& $Test) { Add-Result $Category $Item 'PASS' $Evidence ''; return }
        if ($Manual -or -not $Apply) { Add-Result $Category $Item 'REVIEW' $Evidence $Recommendation; return }
        if ($WhatIfPreference -or -not $script:CallerCmdlet.ShouldProcess($Item, $Recommendation)) {
            Add-Result $Category $Item 'SKIPPED' 'Change was not approved by ShouldProcess.' $Recommendation
            return
        }
        & $Action | Out-Null
        if (-not (& $Test)) { throw 'The change did not pass readback verification.' }
        Add-Result $Category $Item 'CHANGED' 'Applied and verified.' ''
        Add-Ledger 'CHANGED' "$Category/$Item" $Evidence
    } catch { Add-Result $Category $Item 'FAILED' $_.Exception.Message $Recommendation }
}

function Get-RegistryState {
    param([string]$Path, [string]$Name)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        $property = $item.PSObject.Properties[$Name]
        if ($null -ne $property) { return [pscustomobject]@{Exists=$true;Value=$property.Value} }
    }
    return [pscustomobject]@{Exists=$false;Value=$null}
}

function Set-RegistryBaseline {
    param([string]$Category, [string]$Path, [string]$Name, $Value,
        [string]$Type='DWord', [switch]$Manual)
    Invoke-Setting $Category "$Path\$Name" {
        $state = Get-RegistryState $Path $Name
        $state.Exists -and (($state.Value -join "`0") -eq ($Value -join "`0"))
    } {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
    } "Required value: $Value" "Set $Name to $Value." -Manual:$Manual
}

function Invoke-Native {
    param([string]$File, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    $command = Get-Command -Name $File -CommandType Application -ErrorAction Stop
    $output = & $command.Source @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "$File exited with code ${exitCode}: $($output -join ' ')" }
    $output
}

function ConvertFrom-SecurityPolicyLines {
    param([string[]]$Lines)
    $policy = @{}; $section = ''
    foreach ($line in $Lines) {
        $text = $line.Trim().TrimStart([char]0xFEFF)
        if ($text -match '^\[([^\]]+)\]$') { $section=$matches[1]; $policy[$section]=@{} }
        elseif ($section -and $text -notmatch '^;' -and $text -match '^([^=]+?)\s*=\s*(.*)$') {
            $policy[$section][$matches[1].Trim()] = $matches[2].Trim()
        }
    }
    return $policy
}

function Get-SecurityPolicy {
    $prefix = Join-Path ([IO.Path]::GetTempPath()) ('CYPat-export-' + [guid]::NewGuid().ToString('N'))
    try {
        $diagnostics=New-Object 'System.Collections.Generic.List[string]'
        foreach ($merged in @($true,$false)) {
            if (-not $merged -and ($script:IsDomainController -or $script:IsDomainJoined)) { break }
            if (Test-Path -LiteralPath "$prefix.inf") { Remove-Item -LiteralPath "$prefix.inf" -ErrorAction Stop }
            $arguments=@('/export','/cfg',"$prefix.inf",'/areas','SECURITYPOLICY','USER_RIGHTS','/log',"$prefix.log",'/quiet')
            if ($merged) { $arguments+='/mergedpolicy' }
            Invoke-Native 'secedit.exe' $arguments | Out-Null
            if (-not (Test-Path -LiteralPath "$prefix.inf")) { throw 'Security policy export produced no file.' }
            $bytes=[IO.File]::ReadAllBytes("$prefix.inf")
            # Secedit may export UTF-16 without a BOM; Get-Content then decodes it as ANSI in Windows PowerShell.
            if ($bytes.Length -ge 4 -and (($bytes[0] -eq 255 -and $bytes[1] -eq 254) -or ($bytes[1] -eq 0 -and $bytes[3] -eq 0))) { $text=[Text.Encoding]::Unicode.GetString($bytes) }
            elseif ($bytes.Length -ge 4 -and (($bytes[0] -eq 254 -and $bytes[1] -eq 255) -or ($bytes[0] -eq 0 -and $bytes[2] -eq 0))) { $text=[Text.Encoding]::BigEndianUnicode.GetString($bytes) }
            else { $text=[IO.File]::ReadAllText("$prefix.inf") }
            $policy=ConvertFrom-SecurityPolicyLines ([regex]::Split($text,'\r?\n'))
            if ($policy.ContainsKey('System Access')) { return $policy }
            $mode='local'; if ($merged) { $mode='merged' }
            $diagnostics.Add(('{0} export: {1} bytes, sections: {2}' -f $mode,$bytes.Length,(($policy.Keys | Sort-Object) -join ', ')))
        }
        throw ('Security policy export has no System Access section. ' + ($diagnostics -join '; ') + '. Check secedit permissions and the local security database; no policy was changed.')
    } finally {
        foreach ($file in @("$prefix.inf","$prefix.log")) {
            if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue }
        }
    }
}

function Test-PolicyValue {
    param([string]$Name, $Current, $Desired)
    $actual = 0; $target = 0
    if (-not [int]::TryParse([string]$Current,[ref]$actual) -or -not [int]::TryParse([string]$Desired,[ref]$target)) {
        return ([string]$Current -eq [string]$Desired)
    }
    switch ($Name) {
        'MaximumPasswordAge' { return ($actual -gt 0 -and $actual -le $target) -or ($actual -eq $target) }
        'LockoutBadCount' { return ($actual -ge 5 -and $actual -le $target) -or ($actual -eq $target) }
        { $_ -in @('MinimumPasswordLength','MinimumPasswordAge','PasswordHistorySize','LockoutDuration','ResetLockoutCount') } {
            return $actual -ge $target
        }
        default { return $actual -eq $target }
    }
}

function Invoke-LocalAccountPolicy {
    param([System.Collections.IDictionary]$Baseline)
    $recommendation = 'Apply the local password and lockout baseline; retain stronger values.'
    if ($script:IsDomainController -or $script:IsDomainJoined) {
        Add-Result 'Accounts' 'Password and lockout policy' 'REVIEW' 'Domain policy controls this server; local policy was not changed.' 'Review the applicable domain GPO.'
        return
    }
    Invoke-Setting 'Accounts' 'Password and lockout policy' {
        $policy = Get-SecurityPolicy
        if (-not $policy.ContainsKey('System Access')) { return $false }
        foreach ($key in $Baseline.Keys) {
            if (-not $policy['System Access'].ContainsKey($key) -or -not (Test-PolicyValue $key $policy['System Access'][$key] $Baseline[$key])) { return $false }
        }
        return $true
    } {
        $policy = Get-SecurityPolicy
        $prefix = Join-Path ([IO.Path]::GetTempPath()) ('CYPat-policy-' + [guid]::NewGuid().ToString('N'))
        try {
            $lines = @('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[System Access]')
            foreach ($key in $Baseline.Keys) {
                if (-not $policy.ContainsKey('System Access') -or -not $policy['System Access'].ContainsKey($key) -or -not (Test-PolicyValue $key $policy['System Access'][$key] $Baseline[$key])) {
                    $lines += "$key = $($Baseline[$key])"
                }
            }
            $lines | Set-Content -LiteralPath "$prefix.inf" -Encoding Unicode -ErrorAction Stop
            Invoke-Native 'secedit.exe' @('/configure','/db',"$prefix.sdb",'/cfg',"$prefix.inf",'/areas','SECURITYPOLICY','/log',"$prefix.log",'/quiet') | Out-Null
        } finally {
            foreach ($file in @("$prefix.inf","$prefix.sdb","$prefix.log","$prefix.jfm","$prefix.sdb.jfm")) {
                if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue }
            }
        }
    } 'Merged password and lockout settings checked against the baseline.' $recommendation
}

function Get-NetworkLogonPrincipals {
    $policy=Get-SecurityPolicy
    if (-not $policy.ContainsKey('Privilege Rights') -or -not $policy['Privilege Rights'].ContainsKey('SeNetworkLogonRight')) {
        throw 'Security policy export does not contain SeNetworkLogonRight; no user right was changed.'
    }
    $principals=@(([string]$policy['Privilege Rights']['SeNetworkLogonRight']) -split ',' | ForEach-Object { $_.Trim() })
    if ($principals.Count -eq 0 -or @($principals | Where-Object { -not $_ }).Count -gt 0) {
        throw 'SeNetworkLogonRight contains an empty principal; no user right was changed.'
    }
    return $principals
}

function Invoke-NetworkLogonRightDecision {
    $principals=@(Get-NetworkLogonPrincipals)
    if (@($principals | Where-Object { $_ -match '^(\*?S-1-1-0|Everyone)$' }).Count -eq 0) {
        Add-Result 'User rights' 'SeNetworkLogonRight without Everyone' PASS 'Everyone is not assigned this right.' ''
        return
    }
    if ($script:IsDomainJoined) {
        Add-Result 'User rights' 'Domain policy may control SeNetworkLogonRight' REVIEW 'The local right will be updated, but a governing GPO may override it.' 'Verify the effective right and governing GPO after the run.'
    }
    Invoke-Setting 'User rights' 'SeNetworkLogonRight without Everyone' {
        $principals=@(Get-NetworkLogonPrincipals)
        return @($principals | Where-Object { $_ -match '^(\*?S-1-1-0|Everyone)$' }).Count -eq 0
    } {
        $principals=@(Get-NetworkLogonPrincipals)
        $remaining=@($principals | Where-Object { $_ -notmatch '^(\*?S-1-1-0|Everyone)$' })
        if ($remaining.Count -eq $principals.Count) { return }
        $hasAdministrators=($remaining -contains '*S-1-5-32-544') -or ($remaining -contains 'S-1-5-32-544')
        $hasUsers=($remaining -contains '*S-1-5-32-545') -or ($remaining -contains 'S-1-5-32-545') -or
            ($remaining -contains '*S-1-5-11') -or ($remaining -contains 'S-1-5-11')
        # Keep legitimate network access after Everyone is removed. Add the
        # standard local groups only when the existing right would otherwise
        # leave no authorized principals.
        if (-not $hasAdministrators) { $remaining += '*S-1-5-32-544' }
        if (-not $hasUsers) { $remaining += '*S-1-5-32-545' }
        $remaining=@($remaining | Select-Object -Unique)
        $prefix=Join-Path ([IO.Path]::GetTempPath()) ('CYPat-network-right-' + [guid]::NewGuid().ToString('N'))
        try {
            $lines=@('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1',
                '[Privilege Rights]',('SeNetworkLogonRight = ' + ($remaining -join ',')))
            $lines | Set-Content -LiteralPath "$prefix.inf" -Encoding Unicode -ErrorAction Stop
            Invoke-Native 'secedit.exe' @('/validate',"$prefix.inf") | Out-Null
            Invoke-Native 'secedit.exe' @('/configure','/db',"$prefix.sdb",'/cfg',"$prefix.inf",'/areas','USER_RIGHTS','/log',"$prefix.log",'/quiet') | Out-Null
        } finally {
            foreach ($file in @("$prefix.inf","$prefix.sdb","$prefix.log","$prefix.jfm","$prefix.sdb.jfm")) {
                if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue }
            }
        }
    } 'Everyone is present in SeNetworkLogonRight.' 'Remove only Everyone and preserve Administrators, Users, and all other assigned principals.'
    $result=$script:Results[$script:Results.Count-1]
    if ($result.Item -eq 'SeNetworkLogonRight without Everyone' -and $result.Status -eq 'CHANGED') {
        Write-Host 'Removed Everyone from Access this computer from the network.' -ForegroundColor Green
    }
}

function Read-YesNo {
    param([string]$Prompt)
    if ($NonInteractive) { return $null }
    $answer = (Read-Host "$Prompt [Y/N]").Trim().ToUpperInvariant()
    if ($answer -in @('Y','YES')) { return 'Y' }
    if ($answer -in @('N','NO')) { return 'N' }
    Write-Warning 'No valid Y/N answer was received; the current setting was left unchanged.'
    return $null
}

function Test-RemoteSession {
    $senderInfo = Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue
    return ($env:SESSIONNAME -like 'RDP*') -or ($null -ne $senderInfo -and $null -ne $senderInfo.Value)
}

function Get-ServiceStartMode {
    param($Service)
    $property = $Service.PSObject.Properties['StartType']
    if ($null -ne $property) { return [string]$property.Value }
    $name = $Service.Name.Replace("'","''")
    $instance = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'" -ErrorAction Stop
    if ($instance.StartMode -eq 'Auto') { return 'Automatic' }
    return [string]$instance.StartMode
}

function Get-CoreProperty {
    param($Object, [string]$Name, $Default=$null)
    if ($null -ne $Object) {
        $property = $Object.PSObject.Properties[$Name]
        if ($null -ne $property) { return $property.Value }
    }
    return $Default
}

function Test-ServiceProtected {
    param([string]$Name)
    $state = Get-Variable -Name ProtectedServices -Scope Script -ErrorAction SilentlyContinue
    return $null -ne $state -and $null -ne $state.Value -and $state.Value.ContainsKey($Name)
}

function Add-RequiredServiceProtection {
    param([string]$Name, [string]$Reason, [switch]$Primary)
    if ($Primary) { $script:RequiredPrimaryServices[$Name]=$true }
    if ($script:ProtectedServices.ContainsKey($Name)) { return }
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) { Add-Result 'Required services' $Name 'FAILED' "Required service or dependency is not installed ($Reason)." 'Review the README and installed roles; no role was created.'; return }
    $script:ProtectedServices[$service.Name]=$Reason
    if ($service.Name -eq 'LanmanServer') { $script:RequiredLogical['SMB']=$true }
    if ($service.Name -eq 'TermService') { $script:RequiredLogical['RDP']=$true }
    foreach ($dependency in @(Get-CoreProperty $service 'ServicesDependedOn' @())) {
        $dependencyName = [string](Get-CoreProperty $dependency 'Name' '')
        if ($dependencyName) { Add-RequiredServiceProtection $dependencyName "Dependency of $($service.Name), $Reason" }
        else { Add-Result 'Required services' $service.Name 'REVIEW' 'A required dependency could not be identified.' 'Review service dependencies at the console.' }
    }
    $script:RequiredServiceOrder.Add($service.Name)
}

function Initialize-RequiredServices {
    $script:ProtectedServices=@{}; $script:RequiredLogical=@{}; $script:RequiredPrimaryServices=@{}
    $script:RequiredServiceOrder=New-Object 'System.Collections.Generic.List[string]'
    $aliases=@{
        SMB=@('LanmanServer','LanmanWorkstation'); RDP=@('TermService','SessionEnv','UmRdpService')
        DNS=@('DNS'); DHCP=@('DHCPServer'); IIS=@('W3SVC','WAS'); FTP=@('FTPSVC')
        SMTP=@('SMTPSVC'); WinRM=@('WinRM'); SSH=@('sshd'); Print=@('Spooler')
    }
    foreach ($entry in $RequiredServices) {
        $name=[string]$entry
        if (-not $name.Trim() -or [WildcardPattern]::ContainsWildcardCharacters($name)) {
            Add-Result 'Required services' $name 'FAILED' 'Required service entry must be an exact service name or supported alias.' 'Correct RequiredServices.'; continue
        }
        if ($aliases.ContainsKey($name)) {
            $script:RequiredLogical[$name]=$true
            $found=$false
            foreach ($candidate in $aliases[$name]) {
                $service=Get-Service -Name $candidate -ErrorAction SilentlyContinue
                if ($null -ne $service) {
                    $found=$true; $primary=($name -ne 'RDP' -or $candidate -eq 'TermService')
                    Add-RequiredServiceProtection $service.Name "Required by $name" -Primary:$primary
                }
            }
            if (-not $found) { Add-Result 'Required services' $name 'FAILED' 'No installed service matches this required role.' 'Review the README and installed roles; no role was created.' }
        } else { Add-RequiredServiceProtection $name "Explicitly required: $name" -Primary }
    }
    # Required shares need port 445 even though the Server service itself is
    # still offered as a normal Y/N service decision after the share review.
    if ($RequiredShares.Count) { $script:RequiredLogical['SMB']=$true }
    # Start dependencies before their consumers; retain non-disabled dependency start modes.
    foreach ($name in $script:RequiredServiceOrder) {
        $script:ServiceDecisions[$name]='Y'; Invoke-Check $name { Set-SelectedService $name 'Y' }
    }
}

function Set-SelectedService {
    param([string]$Name, [string]$Choice)
    $service = Get-Service -Name $Name -ErrorAction Stop
    $protected=Test-ServiceProtected $Name
    if ($Choice -eq 'N' -and $protected) {
        $script:ServiceDecisions[$Name]='Y'
        Add-Result 'Required services' $Name 'REVIEW' "N was refused: $($script:ProtectedServices[$Name]). Service was retained." 'Change RequiredServices only after reviewing the README.'
        return
    }
    $senderInfo = Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue
    if ($Choice -eq 'N' -and $Name -eq 'WinRM' -and $null -ne $senderInfo -and $null -ne $senderInfo.Value) {
        Add-Result 'Services' $Name 'REVIEW' 'PowerShell remoting session detected; disabling WinRM was refused.' 'Use the local console to review WinRM.'
        return
    }
    if ($Choice -eq 'N' -and $Name -eq 'TermService' -and (Test-RemoteSession)) {
        Add-Result 'Services' $Name 'REVIEW' 'Remote session detected; disabling Remote Desktop was refused.' 'Use the local console to review RDP.'
        return
    }
    if ($script:IsDomainController -and $Name -in @('DNS','DHCPServer','LanmanServer','Netlogon','NTDS','DFSR','Kdc')) {
        Add-Result 'Services' $Name 'REVIEW' 'Domain controller role service was retained.' 'Review domain role requirements.'
        return
    }
    if ($Choice -eq 'N' -and $Name -eq 'TermService' -and $Apply -and -not $WhatIfPreference) {
        # UmRdpService and SessionEnv are part of the Remote Desktop stack and
        # would otherwise block the scored TermService disable.
        foreach ($dependencyName in @('UmRdpService','SessionEnv')) {
            $dependencyService=Get-Service -Name $dependencyName -ErrorAction SilentlyContinue
            if ($null -ne $dependencyService -and [string]$dependencyService.Status -ne 'Stopped') {
                try {
                    Stop-Service -Name $dependencyName -Force -ErrorAction Stop
                    Add-Result 'Services' $dependencyName 'CHANGED' 'Stopped so TermService could be disabled with the RDP decision.' ''
                } catch {
                    Add-Result 'Services' $dependencyName 'REVIEW' $_.Exception.Message 'Stop this Remote Desktop dependency at the console before disabling TermService.'
                }
            }
        }
        $service=Get-Service -Name $Name -ErrorAction Stop
    }
    if ($Choice -eq 'N') {
        $dependents = @($service.DependentServices | Where-Object { [string]$_.Status -eq 'Running' })
        if ($dependents.Count -gt 0) {
            Add-Result 'Services' $Name 'REVIEW' ('Running dependent services: ' + (($dependents | ForEach-Object {$_.Name}) -join ', ')) 'Review dependencies at the console before stopping this service.'
            return
        }
    }
    $desiredStatus = 'Stopped'; $desiredStart = 'Disabled'
    if ($Choice -eq 'Y') {
        $desiredStatus='Running'; $desiredStart='Automatic'
        if ($protected -and -not $script:RequiredPrimaryServices.ContainsKey($Name)) {
            $desiredStart=Get-ServiceStartMode $service
            if ($desiredStart -eq 'Disabled') { $desiredStart='Manual' }
        }
    }
    Invoke-Setting 'Services' $Name {
        $current = Get-Service -Name $Name -ErrorAction Stop
        ([string]$current.Status -eq $desiredStatus) -and ((Get-ServiceStartMode $current) -eq $desiredStart)
    } {
        if ($Choice -eq 'Y') {
            if ((Get-ServiceStartMode (Get-Service -Name $Name -ErrorAction Stop)) -ne $desiredStart) { Set-Service -Name $Name -StartupType $desiredStart -ErrorAction Stop }
            if ([string](Get-Service -Name $Name -ErrorAction Stop).Status -ne 'Running') { Start-Service -Name $Name -ErrorAction Stop }
        } else {
            if ([string](Get-Service -Name $Name -ErrorAction Stop).Status -ne 'Stopped') { Stop-Service -Name $Name -ErrorAction Stop }
            Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
        }
    } "Requested $desiredStatus / $desiredStart." "Set service $Name to $desiredStatus / $desiredStart."
}

function Invoke-ServiceDecision {
    param([string]$Label, [string[]]$Names, [string]$Warning)
    $installed = @($Names | ForEach-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue })
    if ($installed.Count -eq 0) { Add-Result 'Services' $Label 'SKIPPED' 'Service is not installed.' ''; return }
    $optional=@($installed | Where-Object {-not (Test-ServiceProtected $_.Name)})
    $choice=$null
    if ($optional.Count -gt 0) {
        if ($Warning) { Write-Warning $Warning }
        $choice=Read-YesNo "Keep $Label enabled and running?"
    }
    foreach ($service in $installed) {
        $selected=$choice
        if (Test-ServiceProtected $service.Name) { $selected='Y' }
        $script:ServiceDecisions[$service.Name]=$selected
        if (-not $selected) { Add-Result 'Services' $service.Name 'REVIEW' 'No explicit Y/N decision; service was not changed.' 'Run interactively to select Y or N.' }
        else {
            Invoke-Check $service.Name { Set-SelectedService $service.Name $selected }
            # Record the effective state, not just the requested answer. A
            # protected service or a running dependent can refuse a disable.
            $current=Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            if ($null -ne $current) {
                $currentMode=Get-ServiceStartMode $current
                $script:ServiceDecisions[$service.Name]=if ([string]$current.Status -eq 'Stopped' -and $currentMode -eq 'Disabled') { 'N' } else { 'Y' }
            }
        }
    }
}

function Get-SshEvidence {
    $service = Get-Service -Name sshd -ErrorAction SilentlyContinue
    $capability = $null
    if (Get-Command Get-WindowsCapability -ErrorAction SilentlyContinue) {
        try { $capability = @(Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop | Select-Object -First 1) | Select-Object -First 1 }
        catch { $capability = $null }
    }
    $binary = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    $sshDirectory = Join-Path $env:ProgramData 'ssh'
    $configPath = Join-Path $sshDirectory 'sshd_config'
    $listeners = @()
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        try { $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction Stop) } catch { $listeners = @() }
    }
    $firewallRules = @()
    if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
        try {
            $firewallRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
                ([string](Get-OptionalProperty $_ 'DisplayName' '')) -match '(?i)ssh|openssh' -or
                ([string](Get-OptionalProperty $_ 'Name' '')) -match '(?i)ssh|openssh'
            })
        } catch { $firewallRules = @() }
    }
    $config = [ordered]@{}
    $configExists = Test-Path -LiteralPath $configPath -PathType Leaf
    if ($configExists) {
        foreach ($line in @(Get-Content -LiteralPath $configPath -ErrorAction Stop)) {
            $trimmed = $line.Trim()
            if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
            if ($trimmed -match '^([^\s]+)\s+(.+)$') { $config[$matches[1].ToLowerInvariant()] = $matches[2].Trim() }
        }
    }
    $hostKeys = @()
    if (Test-Path -LiteralPath $sshDirectory -PathType Container) {
        $hostKeys = @(Get-ChildItem -LiteralPath $sshDirectory -Filter 'ssh_host_*_key' -File -Force -ErrorAction SilentlyContinue)
    }
    $authorizedKeys = @()
    $administratorKeys = Join-Path $sshDirectory 'administrators_authorized_keys'
    if (Test-Path -LiteralPath $administratorKeys -PathType Leaf) { $authorizedKeys += $administratorKeys }
    $userKeyPattern = Join-Path $env:SystemDrive 'Users\*\.ssh\authorized_keys'
    $authorizedKeys += @(Get-ChildItem -Path $userKeyPattern -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $capabilityState = if ($null -ne $capability) { [string](Get-OptionalProperty $capability 'State' '') } else { '' }
    $serviceState = if ($null -ne $service) { [string]$service.Status } else { 'NotInstalled' }
    $serviceStart = if ($null -ne $service) { Get-ServiceStartMode $service } else { 'NotInstalled' }
    $listenerText = @($listeners | ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) PID=$($_.OwningProcess)" }) -join '; '
    $ruleText = @($firewallRules | ForEach-Object { "$([string](Get-OptionalProperty $_ 'DisplayName' '')) [$([string](Get-OptionalProperty $_ 'Enabled' ''))]" }) -join '; '
    $found = ($null -ne $service) -or ($capabilityState -and $capabilityState -ne 'NotPresent') -or
        (Test-Path -LiteralPath $binary -PathType Leaf) -or ($listeners.Count -gt 0) -or
        $configExists -or ($hostKeys.Count -gt 0) -or ($authorizedKeys.Count -gt 0)
    return [pscustomobject]@{
        Found=$found; Service=$service; ServiceStatus=$serviceState; ServiceStartMode=$serviceStart;
        Capability=$capabilityState; Binary=$binary; BinaryExists=(Test-Path -LiteralPath $binary -PathType Leaf);
        Listeners=$listeners; ListenerText=$listenerText; FirewallRules=$firewallRules; FirewallText=$ruleText;
        ConfigPath=$configPath; ConfigExists=$configExists; Config=$config;
        HostKeys=@($hostKeys | ForEach-Object { $_.FullName }); AuthorizedKeys=@($authorizedKeys);
        Protected=(Test-ServiceProtected 'sshd')
    }
}
function Invoke-SshConfigAudit {
    param($Evidence)
    if (-not $Evidence.ConfigExists) {
        Add-Result SSH 'sshd_config' SKIPPED 'No sshd_config file was found at the standard OpenSSH Server path.' ''
        return
    }
    $config = $Evidence.Config
    $get = {
        param([string]$Name)
        if ($config.Contains($Name)) { return ([string]$config[$Name]).Trim('"') }
        return ''
    }
    $findings = [System.Collections.Generic.List[string]]::new()
    $permitRoot = & $get 'permitrootlogin'
    if ($permitRoot -match '^(?i)yes$') { $findings.Add('PermitRootLogin=yes') }
    $passwordAuth = & $get 'passwordauthentication'
    if ($passwordAuth -match '^(?i)yes$') { $findings.Add('PasswordAuthentication=yes') }
    $emptyPasswords = & $get 'permitemptypasswords'
    if ($emptyPasswords -match '^(?i)yes$') { $findings.Add('PermitEmptyPasswords=yes') }
    $x11 = & $get 'x11forwarding'
    if ($x11 -match '^(?i)yes$') { $findings.Add('X11Forwarding=yes') }
    $tcpForward = & $get 'allowtcpforwarding'
    if ($tcpForward -match '^(?i)yes$') { $findings.Add('AllowTcpForwarding=yes') }
    $pubkey = & $get 'pubkeyauthentication'
    if ($pubkey -match '^(?i)no$') { $findings.Add('PubkeyAuthentication=no') }
    $maxAuth = & $get 'maxauthtries'
    $maxAuthValue=0
    if ([int]::TryParse($maxAuth,[ref]$maxAuthValue) -and $maxAuthValue -gt 6) { $findings.Add("MaxAuthTries=$maxAuthValue") }
    $grace = & $get 'logingracetime'
    $graceValue=0
    if ([int]::TryParse($grace,[ref]$graceValue) -and $graceValue -gt 120) { $findings.Add("LoginGraceTime=$graceValue") }
    if ($findings.Count) {
        Add-Result SSH 'sshd_config review' REVIEW ($findings -join '; ') 'Review these values against the scenario. This script does not rewrite sshd_config automatically.'
    } else {
        Add-Result SSH 'sshd_config review' PASS 'No weak values matched the audited OpenSSH settings (root login, password auth, empty passwords, forwarding, key auth, MaxAuthTries, LoginGraceTime).' ''
    }
    if ($Evidence.AuthorizedKeys.Count) {
        Add-Result SSH 'Authorized keys' REVIEW (($Evidence.AuthorizedKeys | ForEach-Object { [string]$_ }) -join '; ') 'Authorized key files can provide persistent access. Confirm every key against the scenario; contents are deliberately not printed.'
    } else {
        Add-Result SSH 'Authorized keys' PASS 'No administrators_authorized_keys or per-user authorized_keys file was found.' ''
    }
    if ($Evidence.HostKeys.Count) {
        Add-Result SSH 'Host keys' PASS "Host key files present: $($Evidence.HostKeys.Count)." ''
    }
}
function Invoke-SshAudit {
    $evidence = Get-SshEvidence
    $script:Inventory.Ssh = $evidence
    if (-not $evidence.Found) {
        Add-Result SSH 'OpenSSH server' PASS 'No sshd service, OpenSSH Server capability, sshd.exe, TCP 22 listener, config, host key, or authorized-key file was found.' ''
        return
    }
    $summary = "Service=$($evidence.ServiceStatus)/$($evidence.ServiceStartMode); capability=$($evidence.Capability); binary=$($evidence.BinaryExists); listeners=$($evidence.ListenerText); firewall=$($evidence.FirewallText); config=$($evidence.ConfigExists); hostKeys=$($evidence.HostKeys.Count); authorizedKeys=$($evidence.AuthorizedKeys.Count)"
    if ($evidence.ServiceStatus -ne 'Running' -and $evidence.ServiceStartMode -eq 'Disabled') {
        Add-Result SSH 'OpenSSH server' PASS "OpenSSH artifacts are present but the service is stopped and disabled. $summary" ''
        Invoke-SshConfigAudit $evidence
        return
    }
    if ($evidence.Protected) {
        Add-Result SSH 'OpenSSH server' REVIEW "OpenSSH is protected by RequiredServices and was not offered for shutdown. $summary" 'Change RequiredServices only after confirming the README requires SSH.'
        Invoke-SshConfigAudit $evidence
        return
    }
    if (-not $Apply) {
        Add-Result SSH 'OpenSSH server' REVIEW "OpenSSH is present and not fully disabled. $summary" 'Run with -Apply interactively and answer Y to stop and disable it, or N to keep it.'
        Invoke-SshConfigAudit $evidence
        return
    }
    if ($NonInteractive) {
        Add-Result SSH 'OpenSSH server' REVIEW "OpenSSH is present and not fully disabled; NonInteractive mode will not change it. $summary" 'Run interactively and answer Y to stop and disable SSH, or N to keep it.'
        Invoke-SshConfigAudit $evidence
        return
    }
    if ($null -eq $evidence.Service) {
        Add-Result SSH 'TCP 22 listener' REVIEW "No sshd service was found, but OpenSSH artifacts or a TCP 22 listener are present. $summary" 'Identify the listening process and remove or disable the third-party SSH service manually; this script does not kill an unknown process.'
        Invoke-SshConfigAudit $evidence
        return
    }
    $choice=Read-YesNo 'OpenSSH Server was found. Turn it off? Y stops and disables it; N keeps it'
    if ($choice -eq 'Y') {
        try {
            Set-SelectedService 'sshd' 'N'
            foreach ($rule in @($evidence.FirewallRules)) {
                $ruleName=[string](Get-OptionalProperty $rule 'Name' '')
                if ($ruleName) {
                    try { Set-NetFirewallRule -Name $ruleName -Enabled False -ErrorAction Stop | Out-Null }
                    catch { Add-Result SSH "Firewall rule/$ruleName" REVIEW $_.Exception.Message 'Disable this OpenSSH firewall rule manually; the service was stopped separately.' }
                }
            }
            $after=Get-Service -Name sshd -ErrorAction SilentlyContinue
            if ($null -ne $after -and $after.Status -eq 'Stopped' -and (Get-ServiceStartMode $after) -eq 'Disabled') {
                $script:ServiceDecisions['sshd']='N'
                Add-Result SSH 'OpenSSH server' CHANGED "Service stopped and disabled; OpenSSH firewall rules disabled. $summary" ''
            } else {
                Add-Result SSH 'OpenSSH server' REVIEW "The shutdown request did not fully verify. $summary" 'Stop and disable sshd manually, then disable its inbound firewall rule.'
            }
        } catch {
            Add-Result SSH 'OpenSSH server' FAILED $_.Exception.Message 'Stop and disable sshd manually, then disable its inbound firewall rule.'
        }
        return
    }
    if ($choice -eq 'N') {
        $script:ServiceDecisions['sshd']='Y'
        Add-Result SSH 'OpenSSH server' SKIPPED "Left enabled by operator decision. $summary" 'Verify that SSH is required by the scenario and harden sshd_config and authorized keys.'
        Invoke-SshConfigAudit $evidence
        return
    }
    Add-Result SSH 'OpenSSH server' REVIEW "No valid Y/N answer was received; OpenSSH was left unchanged. $summary" 'Run again and answer Y to stop and disable SSH, or N to keep it.'
    Invoke-SshConfigAudit $evidence
}
function Invoke-BaselineServiceStartup {
    foreach ($name in @('EventLog','AppIDSvc','EFS','PolicyAgent','Sppsvc')) {
        $service=Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Add-Result Services "$name baseline" SKIPPED 'Service is not installed on this image.' ''
            continue
        }
        Invoke-Setting Services "$name baseline" {
            $current=Get-Service -Name $name -ErrorAction Stop
            (Get-ServiceStartMode $current) -eq 'Automatic' -and $current.Status -eq 'Running'
        } {
            $current=Get-Service -Name $name -ErrorAction Stop
            if ((Get-ServiceStartMode $current) -ne 'Automatic') { Set-Service -Name $name -StartupType Automatic -ErrorAction Stop }
            if ($current.Status -ne 'Running') { Start-Service -Name $name -ErrorAction Stop }
        } 'Baseline services should be Automatic and Running where the image supports them.' 'Start the service and verify its dependencies; report a platform limitation instead of forcing a disabled service.'
    }
}
function Read-ConfigureAutomaticUpdatesMode {
    Write-Host 'Configure Automatic Updates options (same radio buttons as the GPO):' -ForegroundColor Cyan
    Write-Host '  [2] Notify for download and auto-install' -ForegroundColor Gray
    Write-Host '  [3] Automatically download updates and notify for install (GPO default)' -ForegroundColor Gray
    Write-Host '  [4] Automatically download updates and scheduled install' -ForegroundColor Gray
    for ($attempt=1; $attempt -le 3; $attempt++) {
        $answer = (Read-Host 'Choose the Configure Automatic Updates option [2/3/4]').Trim()
        if ($answer -in @('2','3','4')) { return [int]$answer }
        Write-Warning 'Enter 2, 3, or 4. Nothing is applied by default.'
    }
    Write-Warning 'No valid Configure Automatic Updates option was received; the policy was not changed.'
    return $null
}
function Get-AutomaticUpdatesPlan {
    param([string]$Decision='', [int]$Mode=0)
    if ($Decision -eq 'Y' -and $Mode -in @(2,3,4)) {
        $label = switch ($Mode) {
            2 { 'notify for download and auto-install' }
            3 { 'automatically download updates and notify for install' }
            4 { 'automatically download updates and schedule install' }
        }
        return [pscustomobject]@{ Apply=$true; NoAutoUpdate=0; AUOptions=$Mode; Status='PASS';
            Evidence="Configure Automatic Updates is Enabled with option $Mode ($label)."
            Recommendation='Configure Automatic Updates is set at Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage end user experience.' }
    }
    if ($Decision -eq 'Y') {
        return [pscustomobject]@{ Apply=$false; NoAutoUpdate=$null; AUOptions=$null; Status='REVIEW';
            Evidence='Automatic updates were enabled, but no Configure Automatic Updates option was selected.'
            Recommendation='Run again and choose 2, 3, or 4 to apply the GPO radio button (NoAutoUpdate=0 with AUOptions=2, 3, or 4).' }
    }
    if ($Decision -eq 'N') {
        return [pscustomobject]@{ Apply=$true; NoAutoUpdate=1; AUOptions=$null; Status='SKIPPED';
            Evidence='Automatic updates are off by operator decision.'
            Recommendation='Answer Y for the Windows Update question and pick 2, 3, or 4 to enable Configure Automatic Updates.' }
    }
    return [pscustomobject]@{ Apply=$false; NoAutoUpdate=$null; AUOptions=$null; Status='REVIEW';
        Evidence='No Windows Update decision was recorded; the Configure Automatic Updates policy was not changed.'
        Recommendation='Run interactively and answer the Windows Update question: Y enables automatic updates and asks for option 2, 3, or 4; N disables them.' }
}
function Invoke-AutomaticUpdatesPolicy {
    param([string]$Decision='', [int]$Mode=0)
    $updatePolicy='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auPolicy="$updatePolicy\AU"
    $plan=Get-AutomaticUpdatesPlan -Decision $Decision -Mode $Mode
    if ($plan.Apply) {
        Set-RegistryBaseline Updates "$auPolicy" NoAutoUpdate $plan.NoAutoUpdate
        if ($plan.AUOptions) { Set-RegistryBaseline Updates "$auPolicy" AUOptions $plan.AUOptions }
    }
    # A daily detection cadence belongs with every enabled automatic-update mode.
    # 22 hours is the ADMX maximum and is therefore at least once per day.
    if ($Decision -eq 'Y' -and $Mode -in @(2,3,4) -and $plan.Apply) {
        Set-RegistryBaseline Updates "$auPolicy" DetectionFrequencyEnabled 1
        $frequency = Get-RegistryState $auPolicy DetectionFrequency
        $frequencyText = if ($frequency.Exists) { [string]$frequency.Value } else { 'not set' }
        Invoke-Setting Updates 'Daily update detection frequency' {
            $current = Get-RegistryState $auPolicy DetectionFrequency
            if (-not $current.Exists) { return $false }
            $hours=0
            return [int]::TryParse([string]$current.Value,[ref]$hours) -and $hours -ge 1 -and $hours -le 22
        } {
            if (-not (Test-Path -LiteralPath $auPolicy)) { New-Item -Path $auPolicy -Force -ErrorAction Stop | Out-Null }
            New-ItemProperty -LiteralPath $auPolicy -Name DetectionFrequency -Value 22 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        } "Current=$frequencyText; required 1-22 hours (22 is the ADMX maximum and checks at least daily)." 'Set Automatic Updates detection frequency to 22 hours; a governing GPO may override it. Microsoft documents that this policy has effect only with an intranet/WSUS update source.'
        if ($Mode -eq 4) {
            Set-RegistryBaseline Updates "$auPolicy" ScheduledInstallDay 0
            $installTime = Get-RegistryState $auPolicy ScheduledInstallTime
            $validTime=$false
            if ($installTime.Exists) {
                $hour=0
                $validTime=[int]::TryParse([string]$installTime.Value,[ref]$hour) -and $hour -ge 0 -and $hour -le 23
            }
            if (-not $validTime) { Set-RegistryBaseline Updates "$auPolicy" ScheduledInstallTime 3 }
            else { Add-Result Updates 'Scheduled install time' PASS "Existing ScheduledInstallTime=$($installTime.Value) was preserved with the new daily schedule." '' }
        }
    }
    $state=Get-RegistryState $auPolicy NoAutoUpdate
    $options=Get-RegistryState $auPolicy AUOptions
    $frequencyState=Get-RegistryState $auPolicy DetectionFrequency
    $frequencyEnabled=Get-RegistryState $auPolicy DetectionFrequencyEnabled
    $installDay=Get-RegistryState $auPolicy ScheduledInstallDay
    $installTime=Get-RegistryState $auPolicy ScheduledInstallTime
    $wsus=Get-RegistryState $updatePolicy WUServer
    $useWsus=Get-RegistryState $auPolicy UseWUServer
    $noAutoUpdateText = if ($state.Exists) { [string]$state.Value } else { 'not set' }
    $optionsText = if ($options.Exists) { [string]$options.Value } else { 'not set' }
    $policyMatches=$plan.Apply -and $state.Exists -and ([string]$state.Value -eq [string]$plan.NoAutoUpdate)
    if ($plan.Apply -and $plan.AUOptions) {
        $policyMatches=$policyMatches -and $options.Exists -and ([string]$options.Value -eq [string]$plan.AUOptions)
    }
    $status = if ($plan.Apply) { if ($policyMatches) { $plan.Status } else { 'REVIEW' } } else { $plan.Status }
    Add-Result Updates 'Configure Automatic Updates' $status "$($plan.Evidence) NoAutoUpdate=$noAutoUpdateText; AUOptions=$optionsText; WSUS=$($wsus.Value); UseWUServer=$($useWsus.Value)" $plan.Recommendation
    $frequencyText = if ($frequencyState.Exists) { [string]$frequencyState.Value } else { 'not set' }
    $frequencyEnabledText = if ($frequencyEnabled.Exists) { [string]$frequencyEnabled.Value } else { 'not set' }
    $installDayText = if ($installDay.Exists) { [string]$installDay.Value } else { 'not set' }
    $installTimeText = if ($installTime.Exists) { [string]$installTime.Value } else { 'not set' }
    $script:Inventory.UpdatePolicy = [pscustomobject]@{
        NoAutoUpdate=$noAutoUpdateText; AUOptions=$optionsText;
        DetectionFrequencyEnabled=$frequencyEnabledText;
        DetectionFrequency=$frequencyText;
        ScheduledInstallDay=$installDayText;
        ScheduledInstallTime=$installTimeText
    }
    if ($Decision -eq 'Y' -and (Get-Service -Name wuauserv -ErrorAction SilentlyContinue)) {
        Invoke-Setting Updates 'Windows Update service start mode' {
            (Get-ServiceStartMode (Get-Service -Name wuauserv -ErrorAction Stop)) -ne 'Disabled'
        } {
            Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
        } 'Automatic Updates needs the Windows Update service (wuauserv) to be enabled.' 'Re-enable the Windows Update service if the scenario disables it.'
    }
}
function Invoke-WindowsUpdateDecision {
    $service = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        $script:AutomaticUpdatesDecision=$null
        $script:AutomaticUpdatesMode=$null
        Add-Result 'Services' 'Windows Update' SKIPPED 'The Windows Update service (wuauserv) is not installed on this image.' 'Configure Automatic Updates cannot be enforced without the Windows Update service.'
        return
    }
    Write-Warning 'Y enables the Windows Update service and the Configure Automatic Updates policy (Computer Configuration > Administrative Templates > Windows Components > Windows Update > Manage end user experience). N disables both. No update is ever downloaded or installed by this script.'
    $choice = Read-YesNo 'Enable Windows Update automatic updates? Y enables them; N disables them'
    if ($choice -eq 'N') {
        $script:AutomaticUpdatesDecision='N'
        $script:AutomaticUpdatesMode=$null
        $script:ServiceDecisions['wuauserv']='N'
        Invoke-Check 'wuauserv' { Set-SelectedService 'wuauserv' 'N' }
        return
    }
    if ($choice -ne 'Y') {
        $script:AutomaticUpdatesDecision=$null
        $script:AutomaticUpdatesMode=$null
        $script:ServiceDecisions['wuauserv']=$null
        Add-Result 'Services' 'wuauserv' REVIEW 'No valid Y/N answer was received; the Windows Update service and the automatic-updates policy were not changed.' 'Run interactively and answer Y or N for Windows Update.'
        return
    }
    $mode = Read-ConfigureAutomaticUpdatesMode
    $script:AutomaticUpdatesDecision='Y'
    $script:AutomaticUpdatesMode=$mode
    $script:ServiceDecisions['wuauserv']='Y'
    Invoke-Check 'wuauserv' { Set-SelectedService 'wuauserv' 'Y' }
    if ($null -eq $mode) {
        Add-Result Updates 'Configure Automatic Updates' REVIEW 'Automatic updates were enabled, but no Configure Automatic Updates option was selected.' 'Run again and choose 2, 3, or 4 to apply the GPO radio button (NoAutoUpdate=0 with AUOptions=2, 3, or 4).'
    }
}

function Invoke-RdpPortStandard {
    # RDP stays on the standard port. A moved RDP port is a common planted change,
    # and the listener only moves after the Remote Desktop service restarts.
    # It also records, in $script:RdpRulePort, the port the listener really uses
    # afterwards, so the firewall rules are never moved away from a live listener.
    $script:RdpRulePort=3389
    $key='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $state=Get-RegistryState $key 'PortNumber'
    $current=if ($state.Exists) { [string]$state.Value } else { 'not set' }
    if ($state.Exists -and $current -ne '3389') {
        $parsed=0
        if ([int]::TryParse($current,[ref]$parsed) -and $parsed -gt 0 -and $parsed -le 65535) { $script:RdpRulePort=$parsed } else { $script:RdpRulePort=0 }
    }
    if (-not $state.Exists -or $current -eq '3389') {
        Add-Result 'Remote access' 'RDP port 3389' PASS "PortNumber=$current; Remote Desktop uses the standard port 3389." ''
        return
    }
    if (-not $Apply -or $WhatIfPreference) {
        Add-Result 'Remote access' 'RDP port 3389' REVIEW "PortNumber=$current; the standard RDP port is 3389." 'Run with -Apply and answer Y to the RDP question to move it back to 3389.'
        return
    }
    if (Test-RemoteSession) {
        Add-Result 'Remote access' 'RDP port 3389' REVIEW "PortNumber=$current. This session is remote, and moving the port would disconnect it." 'Run the script at the local console to move RDP back to 3389.'
        return
    }
    try {
        New-ItemProperty -LiteralPath $key -Name 'PortNumber' -Value 3389 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        $readback=Get-RegistryState $key 'PortNumber'
        if (-not ($readback.Exists -and [string]$readback.Value -eq '3389')) { throw 'PortNumber did not read back as 3389.' }
        $script:RdpRulePort=3389
        Add-Ledger 'RDP' 'PortNumber' "Changed from $current to 3389."
        $note=' The listener moves to 3389 when Remote Desktop Services next starts.'
        $service=Get-Service -Name TermService -ErrorAction SilentlyContinue
        if ($null -ne $service -and [string]$service.Status -eq 'Running') {
            Restart-Service -Name TermService -Force -ErrorAction Stop
            $listening=$false
            for ($attempt=0; $attempt -lt 20 -and -not $listening; $attempt++) {
                Start-Sleep -Milliseconds 500
                $listening=@(Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction SilentlyContinue).Count -gt 0
            }
            if ($listening) { $note=' Remote Desktop Services was restarted and is listening on 3389.' }
            else { $note=' Remote Desktop Services was restarted, but nothing is listening on 3389 yet; check it at the console.' }
        }
        Add-Result 'Remote access' 'RDP port 3389' CHANGED "PortNumber changed from $current to 3389.$note" ''
    } catch {
        Add-Result 'Remote access' 'RDP port 3389' FAILED $_.Exception.Message 'Set HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber to 3389 (DWORD) and restart Remote Desktop Services.'
    }
}
function Invoke-RdpFirewallRules {
    # The built-in Remote Desktop firewall rules. Y: the two User Mode rules are
    # enabled and point at the listener port (3389 once the port is standard).
    # N: every local rule in the Remote Desktop group is disabled, including
    # session shadowing. Only these built-in rules are touched.
    param([bool]$Enabled,[int]$Port=3389)
    $names=[System.Collections.Generic.List[string]]::new()
    foreach ($ruleName in @('RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP')) { $names.Add($ruleName) }
    if (-not $Enabled) {
        $names.Add('RemoteDesktop-Shadow-In-TCP')
        # '@FirewallAPI.dll,-28752' is the language-neutral id of the built-in
        # "Remote Desktop" rule group.
        foreach ($groupRule in @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -PolicyStore PersistentStore -ErrorAction SilentlyContinue)) {
            $groupName=[string]$groupRule.Name
            if ($groupName -and -not $names.Contains($groupName)) { $names.Add($groupName) }
        }
    }
    $desired=if ($Enabled) { 'True' } else { 'False' }
    $manual=(Test-RemoteSession) -and (-not $Enabled)
    foreach ($ruleName in $names) {
        $rules=@(Get-NetFirewallRule -Name $ruleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
        if (-not $rules.Count) {
            Add-Result 'Required firewall' $ruleName SKIPPED 'No local copy of this built-in Remote Desktop rule exists (it may be missing or delivered by Group Policy).' ''
            continue
        }
        $checkPort=$Enabled -and $Port -gt 0 -and $ruleName -like 'RemoteDesktop-UserMode-*'
        $portText=if ($checkPort) { " on port $Port" } else { '' }
        Invoke-Setting 'Required firewall' $ruleName {
            $rule=Get-NetFirewallRule -Name $ruleName -PolicyStore PersistentStore -ErrorAction Stop
            $portOk=$true
            if ($checkPort) {
                $ports=@((Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop).LocalPort)
                $portOk=($ports.Count -eq 1 -and [string]$ports[0] -eq [string]$Port)
            }
            ([string]$rule.Enabled -eq $desired) -and $portOk
        } {
            $rule=Get-NetFirewallRule -Name $ruleName -PolicyStore PersistentStore -ErrorAction Stop
            if ($checkPort) {
                Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop | Set-NetFirewallPortFilter -LocalPort $Port -ErrorAction Stop
            }
            Set-NetFirewallRule -Name $ruleName -PolicyStore PersistentStore -Enabled $desired -ErrorAction Stop | Out-Null
        } "Built-in Remote Desktop rule; required Enabled=$desired$portText." 'Change only this built-in Remote Desktop rule.' -Manual:$manual
    }
}
function Invoke-RdpDecision {
    # RDP is one Y/N question. Y keeps Remote Desktop on: connections allowed, the
    # listener on port 3389, Remote Desktop Services running, its helper services
    # not disabled, and the built-in firewall rules enabled on 3389 (Network Level
    # Authentication is required by the RDP security step that follows). N turns
    # Remote Desktop off completely: connections denied, the firewall rules
    # disabled, and TermService, SessionEnv, and UmRdpService stopped and disabled.
    # No answer changes nothing.
    $terminalServer='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if (Test-ServiceProtected 'TermService') {
        $choice='Y'
        Write-Host 'RDP is required by -RequiredServices; keeping it on.'
    } else {
        Write-Warning 'Keep Remote Desktop only when the README requires it. N turns off RDP and all of its services.'
        $choice=Read-YesNo 'Keep Remote Desktop (RDP) on? Y keeps it on port 3389; N turns RDP and its services off'
    }
    $script:ServiceDecisions['RDP']=$choice
    if (-not $choice) {
        Add-Result 'Remote access' 'RDP' REVIEW 'No Y/N answer; Remote Desktop was not changed.' 'Run interactively and answer Y to keep RDP on or N to turn it off.'
        return
    }
    if ($choice -eq 'N' -and (Test-RemoteSession)) {
        Add-Result 'Remote access' 'RDP' REVIEW 'This session is remote; turning RDP off now would disconnect it, so nothing was changed.' 'Run the script at the local console to turn RDP off.'
        return
    }
    if ($choice -eq 'Y') {
        Set-RegistryBaseline 'Remote access' $terminalServer 'fDenyTSConnections' 0
        Invoke-RdpPortStandard
        if (Get-Service -Name 'TermService' -ErrorAction SilentlyContinue) {
            $script:ServiceDecisions['TermService']='Y'
            Invoke-Check 'TermService' { Set-SelectedService 'TermService' 'Y' }
        } else {
            Add-Result 'Remote access' 'TermService' SKIPPED 'Remote Desktop Services is not installed on this image.' ''
        }
        foreach ($helperName in @('SessionEnv','UmRdpService')) {
            if ($null -eq (Get-Service -Name $helperName -ErrorAction SilentlyContinue)) { continue }
            Invoke-Setting 'Remote access' "$helperName not disabled" {
                (Get-ServiceStartMode (Get-Service -Name $helperName -ErrorAction Stop)) -ne 'Disabled'
            } {
                Set-Service -Name $helperName -StartupType Manual -ErrorAction Stop
            } 'Remote Desktop helper service; it must not be disabled while RDP is kept.' 'Set it back to Manual so Remote Desktop can start it.'
        }
        Invoke-RdpFirewallRules -Enabled $true -Port $script:RdpRulePort
        return
    }
    # N: turn Remote Desktop and every Remote Desktop service off.
    Set-RegistryBaseline 'Remote access' $terminalServer 'fDenyTSConnections' 1
    Invoke-RdpFirewallRules -Enabled $false
    foreach ($serviceName in @('UmRdpService','SessionEnv','TermService')) {
        if ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { continue }
        $script:ServiceDecisions[$serviceName]='N'
        Invoke-Check $serviceName { Set-SelectedService $serviceName 'N' }
    }
}

function Invoke-RemoteAssistanceDecision {
    $path='HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
    $state=Get-RegistryState $path fAllowToGetHelp
    $current=if ($state.Exists) { [string]$state.Value } else { 'not set' }
    if (-not $Apply) {
        Add-Result 'Remote access' 'Remote Assistance' REVIEW "fAllowToGetHelp=$current" 'Run with -Apply and answer Y to enable or N to disable Remote Assistance.'
        return
    }
    if ($NonInteractive) {
        Add-Result 'Remote access' 'Remote Assistance' REVIEW "fAllowToGetHelp=$current; NonInteractive mode cannot ask the enable/disable question." 'Run interactively and answer Y to enable or N to disable Remote Assistance.'
        return
    }
    Write-Warning 'Remote Assistance allows another user to view or control this session. Enable it only when the scenario requires it.'
    $choice=Read-YesNo 'Enable Remote Assistance? Y enables it; N disables it'
    if ($choice -eq 'Y') {
        $script:RemoteAssistanceDecision='Y'
        Set-RegistryBaseline 'Remote access' $path fAllowToGetHelp 1
        return
    }
    if ($choice -eq 'N') {
        $script:RemoteAssistanceDecision='N'
        Set-RegistryBaseline 'Remote access' $path fAllowToGetHelp 0
        return
    }
    Add-Result 'Remote access' 'Remote Assistance' REVIEW "fAllowToGetHelp=$current; no valid Y/N answer was received." 'Run again and answer Y to enable or N to disable Remote Assistance.'
}

function Get-RdpConfiguredPort {
    $state=Get-RegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'PortNumber'
    if (-not $state.Exists) { return 3389 }
    $port=0
    if ([int]::TryParse([string]$state.Value,[ref]$port) -and $port -gt 0 -and $port -le 65535) { return $port }
    Add-Result 'Remote access' 'RDP port' 'FAILED' 'Configured RDP port is unreadable or outside 1-65535.' 'Review the listener at the local console.'
    return $null
}

function Invoke-ExistingServiceFirewall {
    param([string]$Name,[string]$Protocol,[int]$Port,[bool]$Enabled=$true,[switch]$VerifyOnly)
    Invoke-Check $Name {
        $rules=@(Get-NetFirewallRule -Name $Name -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
        if ($rules.Count -ne 1) { Add-Result 'Required firewall' $Name 'REVIEW' 'Exactly one active built-in rule was not found.' 'Review service firewall rules; no rule was created.'; return }
        $rule=$rules[0]
        $filters=@(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
        $valid=([string](Get-CoreProperty $rule 'Direction') -eq 'Inbound') -and ([string](Get-CoreProperty $rule 'Action') -eq 'Allow') -and $filters.Count -eq 1
        if ($valid) {
            $actualProtocol=[string](Get-CoreProperty $filters[0] 'Protocol')
            $ports=@(Get-CoreProperty $filters[0] 'LocalPort')
            $protocolNumber='6'; if ($Protocol -eq 'UDP') { $protocolNumber='17' }
            $valid=($actualProtocol -in @($Protocol,$protocolNumber)) -and $ports.Count -eq 1 -and [string]$ports[0] -eq [string]$Port
        }
        if (-not $valid) { Add-Result 'Required firewall' $Name 'REVIEW' "Rule action/direction/port conflicts with required inbound Allow $Protocol/$Port." 'Review the existing rule or configured listener; port and scope were not changed.'; return }
        $desired=[string]$Enabled
        $test={ [string](Get-NetFirewallRule -Name $Name -PolicyStore ActiveStore -ErrorAction Stop).Enabled -eq $desired }
        if ($VerifyOnly) {
            $status='REVIEW'; if (& $test) { $status='PASS' } elseif ($Apply) { $status='FAILED' }
            Add-Result 'Required firewall' $Name $status "Active inbound Allow $Protocol/$Port; expected Enabled=$desired." 'Review effective firewall policy.'
            return
        }
        $gpo=([string](Get-CoreProperty $rule 'PolicyStoreSourceType') -eq 'GroupPolicy')
        Invoke-Setting 'Required firewall' $Name $test {
            Set-NetFirewallRule -Name $Name -PolicyStore PersistentStore -Enabled $desired -ErrorAction Stop | Out-Null
        } "Active inbound Allow $Protocol/$Port; expected Enabled=$desired." 'Enable or disable only this existing local built-in service rule.' -Manual:$gpo
    }
}

function Invoke-RequiredServiceFirewall {
    param([switch]$VerifyOnly)
    if ($script:RequiredLogical.ContainsKey('SMB') -and $script:ServiceDecisions['LanmanServer'] -ne 'N') { Invoke-ExistingServiceFirewall 'FPS-SMB-In-TCP' 'TCP' 445 $true -VerifyOnly:$VerifyOnly }
    if ($script:RequiredLogical.ContainsKey('RDP')) {
        $port=Get-RdpConfiguredPort
        if ($null -ne $port) {
            Invoke-ExistingServiceFirewall 'RemoteDesktop-UserMode-In-TCP' 'TCP' $port $true -VerifyOnly:$VerifyOnly
            Invoke-ExistingServiceFirewall 'RemoteDesktop-UserMode-In-UDP' 'UDP' $port $true -VerifyOnly:$VerifyOnly
        }
    }
}

function Invoke-RequiredServicesVerification {
    foreach ($name in $script:ProtectedServices.Keys) {
        Invoke-Check $name {
            $service=Get-Service -Name $name -ErrorAction SilentlyContinue
            $valid=$null -ne $service -and [string]$service.Status -eq 'Running' -and (Get-ServiceStartMode $service) -ne 'Disabled'
            $status='REVIEW'; if ($valid) { $status='PASS' } elseif ($Apply) { $status='FAILED' }
            Add-Result 'Required services' $name $status "Required service must be running and not disabled: $($script:ProtectedServices[$name])." 'Review required service state and dependencies.'
        }
    }
    if ($script:RequiredLogical.ContainsKey('RDP')) {
        $state=Get-RegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
        $status='REVIEW'; if ($state.Exists -and [int]$state.Value -eq 0) { $status='PASS' } elseif ($Apply) { $status='FAILED' }
        Add-Result 'Required services' 'RDP listener' $status 'Required RDP listener must have fDenyTSConnections=0.' 'Review RDP at the console.'
    }
    Invoke-RequiredServiceFirewall -VerifyOnly
}


# Policy planning and read-only inventory. Every apply path uses Invoke-Setting.
function Get-AccountPolicyPlan {
    param([hashtable]$Policy,[hashtable]$Baseline)
    $delta = [ordered]@{}; $issues = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $Baseline.Keys) {
        if ($name -in @('LockoutDuration','ResetLockoutCount')) { continue }
        $desired = [int]$Baseline[$name]; $current = 0
        if ($Policy.ContainsKey($name)) {
            if (-not [int]::TryParse([string]$Policy[$name],[ref]$current)) {
                $issues.Add("$name has an unreadable value; review manually."); continue
            }
        } else { $delta[$name] = $desired; continue }
        $needsChange = switch ($name) {
            'MaximumPasswordAge' { $current -le 0 -or $current -gt $desired }
            'LockoutBadCount' { $current -lt 5 -or $current -gt $desired }
            'PasswordComplexity' { $current -ne 1 }
            'ClearTextPassword' { $current -ne 0 }
            default { $current -lt $desired }
        }
        if ($needsChange) { $delta[$name] = $desired }
    }
    $reset = [int]$Baseline.ResetLockoutCount; $duration = [int]$Baseline.LockoutDuration
    $validReset = $true; $validDuration = $true
    if ($Policy.ContainsKey('ResetLockoutCount')) {
        $raw = 0; $validReset = [int]::TryParse([string]$Policy.ResetLockoutCount,[ref]$raw)
        if ($validReset -and $raw -gt $reset) { $reset = $raw }
        if (-not $validReset) { $issues.Add('ResetLockoutCount is unreadable; review lockout settings manually.') }
    }
    if ($Policy.ContainsKey('LockoutDuration')) {
        $raw = 0; $validDuration = [int]::TryParse([string]$Policy.LockoutDuration,[ref]$raw)
        if ($validDuration -and $raw -eq 0) {
            $issues.Add('Lockout duration is indefinite (administrator must unlock). Review before changing it.'); $duration = 0
        } elseif ($validDuration -and $raw -gt $duration) { $duration = $raw }
        if (-not $validDuration) { $issues.Add('LockoutDuration is unreadable; review lockout settings manually.') }
    }
    if ($validReset -and $validDuration) {
        if ($duration -gt 0) { $duration = [Math]::Max($duration,$reset) }
        if (-not $Policy.ContainsKey('ResetLockoutCount') -or [int]$Policy.ResetLockoutCount -lt $reset) { $delta.ResetLockoutCount = $reset }
        if ($duration -gt 0 -and (-not $Policy.ContainsKey('LockoutDuration') -or [int]$Policy.LockoutDuration -lt $duration)) { $delta.LockoutDuration = $duration }
    }
    # Never emit an invalid minimum-age/maximum-age pair.
    $minAge = if ($delta.Contains('MinimumPasswordAge')) { [int]$delta.MinimumPasswordAge } elseif ($Policy.ContainsKey('MinimumPasswordAge')) { $x=0; if ([int]::TryParse([string]$Policy.MinimumPasswordAge,[ref]$x)) { $x } else { 0 } } else { 0 }
    $maxAge = if ($delta.Contains('MaximumPasswordAge')) { [int]$delta.MaximumPasswordAge } elseif ($Policy.ContainsKey('MaximumPasswordAge')) { $x=0; if ([int]::TryParse([string]$Policy.MaximumPasswordAge,[ref]$x)) { $x } else { 0 } } else { 0 }
    if ($maxAge -gt 0 -and $minAge -ge $maxAge) {
        $delta.Remove('MinimumPasswordAge'); $delta.Remove('MaximumPasswordAge')
        $issues.Add('Minimum password age must be lower than maximum password age; reconcile manually.')
    }
    [pscustomobject]@{ Delta=$delta; Issues=@($issues) }
}
function Test-AuditCoverage { param([int]$Actual,[int]$Required); return ($Actual -band $Required) -eq $Required }
function Test-BroadExecutableExclusion { param([string]$Extension); return $Extension.Trim().TrimStart('.').ToLowerInvariant() -eq 'exe' }
function Get-OptionalProperty {
    param($Object,[string]$Name,$Default=$null)
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return $property.Value }; return $Default
}
function ConvertFrom-SecureStringToPlainText {
    param([securestring]$Value)
    if ($null -eq $Value -or $Value.Length -eq 0) { return '' }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) } }
}
function Read-KnownPassword {
    param([string]$UserName)
    $senderInfo=Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue
    if ([Environment]::UserInteractive -and ($null -eq $senderInfo -or $null -eq $senderInfo.Value)) {
        try {
            $credential=Get-Credential -UserName $UserName -Message "Paste or type the known password for $UserName. Cancel to skip this account." -ErrorAction Stop
            if ($null -eq $credential) { return $null }
            $enteredUser=([string]$credential.UserName -split '\\')[-1]
            if ($enteredUser -ine $UserName) {
                Write-Warning "The credential dialog named $enteredUser instead of $UserName; this account was skipped."
                return $null
            }
            return $credential.Password
        } catch {
            Write-Warning 'The credential dialog was unavailable; using the masked console prompt.'
        }
    }
    return Read-Host "Known/current password for $UserName (blank if unknown)" -AsSecureString
}
function Test-PasswordComplexity {
    param([string]$Password,[int]$MinimumLength=$KnownPasswordMinimumLength)
    if ([string]::IsNullOrEmpty($Password) -or $Password.Length -lt $MinimumLength) { return $false }
    $classes = 0
    if ($Password -match '[a-z]') { $classes++ }
    if ($Password -match '[A-Z]') { $classes++ }
    if ($Password -match '\d') { $classes++ }
    if ($Password -match '[^a-zA-Z0-9]') { $classes++ }
    return $classes -ge 3
}
function New-ComplexPassword {
    param([int]$Length=$GeneratedPasswordLength)
    $upper='ABCDEFGHJKLMNPQRSTUVWXYZ'; $lower='abcdefghijkmnopqrstuvwxyz'
    $digits='23456789'; $symbols='!@#$%^&*_-+='
    $sets=@($upper,$lower,$digits,$symbols); $all=($sets -join '')
    $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        do {
            $chars=New-Object 'System.Collections.Generic.List[char]'
            foreach ($set in $sets) { $chars.Add($set[(Get-SecureRandomIndex $rng $set.Length)]) }
            while ($chars.Count -lt $Length) { $chars.Add($all[(Get-SecureRandomIndex $rng $all.Length)]) }
            for ($i=0; $i -lt $chars.Count; $i++) {
                $j=Get-SecureRandomIndex $rng $chars.Count
                $tmp=$chars[$i]; $chars[$i]=$chars[$j]; $chars[$j]=$tmp
            }
            $candidate=-join $chars
        } until (Test-PasswordComplexity $candidate 10)
        return $candidate
    } finally { $rng.Dispose() }
}
function Get-SecureRandomIndex {
    param([Security.Cryptography.RandomNumberGenerator]$Generator,[int]$ExclusiveMax)
    $bytes=New-Object byte[] 4
    do {
        $Generator.GetBytes($bytes)
        $value=[BitConverter]::ToUInt32($bytes,0)
        $limit=[uint32]::MaxValue - ([uint32]::MaxValue % [uint32]$ExclusiveMax)
    } while ($value -ge $limit)
    return [int]($value % [uint32]$ExclusiveMax)
}
function Initialize-AccountProbe {
    # Compiled once per session. NetUserGetInfo gives the bad-password count and the
    # lockout flag; LogonUser tests exactly one password and never impersonates.
    if ('CYPatAccountProbe.Probe' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace CYPatAccountProbe
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_INFO_3
    {
        public IntPtr name;
        public IntPtr password;
        public uint passwordAge;
        public uint privilege;
        public IntPtr homeDir;
        public IntPtr comment;
        public uint flags;
        public IntPtr scriptPath;
        public uint authFlags;
        public IntPtr fullName;
        public IntPtr userComment;
        public IntPtr parameters;
        public IntPtr workstations;
        public uint lastLogon;
        public uint lastLogoff;
        public uint accountExpires;
        public uint maxStorage;
        public uint unitsPerWeek;
        public IntPtr logonHours;
        public uint badPasswordCount;
        public uint logonCount;
        public IntPtr logonServer;
        public uint countryCode;
        public uint codePage;
        public uint userId;
        public uint primaryGroupId;
        public IntPtr profile;
        public IntPtr homeDirDrive;
        public uint passwordExpired;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct USER_MODALS_INFO_3
    {
        public uint lockoutDuration;
        public uint lockoutObservationWindow;
        public uint lockoutThreshold;
    }

    public sealed class AccountState
    {
        public int BadAttempts;
        public bool Locked;
    }

    internal static class NativeMethods
    {
        [DllImport("netapi32.dll", CharSet=CharSet.Unicode)]
        internal static extern int NetUserGetInfo(string server, string user, int level, out IntPtr buffer);

        [DllImport("netapi32.dll", CharSet=CharSet.Unicode)]
        internal static extern int NetUserModalsGet(string server, int level, out IntPtr buffer);

        [DllImport("netapi32.dll")]
        internal static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("advapi32.dll", EntryPoint="LogonUserW", CharSet=CharSet.Unicode, SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LogonUser(string user, string domain, string password, int logonType, int logonProvider, out IntPtr token);

        [DllImport("kernel32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
    }

    public static class Probe
    {
        public static AccountState GetState(string name)
        {
            IntPtr buffer = IntPtr.Zero;
            try
            {
                int error = NativeMethods.NetUserGetInfo(null, name, 3, out buffer);
                if (error != 0) throw new System.ComponentModel.Win32Exception(error);
                USER_INFO_3 info = (USER_INFO_3)Marshal.PtrToStructure(buffer, typeof(USER_INFO_3));
                AccountState state = new AccountState();
                state.BadAttempts = unchecked((int)info.badPasswordCount);
                state.Locked = (info.flags & 0x0010u) != 0;
                return state;
            }
            finally
            {
                if (buffer != IntPtr.Zero) NativeMethods.NetApiBufferFree(buffer);
            }
        }

        public static int GetLockoutThreshold()
        {
            IntPtr buffer = IntPtr.Zero;
            try
            {
                int error = NativeMethods.NetUserModalsGet(null, 3, out buffer);
                if (error != 0) throw new System.ComponentModel.Win32Exception(error);
                USER_MODALS_INFO_3 info = (USER_MODALS_INFO_3)Marshal.PtrToStructure(buffer, typeof(USER_MODALS_INFO_3));
                return checked((int)info.lockoutThreshold);
            }
            finally
            {
                if (buffer != IntPtr.Zero) NativeMethods.NetApiBufferFree(buffer);
            }
        }

        // Tests only the supplied local password. The token is closed immediately and
        // no process is launched with it.
        public static int CheckPassword(string user, string password)
        {
            IntPtr token = IntPtr.Zero;
            bool ok = NativeMethods.LogonUser(user, ".", password, 2, 0, out token);
            int error = ok ? 0 : Marshal.GetLastWin32Error();
            if (!ok && error == 0) error = 1326;
            if (token != IntPtr.Zero) NativeMethods.CloseHandle(token);
            return error;
        }
    }
}
'@ -ErrorAction Stop
}
function Get-LimitBlankPasswordUse {
    $state = Get-RegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse'
    if (-not $state.Exists -or $null -eq $state.Value) { return $null }
    $parsed = 0
    if (-not [int]::TryParse([string]$state.Value, [ref]$parsed)) { return $null }
    return $parsed
}
function Set-LimitBlankPasswordUse {
    param([int]$Value)
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
    New-ItemProperty -LiteralPath $path -Name 'LimitBlankPasswordUse' -Value $Value -PropertyType DWord -Force -ErrorAction Stop | Out-Null
}
function Test-BlankLocalPassword {
    param([string]$Name,[bool]$Enabled=$true)
    if (-not $Enabled) { return [pscustomobject]@{Status='Unknown';Code=$null;PolicyLifted=$false;Evidence='Account is disabled; an empty-password logon cannot be tested.'} }
    try { Initialize-AccountProbe }
    catch { return [pscustomobject]@{Status='Unknown';Code=$null;PolicyLifted=$false;Evidence="Native account probe unavailable: $($_.Exception.Message)"} }
    try {
        $state=[CYPatAccountProbe.Probe]::GetState($Name)
        $threshold=[CYPatAccountProbe.Probe]::GetLockoutThreshold()
        if ($state.Locked) { return [pscustomobject]@{Status='Unknown';Code=$null;PolicyLifted=$false;Evidence='Empty-password test skipped: the account is locked out.'} }
        if ($threshold -gt 0 -and [int]$state.BadAttempts -ge ($threshold - 1)) {
            return [pscustomobject]@{Status='Unknown';Code=$null;PolicyLifted=$false;Evidence="Empty-password test skipped: $($state.BadAttempts) earlier bad-password attempt(s) leave no safe headroom under lockout threshold $threshold."}
        }
        # Windows rejects an empty password with 1326/1327 while LimitBlankPasswordUse=1,
        # even when the account is genuinely blank. Lift the restriction for this one
        # attempt only, then restore the original value in finally. The later registry
        # audit also writes LimitBlankPasswordUse=1, so an interrupted run self-heals.
        $original=Get-LimitBlankPasswordUse
        $restore=if ($null -eq $original) { 1 } else { [int]$original }
        $lifted=$false
        $liftError=$null
        $restoreError=$null
        $code=$null
        try {
            if ($restore -ne 0) {
                try {
                    Set-LimitBlankPasswordUse 0
                    $lifted=((Get-LimitBlankPasswordUse) -eq 0)
                    if (-not $lifted) { $liftError='the policy readback did not show 0' }
                } catch { $liftError=$_.Exception.Message; $lifted=$false }
            } else { $lifted=$true }
            # Exactly one attempt. A rejection can still increase the local bad-password count.
            $code=[CYPatAccountProbe.Probe]::CheckPassword($Name,'')
        } finally {
            if ($restore -ne 0) {
                try { Set-LimitBlankPasswordUse $restore }
                catch {
                    $restoreError=$_.Exception.Message
                    $script:BlankPolicyRestoreError="LimitBlankPasswordUse could not be restored to $restore after the probe: $restoreError"
                }
            }
        }
        $policyNote=if ($restoreError) { " The registry restore failed: $restoreError. The registry audit later sets it back to 1." }
            elseif ($restore -eq 0) { ' The blank-password policy was already disabled.' }
            elseif ($lifted) { ' The blank-password policy was lifted for this one attempt and restored.' }
            elseif ($liftError) { " The blank-password policy could not be lifted ($liftError), so the result is treated conservatively." }
            else { '' }
        if ($code -eq 0) { return [pscustomobject]@{Status='ConfirmedBlank';Code=0;PolicyLifted=$lifted;Evidence="One empty-password local logon succeeded; the token was closed immediately.$policyNote"} }
        # 1330 = password expired, 1907 = password must change. Both mean the supplied
        # (empty) password was correct, so the account is still blank.
        if ($code -in 1330,1907) { return [pscustomobject]@{Status='ConfirmedBlank';Code=$code;PolicyLifted=$lifted;Evidence="An empty-password logon was accepted but flagged (Windows error $code); the token was closed immediately.$policyNote"} }
        # 1327 = ERROR_ACCOUNT_RESTRICTION. For a local account with an empty password this
        # is the blank-password policy, so the password is still blank and must be reset.
        # That reading only holds when the restriction was actually in force before the
        # probe; with blank logons already permitted, 1327 means some other restriction.
        if ($code -eq 1327 -and $restore -ne 0) { return [pscustomobject]@{Status='ConfirmedBlank';Code=$code;PolicyLifted=$lifted;Evidence="An empty-password logon was blocked by an account restriction (Windows error 1327), which for a local account means the password is blank.$policyNote"} }
        if ($code -eq 1327) { return [pscustomobject]@{Status='Unknown';Code=$code;PolicyLifted=$lifted;Evidence='An empty-password logon was blocked by an account restriction (Windows error 1327) even though blank-password logons were already permitted. That is not proof of a blank password, so the account is left for manual review.'} }
        # 1326 proves a real password only when the lift was confirmed by readback.
        if ($code -eq 1326 -and $lifted) { return [pscustomobject]@{Status='HasPassword';Code=$code;PolicyLifted=$true;Evidence='An empty-password logon was rejected (Windows error 1326) with blank-password logons permitted by policy, so this account already has a password.'} }
        if ($code -eq 1326) { return [pscustomobject]@{Status='Unknown';Code=$code;PolicyLifted=$false;Evidence="An empty-password logon was rejected (Windows error 1326) while the blank-password policy could not be lifted. A rejection under that policy is not proof of a password, so the account is reset rather than trusted.$policyNote"} }
        return [pscustomobject]@{Status='Unknown';Code=$code;PolicyLifted=$lifted;Evidence="Empty-password logon was inconclusive (Windows error $code).$policyNote"}
    } catch {
        return [pscustomobject]@{Status='Unknown';Code=$null;PolicyLifted=$false;Evidence="Account probe failed: $($_.Exception.Message)"}
    }
}
function Test-AppliedPassword {
    param([string]$Name,[string]$Password,[bool]$Enabled=$true)
    if ([string]::IsNullOrEmpty($Password)) { return [pscustomobject]@{Verified=$false;Evidence='No candidate password was supplied.'} }
    if (-not $Enabled) { return [pscustomobject]@{Verified=$false;Evidence='Account is disabled, so a verification logon cannot be made.'} }
    try {
        Initialize-AccountProbe
        # A wrong verification attempt counts against lockout. Stop before the last
        # permitted failure so a stuck password cannot lock the account out.
        $state=[CYPatAccountProbe.Probe]::GetState($Name)
        $threshold=[CYPatAccountProbe.Probe]::GetLockoutThreshold()
        if ($state.Locked) { return [pscustomobject]@{Verified=$false;Evidence='The account is locked out, so the new password was not verified.'} }
        if ($threshold -gt 0 -and [int]$state.BadAttempts -ge ($threshold - 1)) {
            return [pscustomobject]@{Verified=$false;Evidence="Verification skipped: $($state.BadAttempts) earlier bad-password attempt(s) leave no safe headroom under lockout threshold $threshold."}
        }
        $code=[CYPatAccountProbe.Probe]::CheckPassword($Name,$Password)
        if ($code -eq 0) { return [pscustomobject]@{Verified=$true;Evidence='A local logon with the new password succeeded.'} }
        if ($code -in 1330,1907) { return [pscustomobject]@{Verified=$true;Evidence="A local logon accepted the new password but flagged it (Windows error ${code}: expired or must-change)."} }
        return [pscustomobject]@{Verified=$false;Evidence="A local logon with the new password failed (Windows error $code)."}
    } catch { return [pscustomobject]@{Verified=$false;Evidence="Password verification failed: $($_.Exception.Message)"} }
}
function Get-PasswordState {
    param($User)
    if ($null -eq $User) { return [pscustomobject]@{Passwordless=$false;HasPassword=$true;Required='unknown';LastSet='unknown';Reason='account not found'} }
    $required='unknown'; $lastSet='unknown'; $passwordless=$false; $hasPassword=$true; $reasons=@()
    $requiredProperty=$User.PSObject.Properties['PasswordRequired']
    if ($null -ne $requiredProperty) {
        $required=[string]$requiredProperty.Value
        if (-not $requiredProperty.Value) { $passwordless=$true; $reasons+='PasswordRequired=False' }
    }
    $lastProperty=$User.PSObject.Properties['PasswordLastSet']
    if ($null -ne $lastProperty) {
        $value=$lastProperty.Value
        if ($null -eq $value) {
            $lastSet='<null>'; $passwordless=$true; $hasPassword=$false; $reasons+='PasswordLastSet=<null>'
        } else {
            try {
                $date=[datetime]$value
                $lastSet=$date.ToString('yyyy-MM-dd HH:mm:ss')
                # Windows reports "never set" as 1601-01-01, not as null.
                if ($date.Year -le 1601) { $passwordless=$true; $hasPassword=$false; $reasons+="PasswordLastSet=$lastSet (never set)" }
            } catch { $lastSet=[string]$value }
        }
    }
    if (-not $reasons.Count) { $reasons+='a password is set' }
    return [pscustomobject]@{Passwordless=$passwordless;HasPassword=$hasPassword;Required=$required;LastSet=$lastSet;Reason=($reasons -join '; ')}
}
function Get-ManualPasswordHelp {
    param([string]$Name='<account>',[switch]$Disabled,[switch]$MultiLine)
    $steps=[System.Collections.Generic.List[string]]::new()
    $steps.Add("Manual password change for $Name (run from an elevated PowerShell or Command Prompt):")
    $steps.Add("  1. net user `"$Name`" `"<new-password>`"")
    $steps.Add("  2. net user `"$Name`" /passwordreq:yes")
    if ($Disabled) { $steps.Add('  3. Keep the account disabled. Do not add /active:yes unless the README requires it.') }
    else { $steps.Add("  3. net user `"$Name`" /expires:never    (only when the password policy allows it)") }
    $steps.Add("  GUI: Win+R, run lusrmgr.msc, open Users, right-click $Name, choose Set Password.")
    $steps.Add("  PowerShell: `$p=Read-Host -AsSecureString 'New password'; Set-LocalUser -Name '$Name' -Password `$p")
    $steps.Add("  Check: net user `"$Name`"   ->   'Password required    Yes'")
    $steps.Add('  The new password must meet length and complexity policy. Record it before closing the window.')
    if ($MultiLine) { return ($steps -join [Environment]::NewLine) }
    return ("net user `"$Name`" `"<new-password>`"; net user `"$Name`" /passwordreq:yes; GUI: lusrmgr.msc > Users > $Name > Set Password.")
}
function Test-PasswordlessAccount {
    param($User)
    if ($null -eq $User -or -not $User.Enabled) { return $false }
    # Guest, DefaultAccount and WDAGUtilityAccount are built-in and normally disabled.
    if ($User.SID.Value -match '-(501|503|504)$') { return $false }
    return (Get-PasswordState $User).Passwordless
}
function Get-EffectiveMinimumPasswordLength {
    try {
        $policy=Get-SecurityPolicy
        if ($policy.ContainsKey('System Access') -and $policy['System Access'].ContainsKey('MinimumPasswordLength')) {
            $value=0
            if ([int]::TryParse([string]$policy['System Access']['MinimumPasswordLength'],[ref]$value) -and $value -gt 0) { return $value }
        }
    } catch {
        # secedit may be unavailable or the policy may not expose the value; fall
        # back to the configured minimum so the generated password is never short.
        Write-Verbose "Minimum password length could not be read from local security policy: $($_.Exception.Message)"
    }
    return 0
}
function Set-LocalAccountPassword {
    param([string]$Name,[string]$Password,[bool]$CanVerify=$true)
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $secure=$null
    try {
        # Build the SecureString directly; ConvertTo-SecureString -AsPlainText trips a
        # PSScriptAnalyzer error even though the password is generated in memory.
        $secure=New-Object System.Security.SecureString
        foreach ($character in $Password.ToCharArray()) { $secure.AppendChar($character) }
        $secure.MakeReadOnly()
        Set-LocalUser -Name $Name -Password $secure -ErrorAction Stop
        if (-not $CanVerify) { return 'Set-LocalUser' }
        # Set-LocalUser can return success while the account still rejects the new
        # password (blank-password accounts are the usual case). Verify before trusting.
        $check=Test-AppliedPassword -Name $Name -Password $Password -Enabled $true
        if ($check.Verified) { return 'Set-LocalUser' }
        $errors.Add("Set-LocalUser did not stick: $($check.Evidence)")
    } catch {
        $errors.Add("Set-LocalUser: $($_.Exception.Message)")
    } finally {
        if ($null -ne $secure) { $secure.Dispose() }
    }
    try {
        $computer=if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { '.' }
        $account=[ADSI]"WinNT://$computer/$Name,user"
        $account.SetPassword($Password)
        if (-not $CanVerify) { return 'ADSI WinNT provider' }
        $check=Test-AppliedPassword -Name $Name -Password $Password -Enabled $true
        if ($check.Verified) { return 'ADSI WinNT provider' }
        $errors.Add("ADSI did not stick: $($check.Evidence)")
    } catch {
        $errors.Add("ADSI: $($_.Exception.Message)")
    }
    # Last resort for an account that never had a password. The generated password is
    # briefly on the command line, so this path is used only after both APIs fail.
    try {
        Invoke-Native 'net.exe' @('user', $Name, $Password) | Out-Null
        return 'net user'
    } catch {
        $errors.Add("net user: $($_.Exception.Message)")
        throw ($errors -join ' | ')
    }
}
function Set-LocalPasswordRequired {
    param([string]$Name)
    # Set-LocalUser has no -PasswordRequired parameter. Clear ADS_UF_PASSWD_NOTREQD
    # (0x20) through the WinNT provider, which also works for disabled accounts.
    $firstError=$null
    try {
        $computer=if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { '.' }
        $account=[ADSI]"WinNT://$computer/$Name,user"
        $flags=[int]$account.UserFlags
        if ($flags -band 0x20) {
            $account.UserFlags = ($flags -band (-bnot 0x20))
            $account.SetInfo()
            return 'ADSI UserFlags (cleared ADS_UF_PASSWD_NOTREQD)'
        }
        return 'ADSI UserFlags (ADS_UF_PASSWD_NOTREQD was already clear)'
    } catch {
        $firstError=$_.Exception.Message
    }
    try {
        Invoke-Native 'net.exe' @('user',$Name,'/passwordreq:yes') | Out-Null
        return "net user /passwordreq:yes (ADSI UserFlags failed: $firstError)"
    } catch {
        throw "ADSI UserFlags failed: $firstError. net user fallback failed: $($_.Exception.Message)"
    }
}
function Invoke-PasswordlessReset {
    param([object[]]$Users=@())
    $exempt = @($PasswordExemptUsers | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    $minimumLength=Get-EffectiveMinimumPasswordLength
    $passwordLength=[Math]::Max($GeneratedPasswordLength,$minimumLength)
    $states = @($Users | ForEach-Object {
        $user=$_
        if ($null -eq $user) { return }
        $sid=[string](Get-OptionalProperty $user 'SID' '')
        if ($sid -match '-(501|503|504)$') { return }
        [pscustomobject]@{
            User=$user
            Name=[string]$user.Name
            Enabled=[bool](Get-OptionalProperty $user 'Enabled' $false)
            State=(Get-PasswordState $user)
        }
    })
    $targets = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $states) {
        if ($item.State.Passwordless) { $targets.Add($item) }
    }
    # Flags alone miss an account whose password is blank but whose PasswordLastSet is
    # populated. In Apply mode, one empty-password logon per eligible account settles it.
    $probeAllowed = $Apply -and -not $WhatIfPreference
    $probes = [System.Collections.Generic.List[object]]::new()
    $probeByAccount = @{}
    if ($probeAllowed) {
        foreach ($item in $states) {
            if (-not $item.Enabled) { continue }
            if ($item.Name -in $exempt) { continue }
            $probe = Test-BlankLocalPassword -Name $item.Name -Enabled $true
            $probeByAccount[$item.Name] = $probe
            $probes.Add([pscustomobject]@{Name=$item.Name;Probe=$probe})
            if ($probe.Status -eq 'ConfirmedBlank' -and -not $item.State.Passwordless) {
                $targets.Add([pscustomobject]@{
                    User=$item.User; Name=$item.Name; Enabled=$true
                    State=[pscustomobject]@{
                        Passwordless=$true; HasPassword=$false; Required='unknown'; LastSet='unknown'
                        Reason='an empty-password local logon succeeded'
                    }
                })
            }
        }
    }
    if ($probeAllowed) {
        $confirmed = @($probes | Where-Object { $_.Probe.Status -eq 'ConfirmedBlank' })
        $held = @($probes | Where-Object { $_.Probe.Status -eq 'Unknown' })
        if ($confirmed.Count) {
            Add-Result Accounts 'Empty-password probe' REVIEW "$($confirmed.Count) of $($probes.Count) tested account(s) were confirmed blank: $(($confirmed.Name) -join ', ')." 'Each confirmed account is reset below, including accounts whose PasswordRequired flag looked correct.'
        } elseif ($probes.Count -and $held.Count -eq 0) {
            Add-Result Accounts 'Empty-password probe' PASS "Tested $($probes.Count) enabled account(s) with one empty local logon each, with LimitBlankPasswordUse lifted and restored; every attempt was rejected, so those accounts already have a password." ''
        } elseif ($probes.Count) {
            Add-Result Accounts 'Empty-password probe' REVIEW "Tested $($probes.Count) enabled account(s); $($held.Count) result(s) were inconclusive." 'An inconclusive probe never counts as proof of a password. Flagged accounts are reset from the account flags.'
        }
        if ($held.Count) {
            Add-Result Accounts 'Empty-password probe exceptions' REVIEW (($held | ForEach-Object { "$($_.Name): $($_.Probe.Evidence)" }) -join '; ') 'A locked, restricted, or previously failed account may need a manual reset. Check the row and the Password-Help.txt commands.'
        }
        if ($script:BlankPolicyRestoreError) {
            Add-Result Accounts 'Blank-password policy restore' REVIEW $script:BlankPolicyRestoreError 'Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse back to 1 manually if the registry audit does not run; the script sets it to 1 later in Apply mode.'
            $script:BlankPolicyRestoreError=$null
        }
    } else {
        Add-Result Accounts 'Empty-password probe' SKIPPED 'AuditOnly and WhatIf compare account flags only; no logon is attempted.' 'Run with -Apply to test one empty password per eligible account.'
    }
    if (-not $targets.Count) {
        Add-Result Accounts 'Passwordless accounts' PASS 'No local account is missing a password requirement, a password set date, or an empty-password logon result.' ''
        return
    }
    if ($Apply -and -not $WhatIfPreference -and [string]::IsNullOrWhiteSpace($script:RunDirectory)) {
        Add-Result Accounts 'Passwordless reset' FAILED 'The private run folder is unavailable; refusing to reset passwords without a durable record.' 'Fix the run-folder path or pass -RunRoot to a writable folder, then re-run.'
        return
    }
    foreach ($item in $targets) {
        $name = $item.Name
        $facts = "Enabled=$($item.Enabled); $($item.State.Reason)"
        if ($name -in $exempt) {
            Add-Result Accounts "Passwordless/$name" SKIPPED $facts ("Excluded by -PasswordExemptUsers. " + (Get-ManualPasswordHelp -Name $name))
            Add-Ledger 'EXEMPT' "Account/$name" 'Passwordless account left unchanged by -PasswordExemptUsers.'
            continue
        }
        if (-not $Apply) {
            Add-Result Accounts "Passwordless/$name" REVIEW $facts 'Run with -Apply to set a password or clear the password-not-required flag.'
            continue
        }
        # Set a password unless a probe with the blank-password policy lifted positively
        # proved that the account already has one AND the account still shows a password
        # date. A rejection under the default policy is not proof, and a null/1601 date
        # always forces a reset.
        $needsPassword = $true
        $probe = if ($probeByAccount.ContainsKey($name)) { $probeByAccount[$name] } else { $null }
        if ($null -ne $probe -and $probe.Status -eq 'HasPassword' -and $item.State.HasPassword) { $needsPassword = $false }
        $action = if ($needsPassword) { 'Generate and set a password for this passwordless account' } else { 'Clear the password-not-required flag on this account' }
        if ($WhatIfPreference -or -not $script:CallerCmdlet.ShouldProcess($name,$action)) {
            Add-Result Accounts "Passwordless/$name" SKIPPED $facts 'Change suppressed by -WhatIf or ShouldProcess.'
            continue
        }
        try {
            if (-not $needsPassword) {
                $flagMethod = Set-LocalPasswordRequired -Name $name
                $after = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
                $afterState = Get-PasswordState $after
                if ($afterState.Passwordless) {
                    Add-Result Accounts "Passwordless/$name" REVIEW "$facts; the password-not-required flag could not be cleared via $flagMethod ($($afterState.Reason))." ("The account still reports the password-not-required flag. " + (Get-ManualPasswordHelp -Name $name))
                } else {
                    $probeNote = if ($null -ne $probe -and $probe.Status -eq 'HasPassword') { ' An empty-password logon was rejected with the blank-password policy lifted, which is the evidence that a password exists.' } else { '' }
                    Add-Result Accounts "Passwordless/$name" CHANGED "$facts; existing password was retained and PasswordRequired was cleared via $flagMethod (PasswordRequired=$($afterState.Required), PasswordLastSet=$($afterState.LastSet)).$probeNote" ''
                }
                continue
            }
            $password = New-ComplexPassword $passwordLength
            $method = Set-LocalAccountPassword -Name $name -Password $password -CanVerify:$item.Enabled
            $flagMethod = $null
            try { $flagMethod = Set-LocalPasswordRequired -Name $name }
            catch {
                Add-Result Accounts "Passwordless/$name flag" REVIEW $_.Exception.Message ("The password was set, but the password-not-required flag could not be cleared. " + (Get-ManualPasswordHelp -Name $name))
            }
            try { Set-LocalUser -Name $name -PasswordNeverExpires $false -ErrorAction Stop }
            catch {
                Add-Result Accounts "Passwordless/$name password expiry" REVIEW $_.Exception.Message 'The password was set, but the "password never expires" flag could not be cleared. Clear it manually if the account policy requires it.'
            }
            $after = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
            $afterState = Get-PasswordState $after
            $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Write-Host "NEW PASSWORD for $name : $password" -ForegroundColor Yellow
            try { Write-PrivateLine 'Changed-Passwords.txt' "$stamp | $name | $password" }
            catch { Add-Result Accounts "Passwordless/$name record" FAILED $_.Exception.Message 'The password was set but could not be written to the private run folder. Record it manually.' }
            $flagDetail = if ($flagMethod) { " PasswordRequired cleared via $flagMethod." } else { '' }
            Add-Ledger 'PASSWORD' "Account/$name" "Generated and set a password via $method; the previous password was blank or unknown.$flagDetail"
            $verification = Test-AppliedPassword -Name $name -Password $password -Enabled $item.Enabled
            if (-not $item.Enabled) {
                $verification = [pscustomobject]@{Verified=(-not $afterState.Passwordless);Evidence='Account is disabled; the password flags were read back instead of a logon.'}
            }
            if ($verification.Verified) {
                Add-Result Accounts "Passwordless/$name" CHANGED "$facts; new password applied via $method and verified ($($verification.Evidence)) (PasswordRequired=$($afterState.Required), PasswordLastSet=$($afterState.LastSet)). Saved in the private run folder.$flagDetail" ''
                $script:ResetPasswordAccounts[$name] = $true
            } else {
                Add-Result Accounts "Passwordless/$name" REVIEW "$facts; the password was applied at $stamp but verification failed ($($verification.Evidence)). The candidate is in Changed-Passwords.txt." ("Reset the account with the saved password. " + (Get-ManualPasswordHelp -Name $name))
            }
        } catch {
            Add-Result Accounts "Passwordless/$name" FAILED $_.Exception.Message ("The automatic reset failed. " + (Get-ManualPasswordHelp -Name $name -MultiLine -Disabled:(-not $item.Enabled)))
        }
    }
}
function Invoke-AllUserPasswordReset {
    if (-not $ResetAllUserPasswords) { return }
    if ($script:IsDomainController) {
        Add-Result Accounts 'All-user password reset' SKIPPED 'Domain controller detected; local-account password reset does not apply.' 'Review domain accounts and fine-grained password policies manually.'
        return
    }
    $users=@(Get-LocalUser -ErrorAction Stop)
    $exempt = @($PasswordExemptUsers | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    $targets=@($users | Where-Object {
        $_.Enabled -and $_.SID.Value -notmatch '-(501|503|504)$' -and $_.Name -notin $exempt
    })
    if (-not $targets.Count) {
        Add-Result Accounts 'All-user password reset' PASS 'No enabled local accounts remain after exclusions.' ''
        return
    }
    if (-not $Apply) {
        Add-Result Accounts 'All-user password reset' REVIEW "Would reset $($targets.Count) enabled local account(s): $(($targets.Name) -join ', ')." 'Run with -Apply and answer Y to reset every enabled local account.'
        return
    }
    if ($WhatIfPreference) {
        Add-Result Accounts 'All-user password reset' SKIPPED "Change suppressed by -WhatIf; targets: $(($targets.Name) -join ', ')." ''
        return
    }
    if ($NonInteractive) {
        Add-Result Accounts 'All-user password reset' REVIEW "NonInteractive mode cannot confirm an all-user reset. Targets: $(($targets.Name) -join ', ')." 'Run interactively and answer Y, or reset passwords manually.'
        return
    }
    Write-Warning 'This resets every enabled local account, including the built-in Administrator (RID 500). Make sure the README has no documented password exceptions.'
    $choice=Read-YesNo "Reset passwords for $($targets.Count) enabled local account(s)? Y resets all; N skips"
    if ($choice -ne 'Y') {
        Add-Result Accounts 'All-user password reset' SKIPPED "Operator did not approve the all-user reset. Targets: $(($targets.Name) -join ', ')." 'Run again and answer Y if the scenario requires every account to have a new password.'
        return
    }
    if ([string]::IsNullOrWhiteSpace($script:RunDirectory)) {
        Add-Result Accounts 'All-user password reset' FAILED 'The private run folder is unavailable; refusing to reset passwords without a durable record.' 'Fix the run-folder path or pass -RunRoot to a writable folder, then re-run.'
        return
    }
    $minimumLength=Get-EffectiveMinimumPasswordLength
    $passwordLength=[Math]::Max($GeneratedPasswordLength,$minimumLength)
    foreach ($user in $targets) {
        $name=[string]$user.Name
        if ($script:ResetPasswordAccounts.ContainsKey($name)) {
            Add-Result Accounts "All-user password/$name" SKIPPED 'A generated password was already applied earlier in this run.' ''
            continue
        }
        try {
            $password=New-ComplexPassword $passwordLength
            $method=Set-LocalAccountPassword -Name $name -Password $password
            $flagMethod=$null
            try { $flagMethod=Set-LocalPasswordRequired -Name $name }
            catch {
                Add-Result Accounts "All-user password/$name flag" REVIEW $_.Exception.Message ("The password was set, but the password-not-required flag could not be cleared. " + (Get-ManualPasswordHelp -Name $name))
            }
            try { Set-LocalUser -Name $name -PasswordNeverExpires $false -ErrorAction Stop }
            catch {
                Add-Result Accounts "All-user password/$name expiry" REVIEW $_.Exception.Message 'The password was set, but the "password never expires" flag could not be cleared. Clear it manually if the account policy requires it.'
            }
            $after=Get-LocalUser -Name $name -ErrorAction Stop
            $afterState=Get-PasswordState $after
            $stamp=Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Write-Host "NEW PASSWORD for $name : $password" -ForegroundColor Yellow
            try { Write-PrivateLine 'Changed-Passwords.txt' "$stamp | $name | $password" }
            catch { Add-Result Accounts "All-user password/$name record" FAILED $_.Exception.Message 'The password was set but could not be written to the private run folder. Record it manually.' }
            $flagDetail = if ($flagMethod) { " PasswordRequired cleared via $flagMethod." } else { '' }
            Add-Ledger 'PASSWORD' "Account/$name" "All-user reset: generated and set a password via $method.$flagDetail"
            $verification = Test-AppliedPassword -Name $name -Password $password -Enabled $true
            if ($verification.Verified) {
                Add-Result Accounts "All-user password/$name" CHANGED "New password applied via $method and verified ($($verification.Evidence)) (PasswordRequired=$($afterState.Required), PasswordLastSet=$($afterState.LastSet)). Saved in the private run folder.$flagDetail" ''
                $script:ResetPasswordAccounts[$name]=$true
            } else {
                Add-Result Accounts "All-user password/$name" REVIEW "The password was applied at $stamp but verification failed ($($verification.Evidence)). The candidate is in Changed-Passwords.txt." ("Reset the account with the saved password. " + (Get-ManualPasswordHelp -Name $name))
            }
        } catch {
            Add-Result Accounts "All-user password/$name" FAILED $_.Exception.Message ("The automatic reset failed. " + (Get-ManualPasswordHelp -Name $name -MultiLine))
        }
    }
}
function Invoke-KnownPasswordWorkflow {
    param([object[]]$Users)
    if ($SkipKnownPasswordCheck) { Add-Result Accounts 'Known password check' SKIPPED 'Skipped by -SkipKnownPasswordCheck.' ''; return }
    if ($NonInteractive) {
        Add-Result Accounts 'Known password check' REVIEW 'NonInteractive mode cannot ask for README-known/current passwords.' 'Run interactively to enter known weak passwords, or change known weak passwords manually.'
        return
    }
    if ($WhatIfPreference) { Add-Result Accounts 'Known password check' SKIPPED 'Change suppressed by -WhatIf.' ''; return }
    if ($Apply -and [string]::IsNullOrWhiteSpace($script:RunDirectory)) {
        Add-Result Accounts 'Known password check' FAILED 'The private run folder is unavailable; refusing to generate passwords without a durable record.' 'Fix the run-folder path or pass -RunRoot to a writable folder, then re-run.'
        return
    }
    $targets=@($Users | Where-Object { $_.Enabled -and $_.SID.Value -notmatch '-(500|501|503|504)$' -and -not $script:ResetPasswordAccounts.ContainsKey($_.Name) })
    if (-not $targets.Count) { return }
    Write-Host 'Known-password check: enter only README-listed or otherwise known passwords. Paste into the credential dialog; cancel it to skip an unknown account. Console fallback accepts a blank answer to skip.' -ForegroundColor Yellow
    foreach ($user in $targets) {
        $plain = $null
        try {
            $secure = Read-KnownPassword -UserName $user.Name
            $plain = ConvertFrom-SecureStringToPlainText $secure
            if ([string]::IsNullOrEmpty($plain)) { continue }
            if (Test-PasswordComplexity $plain $KnownPasswordMinimumLength) {
                Add-Result Accounts "Known password/$($user.Name)" PASS 'Supplied known password meets the configured complexity floor.' ''
                continue
            }
            if (-not $Apply) {
                Add-Result Accounts "Known password/$($user.Name)" REVIEW 'Supplied known password is weak.' 'In apply mode, this script generates and sets a complex replacement.'
                continue
            }
            try {
                $newPassword = New-ComplexPassword $GeneratedPasswordLength
                $secureNew = ConvertTo-SecureString $newPassword -AsPlainText -Force
                Set-LocalUser -Name $user.Name -Password $secureNew -ErrorAction Stop
                $flagMethod = $null
                try { $flagMethod = Set-LocalPasswordRequired -Name $user.Name }
                catch {
                    Add-Result Accounts "Known password/$($user.Name) flag" REVIEW $_.Exception.Message ("The password was set, but the password-not-required flag could not be cleared. " + (Get-ManualPasswordHelp -Name $user.Name))
                }
                try { Set-LocalUser -Name $user.Name -PasswordNeverExpires $false -ErrorAction Stop }
                catch {
                    Add-Result Accounts "Known password/$($user.Name) expiry" REVIEW $_.Exception.Message 'The password was set, but the "password never expires" flag could not be cleared. Clear it manually if the account policy requires it.'
                }
                $after = Get-LocalUser -Name $user.Name -ErrorAction Stop
                $afterState = Get-PasswordState $after
                if (-not $afterState.HasPassword) { throw 'Readback still reports no password date for this account.' }
                $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                Write-Host "NEW PASSWORD for $($user.Name): $newPassword" -ForegroundColor Yellow
                $flagDetail = if ($flagMethod) { " PasswordRequired cleared via $flagMethod." } else { '' }
                try { Write-PrivateLine 'Changed-Passwords.txt' "$stamp | $($user.Name) | $newPassword" }
                catch { Add-Result Accounts "Known password/$($user.Name) record" FAILED $_.Exception.Message 'The password was set but could not be written to the private run folder. Record it manually.' }
                Add-Ledger 'PASSWORD' "Account/$($user.Name)" "Known weak password replaced with a generated password.$flagDetail"
                $verification = Test-AppliedPassword -Name $user.Name -Password $newPassword -Enabled $true
                if ($verification.Verified) {
                    Add-Result Accounts "Known password/$($user.Name)" CHANGED "Weak supplied password replaced and verified ($($verification.Evidence)) (PasswordRequired=$($afterState.Required), PasswordLastSet=$($afterState.LastSet)); the generated password was printed once and saved in the private run folder.$flagDetail" ''
                } else {
                    Add-Result Accounts "Known password/$($user.Name)" REVIEW "The replacement password was applied but verification failed ($($verification.Evidence)). The candidate is in Changed-Passwords.txt." ("Set the password again with the saved value. " + (Get-ManualPasswordHelp -Name $user.Name))
                }
            } catch {
                Add-Result Accounts "Known password/$($user.Name)" FAILED $_.Exception.Message ("Set the password manually, then verify the account password date. " + (Get-ManualPasswordHelp -Name $user.Name -MultiLine))
            }
        } catch {
            Add-Result Accounts "Known password/$($user.Name)" FAILED $_.Exception.Message ("Enter the password again, or change it manually. " + (Get-ManualPasswordHelp -Name $user.Name))
        } finally {
            $plain = $null
        }
    }
}
function Invoke-AccountAudit {
    if ($script:IsDomainController) {
        Add-Result Accounts 'Domain accounts' REVIEW 'This is a domain controller; local-account commands do not describe domain accounts.' 'Review AD users, service accounts, privileged groups, fine-grained password policies, and the scenario. Domain changes are manual.'
        if (Get-Command Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue) {
            $script:Inventory.DomainPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop | Select-Object MinPasswordLength,PasswordHistoryCount,MinPasswordAge,MaxPasswordAge,ComplexityEnabled,ReversibleEncryptionEnabled,LockoutThreshold,LockoutDuration,LockoutObservationWindow
        }
        return
    }
    $users = @(Get-LocalUser -ErrorAction Stop)
    $cimUsers = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
    $script:Inventory.Accounts = @($users | Select-Object Name,Enabled,SID,PasswordRequired,PasswordLastSet,PasswordExpires,LastLogon)
    $candidates = @($users | Where-Object { $_.SID.Value -notmatch '-(500|501|503|504)$' })
    $guest = @($users | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1)
    if ($guest.Count) {
        if ($script:HasUserAllowlist -and ($guest[0].Name -in $AuthorizedUsers -or $guest[0].Name -in $AuthorizedAdministrators)) {
            Add-Result Accounts 'Built-in Guest' REVIEW 'Guest is enabled and appears in the supplied allowlist.' 'Confirm this is intentional; an enabled Guest account is normally a scored finding.'
        } else {
            Invoke-Setting Accounts 'Built-in Guest disabled' { -not (Get-LocalUser -Name $guest[0].Name -ErrorAction Stop).Enabled } {
                Disable-LocalUser -Name $guest[0].Name -ErrorAction Stop
            } 'Built-in Guest should be disabled.' 'Verify no documented workflow depends on Guest access.'
        }
    }
    if ($script:HasUserAllowlist) {
        $unknown = @($candidates | Where-Object { $_.Name -notin $AuthorizedUsers -and $_.Name -notin $AuthorizedAdministrators })
        if ($unknown.Count) { Add-Result Accounts 'Not in supplied allowlist' REVIEW ($unknown.Name -join ', ') 'Confirm service/system accounts and the README before removing any account.' }
        else { Add-Result Accounts 'User allowlist' PASS 'All ordinary accounts match the supplied lists.' '' }
    } else {
        Add-Result Accounts 'Authorization' REVIEW (($candidates | ForEach-Object { "$($_.Name) (enabled=$($_.Enabled))" }) -join ', ') 'Compare with README; supply -AuthorizedUsers and -AuthorizedAdministrators to narrow future output. Review known weak passwords manually.'
    }
    Invoke-PasswordlessReset -Users $users
    Invoke-AllUserPasswordReset
    $users = @(Get-LocalUser -ErrorAction Stop)
    $cimUsers = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop)
    $script:Inventory.Accounts = @($users | Select-Object Name,Enabled,SID,PasswordRequired,PasswordLastSet,PasswordExpires,LastLogon)
    foreach ($user in $users | Where-Object { $_.Enabled -and $_.SID.Value -notmatch '-501$' }) {
        $machineUser = $cimUsers | Where-Object SID -eq $user.SID.Value | Select-Object -First 1
        $facts = [System.Collections.Generic.List[string]]::new()
        if (-not $user.PasswordRequired) { $facts.Add('Password not required') }
        if ($machineUser -and -not $machineUser.PasswordExpires) {
            $name = [string]$user.Name
            Invoke-Setting Accounts "$name password expiration" { $null -ne (Get-LocalUser -Name $name -ErrorAction Stop).PasswordExpires } {
                Set-LocalUser -Name $name -PasswordNeverExpires $false -ErrorAction Stop
            } 'Local user password should expire under the account policy.' 'Preserve only documented service-account exceptions.'
        }
        if ($facts.Count) { Add-Result Accounts $user.Name REVIEW ($facts -join '; ') 'Verify purpose, password strength, and account policy. Account changes are manual.' }
    }
    Invoke-KnownPasswordWorkflow -Users $users
    $memberships = [ordered]@{}
    foreach ($rid in 544,555,551,547) {
        $group = Get-LocalGroup -SID "S-1-5-32-$rid" -ErrorAction SilentlyContinue
        if (-not $group) { continue }
        try { $members = @(Get-LocalGroupMember -Group $group -ErrorAction Stop) }
        catch { Add-Result Accounts $group.Name REVIEW $_.Exception.Message 'Resolve every member, including deleted/domain SIDs; do not assume an empty group.'; continue }
        $memberships[$group.Name] = @($members | Select-Object Name,SID,ObjectClass,PrincipalSource)
        if (-not $members.Count) { continue }
        if ($rid -eq 544 -and $script:HasAdminAllowlist) {
            $unknown = @($members | Where-Object {
                $_.Name -notin $AuthorizedAdministrators -and ($_.Name -replace '^.*\\','') -notin $AuthorizedAdministrators
            })
            if ($unknown.Count) { Add-Result Accounts $group.Name REVIEW ($unknown.Name -join ', ') 'These members are absent from the supplied administrator list; check domain groups and README.' }
            else { Add-Result Accounts $group.Name PASS 'Membership matches the supplied administrator list.' '' }
        } else { Add-Result Accounts $group.Name REVIEW ($members.Name -join ', ') 'Confirm every privileged or remote-access member against the scenario.' }
    }
    $script:Inventory.Groups = $memberships
    $passwordIssues=@($script:Results | Where-Object {
        $_.Category -eq 'Accounts' -and $_.Status -in @('FAILED','REVIEW') -and
        $_.Item -match '^(?i)(Passwordless|All-user password|Known password)/'
    } | ForEach-Object {
        $account=$_.Item -replace '^(?i)(Passwordless|All-user password|Known password)/',''
        $account=$account -replace '(?i)\s+(flag|record|password expiry)$',''
        [pscustomobject]@{Account=$account;Status=$_.Status}
    } | Group-Object Account | ForEach-Object {
        $status=if (@($_.Group.Status) -contains 'FAILED') { 'FAILED' } else { 'REVIEW' }
        [pscustomobject]@{Account=$_.Name;Status=$status}
    } | Sort-Object Account)
    if ($passwordIssues.Count) {
        Write-Host 'PASSWORDS NEEDING MANUAL ATTENTION' -ForegroundColor Yellow
        if ($script:RunDirectory) { Write-Host "  Manual commands: $(Join-Path $script:RunDirectory 'Password-Help.txt')" -ForegroundColor Yellow }
        foreach ($entry in $passwordIssues) {
            Write-Host "  $($entry.Account) [$($entry.Status)] : $(Get-ManualPasswordHelp -Name $entry.Account)" -ForegroundColor Yellow
        }
    }
}
function Get-UserRightPrincipals {
    param($Rights,[string]$Name)
    if ($null -eq $Rights -or -not $Rights.ContainsKey($Name)) { return @() }
    $raw = [string]$Rights[$Name]
    return @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
function Test-AdministratorsOnly {
    param([string[]]$Principals)
    if ($null -eq $Principals -or $Principals.Count -eq 0) { return $false }
    foreach ($principal in $Principals) {
        if ($principal -notmatch '^(\*?S-1-5-32-544|(BUILTIN\\)?Administrators)$') { return $false }
    }
    return $true
}
function Invoke-AdministratorsOnlyRight {
    param([string]$Name,[string]$Label)
    $principals = @()
    try {
        $policy = Get-SecurityPolicy
        if ($policy.ContainsKey('Privilege Rights')) { $principals = @(Get-UserRightPrincipals $policy['Privilege Rights'] $Name) }
    } catch {
        Add-Result 'User rights' $Label FAILED "Unable to read the current right: $($_.Exception.Message)" 'Correct this in secpol.msc or the governing GPO.'
        return
    }
    $current = if ($principals.Count) { $principals -join ', ' } else { 'not assigned' }
    if (Test-AdministratorsOnly $principals) {
        Add-Result 'User rights' $Label PASS "Assigned principals: $current. Administrators only." ''
        return
    }
    if (-not $Apply) {
        Add-Result 'User rights' $Label REVIEW "Current principals: $current. Required: *S-1-5-32-544 (Administrators) only." 'Run with -Apply to replace every non-Administrators principal.'
        return
    }
    try {
        $prefix = Join-Path ([IO.Path]::GetTempPath()) ('CYPat-right-' + [guid]::NewGuid().ToString('N'))
        try {
            $lines = @('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1',
                '[Privilege Rights]',"$Name = *S-1-5-32-544")
            $lines | Set-Content -LiteralPath "$prefix.inf" -Encoding Unicode -ErrorAction Stop
            Invoke-Native 'secedit.exe' @('/validate',"$prefix.inf") | Out-Null
            Invoke-Native 'secedit.exe' @('/configure','/db',"$prefix.sdb",'/cfg',"$prefix.inf",'/areas','USER_RIGHTS','/log',"$prefix.log",'/quiet') | Out-Null
        } finally {
            foreach ($file in @("$prefix.inf","$prefix.sdb","$prefix.log","$prefix.jfm","$prefix.sdb.jfm")) {
                if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue }
            }
        }
        $afterPolicy = Get-SecurityPolicy
        $after = if ($afterPolicy.ContainsKey('Privilege Rights')) { @(Get-UserRightPrincipals $afterPolicy['Privilege Rights'] $Name) } else { @() }
        if (-not (Test-AdministratorsOnly $after)) {
            $seen = if ($after.Count) { $after -join ', ' } else { 'not assigned' }
            throw "Readback principals: $seen"
        }
        Add-Ledger 'USER RIGHT' $Name "Previous: $current; new: $($after -join ', ')"
        Add-Result 'User rights' $Label CHANGED "Previous principals: $current. New: $($after -join ', ')." ''
    } catch {
        Add-Result 'User rights' $Label FAILED $_.Exception.Message 'Correct this in secpol.msc or the governing GPO.'
    }
}
function Invoke-SecurityPolicyAudit {
    $policy = Get-SecurityPolicy
    $script:Inventory.SecurityPolicy = $policy
    if (-not $policy.ContainsKey('System Access')) {
        Add-Result 'Account policy' 'Export incomplete' FAILED "Security policy export lacks System Access. Sections returned: $($policy.Keys -join ', ')." 'Run the saved .ps1 from elevated Windows PowerShell. Inspect secpol.msc and net accounts locally; no account-policy changes were attempted. Send this diagnostic if it persists.'
    } else {
        $baseline = @{MinimumPasswordLength=$MinimumPasswordLength;PasswordHistorySize=$PasswordHistory;MinimumPasswordAge=$MinimumPasswordAge;MaximumPasswordAge=$MaximumPasswordAge;PasswordComplexity=1;ClearTextPassword=0;LockoutBadCount=$LockoutThreshold;LockoutDuration=$LockoutMinutes;ResetLockoutCount=$LockoutMinutes}
        if ($policy['System Access'].ContainsKey('AllowAdministratorLockout')) {
            $baseline['AllowAdministratorLockout'] = 1
        } else {
            Add-Result 'Account policy' 'Allow Administrator account lockout' REVIEW 'This build does not expose AllowAdministratorLockout; the setting requires the October 2022 cumulative update (KB5020282).' 'Install current cumulative updates, then re-run. Verify the built-in Administrator can be locked out by network logons.'
        }
        $plan = Get-AccountPolicyPlan $policy['System Access'] $baseline
        foreach ($issue in $plan.Issues) { Add-Result 'Account policy' 'Policy exception' REVIEW $issue 'Review in secpol.msc or the governing domain GPO.' }
        if ($plan.Delta.Count) { Invoke-LocalAccountPolicy -Baseline $plan.Delta }
        elseif (-not $plan.Issues.Count) { Add-Result 'Account policy' 'Password and lockout baseline' PASS 'Current exported settings meet or exceed the selected baseline.' '' }
        try {
            $verifiedPolicy=Get-SecurityPolicy
            if ($verifiedPolicy.ContainsKey('System Access') -and $verifiedPolicy['System Access'].ContainsKey('PasswordHistorySize')) {
                $history=0
                if ([int]::TryParse([string]$verifiedPolicy['System Access']['PasswordHistorySize'],[ref]$history)) {
                    if ($history -ge $PasswordHistory) {
                        Add-Result 'Account policy' 'Password history' PASS "PasswordHistorySize=$history; required minimum=$PasswordHistory. A sufficient history is being kept." ''
                    } else {
                        Add-Result 'Account policy' 'Password history' REVIEW "PasswordHistorySize=$history; required minimum=$PasswordHistory." 'Raise the password history through the local policy or governing GPO.'
                    }
                } else {
                    Add-Result 'Account policy' 'Password history' REVIEW 'PasswordHistorySize is unreadable.' 'Review the password history in secpol.msc or the governing GPO.'
                }
            }
        } catch {
            Add-Result 'Account policy' 'Password history verification' REVIEW $_.Exception.Message 'Verify PasswordHistorySize in secpol.msc or the governing GPO.'
        }
    }
    if ($policy.ContainsKey('Privilege Rights')) {
        $rights = $policy['Privilege Rights']
        foreach ($name in 'SeNetworkLogonRight','SeRemoteInteractiveLogonRight','SeDebugPrivilege','SeBackupPrivilege','SeRestorePrivilege') {
            if (-not $rights.ContainsKey($name)) { continue }
            $assignment = [string]$rights[$name]
            if ($assignment -match '(^|,)\s*\*?S-1-1-0\s*(,|$)|(^|,)\s*Everyone\s*(,|$)') {
                Add-Result 'User rights' $name REVIEW $assignment 'Everyone has this right. Remove only that principal after confirming required groups and domain GPO; never replace the full list blindly.'
            } elseif ($name -eq 'SeNetworkLogonRight') {
                Add-Result 'User rights' $name PASS "Everyone is absent. Assigned principals: $assignment" ''
            } elseif ($name -eq 'SeRemoteInteractiveLogonRight') {
                Add-Result 'User rights' $name REVIEW $assignment 'Verify these SIDs/groups are authorized for network or RDP logon. Account for deny rights and GPO overrides.'
            } else { Add-Result 'User rights' $name PASS 'Everyone is not assigned this privilege; detailed assignments are in the private Report.txt.' '' }
        }
        if ($script:IsDomainJoined) {
            Add-Result 'User rights' 'Domain policy may control privileged user rights' REVIEW 'Local SeTakeOwnershipPrivilege and SeSecurityPrivilege assignments will be set to Administrators only, but a governing GPO may override them.' 'Verify the effective rights and the governing GPO after the run.'
        }
        Invoke-AdministratorsOnlyRight 'SeTakeOwnershipPrivilege' 'Take ownership of files or other objects (Administrators only)'
        Invoke-AdministratorsOnlyRight 'SeSecurityPrivilege' 'Manage auditing and security log (Administrators only)'
    } else { Add-Result 'User rights' 'Export unavailable' REVIEW 'No Privilege Rights section was returned.' 'Inspect effective user rights in secpol.msc and domain GPO.' }
}
function Initialize-AuditReader {
    if ('CYPatGeneralV51.AuditReader' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace CYPatGeneralV51 {
    public sealed class AuditSubcategory { public string Guid; public string Name; }
    public static class AuditReader {
        [StructLayout(LayoutKind.Sequential)] private struct Policy {
            public Guid SubCategory; public uint Information; public Guid Category;
        }
        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy([In] Guid[] ids, uint count, out IntPtr data);
        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditSetSystemPolicy([In] Policy[] policies, uint count);
        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditEnumerateSubCategories(IntPtr category,
            [MarshalAs(UnmanagedType.U1)] bool all, out IntPtr data, out uint count);
        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode, ExactSpelling=true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditLookupSubCategoryNameW(ref Guid id, out IntPtr name);
        [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr data);
        public static uint Read(string id) {
            IntPtr data;
            if (!AuditQuerySystemPolicy(new Guid[] { new Guid(id) }, 1, out data))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try { return ((Policy)Marshal.PtrToStructure(data, typeof(Policy))).Information; }
            finally { AuditFree(data); }
        }
        public static void Write(string id, uint mask) {
            Policy policy = new Policy();
            policy.SubCategory = new Guid(id);
            policy.Information = mask;
            policy.Category = Guid.Empty;
            if (!AuditSetSystemPolicy(new Policy[] { policy }, 1))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public static AuditSubcategory[] Enumerate() {
            IntPtr data; uint count;
            if (!AuditEnumerateSubCategories(IntPtr.Zero, true, out data, out count))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                AuditSubcategory[] entries = new AuditSubcategory[count];
                for (uint index=0; index<count; index++) {
                    Guid id = (Guid)Marshal.PtrToStructure(IntPtr.Add(data, checked((int)index * 16)), typeof(Guid));
                    string display = id.ToString("B"); IntPtr name;
                    if (AuditLookupSubCategoryNameW(ref id, out name)) {
                        try { display = Marshal.PtrToStringUni(name); } finally { AuditFree(name); }
                    }
                    entries[index] = new AuditSubcategory { Guid=id.ToString("B"), Name=display };
                }
                return entries;
            } finally { AuditFree(data); }
        }
    }
}
'@ -ErrorAction Stop
}
function Get-AuditSubcategories { Initialize-AuditReader; [CYPatGeneralV51.AuditReader]::Enumerate() }
function Get-AuditMask { param([string]$Guid); [CYPatGeneralV51.AuditReader]::Read($Guid) }
function Invoke-AuditPolicyAudit {
    Initialize-AuditReader
    $available = @(Get-AuditSubcategories)
    if (-not $available.Count) { throw 'Windows returned no audit subcategories; no audit checks were attempted.' }
    # Every available subcategory is checked; AuditCoverage=Core was removed so
    # Security State Change, Computer Account Management, Detailed File Share,
    # and every other subcategory must carry both Success and Failure.
    $requirements = @($available | ForEach-Object { @{Name=$_.Name;Guid=$_.Guid} })
    $script:Inventory.AuditCoverage='All'
    $script:Inventory.AuditSubcategories=@($requirements | ForEach-Object { [pscustomobject]@{Name=$_.Name;Guid=$_.Guid;RequiredMask=3} })
    if ($Apply -and -not $WhatIfPreference) {
        # Fast path: auditpol applies both bits to every category at once.
        # Per-subcategory readback below is authoritative.
        try {
            Invoke-Native 'auditpol.exe' @('/set','/category:*','/success:enable','/failure:enable') | Out-Null
            Add-Ledger 'AUDIT' 'Category-wide' 'auditpol enabled Success and Failure for every category.'
        } catch {
            Add-Result 'Audit policy' 'Category-wide enable' 'REVIEW' $_.Exception.Message 'Per-subcategory enforcement will still be attempted; check the governing GPO if it fails.'
        }
    }
    $missing = [System.Collections.Generic.List[string]]::new()
    $changed = 0
    foreach ($requirement in $requirements) {
        $guid = [string]$requirement.Guid
        $name = [string]$requirement.Name
        try { $mask = [int](Get-AuditMask $guid) }
        catch {
            $missing.Add($name)
            Add-Result 'Audit policy' $name 'REVIEW' "Unable to read the audit mask: $($_.Exception.Message)" 'Inspect this subcategory with auditpol /get /subcategory in the governing policy.'
            continue
        }
        if (($mask -band 3) -eq 3) {
            Add-Result 'Audit policy' $name 'PASS' 'Success and Failure auditing are enabled.' ''
            continue
        }
        $states = @()
        if ($mask -band 1) { $states += 'Success enabled' } else { $states += 'Success missing' }
        if ($mask -band 2) { $states += 'Failure enabled' } else { $states += 'Failure missing' }
        if (-not $Apply) {
            $missing.Add($name)
            Add-Result 'Audit policy' $name 'REVIEW' "Mask=$mask ($($states -join '; '))." 'Run with -Apply to enable Success and Failure for every checked subcategory.'
            continue
        }
        if ($WhatIfPreference) {
            $missing.Add($name)
            Add-Result 'Audit policy' $name 'SKIPPED' "Mask=$mask ($($states -join '; '))." 'Change suppressed by -WhatIf.'
            continue
        }
        try {
            [CYPatGeneralV51.AuditReader]::Write($guid, 3)
        } catch {
            try {
                Invoke-Native 'auditpol.exe' @('/set','/subcategory',$guid,'/success:enable','/failure:enable') | Out-Null
            } catch {
                $missing.Add($name)
                Add-Result 'Audit policy' $name 'FAILED' "Unable to enable auditing: $($_.Exception.Message)" 'Enable this subcategory in secpol.msc or auditpol; check the effective GPO.'
                continue
            }
        }
        try {
            $after = [int](Get-AuditMask $guid)
            if (($after -band 3) -ne 3) { throw "Readback mask=$after; Success and Failure are not both set." }
            $changed++
            Add-Result 'Audit policy' $name 'CHANGED' "Before: $($states -join '; '). After: Success and Failure enabled and verified." ''
            Add-Ledger 'AUDIT' $name 'Enabled Success and Failure auditing.'
        } catch {
            $missing.Add($name)
            Add-Result 'Audit policy' $name 'FAILED' $_.Exception.Message 'Check for a governing GPO or a subcategory that does not accept both bits.'
        }
    }
    if ($missing.Count) {
        $modeHint = if ($Apply) { 'Check the governing GPO and each failed subcategory; re-run -AuditOnly to confirm.' } else { 'Run with -Apply to enable every subcategory automatically.' }
        Add-Result 'Audit policy' 'Coverage summary' 'REVIEW' "$($missing.Count) of $($requirements.Count) checked subcategory(ies) are missing Success or Failure auditing: $($missing -join ', ')." $modeHint
    } else {
        Add-Result 'Audit policy' 'Coverage summary' 'PASS' "All $($requirements.Count) checked subcategory(ies) have Success and Failure auditing." ''
    }
    if ($changed) { Write-Host "Enabled Success+Failure auditing on $changed subcategory(ies)." -ForegroundColor Green }
    Set-RegistryBaseline 'Audit policy' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1
    Set-RegistryBaseline 'Audit policy' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
}
function Invoke-RegistryAudit {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $system = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    foreach ($setting in @(
        @('Authentication',$lsa,'LimitBlankPasswordUse',1),
        @('Authentication',$lsa,'NoLMHash',1),
        @('Authentication',$lsa,'RestrictAnonymous',1),
        @('Authentication',$lsa,'RestrictAnonymousSAM',1),
        @('Authentication',$lsa,'DisableDomainCreds',1),
        @('Audit',$lsa,'AuditBaseObjects',0),
        @('Authentication',$lsa,'EveryoneIncludesAnonymous',0),
        @('Logon',$system,'DisableCAD',0),
        @('Logon',$system,'DontDisplayLastUserName',1),
        @('Logon',$system,'DontDisplayLockedUserId',3),
        @('Logon',$system,'MaxDevicePasswordFailedAttempts',5),
        @('UAC',$system,'EnableLUA',1),
        @('UAC',$system,'EnableSecureUIAPaths',1),
        @('UAC',$system,'ValidateAdminCodeSignatures',1),
        @('UAC',$system,'PromptOnSecureDesktop',1),
        @('UAC',$system,'ConsentPromptBehaviorAdmin',2),
        @('Devices',$system,'UndockWithoutLogon',0),
        @('AutoRun','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoDriveTypeAutoRun',255),
        @('AutoRun','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoAutorun',1),
        @('AutoRun','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoAutoplayfornonVolume',1),
        @('Installer','HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated',0),
        @('Installer','HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated',0)
    )) { Set-RegistryBaseline $setting[0] $setting[1] $setting[2] $setting[3] }
    # Interactive logon: Machine inactivity limit. Values 1-1800 are retained so a
    # stronger timeout is not weakened to the requested 1800 seconds.
    $inactivity=Get-RegistryState $system InactivityTimeoutSecs
    $inactivityText=if ($inactivity.Exists) { [string]$inactivity.Value } else { 'not set' }
    Invoke-Setting 'Logon' 'Machine inactivity limit (1800 seconds)' {
        $current=Get-RegistryState $system InactivityTimeoutSecs
        if (-not $current.Exists) { return $false }
        $seconds=0
        return [int]::TryParse([string]$current.Value,[ref]$seconds) -and $seconds -ge 1 -and $seconds -le 1800
    } {
        if (-not (Test-Path -LiteralPath $system)) { New-Item -Path $system -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $system -Name InactivityTimeoutSecs -Value 1800 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    } "Current=$inactivityText; required 1-1800 seconds." 'Set the machine inactivity limit to 1800 seconds or retain a shorter value.'
    # Interactive logon: Require domain controller authentication to unlock. The
    # setting is meaningful only on domain-joined or domain-controller systems.
    $forceUnlock = if ($script:IsDomainJoined -or $script:IsDomainController) { 1 } else { 0 }
    $forceUnlockState=Get-RegistryState $system ForceUnlockLogon
    $forceUnlockText=if ($forceUnlockState.Exists) { [string]$forceUnlockState.Value } else { 'not set' }
    Invoke-Setting 'Logon' 'Domain controller authentication to unlock' {
        $current=Get-RegistryState $system ForceUnlockLogon
        return $current.Exists -and ([string]$current.Value -eq [string]$forceUnlock)
    } {
        if (-not (Test-Path -LiteralPath $system)) { New-Item -Path $system -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $system -Name ForceUnlockLogon -Value $forceUnlock -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    } "Current=$forceUnlockText; domainJoined=$($script:IsDomainJoined); domainController=$($script:IsDomainController); required=$forceUnlock." 'Enable this requirement on domain-joined systems and disable it on standalone systems.'
    # Shutdown: Clear virtual memory pagefile.
    Set-RegistryBaseline 'Shutdown' 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' ClearPageFileAtShutdown 1
    # System objects: Strengthen default permissions (ProtectionMode) is set under
    # Session Manager by Invoke-DeepSecurityOptions.
    Set-RegistryBaseline 'Credential UI' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' EnumerateAdministrators 0
    Set-RegistryBaseline 'Password policy' 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM' RelaxMinimumPasswordLengthLimits 0
    Set-RegistryBaseline 'Password policy' 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM' MinimumPasswordLengthAudit 12
    Set-RegistryBaseline 'Devices' 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' AllocateDASD '0' -Type String
    Set-RegistryBaseline 'Devices' 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' AddPrinterDrivers 1
    Set-RegistryBaseline 'Devices' 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' AllocateCDRoms '1' -Type String
    Set-RegistryBaseline 'Devices' 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' AllocateFloppies '1' -Type String
    Set-RegistryBaseline 'SMB signing' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' RequireSecuritySignature 1
    Set-RegistryBaseline 'SMB signing' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' RequireSecuritySignature 1
    Set-RegistryBaseline 'Legacy authentication' $lsa LmCompatibilityLevel 5
    Set-RegistryBaseline 'Legacy authentication' "$lsa\MSV1_0" NtlmMinClientSec 537395200
    Set-RegistryBaseline 'Legacy authentication' "$lsa\MSV1_0" NtlmMinServerSec 537395200
    Set-RegistryBaseline 'NTLM auditing' "$lsa\MSV1_0" AuditReceivingNTLMTraffic 2
    Set-RegistryBaseline 'NTLM auditing' 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' AuditNTLMInDomain 7
    Set-RegistryBaseline 'NTLM auditing' "$lsa\MSV1_0" RestrictSendingNTLMTraffic 1
    Set-RegistryBaseline 'LDAP signing' 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 2
    Set-RegistryBaseline 'Name resolution' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0
    Set-RegistryBaseline Logon 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' CachedLogonsCount '1' -Type String
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $autoLogon = Get-RegistryState $winlogon AutoAdminLogon
    $savedPassword = Get-RegistryState $winlogon DefaultPassword
    if ($autoLogon.Value -eq '1' -or $savedPassword.Exists) {
        Add-Result Logon 'Automatic logon / stored credential' REVIEW 'AutoAdminLogon is enabled or DefaultPassword exists. Credential value is deliberately omitted. The Automatic logon question later in the run can turn it off.' 'Review requirements; remove stored credentials manually. Never include their contents in reports.'
    }
}
function Invoke-DefenderAudit {
    $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($null -eq $defenderService) {
        $feature = $null
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            try { $feature = @(Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Name -like '*Defender*' } | Select-Object -First 1) | Select-Object -First 1 }
            catch { $feature = $null }
        }
        if ($null -ne $feature -and -not $feature.Installed) {
            if ($Apply -and -not $WhatIfPreference) {
                try {
                    Install-WindowsFeature -Name $feature.Name -ErrorAction Stop | Out-Null
                    Add-Ledger 'INSTALL' 'Defender' "Installed Windows feature $($feature.Name)."
                } catch {
                    Add-Result Defender 'Defender installation' FAILED $_.Exception.Message 'Install the Windows Defender feature, then re-run. A restart may be required.'
                    return
                }
            } else {
                Add-Result Defender 'Defender installation' REVIEW "Windows Defender feature $($feature.Name) is not installed." 'Run with -Apply to install it, or install the feature manually and re-run.'
                return
            }
        }
        $defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    }
    if ($null -eq $defenderService) {
        Add-Result Defender 'WinDefend service' FAILED 'The Microsoft Defender Antivirus service (WinDefend) is not installed.' 'Install the Windows Defender feature or repair the image; Defender must be installed and used.'
        return
    }
    $script:Inventory.DefenderService = [pscustomobject]@{Name=$defenderService.Name;Status=[string]$defenderService.Status;StartMode=(Get-ServiceStartMode $defenderService)}
    Invoke-Setting Defender 'WinDefend service' {
        $current=Get-Service -Name WinDefend -ErrorAction Stop
        (Get-ServiceStartMode $current) -eq 'Automatic' -and $current.Status -eq 'Running'
    } {
        $current=Get-Service -Name WinDefend -ErrorAction Stop
        if ((Get-ServiceStartMode $current) -ne 'Automatic') { Set-Service -Name WinDefend -StartupType Automatic -ErrorAction Stop }
        if ($current.Status -ne 'Running') { Start-Service -Name WinDefend -ErrorAction Stop }
    } 'Microsoft Defender Antivirus service must be installed, Automatic, and Running.' 'Start WinDefend and check for a disabling policy. Defender must be the active antivirus engine.'
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        Add-Result Defender 'Availability' FAILED 'The WinDefend service exists, but the Defender cmdlets are unavailable.' 'Repair the Defender platform and re-run; do not leave the image without an active antivirus engine.'
        return
    }
    $status = Get-MpComputerStatus -ErrorAction Stop
    $script:Inventory.Defender = $status | Select-Object AntivirusEnabled,AMRunningMode,RealTimeProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureLastUpdated,IsTamperProtected
    $mode = Get-OptionalProperty $status AMRunningMode ''
    if ($mode -match 'Passive|EDR' -or -not $status.AntivirusEnabled) {
        Add-Result Defender 'Defender in use' REVIEW "AntivirusEnabled=$($status.AntivirusEnabled); AMRunningMode=$mode" 'Defender must be the active antivirus engine. Remove any passive-mode or third-party-AV policy that prevents it from being used, then re-run.'
    } else {
        Add-Result Defender 'Defender in use' PASS "AntivirusEnabled=$($status.AntivirusEnabled); AMRunningMode=$mode; RealTimeProtection=$($status.RealTimeProtectionEnabled)." ''
    }
    if ($mode -match 'Passive|EDR') { Add-Result Defender 'Protection mode' REVIEW $mode 'Verify approved antivirus; do not force Defender active over another product.' }
    else {
        $preferences = Get-MpPreference -ErrorAction Stop
        foreach ($name in 'DisableRealtimeMonitoring','DisableBehaviorMonitoring','DisableIOAVProtection','DisableScriptScanning') {
            if ($null -eq (Get-OptionalProperty $preferences $name)) { continue }
            Invoke-Setting Defender $name { (Get-MpPreference -ErrorAction Stop).$name -eq $false } {
                $arguments = @{ErrorAction='Stop'}; $arguments[$name]=$false; Set-MpPreference @arguments
            } 'The protection preference should not be disabled.' 'Tamper protection or a GPO may require manual repair; verify effective protection.'
        }
        $actual = Get-MpComputerStatus -ErrorAction Stop
        if (-not $actual.AntivirusEnabled -or -not $actual.RealTimeProtectionEnabled -or -not $actual.BehaviorMonitorEnabled) {
            Add-Result Defender 'Effective protection' REVIEW "AV=$($actual.AntivirusEnabled); realtime=$($actual.RealTimeProtectionEnabled); behavior=$($actual.BehaviorMonitorEnabled)" 'Check passive mode, tamper protection, GPO, and Defender services. Changing a preference alone does not prove protection is running.'
        } else { Add-Result Defender 'Effective protection' PASS 'Antivirus, real-time, and behavior protection are enabled.' '' }
    }
    $preferences = Get-MpPreference -ErrorAction Stop
    $extensionValues = @(Get-OptionalProperty $preferences ExclusionExtension @() | Where-Object { $_ })
    $broadExtensions = @($extensionValues | Where-Object { Test-BroadExecutableExclusion $_ } | Select-Object -Unique)
    if ($broadExtensions.Count) {
        Invoke-Setting Defender 'Executable extension exclusions' {
            $current = @(Get-OptionalProperty (Get-MpPreference -ErrorAction Stop) ExclusionExtension @() | Where-Object { $_ })
            @($current | Where-Object { Test-BroadExecutableExclusion $_ }).Count -eq 0
        } {
            $current = @(Get-OptionalProperty (Get-MpPreference -ErrorAction Stop) ExclusionExtension @() | Where-Object { $_ })
            foreach ($extension in @($current | Where-Object { Test-BroadExecutableExclusion $_ } | Select-Object -Unique)) {
                Remove-MpPreference -ExclusionExtension $extension -ErrorAction Stop
            }
        } "Executable extensions excluded: $($broadExtensions -join ', ')" 'Remove exe/.exe from Defender extension exclusions. Other exclusions stay review-only unless the README proves they are unauthorized.'
        # Re-read effective preferences so the review below does not report a
        # just-removed extension from the earlier snapshot.
        $preferences = Get-MpPreference -ErrorAction Stop
    }
    foreach ($property in 'ExclusionExtension','ExclusionPath','ExclusionProcess') {
        $values = @(Get-OptionalProperty $preferences $property @() | Where-Object { $_ })
        if ($property -eq 'ExclusionExtension') { $values = @($values | Where-Object { -not (Test-BroadExecutableExclusion $_) }) }
        if ($values.Count) {
            $hint = 'Validate each exclusion against the role and README; do not clear legitimate exclusions.'
            Add-Result Defender $property REVIEW ($values -join ', ') "$hint Approved local removals use Remove-MpPreference; policy exclusions must be fixed in their governing GPO."
        }
    }
    foreach ($kind in 'Extensions','Paths','Processes') {
        $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\$kind"
        if (Test-Path -LiteralPath $key) {
            $names = @((Get-Item -LiteralPath $key -ErrorAction Stop).GetValueNames() | Where-Object { $_ })
            if ($kind -eq 'Extensions') {
                $broadPolicy = @($names | Where-Object { Test-BroadExecutableExclusion $_ } | Select-Object -Unique)
                if ($broadPolicy.Count) {
                    Invoke-Setting Defender 'Policy executable extension exclusions' {
                        if (-not (Test-Path -LiteralPath $key)) { return $true }
                        $current = @((Get-Item -LiteralPath $key -ErrorAction Stop).GetValueNames() | Where-Object { $_ })
                        @($current | Where-Object { Test-BroadExecutableExclusion $_ }).Count -eq 0
                    } {
                        $current = @((Get-Item -LiteralPath $key -ErrorAction Stop).GetValueNames() | Where-Object { $_ })
                        foreach ($name in @($current | Where-Object { Test-BroadExecutableExclusion $_ } | Select-Object -Unique)) {
                            Remove-ItemProperty -LiteralPath $key -Name $name -Force -ErrorAction Stop
                        }
                    } "Policy executable extensions excluded: $($broadPolicy -join ', ')" 'Remove exe/.exe from local Defender policy extension exclusions. Domain GPO may reapply this value; verify effective policy after gpupdate.'
                    $names = @($names | Where-Object { -not (Test-BroadExecutableExclusion $_) })
                }
            }
            if ($names.Count) { Add-Result Defender "Policy exclusions/$kind" REVIEW ($names -join ', ') 'Policy and local exclusions can merge; fix unauthorized values in the governing GPO and recheck Get-MpPreference.' }
        }
    }
    $signatureTime = Get-OptionalProperty $status AntivirusSignatureLastUpdated
    if (-not $signatureTime -or ((Get-Date)-[datetime]$signatureTime).TotalDays -gt 7) { Add-Result Defender 'Signatures' REVIEW ([string]$signatureTime) 'Update security intelligence through permitted sources; no update download is started by this script.' }
    $threats = @(Get-MpThreat -ErrorAction Stop | Where-Object { $_.IsActive })
    if ($threats.Count) { Add-Result Defender 'Active detections' REVIEW ($threats.ThreatName -join ', ') 'Record forensic evidence, then quarantine confirmed threats manually.' }
}
function Get-Smb1OptionalFeatureState {
    # Returns 'Disabled', 'DisabledWithPayloadRemoved', 'Enabled', or 'NotAvailable'.
    # Newer Windows 11 and Windows Server builds no longer ship the SMB1 optional
    # feature at all, and Get-WindowsOptionalFeature throws for an unknown name.
    if (-not (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) { return 'NotAvailable' }
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        if ($null -eq $feature) { return 'NotAvailable' }
        return [string]$feature.State
    } catch {
        return 'NotAvailable'
    }
}
function Test-Smb1OptionalFeatureDisabled {
    $state = Get-Smb1OptionalFeatureState
    return $state -eq 'NotAvailable' -or $state -eq 'Disabled' -or $state -eq 'DisabledWithPayloadRemoved'
}
function Invoke-SmbAudit {
    if (-not (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)) { Add-Result SMB 'Server configuration' SKIPPED 'SMB cmdlets are unavailable.' ''; return }
    Invoke-Setting SMB 'SMB1 server support' { -not (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false -ErrorAction Stop
    } 'SMB1 should be disabled; SMB2/3 and the file sharing service are preserved.' 'Check legacy dependencies before apply. Optional-feature removal and client-driver cleanup remain manual.'
    Invoke-Setting SMB 'SMB2/3 server support' { (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB2Protocol } {
        Set-SmbServerConfiguration -EnableSMB2Protocol $true -Confirm:$false -ErrorAction Stop
    } 'Modern SMB2/3 server support should remain enabled.' 'SMB2/3 is the supported replacement for SMB1.'
    Invoke-Setting SMB 'Server signing required' { (Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Confirm:$false -ErrorAction Stop
    } 'SMB server signing should be required.' 'Check required third-party SMB client compatibility.'
    Invoke-Setting SMB 'Client signing required' { (Get-SmbClientConfiguration -ErrorAction Stop).RequireSecuritySignature } {
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Confirm:$false -ErrorAction Stop
    } 'SMB client signing should be required.' 'Check required third-party SMB server compatibility.'
    Invoke-Setting SMB 'Insecure guest logons disabled' { -not (Get-SmbClientConfiguration -ErrorAction Stop).EnableInsecureGuestLogons } {
        Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Confirm:$false -ErrorAction Stop
    } 'Unauthenticated SMB guest logons should be disabled.' 'Use authenticated access to required shares.'
    $smb1FeatureState = Get-Smb1OptionalFeatureState
    if ($smb1FeatureState -eq 'NotAvailable') {
        Add-Result SMB 'SMB1 optional feature' PASS 'The SMB1 optional feature is not present on this system (Windows removed it or it was never installed).' ''
    } else {
        Invoke-Setting SMB 'SMB1 optional feature' {
            Test-Smb1OptionalFeatureDisabled
        } {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
        } "SMB1 optional feature should be disabled (current state: $smb1FeatureState). Restart may be required for full removal from service." 'Preserve SMB2/3 and required shares.'
    }
    $shares = @(Get-SmbShare -IncludeHidden -ErrorAction Stop)
    $script:Inventory.SharesBeforeDecisions = @($shares | Select-Object Name,Path,Special,Description)
}
function Invoke-ShareServicePreparation {
    $service=Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Add-Result Shares 'LanmanServer availability' FAILED 'The Server service is not installed.' 'Review the image role and SMB installation.'
        return
    }
    if ($service.Status -eq 'Running') { Add-Result Shares 'LanmanServer availability' PASS 'The Server service is running for share review.' ''; return }
    $script:ShareReviewAttemptedServerStart=$true
    Invoke-Setting Shares 'LanmanServer availability' {
        (Get-Service -Name LanmanServer -ErrorAction Stop).Status -eq 'Running'
    } {
        $current=Get-Service -Name LanmanServer -ErrorAction Stop
        if ((Get-ServiceStartMode $current) -eq 'Disabled') { Set-Service -Name LanmanServer -StartupType Manual -ErrorAction Stop }
        Start-Service -Name LanmanServer -ErrorAction Stop
    } 'The Server service must run to enumerate and remove shares.' 'Start LanmanServer for share review; restore its prior state afterward unless SMB was explicitly required.'
}
function Restore-ShareServiceState {
    if (-not $Apply -or $WhatIfPreference -or -not $script:ShareReviewAttemptedServerStart -or
        $script:ShareReviewInitialStatus -ne 'Stopped' -or (Test-ServiceProtected 'LanmanServer')) { return }
    try {
        $service=Get-Service -Name LanmanServer -ErrorAction Stop
        $dependents=@($service.DependentServices | Where-Object { $_.Status -eq 'Running' })
        if ($service.Status -eq 'Running') {
            Stop-Service -Name LanmanServer -Force -ErrorAction Stop
        }
        if ($script:ShareReviewInitialStartMode -eq 'Disabled' -and (Get-ServiceStartMode (Get-Service -Name LanmanServer -ErrorAction Stop)) -ne 'Disabled') {
            Set-Service -Name LanmanServer -StartupType Disabled -ErrorAction Stop
        }
        if ((Get-Service -Name LanmanServer -ErrorAction Stop).Status -eq 'Stopped') {
            $detail='The Server service was returned to its initially stopped state.'
            if ($dependents.Count) { $detail+=' Dependent services also stopped: ' + (($dependents | ForEach-Object { $_.Name }) -join ', ') }
            Add-Result Shares 'LanmanServer state restored' PASS $detail ''
        } else {
            Add-Result Shares 'LanmanServer state restored' FAILED 'The Server service is still running.' 'Review the service at the console.'
        }
    } catch {
        Add-Result Shares 'LanmanServer state restored' FAILED $_.Exception.Message 'Review the service and its dependents at the console.'
    }
}
function Get-RequiredShareMismatch {
    param([object[]]$Shares)
    foreach ($name in $RequiredShares.Keys) {
        $expected=[string]$RequiredShares[$name]
        if ([string]::IsNullOrWhiteSpace([string]$name) -or [WildcardPattern]::ContainsWildcardCharacters([string]$name) -or [string]::IsNullOrWhiteSpace($expected)) {
            return 'RequiredShares must map exact share names to nonempty paths.'
        }
        $found=@($Shares | Where-Object { $_.Name -eq $name })
        if ($found.Count -ne 1 -or ([string]$found[0].Path).TrimEnd([char]92) -ne $expected.TrimEnd([char]92)) {
            return "Required share $name is absent or does not point to $expected."
        }
    }
    return ''
}
function Test-ScenarioShare {
    param([string]$Name, [string]$Path='')
    $names=@($ProtectedShareNames | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    if ($Name -and ($names -contains $Name)) { return $true }
    $paths=@($ProtectedSharePaths | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().TrimEnd('\') } | Where-Object { $_ })
    foreach ($base in $paths) {
        if ([string]::IsNullOrWhiteSpace($Path)) { continue }
        $normalized=$Path.TrimEnd('\')
        if ($normalized -ieq $base -or $normalized -like "$base\*") { return $true }
    }
    return $false
}
function Test-ProtectedShare {
    param([string]$Name, [string]$Path='', [object]$Special=$null)
    # Windows marks administrative shares (ADMIN$, C$, IPC$, PRINT$) with the
    # Special flag; that flag is the authoritative signal. The name list is the
    # fallback for when only a name is available (for example -RemoveShares).
    # USERS$ is not in the name list; it is an ordinary hidden share unless Windows
    # marks it special.
    if ($null -ne $Special -and [bool]$Special) { return $true }
    if (Test-ScenarioShare -Name $Name -Path $Path) { return $true }
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -in @('ADMIN$','IPC$','SYSVOL','NETLOGON','PRINT$')) { return $true }
    if ($Name -match '^[A-Za-z]\$$') { return $true }
    return $false
}
function Test-RiskySharePrincipal {
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $false }
    $text=$Identity.Trim()
    if ($text -match '^S-1-') { return $text -in @('S-1-1-0','S-1-5-7','S-1-5-32-546') }
    if ($text -match '(?i)(^|\\)(Everyone|ANONYMOUS LOGON|Guests?)$') { return $true }
    try {
        $sid=(New-Object -TypeName Security.Principal.NTAccount -ArgumentList $text).Translate([Security.Principal.SecurityIdentifier]).Value
        return $sid -in @('S-1-1-0','S-1-5-7','S-1-5-32-546')
    } catch { return $false }
}
function Test-SensitiveSharePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
        $roots=@($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData,(Join-Path $env:SystemDrive 'Users'))
        foreach ($root in $roots) {
            if ([string]::IsNullOrWhiteSpace($root)) { continue }
            $normalized=[IO.Path]::GetFullPath($root).TrimEnd('\')
            if ($full -ieq $normalized -or $full -like "$normalized\*") { return $true }
        }
        $driveRoot=[IO.Path]::GetPathRoot($full)
        if ($driveRoot -and $full -ieq $driveRoot.TrimEnd('\')) { return $true }
    } catch { return $false }
    return $false
}
function Get-SharePermissionFindings {
    param($Share)
    $path=[string](Get-OptionalProperty $Share 'Path' '')
    $special=[bool](Get-OptionalProperty $Share 'Special' $false)
    $sensitive=(Test-SensitiveSharePath $path) -and -not (Test-ProtectedShare -Name ([string]$Share.Name) -Path $path -Special $special)
    $finding=[pscustomobject]@{
        Name=[string]$Share.Name; Path=$path; Special=$special; Sensitive=$sensitive; Pathless=$false;
        ShareAces=@(); ShareRisky=@(); NtfsExplicitRisky=@(); NtfsInheritedRisky=@(); Errors=@()
    }
    if ([string]::IsNullOrWhiteSpace($path)) {
        # IPC$, ADMIN$, and other pathless special shares are normal Windows shares.
        $finding.Pathless=$true
        return $finding
    }
    try { $finding.ShareAces=@(Get-SmbShareAccess -Name $Share.Name -ErrorAction Stop) }
    catch { $finding.Errors += "Share ACL: $($_.Exception.Message)" }
    foreach ($ace in @($finding.ShareAces)) {
        if ([string](Get-OptionalProperty $ace 'AccessControlType' '') -eq 'Allow' -and (Test-RiskySharePrincipal ([string](Get-OptionalProperty $ace 'AccountName' '')))) {
            $finding.ShareRisky += $ace
        }
    }
    if (-not (Test-Path -LiteralPath $path)) {
        $finding.Errors += "NTFS ACL: share path does not exist ($path)."
        return $finding
    }
    try {
        $aclPath=if ($path.Length -gt 3) { $path.TrimEnd('\') } else { $path }
        $acl=Get-Acl -LiteralPath $aclPath -ErrorAction Stop
        foreach ($ace in @($acl.Access)) {
            if ([string](Get-OptionalProperty $ace 'AccessControlType' '') -ne 'Allow') { continue }
            $identity=[string](Get-OptionalProperty (Get-OptionalProperty $ace 'IdentityReference' $null) 'Value' '')
            if (-not (Test-RiskySharePrincipal $identity)) { continue }
            if ([bool](Get-OptionalProperty $ace 'IsInherited' $false)) { $finding.NtfsInheritedRisky += $ace }
            else { $finding.NtfsExplicitRisky += $ace }
        }
    } catch { $finding.Errors += "NTFS ACL: $($_.Exception.Message)" }
    return $finding
}
function Invoke-SharePermissionAudit {
    if (-not (Get-Command Get-SmbShareAccess -ErrorAction SilentlyContinue)) {
        Add-Result Shares 'Share permission audit' SKIPPED 'Get-SmbShareAccess is unavailable.' 'Review share and NTFS permissions manually.'
        return
    }
    $shares=@(Get-SmbShare -IncludeHidden -ErrorAction Stop)
    $findings=[System.Collections.Generic.List[object]]::new()
    foreach ($share in $shares) {
        $sharePath=[string](Get-OptionalProperty $share 'Path' '')
        if ([string]::IsNullOrWhiteSpace($sharePath)) {
            # IPC$, ADMIN$, and other pathless special shares are normal Windows shares.
            continue
        }
        $finding=Get-SharePermissionFindings $share
        $findings.Add($finding)
        $shareRisky=@($finding.ShareRisky)
        $explicitRisky=@($finding.NtfsExplicitRisky)
        $inheritedRisky=@($finding.NtfsInheritedRisky)
        $riskyCount=$shareRisky.Count + $explicitRisky.Count
        $shareText=@($shareRisky | ForEach-Object { "$([string](Get-OptionalProperty $_ 'AccountName' ''))=$([string](Get-OptionalProperty $_ 'AccessRight' ''))" }) -join ', '
        $ntfsText=@($explicitRisky | ForEach-Object { "$([string](Get-OptionalProperty (Get-OptionalProperty $_ 'IdentityReference' $null) 'Value' ''))=$([string](Get-OptionalProperty $_ 'FileSystemRights' ''))" }) -join ', '
        $inheritedText=@($inheritedRisky | ForEach-Object { "$([string](Get-OptionalProperty (Get-OptionalProperty $_ 'IdentityReference' $null) 'Value' ''))=$([string](Get-OptionalProperty $_ 'FileSystemRights' ''))" }) -join ', '
        $evidence="Path=$($finding.Path); special=$($finding.Special); sensitive=$($finding.Sensitive); shareRisky=[$shareText]; ntfsExplicitRisky=[$ntfsText]; ntfsInheritedRisky=[$inheritedText]"
        if ($finding.Errors.Count) { $evidence += "; errors=$($finding.Errors -join ' | ')" }
        if ($finding.Sensitive) {
            $sensitiveStatus=if ($riskyCount) { 'FAILED' } else { 'REVIEW' }
            Add-Result Shares "$($finding.Name) sensitive share root" $sensitiveStatus $evidence 'A share rooted at Windows, Program Files, ProgramData, Users, or a drive root is high risk. Confirm the README requires it and restrict its permissions.'
        }
        if (-not $riskyCount -and -not $inheritedRisky.Count -and -not $finding.Errors.Count) {
            Add-Result Shares "$($finding.Name) permissions" PASS 'No Everyone, ANONYMOUS LOGON, or Guests Allow ACE is present at the share or NTFS root.' ''
        } elseif (-not $riskyCount -and $inheritedRisky.Count) {
            Add-Result Shares "$($finding.Name) inherited NTFS permissions" REVIEW $evidence 'Risky inherited ACEs come from the parent folder. Fix the parent ACL; this script does not rewrite inherited permissions.'
        } elseif ($riskyCount -or $finding.Errors.Count) {
            $status=if ($finding.Sensitive) { 'FAILED' } else { 'REVIEW' }
            Add-Result Shares "$($finding.Name) permissions" $status $evidence 'Remove Everyone, ANONYMOUS LOGON, and Guests Allow ACEs from the share and explicit NTFS root ACL only after confirming required access.'
        }
        if (-not $riskyCount -or -not $Apply) { continue }
        if ($NonInteractive) {
            Add-Result Shares "$($finding.Name) permission hardening" REVIEW 'NonInteractive mode will not change share or NTFS permissions.' 'Run interactively and answer Y to remove risky Allow ACEs, or N to leave them.'
            continue
        }
        if ($WhatIfPreference) {
            Add-Result Shares "$($finding.Name) permission hardening" SKIPPED 'Change suppressed by -WhatIf.' ''
            continue
        }
        $choice=Read-YesNo "Harden permissions on share $($finding.Name)? Y removes Everyone/ANONYMOUS LOGON/Guests Allow ACEs; N leaves them"
        if ($choice -ne 'Y') {
            Add-Result Shares "$($finding.Name) permission hardening" SKIPPED 'Risky share or explicit NTFS ACEs were left unchanged by operator decision.' 'Review the required access and remove only the risky Allow ACEs.'
            continue
        }
        try {
            foreach ($ace in @($finding.ShareRisky)) {
                $account=[string](Get-OptionalProperty $ace 'AccountName' '')
                if ($account) { Revoke-SmbShareAccess -Name $finding.Name -AccountName $account -Force -ErrorAction Stop | Out-Null }
            }
            if ($finding.NtfsExplicitRisky.Count) {
                $aclPath=if ($finding.Path.Length -gt 3) { $finding.Path.TrimEnd('\') } else { $finding.Path }
                $acl=Get-Acl -LiteralPath $aclPath -ErrorAction Stop
                foreach ($ace in @($finding.NtfsExplicitRisky)) {
                    $removed=$acl.RemoveAccessRule($ace)
                    if (-not $removed) { $acl.RemoveAccessRuleSpecific($ace) }
                }
                Set-Acl -LiteralPath $aclPath -AclObject $acl -ErrorAction Stop
            }
            $after=Get-SharePermissionFindings $share
            if ($after.ShareRisky.Count -eq 0 -and $after.NtfsExplicitRisky.Count -eq 0) {
                Add-Result Shares "$($finding.Name) permission hardening" CHANGED "Removed risky share-level and explicit NTFS Allow ACEs; inherited ACEs were preserved. $evidence" ''
                Add-Ledger 'ACL' "Share/$($finding.Name)" 'Removed Everyone/ANONYMOUS LOGON/Guests Allow ACEs from share and explicit NTFS root ACL.'
            } else {
                Add-Result Shares "$($finding.Name) permission hardening" REVIEW 'One or more risky ACEs remain after readback.' 'Inspect the share and NTFS ACL manually; a governing policy or inherited ACE may be restoring access.'
            }
        } catch {
            Add-Result Shares "$($finding.Name) permission hardening" FAILED $_.Exception.Message 'Inspect the share and NTFS ACL manually; no broad permission reset was attempted.'
        }
    }
    $script:Inventory.SharePermissions=@($findings)
}
function Invoke-ShareDecisions {
    $shares=@(Get-SmbShare -IncludeHidden -ErrorAction Stop)
    foreach ($share in @($shares | Where-Object { Test-ScenarioShare -Name $_.Name -Path $_.Path })) {
        Add-Result Shares "$($share.Name) protected" PASS "Scenario-protected share retained at $($share.Path)." ''
    }
    $mismatch=Get-RequiredShareMismatch -Shares $shares
    if ($mismatch) {
        Add-Result Shares 'Required shares' FAILED $mismatch 'Check the scenario README and restore required shares before removing any share.'
        return
    }
    foreach ($name in $RequiredShares.Keys) { Add-Result Shares "Required share $name" PASS "Present at $($RequiredShares[$name])." '' }
    foreach ($name in $KeepShares) {
        if ([string]::IsNullOrWhiteSpace($name) -or [WildcardPattern]::ContainsWildcardCharacters($name)) {
            Add-Result Shares 'KeepShares input' FAILED 'KeepShares must contain exact, nonempty share names.' 'Correct the approved share names before rerunning.'
            return
        }
    }
    $selected=@($RemoveShares | Select-Object -Unique)
    if (-not $NonInteractive) {
        foreach ($share in @($shares | Where-Object {
            $_.ScopeName -eq '*' -and -not (Test-ProtectedShare -Name $_.Name -Path $_.Path -Special (Get-OptionalProperty $_ 'Special' $false))
        })) {
            if ($RequiredShares.ContainsKey($share.Name) -or $share.Name -in $KeepShares -or $share.Name -in $selected) { continue }
            $choice=Read-YesNo "Keep share $($share.Name) at $($share.Path) because the README requires it? Y keeps; N stops sharing"
            if ($choice -eq 'N') { $selected+=@($share.Name) }
            elseif ($choice -eq 'Y') { Add-Result Shares "$($share.Name) retained" PASS 'Share was approved for this run.' '' }
            else { Add-Result Shares "$($share.Name) retained" REVIEW 'No valid share decision was received.' 'Check the image README and rerun to decide whether this share is required.' }
        }
    }
    foreach ($name in @($selected | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($name) -or [WildcardPattern]::ContainsWildcardCharacters($name)) {
            Add-Result Shares 'Share removal request' FAILED 'RemoveShares must contain exact, nonempty share names.' 'Correct the list using the scenario README.'
            continue
        }
        if ($RequiredShares.ContainsKey($name) -or $name -in $KeepShares -or (Test-ProtectedShare $name)) {
            Add-Result Shares $name REVIEW 'A required, scenario-protected, or administrative share was retained.' 'This script will not remove that share.'
            continue
        }
        $target=@($shares | Where-Object { $_.Name -eq $name })
        if ($target.Count -eq 0) { Add-Result Shares "$name removed" PASS 'The share is absent.' ''; Write-Host "$name is already unshared." -ForegroundColor Green; continue }
        if (Test-ProtectedShare -Name $target[0].Name -Path $target[0].Path -Special (Get-OptionalProperty $target[0] 'Special' $false)) {
            Add-Result Shares $name REVIEW 'A protected scenario or administrative share was retained.' 'This script will not remove that share.'
            continue
        }
        if ($target.Count -ne 1 -or $target[0].ScopeName -ne '*') {
            Add-Result Shares "$name removed" REVIEW "Expected one local share; found $($target.Count), Scope=$($target[0].ScopeName)." 'Inspect this share and its scope before trying again.'
            continue
        }
        $connectedUsers=[int](Get-OptionalProperty $target[0] CurrentUsers 0)
        if ($connectedUsers -gt 0) { Write-Warning "Removing $name will disconnect $connectedUsers active SMB connection(s)." }
        Invoke-Setting Shares "$name removed" {
            return @((Get-SmbShare -IncludeHidden -ErrorAction Stop) | Where-Object { $_.Name -eq $name }).Count -eq 0
        } {
            $current=@(Get-SmbShare -IncludeHidden -ErrorAction Stop)
            $currentMismatch=Get-RequiredShareMismatch -Shares $current
            if ($currentMismatch) { throw "Required share changed since inspection: $currentMismatch" }
            $currentTarget=@($current | Where-Object { $_.Name -eq $name })
            if ($currentTarget.Count -eq 1 -and (Test-ProtectedShare -Name $currentTarget[0].Name -Path $currentTarget[0].Path -Special (Get-OptionalProperty $currentTarget[0] 'Special' $false))) {
                throw 'Target share is protected; no share was removed.'
            }
            if ($currentTarget.Count -ne 1 -or $currentTarget[0].ScopeName -ne '*') {
                throw 'Target share changed or its scope is no longer local; no share was removed.'
            }
            Remove-SmbShare -InputObject $currentTarget[0] -Force -Confirm:$false -ErrorAction Stop
        } 'Only the selected share definition is removed; its files remain.' "Stop sharing $name as authorized by the scenario."
        $result=$script:Results[$script:Results.Count-1]
        if ($result.Item -eq "$name removed" -and $result.Status -eq 'CHANGED') {
            Write-Host "Stopped sharing $name; the share's files remain." -ForegroundColor Green
        }
    }
    $remaining=@(Get-SmbShare -IncludeHidden -ErrorAction Stop)
    $script:Inventory.Shares=@($remaining | Select-Object Name,Path,Special,Description)
    $ordinary=@($remaining | Where-Object {
        -not $RequiredShares.ContainsKey($_.Name) -and $_.Name -notin $KeepShares -and
        -not (Test-ProtectedShare -Name $_.Name -Path $_.Path -Special (Get-OptionalProperty $_ 'Special' $false))
    })
    if ($ordinary.Count) {
        Add-Result Shares 'Remaining ordinary shares' REVIEW (($ordinary | ForEach-Object { "$($_.Name)=$($_.Path)" }) -join '; ') 'Compare these shares with the README. Windows special shares (ADMIN$, C$, IPC$, USERS$, PRINT$) and the scenario-protected list are excluded from this list.'
    }
}
function Test-LocalRuleMergeDisabled {
    # True when local firewall rules are ignored on this profile. An unreadable
    # profile counts as "merging on", which is the Windows default.
    param([string]$ProfileName)
    $current=''
    try { $current=[string](Get-NetFirewallProfile -Name $ProfileName -PolicyStore ActiveStore -ErrorAction Stop).AllowLocalFirewallRules } catch { $current='' }
    if ($current -eq 'False') { return $true }
    $policyValue=Get-RegistryState "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\${ProfileName}Profile" 'AllowLocalPolicyMerge'
    return $policyValue.Exists -and [int]$policyValue.Value -eq 0
}
function Get-RiskyPortRuleMap {
    # The block rules this script made earlier, by rule name.
    $map=@{}
    foreach ($rule in @(Get-NetFirewallRule -Group 'CYPat V6 risky ports' -PolicyStore PersistentStore -ErrorAction SilentlyContinue)) {
        $filter=$null
        try { $filter=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } catch { $filter=$null }
        $ports=@()
        $protocol=''
        if ($null -ne $filter) { $ports=@($filter.LocalPort); $protocol=[string]$filter.Protocol }
        $map[[string]$rule.Name]=[pscustomobject]@{Enabled=[string]$rule.Enabled;Action=[string]$rule.Action;Direction=[string]$rule.Direction;Ports=$ports;Protocol=$protocol}
    }
    return $map
}
function Test-RiskyPortRuleState {
    # True when the rule for this port matches the plan: an enabled inbound Block
    # rule when the port is blocked, and no enabled rule when it is left open.
    param($Map,[string]$Protocol,[int]$Port,[bool]$Block)
    $name="CYPatV6-RiskyPort-$Protocol-$Port"
    if (-not $Map.ContainsKey($name)) { return (-not $Block) }
    $rule=$Map[$name]
    if (-not $Block) { return ($rule.Enabled -ne 'True') }
    $protocolNumber=if ($Protocol -eq 'TCP') { '6' } else { '17' }
    $portOk=(@($rule.Ports).Count -eq 1 -and [string]@($rule.Ports)[0] -eq [string]$Port)
    return ($rule.Enabled -eq 'True' -and $rule.Action -eq 'Block' -and $rule.Direction -eq 'Inbound' -and $portOk -and (@($Protocol,$protocolNumber) -contains $rule.Protocol))
}
function Set-RiskyPortRuleState {
    # Creates, repairs, or switches off this script's own rule for one port. Only
    # rules in the "CYPat V6 risky ports" group are ever touched.
    param([string]$Protocol,[int]$Port,[string]$Label,[bool]$Block)
    $name="CYPatV6-RiskyPort-$Protocol-$Port"
    $existing=@(Get-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction SilentlyContinue)
    if (-not $Block) {
        if ($existing.Count) { Set-NetFirewallRule -Name $name -PolicyStore PersistentStore -Enabled False -ErrorAction Stop | Out-Null }
        return
    }
    if ($existing.Count) { Remove-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop }
    New-NetFirewallRule -Name $name -DisplayName "CYPat V6 - Block risky inbound $Protocol $Port ($Label)" -Group 'CYPat V6 risky ports' -Description 'Made by the CYPat V6 enforcer. It blocks one risky inbound port that the README does not need. Disable or delete this rule to reopen the port.' -Direction Inbound -Action Block -Protocol $Protocol -LocalPort ([string]$Port) -Profile Any -Enabled True -PolicyStore PersistentStore -ErrorAction Stop | Out-Null
}
function Invoke-RiskyPortBlocking {
    # Blocks only risky inbound traffic. Windows' own setting for traffic that no
    # rule mentions is left as it is, and each risky port gets an inbound Block
    # rule unless the README still needs it:
    #   * a port in -AllowedPorts, or one kept at an earlier port prompt, stays open;
    #   * FTP, SSH, Telnet, SMB, RDP, WinRM, and SNMP follow their service:
    #     -RequiredServices or a Y answer keeps the port open and an N answer blocks
    #     it. With no answer, SMB, RDP, and WinRM stay open (silence never turns a
    #     service off);
    #   * any other risky port that a program is listening on right now is left to
    #     the listening-port questions, which show the program and ask.
    # A block rule this script made earlier is switched off when its port is no
    # longer blocked, so a later Y answer always reopens the port.
    $entries=@(
        @{Protocol='TCP';Ports=@(20,21);Label='FTP';Logical='FTP';Decision='FTPSVC';OpenWhenSilent=$false},
        @{Protocol='TCP';Ports=@(22);Label='SSH';Logical='SSH';Decision='sshd';OpenWhenSilent=$false},
        @{Protocol='TCP';Ports=@(23,2323);Label='Telnet';Logical='';Decision='TlntSvr';OpenWhenSilent=$false},
        @{Protocol='UDP';Ports=@(69);Label='TFTP';Logical='';Decision='';OpenWhenSilent=$false},
        @{Protocol='TCP';Ports=@(512,513,514);Label='rexec, rlogin, and rsh';Logical='';Decision='';OpenWhenSilent=$false},
        @{Protocol='TCP';Ports=@(445);Label='SMB file sharing';Logical='SMB';Decision='LanmanServer';OpenWhenSilent=$true},
        @{Protocol='TCP';Ports=@(3389);Label='Remote Desktop';Logical='RDP';Decision='RDP';OpenWhenSilent=$true},
        @{Protocol='UDP';Ports=@(3389);Label='Remote Desktop';Logical='RDP';Decision='RDP';OpenWhenSilent=$true},
        @{Protocol='TCP';Ports=@(5985,5986);Label='WinRM';Logical='WinRM';Decision='WinRM';OpenWhenSilent=$true},
        @{Protocol='UDP';Ports=@(161,162);Label='SNMP';Logical='';Decision='SNMP';OpenWhenSilent=$false},
        @{Protocol='TCP';Ports=@(5800,5801,5900,5901,5902,5903);Label='VNC remote control';Logical='';Decision='';OpenWhenSilent=$false},
        @{Protocol='TCP';Ports=@(4899);Label='Radmin remote control';Logical='';Decision='';OpenWhenSilent=$false},
        @{Protocol='TCP';Ports=@(5938);Label='TeamViewer remote control';Logical='';Decision='';OpenWhenSilent=$false},
        @{Protocol='TCP';Ports=@(6129);Label='DameWare remote control';Logical='';Decision='';OpenWhenSilent=$false},
        @{Protocol='TCP';Ports=@(1337,4444,5554,6666,6667,12345,12346,20034,27374,31337,54320,54321);Label='well-known backdoor or IRC port';Logical='';Decision='';OpenWhenSilent=$false}
    )
    $listening=@{}
    try { foreach ($connection in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) { $listening["tcp:$([int]$connection.LocalPort)"]=$true } } catch { Write-Verbose "TCP listeners unreadable: $($_.Exception.Message)" }
    try { foreach ($endpoint in @(Get-NetUDPEndpoint -ErrorAction Stop)) { $listening["udp:$([int]$endpoint.LocalPort)"]=$true } } catch { Write-Verbose "UDP endpoints unreadable: $($_.Exception.Message)" }
    $remote=Test-RemoteSession
    $plan=[System.Collections.Generic.List[object]]::new()
    foreach ($entry in $entries) {
        $protocol=[string]$entry.Protocol
        $lowerProtocol=$protocol.ToLowerInvariant()
        $decisionKey=[string]$entry.Decision
        $decision=''
        if ($decisionKey -and $script:ServiceDecisions.Contains($decisionKey)) { $decision=[string]$script:ServiceDecisions[$decisionKey] }
        $required=([string]$entry.Logical) -and $script:RequiredLogical.ContainsKey([string]$entry.Logical)
        foreach ($port in @($entry.Ports)) {
            $key="${lowerProtocol}:$port"
            $why=''
            if ($required) { $why="the README requires $($entry.Label) (-RequiredServices)" }
            elseif ((@($script:AllowedPortList) -contains "$lowerProtocol/$port") -or (@($script:AllowedPortList) -contains [string]$port)) { $why='listed in -AllowedPorts' }
            elseif ($null -ne (Get-PortAcknowledgment $key)) { $why='kept at an earlier port question' }
            elseif ($decision -eq 'Y') { $why="you answered Y to keep $($entry.Label)" }
            elseif ($decision -eq 'N') {
                if ($remote -and @('RDP','WinRM') -contains [string]$entry.Logical) { $why='this session is remote, so blocking it now would cut the connection' }
            }
            elseif ($entry.OpenWhenSilent) { $why="no Y/N answer was given for $($entry.Label), so it stays open" }
            elseif ($listening.ContainsKey($key)) { $why='a program is listening on it now; the listening-port questions show the program and ask' }
            $plan.Add([pscustomobject]@{Protocol=$protocol;Port=[int]$port;Label=[string]$entry.Label;Block=(-not $why);Why=$why})
        }
    }
    $toBlock=@($plan | Where-Object { $_.Block })
    $leftOpen=@($plan | Where-Object { -not $_.Block })
    $blockText=if ($toBlock.Count) { (@($toBlock | ForEach-Object { "$($_.Protocol) $($_.Port) ($($_.Label))" }) -join ', ') } else { 'none' }
    Invoke-Setting Firewall 'Risky inbound ports blocked' {
        $map=Get-RiskyPortRuleMap
        foreach ($item in $plan) {
            if (-not (Test-RiskyPortRuleState $map $item.Protocol $item.Port $item.Block)) { return $false }
        }
        return $true
    } {
        $map=Get-RiskyPortRuleMap
        foreach ($item in $plan) {
            if (-not (Test-RiskyPortRuleState $map $item.Protocol $item.Port $item.Block)) { Set-RiskyPortRuleState $item.Protocol $item.Port $item.Label $item.Block }
        }
    } "Blocked with inbound rules: $blockText. Traffic to every other port is handled by Windows' own setting and the allow rules for required services." 'Add an inbound Block rule for each listed port (group "CYPat V6 risky ports"). Delete or disable one of these rules to reopen its port.'
    if ($leftOpen.Count) {
        $status=if (@($leftOpen | Where-Object { $_.Why -like 'a program is listening*' }).Count) { 'REVIEW' } else { 'PASS' }
        Add-Result Firewall 'Risky ports left open on purpose' $status ((@($leftOpen | ForEach-Object { "$($_.Protocol) $($_.Port) ($($_.Label)): $($_.Why)" }) -join '; ')) 'Answer the listening-port and service questions; a port kept by the README stays open.'
    }
}
function Get-InboundPortRules {
    # Inbound rules from one policy store that name a port explicitly, as
    # Protocol / Low / High / Action / Enabled / Rule. Ranges such as 1024-65535
    # are kept as ranges; rules for Any port, RPC, or ICMP are left out.
    param([string]$Store)
    $rules=@{}
    foreach ($rule in @(Get-NetFirewallRule -PolicyStore $Store -Direction Inbound -ErrorAction SilentlyContinue)) {
        $rules[[string](Get-OptionalProperty $rule 'InstanceID' ([string]$rule.Name))]=$rule
    }
    $list=[System.Collections.Generic.List[object]]::new()
    foreach ($filter in @(Get-NetFirewallPortFilter -PolicyStore $Store -ErrorAction SilentlyContinue)) {
        $id=[string](Get-OptionalProperty $filter 'InstanceID' '')
        if (-not $rules.ContainsKey($id)) { continue }
        $rule=$rules[$id]
        $protocol=([string]$filter.Protocol).ToLowerInvariant()
        if ($protocol -eq '6') { $protocol='tcp' } elseif ($protocol -eq '17') { $protocol='udp' }
        if ($protocol -ne 'tcp' -and $protocol -ne 'udp') { continue }
        foreach ($port in @($filter.LocalPort)) {
            $text=[string]$port
            $low=0
            $high=0
            if ($text -match '^(\d+)$') { $low=[int]$Matches[1]; $high=$low }
            elseif ($text -match '^(\d+)-(\d+)$') { $low=[int]$Matches[1]; $high=[int]$Matches[2] }
            else { continue }
            $list.Add([pscustomobject]@{Protocol=$protocol;Low=$low;High=$high;Action=[string]$rule.Action;Enabled=([string]$rule.Enabled -eq 'True');Name=[string]$rule.Name;DisplayName=[string]$rule.DisplayName;Source=[string](Get-OptionalProperty $rule 'PolicyStoreSourceType' 'Local')})
        }
    }
    return @($list)
}
function Invoke-KeptServicePorts {
    # A Y answer keeps a service's port open, not just its service running. For
    # each service kept by a Y answer or -RequiredServices:
    #   * a Block rule made by someone else that names the port is switched off
    #     (this script's own risky-port rules already follow the answers);
    #   * when no enabled Allow rule names the port, the matching built-in Allow
    #     rules (for example "File and Printer Sharing (SMB-In)") are switched on;
    #   * when no such rule exists and a program is listening on the port, one
    #     Allow rule for that port is added in the "CYPat V6 kept services" group.
    # An N answer is handled by the service question and the risky-port rules.
    # Remote Desktop gets the same check after its own Y path has run.
    $services=@(
        @{Label='Remote Desktop';Decision='RDP';Logical='RDP';Ports=@('tcp:3389')},
        @{Label='SMB file sharing';Decision='LanmanServer';Logical='SMB';Ports=@('tcp:445')},
        @{Label='WinRM';Decision='WinRM';Logical='WinRM';Ports=@('tcp:5985')},
        @{Label='FTP';Decision='FTPSVC';Logical='FTP';Ports=@('tcp:21')},
        @{Label='SMTP';Decision='SMTPSVC';Logical='SMTP';Ports=@('tcp:25')},
        @{Label='IIS web server';Decision='W3SVC';Logical='IIS';Ports=@('tcp:80','tcp:443')},
        @{Label='DNS';Decision='DNS';Logical='DNS';Ports=@('tcp:53','udp:53')},
        @{Label='DHCP';Decision='DHCPServer';Logical='DHCP';Ports=@('udp:67')},
        @{Label='SSH';Decision='sshd';Logical='SSH';Ports=@('tcp:22')},
        @{Label='Telnet';Decision='TlntSvr';Logical='';Ports=@('tcp:23')},
        @{Label='SNMP';Decision='SNMP';Logical='';Ports=@('udp:161')}
    )
    $kept=[System.Collections.Generic.List[object]]::new()
    foreach ($service in $services) {
        $decision=''
        if ($script:ServiceDecisions.Contains([string]$service.Decision)) { $decision=[string]$script:ServiceDecisions[[string]$service.Decision] }
        $required=([string]$service.Logical) -and $script:RequiredLogical.ContainsKey([string]$service.Logical)
        if ($decision -eq 'Y' -or $required) { $kept.Add($service) }
    }
    if (-not $kept.Count) {
        Add-Result Firewall 'Ports of kept services' PASS 'No Y answer or -RequiredServices entry names a service with a network port.' ''
        return
    }
    $listening=@{}
    try { foreach ($connection in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) { $listening["tcp:$([int]$connection.LocalPort)"]=$true } } catch { Write-Verbose "TCP listeners unreadable: $($_.Exception.Message)" }
    try { foreach ($endpoint in @(Get-NetUDPEndpoint -ErrorAction Stop)) { $listening["udp:$([int]$endpoint.LocalPort)"]=$true } } catch { Write-Verbose "UDP endpoints unreadable: $($_.Exception.Message)" }
    $active=@(Get-InboundPortRules 'ActiveStore')
    $local=@(Get-InboundPortRules 'PersistentStore')
    foreach ($service in $kept) {
        foreach ($portKey in @($service.Ports)) {
            $protocol=($portKey -split ':')[0]
            $port=[int](($portKey -split ':')[1])
            $label="$($service.Label) ($($protocol.ToUpperInvariant()) $port)"
            $covering=@($active | Where-Object { $_.Enabled -and $_.Protocol -eq $protocol -and $_.Low -le $port -and $_.High -ge $port })
            $blockers=@($covering | Where-Object { $_.Action -eq 'Block' })
            $allowers=@($covering | Where-Object { $_.Action -eq 'Allow' })
            if (-not $blockers.Count -and $allowers.Count) {
                Add-Result Firewall "Kept port open: $label" PASS "Open through: $(@($allowers | ForEach-Object { $_.DisplayName } | Select-Object -Unique) -join '; ')." ''
                continue
            }
            $builtIn=@($local | Where-Object { $_.Action -eq 'Allow' -and -not $_.Enabled -and $_.Protocol -eq $protocol -and $_.Low -le $port -and $_.High -ge $port })
            # An Allow rule is needed only when something can answer on the port.
            $needAllow=$listening.ContainsKey($portKey) -or $builtIn.Count -gt 0
            if (-not $blockers.Count -and -not $allowers.Count -and -not $needAllow) {
                Add-Result Firewall "Kept port open: $label" SKIPPED 'Nothing listens on this port and no rule exists for it, so there is nothing to open.' ''
                continue
            }
            $planText=@()
            if ($blockers.Count) { $planText+="switch off the Block rule(s) $(@($blockers | ForEach-Object { $_.DisplayName } | Select-Object -Unique) -join '; ')" }
            if (-not $allowers.Count -and $builtIn.Count) { $planText+="switch on the built-in Allow rule(s) $(@($builtIn | ForEach-Object { $_.DisplayName } | Select-Object -Unique) -join '; ')" }
            elseif (-not $allowers.Count -and $needAllow) { $planText+='add one Allow rule for this port in the "CYPat V6 kept services" group' }
            Invoke-Setting Firewall "Kept port open: $label" {
                $now=@(Get-InboundPortRules 'ActiveStore' | Where-Object { $_.Enabled -and $_.Protocol -eq $protocol -and $_.Low -le $port -and $_.High -ge $port })
                $stillBlocked=@($now | Where-Object { $_.Action -eq 'Block' }).Count -gt 0
                $allowed=@($now | Where-Object { $_.Action -eq 'Allow' }).Count -gt 0
                (-not $stillBlocked) -and ($allowed -or -not $needAllow)
            } {
                foreach ($blocker in $blockers) {
                    if ($blocker.Source -eq 'GroupPolicy') { throw "The Block rule '$($blocker.DisplayName)' comes from Group Policy; change it in gpedit.msc." }
                    Set-NetFirewallRule -Name $blocker.Name -PolicyStore PersistentStore -Enabled False -ErrorAction Stop | Out-Null
                }
                if (-not $allowers.Count -and $needAllow) {
                    if ($builtIn.Count) {
                        foreach ($rule in $builtIn) { Set-NetFirewallRule -Name $rule.Name -PolicyStore PersistentStore -Enabled True -ErrorAction Stop | Out-Null }
                    } elseif ($listening.ContainsKey($portKey)) {
                        $ruleName="CYPatV6-Kept-$($protocol.ToUpperInvariant())-$port"
                        if (@(Get-NetFirewallRule -Name $ruleName -PolicyStore PersistentStore -ErrorAction SilentlyContinue).Count) { Remove-NetFirewallRule -Name $ruleName -PolicyStore PersistentStore -ErrorAction Stop }
                        New-NetFirewallRule -Name $ruleName -DisplayName "CYPat V6 - Allow kept $($service.Label) $($protocol.ToUpperInvariant()) $port" -Group 'CYPat V6 kept services' -Description 'Made by the CYPat V6 enforcer because the operator kept this service (Y answer or -RequiredServices).' -Direction Inbound -Action Allow -Protocol $protocol.ToUpperInvariant() -LocalPort ([string]$port) -Profile Any -Enabled True -PolicyStore PersistentStore -ErrorAction Stop | Out-Null
                    }
                }
            } "You kept $($service.Label); to keep its port open the script will $($planText -join ' and ')." 'Open the port in wf.msc: enable the service''s Allow rule and disable any rule that blocks it.'
        }
    }
}
function Invoke-FirewallAudit {
    # The Windows Defender Firewall service must exist, start automatically, and be
    # running before profile policy can be effective.
    $firewallService = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
    if ($null -eq $firewallService) {
        Add-Result Firewall 'MpsSvc service' FAILED 'The Windows Defender Firewall service (MpsSvc) is not installed.' 'Repair the Windows Firewall service before relying on any profile setting.'
    } else {
        Invoke-Setting Firewall 'MpsSvc service' {
            $current = Get-Service -Name MpsSvc -ErrorAction Stop
            (Get-ServiceStartMode $current) -eq 'Automatic' -and $current.Status -eq 'Running'
        } {
            $current = Get-Service -Name MpsSvc -ErrorAction Stop
            if ((Get-ServiceStartMode $current) -ne 'Automatic') { Set-Service -Name MpsSvc -StartupType Automatic -ErrorAction Stop }
            if ($current.Status -ne 'Running') { Start-Service -Name MpsSvc -ErrorAction Stop }
        } "Current=$($firewallService.Status)/$(Get-ServiceStartMode $firewallService)." 'Set the Windows Defender Firewall service to Automatic and start it.'
    }
    # The firewall is always on and enforced; nothing here is a question. Every
    # profile is turned on with outbound Allow, and a local policy value that
    # switched a profile off is corrected. Only risky inbound traffic is blocked
    # (Invoke-RiskyPortBlocking): Windows' own setting for traffic that no rule
    # mentions is reported, not changed. Local rule merging stays at the Windows
    # default (on), because turning it off makes Windows ignore the built-in
    # Remote Desktop, File and Printer Sharing, and IIS allow rules.
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    foreach ($firewallProfile in $profiles) {
        $name = [string]$firewallProfile.Name
        Invoke-Setting Firewall "$name profile enabled" {
            (Get-NetFirewallProfile -Name $name -PolicyStore ActiveStore -ErrorAction Stop).Enabled -eq 'True'
        } {
            Set-NetFirewallProfile -Profile $name -Enabled True -ErrorAction Stop
            # A policy value of EnableFirewall=0 overrides the local setting.
            $policyKey="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\${name}Profile"
            $policyValue=Get-RegistryState $policyKey 'EnableFirewall'
            if ($policyValue.Exists -and [string]$policyValue.Value -ne '1') {
                New-ItemProperty -LiteralPath $policyKey -Name EnableFirewall -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            }
        } "Current=$($firewallProfile.Enabled). Every firewall profile must be on." 'Turn this firewall profile on; existing allow rules are kept. If it turns itself off again, a Group Policy disables it: set gpedit.msc > Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Properties > Firewall state to On, then run gpupdate /force.' -Manual:(Test-RemoteSession)
        $inbound=[string](Get-NetFirewallProfile -Name $name -PolicyStore ActiveStore -ErrorAction Stop).DefaultInboundAction
        if ($inbound -eq 'Block') {
            Add-Result Firewall "$name inbound default" PASS 'Inbound=Block, the Windows default: a connection comes in only when an allow rule matches it (the built-in rules for RDP, file sharing, IIS, and other installed roles), so README services keep working. The script did not change it.' ''
        } else {
            Add-Result Firewall "$name inbound default" REVIEW "Inbound=$inbound. Every port without a block rule accepts connections; the script blocks only the risky ports and leaves this setting as found." 'Windows normally uses Block here, and README services keep working through their allow rules. Change it in wf.msc > Windows Defender Firewall Properties only if the README does not need every port open.'
        }
        Invoke-Setting Firewall "$name outbound default" {
            (Get-NetFirewallProfile -Name $name -PolicyStore ActiveStore -ErrorAction Stop).DefaultOutboundAction -eq 'Allow'
        } {
            Set-NetFirewallProfile -Profile $name -DefaultOutboundAction Allow -ErrorAction Stop
        } "Current=$($firewallProfile.DefaultOutboundAction). Default outbound should be Allow so normal client/server traffic is not broken." 'Set outbound to Allow unless the scenario documents a block-outbound design.'
        if (Test-LocalRuleMergeDisabled $name) {
            Add-Result Firewall "$name local rule merge" REVIEW 'Local rule merging is off on this profile, so the allow rules stored on this machine (Remote Desktop, File and Printer Sharing, IIS) do not apply; only Group Policy rules do.' 'If a README-required service cannot be reached, set Apply local firewall rules back to Yes for this profile in gpedit.msc (Windows Defender Firewall with Advanced Security > Properties > Customize), then run gpupdate /force.'
        } else {
            Add-Result Firewall "$name local rule merge" PASS 'Local rule merging is on (the Windows default), so the built-in allow rules for README-required services keep working.' ''
        }
        Invoke-Setting Firewall "$name notifications" {
            $current=(Get-NetFirewallProfile -Name $name -PolicyStore ActiveStore -ErrorAction Stop).NotifyOnListen
            if ([string]$current -eq 'False') { return $true }
            $policyKey="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\${name}Profile"
            $policyValue=Get-RegistryState $policyKey 'DisableNotifications'
            return $policyValue.Exists -and [int]$policyValue.Value -eq 1
        } {
            try {
                Set-NetFirewallProfile -Profile $name -NotifyOnListen 'False' -ErrorAction Stop
            } catch {
                Write-Verbose "Set-NetFirewallProfile NotifyOnListen failed for ${name}; using the policy registry value. $($_.Exception.Message)"
            }
            $policyKey="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\${name}Profile"
            if (-not (Test-Path -LiteralPath $policyKey)) { New-Item -Path $policyKey -Force -ErrorAction Stop | Out-Null }
            New-ItemProperty -LiteralPath $policyKey -Name DisableNotifications -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        } "Current=$($firewallProfile.NotifyOnListen). Listen notifications should be off." 'Disable firewall listen notifications to prevent blocked-program prompts from training users to allow traffic.'
        Invoke-Setting Firewall "$name blocked-packet logging" {
            $current = Get-NetFirewallProfile -Name $name -PolicyStore ActiveStore -ErrorAction Stop
            $current.LogBlocked -eq 'True' -and [string]$current.LogFileName -and [int]$current.LogMaxSizeKilobytes -ge 4096
        } {
            $logDirectory = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall'
            if (-not (Test-Path -LiteralPath $logDirectory)) { New-Item -Path $logDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null }
            Set-NetFirewallProfile -Profile $name -LogBlocked True -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384 -ErrorAction Stop
        } "Current LogBlocked=$($firewallProfile.LogBlocked); file=$($firewallProfile.LogFileName); size=$($firewallProfile.LogMaxSizeKilobytes) KB." 'Enable blocked-packet logging with a durable log path and at least a 4 MB file.'
    }
    Invoke-Check 'Risky inbound ports' { Invoke-RiskyPortBlocking }
    Invoke-Check 'Ports of kept services' { Invoke-KeptServicePorts }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $script:Inventory.Firewall = @($profiles | ForEach-Object {
        [pscustomobject]@{
            Name=[string]$_.Name; Enabled=[string]$_.Enabled;
            DefaultInboundAction=[string]$_.DefaultInboundAction;
            DefaultOutboundAction=[string]$_.DefaultOutboundAction;
            AllowLocalFirewallRules=[string]$_.AllowLocalFirewallRules;
            NotifyOnListen=[string]$_.NotifyOnListen;
            LogBlocked=[string]$_.LogBlocked; LogFileName=[string]$_.LogFileName;
            LogMaxSizeKilobytes=[string]$_.LogMaxSizeKilobytes
        }
    })
    $offProfiles = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' })
    if (-not $offProfiles.Count) {
        Add-Result Firewall 'Firewall protection' PASS "All $($profiles.Count) firewall profile(s) are on ($(@($profiles | ForEach-Object { "$($_.Name) inbound=$($_.DefaultInboundAction)" }) -join '; '))." ''
    } else {
        Add-Result Firewall 'Firewall protection' REVIEW "Still off: $(@($offProfiles | ForEach-Object { $_.Name }) -join ', ')." 'Turn every profile on. If a profile keeps turning off, a Group Policy controls it: fix it in gpedit.msc and run gpupdate /force.'
    }
    $wide = [System.Collections.Generic.List[string]]::new()
    foreach ($rule in Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop) {
        $port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
        $address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
        $application = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
        $service = $rule | Get-NetFirewallServiceFilter -ErrorAction Stop
        # Port Any alone is normal for many program-specific rules.
        $package=Get-OptionalProperty $application Package 'Any'
        if (@($port.LocalPort) -contains 'Any' -and @($address.RemoteAddress) -contains 'Any' -and @($application.Program) -contains 'Any' -and @($service.Service) -contains 'Any' -and @($package) -contains 'Any') { $wide.Add($rule.DisplayName) }
    }
    if ($wide.Count) { Add-Result Firewall 'Broad inbound rules' REVIEW (($wide | Sort-Object -Unique) -join '; ') 'Review protocol and profile scope and the scenario before narrowing any rule.' }
}
function Initialize-ProcessImageReader {
    # QueryFullProcessImageName needs only PROCESS_QUERY_LIMITED_INFORMATION, which
    # Windows grants to administrators even for protected processes (smss, csrss,
    # wininit, services, and lsass with LSA protection). WMI leaves their path empty.
    if ($null -ne ('CYPatProcessImage.Reader' -as [type])) { return $true }
    if ($script:ProcessImageReaderFailed) { return $false }
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CYPatProcessImage
{
    public static class Reader
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder exeName, ref uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static string GetPath(int processId)
        {
            IntPtr handle = OpenProcess(0x1000, false, processId);
            if (handle == IntPtr.Zero) { return null; }
            try
            {
                StringBuilder buffer = new StringBuilder(1024);
                uint size = (uint)buffer.Capacity;
                if (!QueryFullProcessImageName(handle, 0, buffer, ref size)) { return null; }
                return buffer.ToString(0, (int)size);
            }
            finally
            {
                CloseHandle(handle);
            }
        }
    }
}
'@ -ErrorAction Stop
        return $true
    } catch {
        $script:ProcessImageReaderFailed=$true
        return $false
    }
}
function Get-ProcessImagePath {
    param([int]$ProcessId)
    if ($ProcessId -le 4) { return '' }
    if (-not (Initialize-ProcessImageReader)) { return '' }
    try {
        $imagePath=[string][CYPatProcessImage.Reader]::GetPath($ProcessId)
        if (-not [string]::IsNullOrWhiteSpace($imagePath) -and [IO.Path]::IsPathRooted($imagePath)) { return $imagePath }
    } catch { }
    return ''
}
function Get-ServerInventory {
    $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath)
    # Command lines may contain credentials; deliberately collect paths and PIDs only.
    # Fill the paths WMI hides for protected processes, so later audits judge the
    # real file instead of reporting a missing path as a masquerade.
    foreach ($processEntry in $processes) {
        if (-not [string]::IsNullOrWhiteSpace([string]$processEntry.ExecutablePath)) { continue }
        $resolvedImage=Get-ProcessImagePath ([int]$processEntry.ProcessId)
        if ($resolvedImage) { $processEntry.ExecutablePath=$resolvedImage }
    }
    $script:Inventory.Processes = $processes
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
        $connection=$_; $process=$processes | Where-Object ProcessId -eq $connection.OwningProcess | Select-Object -First 1
        [pscustomobject]@{Address=$connection.LocalAddress;Port=$connection.LocalPort;PID=$connection.OwningProcess;Process=(Get-OptionalProperty $process Name);Path=(Get-OptionalProperty $process ExecutablePath)}
    })
    $script:Inventory.TcpListeners = $listeners
    $script:Inventory.UdpListeners = @(Get-NetUDPEndpoint -ErrorAction Stop | Select-Object LocalAddress,LocalPort,OwningProcess)
    $apps = @(foreach ($key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } | Select-Object DisplayName,DisplayVersion,Publisher,InstallLocation
    })
    $script:Inventory.Applications = @($apps | Sort-Object DisplayName,DisplayVersion -Unique)
    $userPathPattern = '(?i)\\Users\\[^\\]+\\(AppData|Downloads|Desktop)\\|\\(Temp|ProgramData)\\'
    $unusual = @($listeners | Where-Object { $_.Path -match $userPathPattern })
    if ($unusual.Count) { Add-Result Forensics 'Listeners from writable locations' REVIEW (($unusual | ForEach-Object { "$($_.Process) PID=$($_.PID) $($_.Address):$($_.Port) $($_.Path)" }) -join '; ') 'Investigate paths, signatures, and purpose; a writable path is a lead, not proof of malware. Record evidence before remediation.' }
    Add-Result Forensics 'Processes, ports, software' REVIEW "Collected $($processes.Count) processes, $($listeners.Count) TCP listeners, and $($apps.Count) application entries." 'Use -ReportPath or -PassThru to inspect the full inventory. Portable and per-user software need a separate search; answer forensics before deleting anything.'
}
function Get-FileSignatureStatus {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'file not found' }
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $subject = if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { '' }
        if ($signature.Status -eq 'Valid' -and $subject -match 'O=Microsoft Corporation') { return 'Valid Microsoft signature' }
        return "$($signature.Status) ($subject)"
    } catch { return "unavailable: $($_.Exception.Message)" }
}
function Get-BackdoorCandidates {
    $names = @('nc.exe','ncat.exe','netcat.exe','mfc.exe','nc64.exe','cryptcat.exe')
    $listeners = @()
    if ($script:Inventory.Contains('TcpListeners')) { $listeners = @($script:Inventory.TcpListeners) }
    $processes = @()
    if ($script:Inventory.Contains('Processes')) { $processes = @($script:Inventory.Processes) }
    $seen = @{}
    $candidates = [System.Collections.Generic.List[object]]::new()
    foreach ($process in $processes) {
        $processName = [string](Get-OptionalProperty $process Name '')
        if (-not $processName -or ($names -notcontains $processName.ToLowerInvariant())) { continue }
        $path = [string](Get-OptionalProperty $process ExecutablePath '')
        $key = if ($path) { $path.ToLowerInvariant() } else { "pid:$($process.ProcessId)" }
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $ports = @($listeners | Where-Object { $_.PID -eq $process.ProcessId } | ForEach-Object { "$($_.Address):$($_.Port)" })
        $candidates.Add([pscustomobject]@{
            Name=$processName;PID=[int]$process.ProcessId;Path=$path;
            Ports=($ports -join ', ');Signature=(Get-FileSignatureStatus $path)
        })
    }
    foreach ($directory in @((Join-Path $env:SystemRoot 'System32'),(Join-Path $env:SystemRoot 'SysWOW64'))) {
        foreach ($name in $names) {
            $path = Join-Path $directory $name
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
            $key = $path.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $candidates.Add([pscustomobject]@{Name=$name;PID=$null;Path=$path;Ports='';Signature=(Get-FileSignatureStatus $path)})
        }
    }
    return @($candidates)
}
function Invoke-BackdoorDecision {
    $candidates = @(Get-BackdoorCandidates)
    if (-not $candidates.Count) {
        Add-Result Backdoor 'Netcat-family scan' PASS 'No running process and no System32/SysWOW64 file matched the netcat family (nc, ncat, netcat, mfc, nc64, cryptcat).' ''
        return
    }
    $script:Inventory.BackdoorCandidates = $candidates
    foreach ($candidate in $candidates) {
        $label = "$($candidate.Name) PID=$($candidate.PID) path=$($candidate.Path) signature=$($candidate.Signature)"
        if ($candidate.Signature -eq 'Valid Microsoft signature') {
            Add-Result Backdoor 'Netcat-family signed Microsoft candidate' REVIEW $label 'A valid Microsoft-signed binary was not stopped or removed; confirm the scenario before changing it.'
            continue
        }
        if (-not $Apply) {
            Add-Result Backdoor 'Netcat-family candidate' REVIEW "$label; listeners=$($candidate.Ports)" 'Run with -Apply interactively and answer Y to stop and quarantine this file.'
            continue
        }
        if ($WhatIfPreference) {
            Add-Result Backdoor 'Netcat-family candidate' SKIPPED $label 'Change suppressed by -WhatIf.'
            continue
        }
        if ($NonInteractive) {
            Add-Result Backdoor 'Netcat-family candidate' REVIEW $label 'NonInteractive mode will not stop or delete a file. Resolve this manually or run interactively.'
            continue
        }
        $answer = Read-YesNo "Stop and quarantine $($candidate.Name) at $($candidate.Path)?"
        if ($answer -eq 'N') {
            Add-Result Backdoor "Netcat-family/$($candidate.Name)" SKIPPED $label 'Left unchanged by operator decision.'
            Add-Ledger 'BACKDOOR' "File/$($candidate.Path)" 'Operator answered N; no change.'
            continue
        }
        if ($answer -ne 'Y') {
            Add-Result Backdoor "Netcat-family/$($candidate.Name)" REVIEW $label 'No valid Y/N answer was received; the process and file were left unchanged.'
            Add-Ledger 'BACKDOOR' "File/$($candidate.Path)" 'No valid Y/N answer; no change.'
            continue
        }
        if ($WhatIfPreference -or -not $script:CallerCmdlet.ShouldProcess($candidate.Path,'Stop the process, quarantine the file, and delete the original')) {
            Add-Result Backdoor "Netcat-family/$($candidate.Name)" SKIPPED 'Change was not approved by ShouldProcess.' 'Re-run without -WhatIf and answer Y.'
            continue
        }
        try {
            if ([string]::IsNullOrWhiteSpace($script:RunDirectory)) { throw 'The private run folder is unavailable; refusing to delete without a quarantine copy.' }
            $path = [string]$candidate.Path
            if ([string]::IsNullOrWhiteSpace($path)) { throw 'No executable path was returned; stop the process and locate the file manually.' }
            $hash = ''
            if (Test-Path -LiteralPath $path -PathType Leaf) { $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash }
            $stamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
            $quarantineName = "$stamp-$($candidate.Name).quarantine"
            $quarantinePath = Join-Path (Join-Path $script:RunDirectory 'Quarantine') $quarantineName
            if ($candidate.PID) {
                $process = Get-Process -Id $candidate.PID -ErrorAction SilentlyContinue
                if ($process) { Stop-Process -Id $candidate.PID -Force -ErrorAction Stop; Start-Sleep -Milliseconds 300 }
            }
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                Copy-Item -LiteralPath $path -Destination $quarantinePath -Force -ErrorAction Stop
                if ($hash) {
                    $copiedHash = (Get-FileHash -LiteralPath $quarantinePath -Algorithm SHA256 -ErrorAction Stop).Hash
                    if ($copiedHash -ne $hash) { throw 'Quarantine copy hash does not match the original.' }
                }
                Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                if (Test-Path -LiteralPath $path) { throw 'The original file still exists after removal.' }
            }
            $record = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | QUARANTINED | $($candidate.Name) | $path | $hash | PID=$($candidate.PID); listeners=$($candidate.Ports); signature=$($candidate.Signature); copy=$quarantineName"
            Write-PrivateLine 'Quarantine.txt' $record
            Add-Ledger 'QUARANTINE' "File/$path" "SHA256=$hash; copy=$quarantineName"
            Add-Result Backdoor "Netcat-family/$($candidate.Name)" CHANGED "Process stopped (if running); file copied to $quarantinePath, hash verified, and original deleted." ''
            Write-Host "QUARANTINED $path -> $quarantinePath" -ForegroundColor Yellow
        } catch {
            Add-Result Backdoor "Netcat-family/$($candidate.Name)" FAILED $_.Exception.Message 'Stop the process and remove the file manually, or resolve the ACL/ownership problem and re-run.'
        }
    }
}
function Test-UserWritableLocation {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return [bool]($Path -match '(?i)\\Users\\[^\\]+\\(AppData|Downloads|Desktop)\\|\\(Temp|Windows\\Temp|ProgramData|Public|Recycle\.Bin|PerfLogs)\\')
}
function Test-TrustedProgramLocation {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    foreach ($root in @($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)})) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        if ($Path.StartsWith($root.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}
function ConvertFrom-ServiceCommandLine {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
    $text=$CommandLine.Trim()
    if ($text.StartsWith('"')) {
        $end=$text.IndexOf('"',1)
        if ($end -gt 1) { return $text.Substring(1,$end-1) }
        return ''
    }
    if ($text -match '(?i)^(.+?\.(exe|sys|com|bat|cmd|dll))(\s|$)') { return $Matches[1] }
    return ($text -split '\s+',2)[0]
}
function Resolve-ServiceImagePath {
    # Service and driver registry values can use NT prefixes that Test-Path does not
    # resolve directly ('\??\C:\...', '\SystemRoot\System32\...', 'System32\...').
    param([string]$CommandLine)
    $binary=[string](ConvertFrom-ServiceCommandLine $CommandLine)
    if (-not $binary) { return '' }
    if ($binary -match '^\\\?\?\\') { $binary=$binary.Substring(4) }
    if ($binary -match '^(?i)\\SystemRoot\\') { $binary=[IO.Path]::Combine($env:SystemRoot, ($binary -replace '^(?i)\\SystemRoot\\','')) }
    elseif ($binary -match '^(?i)System32\\') { $binary=[IO.Path]::Combine($env:SystemRoot, $binary) }
    return $binary
}
function Get-FileTrust {
    param([string]$Path)
    $result=[pscustomobject]@{Status='file not found';Subject='';Valid=$false;Microsoft=$false}
    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }
    $cacheKey=$Path.ToLowerInvariant()
    if ($script:FileTrustCache.ContainsKey($cacheKey)) { return $script:FileTrustCache[$cacheKey] }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { $script:FileTrustCache[$cacheKey]=$result; return $result }
    try {
        $signature=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $subject=if ($signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { '' }
        $result.Status=[string]$signature.Status
        $result.Subject=$subject
        $result.Valid=($signature.Status -eq 'Valid')
        $result.Microsoft=($signature.Status -eq 'Valid' -and $subject -match 'O=Microsoft Corporation')
    } catch { $result.Status="unavailable: $($_.Exception.Message)" }
    $script:FileTrustCache[$cacheKey]=$result
    return $result
}
function Invoke-ServiceBinaryAudit {
    # Gap 1: a service whose image path is writable, missing, unquoted, or unsigned is
    # the most common persistence location on a competition image.
    $services=@(Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,StartName,PathName)
    $script:Inventory.Services=@($services)
    $outside=[System.Collections.Generic.List[string]]::new()
    $missing=[System.Collections.Generic.List[string]]::new()
    $unquoted=[System.Collections.Generic.List[string]]::new()
    $unsigned=[System.Collections.Generic.List[string]]::new()
    $unowned=[System.Collections.Generic.List[string]]::new()
    $named=[System.Collections.Generic.List[string]]::new()
    foreach ($service in $services) {
        $raw=[string]$service.PathName
        $binary=Resolve-ServiceImagePath $raw
        if (-not $binary) { continue }
        if (-not [IO.Path]::IsPathRooted($binary)) { $missing.Add("$($service.Name) -> $raw"); continue }
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { $missing.Add("$($service.Name) -> $binary"); continue }
        if (Test-UserWritableLocation $binary) { $outside.Add("$($service.Name) [$($service.StartMode)/$($service.State)] -> $binary") }
        elseif (-not (Test-TrustedProgramLocation $binary)) { $outside.Add("$($service.Name) [$($service.StartMode)/$($service.State)] -> $binary") }
        if (-not $raw.TrimStart().StartsWith('"') -and $binary -match '\s') { $unquoted.Add("$($service.Name) -> $binary") }
        $trust=Get-FileTrust $binary
        $provenance=Get-FileProvenance $binary
        if ($provenance.Severity -eq 'High') {
            $unowned.Add("$($service.Name) [$($service.StartMode)/$($service.State)] -> $binary [$([string]$provenance.Class); $($provenance.Reason)]")
            Add-HighSignal 'SERVICE' $binary "$($service.Name) -> $binary [$([string]$provenance.Class)]" 'A service that cannot prove its origin is the strongest persistence signal on the image. Record the hash, then disable only with scenario approval.'
            Add-SuspiciousPath $binary
        } elseif (-not $trust.Valid) {
            $unsigned.Add("$($service.Name) -> $binary [$($trust.Status)]")
        }
        if ($service.StartName -and $service.StartName -notmatch '(?i)^(LocalSystem|NT AUTHORITY\\(SYSTEM|LocalService|NetworkService)|NT SERVICE\\.+|LocalService|NetworkService)$') {
            $named.Add("$($service.Name) as $($service.StartName)")
        }
    }
    if ($outside.Count) {
        Add-Result Services 'Service binaries outside trusted roots' REVIEW ($outside -join '; ') 'A service binary under Users, Temp, ProgramData, Public, or a non-standard root is a persistence lead. Confirm the vendor and the README before stopping or removing anything.'
    } else {
        Add-Result Services 'Service binaries outside trusted roots' PASS "All $($services.Count) services that expose a path resolve under Windows, Program Files, or another protected root." ''
    }
    if ($unowned.Count) {
        Add-Result Services 'Service binaries without a verifiable origin' REVIEW (($unowned | Select-Object -First 10) -join '; ') 'No servicing ownership, no matching installed product, and no signature that matches the claimed publisher. This is how a fake vendor service hides; treat it as evidence, not as housekeeping.'
    }
    if ($missing.Count) { Add-Result Services 'Service binary missing' REVIEW ($missing -join '; ') 'A service points at a file that no longer exists. Confirm whether the service is required; a missing path is common after a rushed image cleanup.' }
    if ($unquoted.Count) { Add-Result Services 'Unquoted service paths' REVIEW ($unquoted -join '; ') 'An unquoted path containing a space can be hijacked by a same-named executable in an earlier directory. Quote the path on a copy of the service and verify the change.' }
    if ($unsigned.Count) { Add-Result Services 'Unsigned service binaries' REVIEW ($unsigned -join '; ') 'Windows cannot verify the publisher, or the file is catalog-signed and reports as NotSigned here. Check with signtool or the file properties before touching the service; some third-party agents are legitimately installed.' }
    if ($named.Count) { Add-Result Services 'Services running as a named account' REVIEW ($named -join '; ') 'Verify each named logon account is required and holds only the rights the service needs.' }
}
function Invoke-ProcessAnomalyAudit {
    # v6: identity is proven, not assumed. v5 trusted any path under Program
    # Files, so an unsigned impostor in a vendor folder was never even looked at
    # (the old gate was: unsigned AND (writable OR outside Program Files)).
    $processes=@()
    if ($script:Inventory.Contains('Processes')) { $processes=@($script:Inventory.Processes) }
    $systemNames=@('smss','csrss','wininit','winlogon','services','lsass','svchost','spoolsv','taskhostw','dwm','conhost','dllhost','lsm','fontdrvhost','sihost','ctfmon','userinit','runtimebroker','searchindexer','wmiprvse','audiodg','explorer')
    $wrongHost=[System.Collections.Generic.List[string]]::new()
    $high=[System.Collections.Generic.List[string]]::new()
    $review=[System.Collections.Generic.List[string]]::new()
    $trusted=0
    $seen=@{}
    $systemPrefix=([string]$env:SystemRoot).TrimEnd('\')+'\'
    $servicePaths=@{}
    if ($script:Inventory.Contains('Services')) {
        foreach ($service in @($script:Inventory.Services)) {
            $image=Resolve-ServiceImagePath ([string](Get-OptionalProperty $service 'PathName' ''))
            if ($image) { $servicePaths[$image.ToLowerInvariant()]=[string](Get-OptionalProperty $service 'Name' '') }
        }
    }
    foreach ($process in $processes) {
        $path=[string](Get-OptionalProperty $process 'ExecutablePath' '')
        $name=[string](Get-OptionalProperty $process 'Name' '')
        if (-not $path -or -not $name) {
            # Get-ServerInventory already asked Windows for the image path of
            # protected processes. A system name that still has no path is only
            # worth a look: a real impostor is not protected and shows its path.
            $unresolvedName=$name
            if ($unresolvedName -and ($systemNames -contains ([IO.Path]::GetFileNameWithoutExtension($unresolvedName).ToLowerInvariant()))) {
                $review.Add("$name PID=$($process.ProcessId) (image path could not be read)")
            }
            continue
        }
        $key=$path.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key]=$true
        $base=[IO.Path]::GetFileNameWithoutExtension($name).ToLowerInvariant()
        $inWindows=$path.StartsWith($systemPrefix,[StringComparison]::OrdinalIgnoreCase)
        if (($systemNames -contains $base) -and -not $inWindows) {
            $wrongHost.Add("$name PID=$($process.ProcessId) $path")
            Add-HighSignal 'PROCESS' $path "$name PID=$($process.ProcessId) runs outside %SystemRoot%: $path" 'A core Windows binary name outside the Windows directory is never legitimate.'
            Add-SuspiciousPath $path
        }
        if (-not $inWindows -and -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $review.Add("$name PID=$($process.ProcessId) $path (file no longer exists)")
            continue
        }
        $provenance=Get-FileProvenance $path
        $parent=[string](Get-OptionalProperty $process 'ParentProcessId' '')
        $label="$name PID=$($process.ProcessId) PPID=$parent $path [$([string]$provenance.Class); $($provenance.Reason)]"
        if ($provenance.Severity -eq 'High') {
            $high.Add($label)
            Add-SuspiciousPath $path
            Add-HighSignal 'PROCESS' $path $label 'Capture the path and hash, confirm the scenario, then stop and quarantine.'
        } elseif ($provenance.Severity -eq 'Review') {
            $review.Add($label)
        } else {
            $trusted++
        }
    }
    if ($wrongHost.Count) {
        Add-Result Processes 'Masquerading system process names' REVIEW ($wrongHost -join '; ') 'A system binary name running from outside the Windows directory is a strong malware signal. Capture the path and hash, then handle it as evidence before stopping it.'
        foreach ($item in $wrongHost) { Add-HighSignal 'MASQUERADE' $item $item 'Verify the image path; a core Windows name outside %SystemRoot% is not legitimate.' }
    } else {
        Add-Result Processes 'Masquerading system process names' PASS 'Every process using a core Windows binary name runs from the Windows directory.' ''
    }
    if ($high.Count) {
        Add-Result Processes 'Unverifiable running processes' REVIEW (($high | Select-Object -First 12) -join '; ') 'These processes cannot prove where they came from: no servicing ownership, no matching installed product, and no signature that matches the publisher they claim. Review each one as evidence before stopping anything.'
    } else {
        Add-Result Processes 'Unverifiable running processes' PASS "$trusted running executable(s) resolve to a servicing-owned component, a Microsoft signature, or the publisher of an installed product." ''
    }
    if ($review.Count) {
        Add-Result Processes 'Running processes with a weak publisher claim' REVIEW (($review | Select-Object -First 10) -join '; ') 'A file can legitimately appear here when it is catalog-signed rather than embedded-signed. Check File Properties > Digital Signatures before treating it as malware.'
    }
}
function Get-StartupFolderPaths {
    $folders=[System.Collections.Generic.List[string]]::new()
    $folders.Add((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'))
    if ($env:APPDATA) { $folders.Add((Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup')) }
    $usersRoot=Join-Path $env:SystemDrive 'Users'
    if (Test-Path -LiteralPath $usersRoot) {
        foreach ($profileFolder in Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue) {
            $folders.Add((Join-Path $profileFolder.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
        }
    }
    return @($folders | Sort-Object -Unique)
}
function Invoke-StartupFolderAudit {
    # Gap 3: startup-folder shortcuts and scripts, machine-wide and per profile.
    $items=[System.Collections.Generic.List[object]]::new()
    foreach ($folder in Get-StartupFolderPaths) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        foreach ($file in Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue) {
            if ($file.Name -ieq 'desktop.ini') { continue }
            $target=$file.FullName
            if ($file.Extension -ieq '.lnk') {
                try {
                    $shell=New-Object -ComObject WScript.Shell
                    $shortcut=$shell.CreateShortcut($file.FullName)
                    if ($shortcut.TargetPath) { $target=[string]$shortcut.TargetPath }
                    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shortcut)
                    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
                } catch { $target=$file.FullName }
            }
            $trust=Get-FileTrust $target
            $provenance=Get-FileProvenance $target
            $items.Add([pscustomobject]@{File=$file.FullName;Target=$target;Signature=$trust.Status;Class=[string]$provenance.Class;Severity=$provenance.Severity;Reason=$provenance.Reason})
            if ($provenance.Severity -eq 'High') { Add-SuspiciousPath $target; Add-HighSignal 'STARTUP' $target "$($file.FullName) -> $target [$([string]$provenance.Class)]" 'Verify the target publisher before the logon that launches it.' }
        }
    }
    if ($items.Count) {
        Add-Result Persistence 'Startup folder items' REVIEW (($items | ForEach-Object { "$($_.File) -> $($_.Target) [$($_.Class); $($_.Signature)]" }) -join '; ') 'A hardened server image normally has no startup-folder items. Confirm each one against the README before removing it.'
    } else {
        Add-Result Persistence 'Startup folder items' PASS 'No startup-folder items were found for the machine or any user profile folder.' ''
    }
}
function Invoke-WmiPersistenceAudit {
    # Gap 4: permanent WMI event subscriptions are a fileless persistence mechanism.
    $filters=@()
    $consumers=@()
    $bindings=@()
    try { $filters=@(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction SilentlyContinue) } catch { $filters=@() }
    foreach ($className in 'CommandLineEventConsumer','ActiveScriptEventConsumer','LogFileEventConsumer','NTEventLogEventConsumer','SMTPEventConsumer') {
        try { $consumers+=@(Get-CimInstance -Namespace 'root\subscription' -ClassName $className -ErrorAction SilentlyContinue) }
        catch { Write-Verbose "WMI consumer class $className could not be read: $($_.Exception.Message)" }
    }
    try { $bindings=@(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction SilentlyContinue) } catch { $bindings=@() }
    $details=[System.Collections.Generic.List[string]]::new()
    foreach ($filter in $filters) { $details.Add("Filter '$($filter.Name)' query=$($filter.Query)") }
    foreach ($consumer in $consumers) {
        $command=[string](Get-OptionalProperty $consumer 'CommandLineTemplate' '')
        $scriptText=[string](Get-OptionalProperty $consumer 'ScriptText' '')
        if (-not $command -and $scriptText) { $command="script text of $($scriptText.Length) characters (not printed)" }
        if (-not $command) { $command=[string](Get-OptionalProperty $consumer 'ExecutablePath' '') }
        $details.Add("$($consumer.CimClass.CimClassName) '$($consumer.Name)' $command")
    }
    foreach ($binding in $bindings) {
        $filterRef=[string](Get-OptionalProperty $binding 'Filter' '')
        $consumerRef=[string](Get-OptionalProperty $binding 'Consumer' '')
        $details.Add("Binding filter=$filterRef consumer=$consumerRef")
    }
    if ($details.Count) {
        Add-Result Persistence 'WMI event subscriptions' REVIEW ($details -join '; ') 'Permanent WMI subscriptions survive reboots and are rarely legitimate on a competition image. Export the filter and consumer definitions before deleting anything.'
    } else {
        Add-Result Persistence 'WMI event subscriptions' PASS 'No permanent WMI event filter, consumer, or filter-to-consumer binding was found.' ''
    }
}
function Invoke-LolbinAudit {
    # Gap 5: argument patterns that turn signed system binaries into execution proxies.
    $patterns=@(
        @{Token='encoded command';Pattern='(?i)\s-(e|ec|en|enc|enco|encod|encode|encodedcommand)\s+[A-Za-z0-9+/=]{24,}'},
        @{Token='download or expression cradle';Pattern='(?i)(invoke-expression|\biex\b|downloadstring|downloadfile|frombase64string)'},
        @{Token='certutil urlcache';Pattern='(?i)certutil(\.exe)?[^|]*?-urlcache'},
        @{Token='bitsadmin transfer';Pattern='(?i)bitsadmin(\.exe)?[^|]*?(/transfer|/addfile)'},
        @{Token='mshta remote content';Pattern='(?i)mshta(\.exe)?[^|]*?(https?://|javascript:|vbscript:)'},
        @{Token='regsvr32 scriptlet';Pattern='(?i)regsvr32(\.exe)?[^|]*?(scrobj\.dll|https?://)'},
        @{Token='wmic process create';Pattern='(?i)wmic(\.exe)?[^|]*?process\s+call\s+create'},
        @{Token='hidden PowerShell window';Pattern='(?i)powershell(\.exe)?[^|]*?-(w|wi|win|wind|windo|window|windows|windowstyle)\s+hidden'},
        @{Token='shadow copy deletion';Pattern='(?i)vssadmin(\.exe)?[^|]*?delete\s+shadows'},
        @{Token='recovery disabled';Pattern='(?i)bcdedit(\.exe)?[^|]*?recoveryenabled\s+no'},
        @{Token='scheduled task creation';Pattern='(?i)schtasks(\.exe)?[^|]*?/create'},
        @{Token='service creation';Pattern='(?i)\bsc(\.exe)?\s+create\s'},
        @{Token='local account creation';Pattern='(?i)\bnet(\.exe)?\s+user\s+\S+\s+/add'}
    )
    $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId,Name,CommandLine,ParentProcessId)
    $hits=[System.Collections.Generic.List[string]]::new()
    $seen=@{}
    foreach ($process in $processes) {
        if ([int]$process.ProcessId -eq $PID) { continue }
        $commandLine=[string]$process.CommandLine
        if ([string]::IsNullOrWhiteSpace($commandLine)) { continue }
        if ($commandLine -match '(?i)/passwordreq:yes|secedit|wevtutil|auditpol') { continue }
        foreach ($entry in $patterns) {
            if ($commandLine -notmatch $entry.Pattern) { continue }
            $key="$($process.ProcessId):$($entry.Token)"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key]=$true
            $hits.Add("$($process.Name) PID=$($process.ProcessId) [$($entry.Token)]")
        }
    }
    if ($hits.Count) {
        Add-Result Persistence 'LOLBin command-line arguments' REVIEW ($hits -join '; ') 'The command text itself is not stored. Capture the full command line manually before acting, and confirm whether an administrator or the image ran it.'
    } else {
        Add-Result Persistence 'LOLBin command-line arguments' PASS "Scanned $($processes.Count) running processes for encoded commands, download cradles, scriptlet execution, and audit-evasion argument patterns." ''
    }
}
function Invoke-DriverBaselineAudit {
    # Gap 6: unsigned drivers and drivers loaded from outside the protected driver roots.
    $drivers=@(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Select-Object Name,DisplayName,State,StartMode,PathName)
    $script:Inventory.Drivers=@($drivers)
    $driverRoot=Join-Path $env:SystemRoot 'System32\drivers'
    $driverPrefix=$driverRoot.TrimEnd('\')+'\'
    $outside=[System.Collections.Generic.List[string]]::new()
    $unsigned=[System.Collections.Generic.List[string]]::new()
    $unowned=[System.Collections.Generic.List[string]]::new()
    $missing=[System.Collections.Generic.List[string]]::new()
    foreach ($driver in $drivers) {
        $binary=Resolve-ServiceImagePath ([string]$driver.PathName)
        if (-not $binary) { continue }
        if (-not [IO.Path]::IsPathRooted($binary)) { $binary=[IO.Path]::Combine($driverRoot, $binary) }
        if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { $missing.Add("$($driver.Name) -> $binary"); continue }
        $trusted=($binary.StartsWith($driverPrefix,[StringComparison]::OrdinalIgnoreCase)) -or ($binary -match '(?i)\\System32\\DriverStore\\')
        if (-not $trusted) { $outside.Add("$($driver.Name) [$($driver.State)/$($driver.StartMode)] -> $binary") }
        $trust=Get-FileTrust $binary
        $provenance=Get-FileProvenance $binary
        if ($provenance.Severity -eq 'High') {
            $unowned.Add("$($driver.Name) [$($driver.State)/$($driver.StartMode)] -> $binary [$([string]$provenance.Class); $($provenance.Reason)]")
            Add-HighSignal 'DRIVER' $binary "$($driver.Name) -> $binary [$([string]$provenance.Class)]" 'A kernel driver with no verifiable origin is the highest-risk persistence. Identify the device before disabling it.'
        } elseif (-not $trust.Valid) {
            $unsigned.Add("$($driver.Name) [$($driver.State)/$($driver.StartMode)] -> $binary [$($trust.Status)]")
        }
    }
    if ($outside.Count) { Add-Result Drivers 'Drivers outside protected driver roots' REVIEW ($outside -join '; ') 'A driver outside System32\drivers or DriverStore is unusual. Confirm the vendor and the device before disabling it; a bad driver change can prevent boot.' }
    else { Add-Result Drivers 'Drivers outside protected driver roots' PASS "All $($drivers.Count) loaded drivers resolve under System32\drivers or the DriverStore." '' }
    if ($unowned.Count) { Add-Result Drivers 'Drivers without a verifiable origin' REVIEW (($unowned | Select-Object -First 8) -join '; ') 'No servicing ownership, no installed product, and no matching signature. Capture the hash and identify the device; disabling the wrong driver can prevent boot.' }
    if ($unsigned.Count) { Add-Result Drivers 'Unsigned drivers' REVIEW ($unsigned -join '; ') 'Unsigned kernel code is a high-risk finding, or the file is catalog-signed and only reports as NotSigned here. Check the file properties or signtool, identify the device, capture the hash, and follow the README before removing the driver.' }
    else { Add-Result Drivers 'Unsigned drivers' PASS 'Every loaded driver has a valid signature.' '' }
    if ($missing.Count) { Add-Result Drivers 'Driver files missing' REVIEW ($missing -join '; ') 'The service entry exists but the driver file does not. Confirm whether a leftover entry can be removed safely.' }
}

function Add-HighSignal {
    param([string]$Kind,[string]$Target,[string]$Detail,[string]$Action='')
    if ([string]::IsNullOrWhiteSpace($Target)) { return }
    foreach ($existing in $script:HighSignal) {
        if ($existing.Kind -eq $Kind -and $existing.Target -eq $Target) { return }
    }
    $script:HighSignal.Add([pscustomobject]@{Kind=$Kind;Target=$Target;Detail=$Detail;Action=$Action})
}
function Add-SuspiciousPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $directory=[IO.Path]::GetDirectoryName($Path)
    if ([string]::IsNullOrWhiteSpace($directory)) { return }
    if (-not $script:SuspiciousPaths.Contains($directory)) { $script:SuspiciousPaths.Add($directory) }
}
function Initialize-CatalogSupport {
    # Compiles the catalog verifier once per run. Any failure disables the check
    # instead of stopping the audit: a missing catalog answer only downgrades a
    # file to REVIEW, it never causes a change.
    if ($null -ne $script:CatalogSupport) { return $script:CatalogSupport }
    $script:CatalogSupport=$false
    if ($null -ne ('CYPatCatalog.Verifier' -as [type])) { $script:CatalogSupport=$true; return $true }
    if ($env:OS -ne 'Windows_NT') { return $false }
    try {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace CYPatCatalog
{
    public static class Verifier
    {
        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 0x1;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        private const uint WTD_UI_NONE = 2;
        private const uint WTD_REVOKE_NONE = 0;
        private const uint WTD_CHOICE_CATALOG = 2;
        private const uint WTD_STATEACTION_VERIFY = 1;
        private const uint WTD_STATEACTION_CLOSE = 2;

        [StructLayout(LayoutKind.Sequential)]
        private struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            public IntPtr pcwszCatalogFilePath;
            public IntPtr pcwszMemberTag;
            public IntPtr pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pCatalog;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptCATAdminAcquireContext2(ref IntPtr phCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

        private static Guid VerifyAction = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        public static bool IsCatalogSigned(string path)
        {
            IntPtr admin = IntPtr.Zero;
            IntPtr catalog = IntPtr.Zero;
            IntPtr file = IntPtr.Zero;
            IntPtr catalogPath = IntPtr.Zero;
            IntPtr memberTag = IntPtr.Zero;
            IntPtr memberPath = IntPtr.Zero;
            IntPtr hashPtr = IntPtr.Zero;
            IntPtr dataPtr = IntPtr.Zero;
            IntPtr catalogPtr = IntPtr.Zero;
            bool signed = false;
            try
            {
                if (!File.Exists(path)) { return false; }
                IntPtr acquired = IntPtr.Zero;
                if (!CryptCATAdminAcquireContext2(ref acquired, IntPtr.Zero, "SHA256", IntPtr.Zero, 0)) { return false; }
                admin = acquired;
                file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (file == IntPtr.Zero || file == new IntPtr(-1)) { return false; }
                uint size = 0;
                CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, null, 0);
                if (size == 0) { return false; }
                byte[] hash = new byte[size];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, hash, 0)) { return false; }
                IntPtr previous = IntPtr.Zero;
                catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, ref previous);
                if (catalog == IntPtr.Zero) { return false; }
                CATALOG_INFO info = new CATALOG_INFO();
                info.cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO));
                if (!CryptCATCatalogInfoFromContext(catalog, ref info, 0)) { return false; }
                if (info.wszCatalogFile == null || info.wszCatalogFile.Length == 0) { return false; }
                catalogPath = Marshal.StringToHGlobalUni(info.wszCatalogFile);
                // Catalogs index their members by the hex string of the file hash.
                StringBuilder tag = new StringBuilder(hash.Length * 2);
                for (int k = 0; k < hash.Length; k++) { tag.Append(hash[k].ToString("X2")); }
                memberTag = Marshal.StringToHGlobalUni(tag.ToString());
                memberPath = Marshal.StringToHGlobalUni(path);
                hashPtr = Marshal.AllocHGlobal(hash.Length);
                Marshal.Copy(hash, 0, hashPtr, hash.Length);

                WINTRUST_CATALOG_INFO cat = new WINTRUST_CATALOG_INFO();
                cat.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO));
                cat.dwCatalogVersion = 0;
                cat.pcwszCatalogFilePath = catalogPath;
                cat.pcwszMemberTag = memberTag;
                cat.pcwszMemberFilePath = memberPath;
                cat.hMemberFile = file;
                cat.pbCalculatedFileHash = hashPtr;
                cat.cbCalculatedFileHash = size;
                cat.pcCatalogContext = catalog;
                cat.hCatAdmin = admin;
                catalogPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)));
                Marshal.StructureToPtr(cat, catalogPtr, false);

                WINTRUST_DATA data = new WINTRUST_DATA();
                data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                data.dwUIChoice = WTD_UI_NONE;
                data.fdwRevocationChecks = WTD_REVOKE_NONE;
                data.dwUnionChoice = WTD_CHOICE_CATALOG;
                data.pCatalog = catalogPtr;
                data.dwStateAction = WTD_STATEACTION_VERIFY;
                data.pSignatureSettings = IntPtr.Zero;
                dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_DATA)));
                Marshal.StructureToPtr(data, dataPtr, false);

                uint result = WinVerifyTrust(IntPtr.Zero, VerifyAction, dataPtr);
                signed = (result == 0);

                data.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(data, dataPtr, false);
                WinVerifyTrust(IntPtr.Zero, VerifyAction, dataPtr);
                return signed;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (dataPtr != IntPtr.Zero) { Marshal.FreeHGlobal(dataPtr); }
                if (catalogPtr != IntPtr.Zero) { Marshal.FreeHGlobal(catalogPtr); }
                if (hashPtr != IntPtr.Zero) { Marshal.FreeHGlobal(hashPtr); }
                if (memberPath != IntPtr.Zero) { Marshal.FreeHGlobal(memberPath); }
                if (memberTag != IntPtr.Zero) { Marshal.FreeHGlobal(memberTag); }
                if (catalogPath != IntPtr.Zero) { Marshal.FreeHGlobal(catalogPath); }
                if (file != IntPtr.Zero && file != new IntPtr(-1)) { CloseHandle(file); }
                if (catalog != IntPtr.Zero) { CryptCATAdminReleaseCatalogContext(admin, catalog, 0); }
                if (admin != IntPtr.Zero) { CryptCATAdminReleaseContext(admin, 0); }
            }
        }
    }
}
'@ -ErrorAction Stop
        $script:CatalogSupport=$true
    } catch {
        $script:CatalogSupport=$false
    }
    return $script:CatalogSupport
}
function Test-CatalogSignature {
    # Answers "is this file covered by a signed Windows catalog?". Inbox and
    # MSI-installed files are usually catalog-signed instead of embedded-signed,
    # and Get-AuthenticodeSignature only reads the embedded signature. Every
    # failure returns $false: the file then lands in REVIEW, never in a change.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    if (-not (Initialize-CatalogSupport)) { return $false }
    try { return [CYPatCatalog.Verifier]::IsCatalogSigned($Path) } catch { return $false }
}
function Test-WinSxSComponent {
    # Servicing-owned files carry a hardlink record under \Windows\WinSxS.
    # Returns $true, $false, or $null when the question cannot be answered.
    # Only files under %SystemRoot% can be CBS components, so the fsutil spawn is
    # skipped for everything else. That keeps a vendor-folder sweep affordable.
    param([string]$Path)
    $systemRoot=[string]$env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($systemRoot)) { return $null }
    if (-not $Path.StartsWith($systemRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { return $false }
    try {
        $lines=@(& fsutil.exe hardlink list $Path 2>$null)
        if ($LASTEXITCODE -ne 0 -or -not $lines) { return $null }
        foreach ($line in $lines) { if ([string]$line -match '(?i)\\WinSxS\\') { return $true } }
        return $false
    } catch { return $null }
}
function Get-InstalledProductMap {
    # Folder -> owning product, from the only registry that software actually
    # registers itself in. Used to answer "did a real installer put this here".
    if ($null -ne $script:InstalledProductMap) { return $script:InstalledProductMap }
    $map=@{}
    $roots=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            try { $item=Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop } catch { continue }
            $location=[string](Get-OptionalProperty $item 'InstallLocation' '')
            if ([string]::IsNullOrWhiteSpace($location)) { continue }
            $location=$location.Trim().Trim('"').TrimEnd('\')
            if ($location.Length -lt 4 -or -not [IO.Path]::IsPathRooted($location)) { continue }
            $map[$location.ToLowerInvariant()]=[pscustomobject]@{
                Name=[string](Get-OptionalProperty $item 'DisplayName' '')
                Publisher=[string](Get-OptionalProperty $item 'Publisher' '')
                Location=$location
                Key=[string]$key.PSChildName
            }
        }
    }
    $script:InstalledProductMap=$map
    return $map
}
function Find-InstalledProductOwner {
    param([string]$Path)
    $map=Get-InstalledProductMap
    if ($map.Count -eq 0) { return $null }
    $directory=[IO.Path]::GetDirectoryName($Path)
    $guard=0
    while (-not [string]::IsNullOrWhiteSpace($directory) -and $directory.Length -gt 3 -and $guard -lt 8) {
        $key=$directory.TrimEnd('\').ToLowerInvariant()
        if ($map.ContainsKey($key)) { return $map[$key] }
        $parent=[IO.Path]::GetDirectoryName($directory)
        if ($parent -eq $directory) { break }
        $directory=$parent
        $guard++
    }
    return $null
}
function Get-FolderSignerProfile {
    # The dominant publisher among a file's peers. A genuine vendor folder is
    # monochrome; a dropped impostor stands out without needing a vendor list.
    param([string]$Path)
    $directory=[IO.Path]::GetDirectoryName($Path)
    if ([string]::IsNullOrWhiteSpace($directory)) { return '' }
    $cacheKey=$directory.ToLowerInvariant()
    if ($script:FolderSignerCache.ContainsKey($cacheKey)) { return $script:FolderSignerCache[$cacheKey] }
    $counts=@{}
    try {
        foreach ($pattern in @('*.exe','*.dll')) {
            foreach ($file in @(Get-ChildItem -LiteralPath $directory -File -Filter $pattern -ErrorAction Stop | Select-Object -First 25)) {
                $trust=Get-FileTrust $file.FullName
                if (-not $trust.Valid -or [string]::IsNullOrWhiteSpace($trust.Subject)) { continue }
                $subject=[string]$trust.Subject
                if ($counts.ContainsKey($subject)) { $counts[$subject]=$counts[$subject]+1 } else { $counts[$subject]=1 }
            }
        }
    } catch { }
    $best=''
    $bestCount=0
    foreach ($subject in @($counts.Keys)) {
        if ($counts[$subject] -gt $bestCount) { $best=$subject; $bestCount=$counts[$subject] }
    }
    $script:FolderSignerCache[$cacheKey]=$best
    return $best
}
function ConvertTo-ExecutablePath {
    # Turns a command line into the file it will execute. Deliberately returns a
    # path only: command text can contain credentials and is never printed.
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return '' }
    $text=[Environment]::ExpandEnvironmentVariables($Command.Trim())
    $candidate=''
    if ($text.StartsWith('"')) {
        $end=$text.IndexOf('"',1)
        if ($end -gt 1) { $candidate=$text.Substring(1,$end-1) }
    } elseif ($text -match '(?i)^(.+?\.(exe|cmd|bat|com|scr|pif|vbs|js|cpl))(\s|,|$)') {
        $candidate=$Matches[1]
    } else {
        $candidate=($text -split '\s+',2)[0]
    }
    $candidate=$candidate.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($candidate)) { return '' }
    if ($candidate -match '(?i)^system32\\') { $candidate=[IO.Path]::Combine($env:SystemRoot,$candidate) }
    if (-not [IO.Path]::IsPathRooted($candidate)) { return '' }
    return $candidate
}
function Test-ProgramFilesPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    foreach ($programRoot in @($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramW6432)) {
        if ([string]::IsNullOrWhiteSpace($programRoot)) { continue }
        if ($Path.StartsWith(([string]$programRoot).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}
function Test-UninstallerFileName {
    # Installers commonly leave their uninstaller unsigned (unins000.exe,
    # uninstall.exe, "Uninstall <product>.exe").
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ([IO.Path]::GetFileName($Path) -match '(?i)^(unins\d+|uninst|uninstall|uninstaller)([ _.-].*)?\.exe$')
}
function Get-VendorTokens {
    # Distinctive words of a vendor or product name: no legal suffixes and no
    # generic words, so "Notepad++" or "NVIDIA" survive and "Corporation" does not.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $stop=@('the','and','for','inc','corp','corporation','company','ltd','limited','llc','gmbh','plc','pty','software','technologies','technology','systems','system','foundation','project','community','development','developers','developer','team','group','labs','international','holdings','solutions','services','networks','communications','studio','studios','digital','media','open','source','www','com','org','net','http','https','windows','edition','version','bit','x64','x86')
    $tokens=[System.Collections.Generic.List[string]]::new()
    foreach ($token in [regex]::Split($Text.ToLowerInvariant(),'[^a-z0-9+]+')) {
        if ($token.Length -lt 3) { continue }
        if ($stop -contains $token) { continue }
        if (-not $tokens.Contains($token)) { $tokens.Add($token) }
    }
    return @($tokens)
}
function Get-SignerNames {
    # The CN and O values of a certificate subject, without the location parts.
    param([string]$Subject)
    if ([string]::IsNullOrWhiteSpace($Subject)) { return @() }
    $names=[System.Collections.Generic.List[string]]::new()
    foreach ($match in [regex]::Matches($Subject,'(?i)(?:^|,)\s*(CN|O)=("(?:[^"]|"")*"|[^,]*)')) {
        $value=$match.Groups[2].Value.Trim().Trim('"')
        if ($value -and -not $names.Contains($value)) { $names.Add($value) }
    }
    return @($names)
}
function Test-VendorClaimMatchesSigner {
    # True when the vendor or product the file names shares a distinctive word with
    # the certificate that signed it, in either direction. Notepad++ is signed as
    # "Notepad++" while its CompanyName is the author's name, so the product name
    # counts too. Nothing to compare means no mismatch.
    param([string]$CompanyName,[string]$ProductName,[string]$Signer)
    $signerNames=@(Get-SignerNames $Signer)
    if (-not $signerNames.Count) { return $true }
    $signerText=($signerNames -join ' ').ToLowerInvariant()
    $claimText="$CompanyName $ProductName".ToLowerInvariant()
    $claimTokens=@(Get-VendorTokens "$CompanyName $ProductName")
    if (-not $claimTokens.Count) { return $true }
    foreach ($token in $claimTokens) {
        if ($signerText -match ('(^|[^a-z0-9])'+[regex]::Escape($token)+'([^a-z0-9]|$)')) { return $true }
    }
    foreach ($token in @(Get-VendorTokens ($signerNames -join ' '))) {
        if ($claimText -match ('(^|[^a-z0-9])'+[regex]::Escape($token)+'([^a-z0-9]|$)')) { return $true }
    }
    return $false
}
function Get-FileProvenance {
    param([string]$Path)
    $result=[pscustomobject]@{
        Path='';Class='Missing';Reason='';Severity='';Valid=$false;Signer='';
        CompanyName='';ProductName='';FileDescription='';OriginalFilename='';
        Renamed=$false;WinSxS=$null;Product=$null;VendorMismatch=$false;Microsoft=$false;Catalog=$false
    }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }
    $result.Path=$Path
    $cacheKey=$Path.ToLowerInvariant()
    if ($script:ProvenanceCache.ContainsKey($cacheKey)) { return $script:ProvenanceCache[$cacheKey] }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { $script:ProvenanceCache[$cacheKey]=$result; return $result }
    try {
        $version=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        $result.CompanyName=[string]$version.CompanyName
        $result.ProductName=[string]$version.ProductName
        $result.FileDescription=[string]$version.FileDescription
        $result.OriginalFilename=[string]$version.OriginalFilename
    } catch { }
    if (-not [string]::IsNullOrWhiteSpace($result.OriginalFilename)) {
        # Compare base names only: Microsoft binaries name their resource file
        # (NOTEPAD.EXE.MUI) and .NET app hosts name their DLL (pwsh.dll for
        # pwsh.exe); neither is a rename.
        $original=($result.OriginalFilename.Trim() -replace '(?i)\.mui$','')
        $result.Renamed=([IO.Path]::GetFileNameWithoutExtension($original) -ine [IO.Path]::GetFileNameWithoutExtension($Path))
    }
    $trust=Get-FileTrust $Path
    $result.Valid=[bool]$trust.Valid
    $result.Signer=[string]$trust.Subject
    $result.Microsoft=[bool]$trust.Microsoft
    $result.WinSxS=Test-WinSxSComponent $Path
    $result.Product=Find-InstalledProductOwner $Path
    if (-not $result.Valid -and $result.WinSxS -ne $true) {
        # A catalog signature is how inbox and MSI-installed files are signed
        # without an embedded signature. The probe is expensive; it is skipped for
        # very large files and cached per path.
        $fileSize=0
        try { $fileSize=[long](Get-Item -LiteralPath $Path -ErrorAction Stop).Length } catch { $fileSize=0 }
        if ($fileSize -gt 0 -and $fileSize -le 134217728) {
            if (Test-CatalogSignature $Path) { $result.Catalog=$true }
        }
    }
    # A valid third-party signature whose signer shares no name with the vendor the
    # file claims. Microsoft-verified files (WinSxS component, Microsoft or WHQL
    # signature) are exempt: inbox and WHQL drivers name their hardware vendor but
    # are signed by Microsoft, and Sysinternals tools are signed by Microsoft.
    $microsoftVerified=($result.WinSxS -eq $true) -or $result.Microsoft
    if ($result.Valid -and -not $microsoftVerified -and -not [string]::IsNullOrWhiteSpace($result.CompanyName)) {
        $result.VendorMismatch=-not (Test-VendorClaimMatchesSigner $result.CompanyName $result.ProductName $result.Signer)
    }
    if ($result.WinSxS -eq $true) {
        $result.Class='OS component'; $result.Reason='Hardlinked into WinSxS; Windows servicing owns this file.'
    } elseif ($result.Valid -and $result.Microsoft) {
        $result.Class='Microsoft signed'; $result.Reason='Valid Microsoft Authenticode signature.'
    } elseif ($result.Catalog -and $null -ne $result.Product) {
        $result.Class='Catalog-signed product'
        $result.Reason="Covered by a Windows catalog signature and installed by '$($result.Product.Name)'."
    } elseif ($result.Catalog) {
        $result.Class='Catalog signed'
        $result.Reason='Covered by a Windows catalog signature with no matching installed product.'
        $result.Severity='Review'
    } elseif ($result.Valid -and $null -ne $result.Product) {
        $result.Class='Installed product'; $result.Reason="Signed by the publisher registered for '$($result.Product.Name)'."
    } elseif ($result.Valid) {
        $result.Class='Unregistered signed'; $result.Reason='Valid third-party signature with no matching installed product.'; $result.Severity='Review'
    } elseif (-not [string]::IsNullOrWhiteSpace($result.CompanyName)) {
        $result.Class='Impersonation candidate'
        $result.Reason="Claims '$($result.CompanyName)' without a valid signature."
        $result.Severity='Review'
    } elseif (-not [string]::IsNullOrWhiteSpace($result.FileDescription) -or -not [string]::IsNullOrWhiteSpace($result.ProductName)) {
        $result.Class='Unregistered unsigned'
        $result.Reason='Version resource present, no embedded signature, no installed product.'
        $result.Severity='Review'
    } else {
        $result.Class='Unknown'
        $result.Reason='No signature, no version resource, no installed product.'
        $result.Severity='Review'
    }
    # A Microsoft-signed file renamed and copied out of Windows is a common
    # disguise (cmd.exe or powershell.exe saved under a vendor name). Noted, not
    # escalated, because portable admin tools can look the same.
    if ($result.Renamed -and @('Microsoft signed','Catalog signed') -contains $result.Class -and $null -eq $result.Product) {
        $systemPrefix=([string]$env:SystemRoot).TrimEnd('\')+'\'
        if (-not $Path.StartsWith($systemPrefix,[StringComparison]::OrdinalIgnoreCase)) {
            $result.Class='Renamed Windows binary'
            $result.Reason="A Microsoft-signed file renamed from '$($result.OriginalFilename)' and kept outside Windows. Renamed copies of cmd.exe, powershell.exe, and similar tools are a common disguise."
            $result.Severity='Review'
        }
    }
    # Escalation for files with no valid signature. A file is High only when
    # something about where it sits contradicts it: signed neighbours, a rename, a
    # program folder where real builds are signed and registered, or a user-writable
    # folder. A product that is unsigned throughout (7-Zip, for example) and an
    # installer's leftover uninstaller stay at Review.
    $unsignedClasses=@('Impersonation candidate','Unregistered unsigned','Unknown')
    if ($unsignedClasses -contains $result.Class) {
        $folderSigner=Get-FolderSignerProfile $Path
        $hasSignedPeers=-not [string]::IsNullOrWhiteSpace($folderSigner)
        $isUninstaller=Test-UninstallerFileName $Path
        $inProgramFiles=Test-ProgramFilesPath $Path
        $inProgramData=(-not [string]::IsNullOrWhiteSpace($env:ProgramData)) -and $Path.StartsWith(([string]$env:ProgramData).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)
        $productName=if ($null -ne $result.Product) { [string]$result.Product.Name } else { '' }
        if ($result.Class -eq 'Impersonation candidate' -and $result.Renamed) {
            $result.Class='Impersonation'
            $result.Reason="Claims '$($result.CompanyName)', carries no valid signature, and was renamed from '$($result.OriginalFilename)'."
            $result.Severity='High'
        } elseif ($isUninstaller -and ($null -ne $result.Product -or $inProgramFiles)) {
            $result.Class='Unsigned uninstaller'
            if ($productName) { $result.Reason="Unsigned uninstaller in the install folder of '$productName'. Installers often leave these unsigned." }
            else { $result.Reason='Unsigned uninstaller under Program Files. Installers often leave these unsigned.' }
            $result.Severity='Review'
        } elseif ($hasSignedPeers -and ($result.Class -eq 'Impersonation candidate' -or $null -ne $result.Product)) {
            $result.Class='Impersonation'
            $claim=if ($result.CompanyName) { " and claims '$($result.CompanyName)'" } else { '' }
            $where=if ($productName) { " in the install folder of '$productName'" } else { ' in this folder' }
            $result.Reason="The other files$where are signed by '$folderSigner', but this one has no valid signature$claim."
            $result.Severity='High'
        } elseif ($null -ne $result.Product) {
            $result.Class='Unsigned product'
            $result.Reason="Part of '$productName', which ships unsigned files. Nothing in this folder is signed, so this is how the product was built rather than proof of tampering."
            $result.Severity='Review'
        } elseif (($inProgramFiles -or $inProgramData) -and $result.Class -eq 'Impersonation candidate') {
            $result.Class='Impersonation'
            $result.Reason="Claims '$($result.CompanyName)' with no valid signature, and sits under a program folder where a real vendor build would be signed and registered."
            $result.Severity='High'
        } elseif ($inProgramFiles -and $result.Class -eq 'Unknown') {
            $result.Class='Unknown executable in Program Files'
            $result.Reason='No signature, no version resource, and no installed product, yet it sits under Program Files.'
            $result.Severity='High'
        } elseif ($result.Class -eq 'Impersonation candidate' -and (Test-UserWritableLocation $Path)) {
            $result.Class='Impersonation'
            $result.Reason="Claims '$($result.CompanyName)' with no valid signature, from a user-writable folder."
            $result.Severity='High'
        }
    }
    if ($result.VendorMismatch) {
        # Escalate only with a second signal; a lone name difference is common for
        # open-source projects signed by a person or foundation.
        $folderSigner=Get-FolderSignerProfile $Path
        $peerSignerDiffers=(-not [string]::IsNullOrWhiteSpace($folderSigner)) -and ($folderSigner -ne $result.Signer)
        if ($result.Renamed -or (Test-UserWritableLocation $Path) -or $peerSignerDiffers -or $null -eq $result.Product) {
            $result.Class='Publisher mismatch'
            $result.Reason="Claims '$($result.CompanyName)' but the signature belongs to '$($result.Signer)'."
            if ($peerSignerDiffers) { $result.Reason+=" The other files in this folder are signed by '$folderSigner'." }
            elseif ($result.Renamed) { $result.Reason+=" It was also renamed from '$($result.OriginalFilename)'." }
            elseif ($null -eq $result.Product) { $result.Reason+=' No installed product owns this folder.' }
            else { $result.Reason+=' It sits in a user-writable folder.' }
            $result.Severity='High'
        } else {
            $result.Reason+=" The version resource names '$($result.CompanyName)' and the signer is '$($result.Signer)', but the folder and its installed product agree with the signer, so this is noted only."
        }
    }
    $script:ProvenanceCache[$cacheKey]=$result
    return $result
}
function Format-Provenance {
    param($Provenance)
    if ($null -eq $Provenance) { return 'unknown provenance' }
    $detail=[string]$Provenance.Class
    if ($Provenance.Signer) { $detail+="; signer=$($Provenance.Signer)" } elseif ($Provenance.CompanyName) { $detail+="; claims=$($Provenance.CompanyName)" }
    if ($Provenance.Reason) { $detail+="; $($Provenance.Reason)" }
    return $detail
}
#endregion
#region v6 autostart, application, and malware-scan audits
function Get-RunKeyEntries {
    $entries=[System.Collections.Generic.List[object]]::new()
    $paths=@(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    foreach ($path in $paths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try { $item=Get-Item -LiteralPath $path -ErrorAction Stop } catch { continue }
        foreach ($valueName in @($item.GetValueNames())) {
            if ([string]::IsNullOrWhiteSpace($valueName)) { continue }
            $command=[string]$item.GetValue($valueName)
            $entries.Add([pscustomobject]@{Source=$path;Name=$valueName;Target=(ConvertTo-ExecutablePath $command)})
        }
    }
    return @($entries)
}
function Invoke-RunKeyAudit {
    # v5 printed only the value name here and never resolved the command, so a
    # vendor-named autorun pointing at an unsigned drop looked like housekeeping.
    $entries=@(Get-RunKeyEntries)
    $script:Inventory.RunEntries=@($entries | Select-Object Source,Name,Target)
    if (-not $entries.Count) {
        Add-Result Persistence 'Autorun registry entries' PASS 'No Run, RunOnce, or Explorer\Run value exists in HKLM or HKCU for this machine or the current user.' ''
        return
    }
    $review=[System.Collections.Generic.List[string]]::new()
    $clean=0
    foreach ($entry in $entries) {
        $label="$($entry.Name) [$($entry.Source)]"
        if ([string]::IsNullOrWhiteSpace($entry.Target)) {
            Add-Result Persistence "Run entry $($entry.Name)" REVIEW "Source=$($entry.Source); the command does not resolve to an absolute file path." 'Inspect the raw command in Registry Editor, then verify its publisher before allowing it to run.'
            continue
        }
        $provenance=Get-FileProvenance $entry.Target
        $detail="$($entry.Source) -> $($entry.Target) [$([string]$provenance.Class)] $($provenance.Reason)"
        if ($provenance.Severity -eq 'High') {
            Add-Result Persistence "Run entry $($entry.Name)" REVIEW $detail 'A value that starts automatically has no verified origin. Capture the path and hash, resolve the scenario, then disable it through its owning product rather than deleting the file.'
            Add-HighSignal 'AUTORUN' $entry.Target $detail 'Disable this autorun after recording evidence.'
            Add-SuspiciousPath $entry.Target
        } elseif ($provenance.Severity -eq 'Review') {
            $review.Add("$label -> $($entry.Target) [$([string]$provenance.Class); $($provenance.Reason)]")
        } else {
            $clean++
        }
    }
    if ($review.Count) {
        Add-Result Persistence 'Autorun entries without a verified publisher' REVIEW (($review | Select-Object -First 12) -join '; ') 'Each of these runs at logon or boot and is either unsigned or not covered by an installed product. Confirm the vendor for each before the scenario deadline; catalog-signed software can appear here without an embedded signature.'
    }
    if ($clean -gt 0 -and -not $review.Count) {
        Add-Result Persistence 'Autorun registry entries' PASS "$clean entr$(if ($clean -eq 1) { 'y' } else { 'ies' }) resolve to a signature-verified publisher or a servicing-owned component." ''
    }
}
function Invoke-ApplicationProvenanceAudit {
    # v5 collected Publisher and InstallLocation into the inventory and never
    # evaluated them. An install location with no signed binary, or a signature
    # that does not match the registered publisher, is the software analogue of
    # a renamed process.
    $apps=@()
    if ($script:Inventory.Contains('Applications')) { $apps=@($script:Inventory.Applications) }
    $missing=[System.Collections.Generic.List[string]]::new()
    $writable=[System.Collections.Generic.List[string]]::new()
    $mismatch=[System.Collections.Generic.List[string]]::new()
    $high=[System.Collections.Generic.List[string]]::new()
    foreach ($app in $apps) {
        $name=[string](Get-OptionalProperty $app 'DisplayName' '')
        $publisher=[string](Get-OptionalProperty $app 'Publisher' '')
        $location=[string](Get-OptionalProperty $app 'InstallLocation' '')
        if ([string]::IsNullOrWhiteSpace($location)) { continue }
        $location=$location.Trim().Trim('"').TrimEnd('\')
        if ($location.Length -lt 4 -or -not [IO.Path]::IsPathRooted($location)) { continue }
        if (-not (Test-Path -LiteralPath $location)) { $missing.Add("$name -> $location"); continue }
        if (Test-UserWritableLocation $location) { $writable.Add("$name -> $location"); continue }
        $probe=@()
        try { $probe=@(Get-ChildItem -LiteralPath $location -File -Filter '*.exe' -ErrorAction Stop | Select-Object -First 1) } catch { }
        if (-not $probe.Count) {
            try {
                foreach ($child in @(Get-ChildItem -LiteralPath $location -Directory -ErrorAction SilentlyContinue | Select-Object -First 6)) {
                    $probe=@(Get-ChildItem -LiteralPath $child.FullName -File -Filter '*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1)
                    if ($probe.Count) { break }
                }
            } catch { }
        }
        if (-not $probe.Count) { continue }
        $binary=$probe[0].FullName
        $provenance=Get-FileProvenance $binary
        if ($provenance.Severity -eq 'High') {
            $high.Add("$name -> $binary [$([string]$provenance.Class)] $($provenance.Reason)")
            Add-SuspiciousPath $binary
            continue
        }
        if (-not [string]::IsNullOrWhiteSpace($publisher) -and $provenance.Valid -and $provenance.Signer) {
            $publisherToken=($publisher -split '[\s,]+')[0]
            if ($publisherToken.Length -ge 4 -and $provenance.Signer -notmatch [regex]::Escape($publisherToken)) {
                $mismatch.Add("$name registered as '$publisher' but $binary is signed by '$($provenance.Signer)'")
            }
        }
    }
    if ($high.Count) {
        Add-Result Software 'Registered software with an unverified binary' REVIEW (($high | Select-Object -First 10) -join '; ') 'An installed product whose own executable cannot prove its publisher is either a repackaged installer or an impostor entry. Confirm against the README before removing the package.'
        foreach ($item in $high) { Add-HighSignal 'SOFTWARE' $item $item 'Verify the package origin; remove only with scenario approval.' }
    }
    if ($missing.Count) {
        Add-Result Software 'Install location missing' REVIEW (($missing | Select-Object -First 10) -join '; ') 'A registered product points at a folder that no longer exists. This is usually rushed cleanup, but it is also how a payload is hidden after its folder is deleted.'
    }
    if ($writable.Count) {
        Add-Result Software 'Software installed in a writable root' REVIEW (($writable | Select-Object -First 10) -join '; ') 'Per-user or temporary install roots are not patched by the product updater and are trivial to replace. Confirm each one belongs to the scenario.'
    }
    if ($mismatch.Count) {
        Add-Result Software 'Publisher and signature disagree' REVIEW (($mismatch | Select-Object -First 10) -join '; ') 'The registry publisher is a claim, not proof. Prefer the signature when deciding whether the software is genuine.'
    }
    # Unnamed uninstall entries are invisible in Programs and Features but still
    # install a product code and an uninstall command.
    $unnamed=[System.Collections.Generic.List[string]]::new()
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            try { $item=Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop } catch { continue }
            $display=[string](Get-OptionalProperty $item 'DisplayName' '')
            $uninstall=[string](Get-OptionalProperty $item 'UninstallString' '')
            if (-not [string]::IsNullOrWhiteSpace($display)) { continue }
            if ([string]::IsNullOrWhiteSpace($uninstall)) { continue }
            $unnamed.Add("$($key.PSChildName) -> $uninstall")
        }
    }
    if ($unnamed.Count) {
        Add-Result Software 'Uninstall entries with no display name' REVIEW (($unnamed | Select-Object -First 10) -join '; ') 'A hidden uninstall entry still runs a command. Resolve each string, check its signature, and confirm the product exists in the README.'
    }
    if (-not $high.Count -and -not $missing.Count -and -not $writable.Count -and -not $mismatch.Count -and -not $unnamed.Count) {
        Add-Result Software 'Installed software provenance' PASS "$($apps.Count) registered application entries resolve to an existing install root with a consistent publisher." ''
    }
}
function Invoke-MalwareScan {
    # v5 read only active Get-MpThreat detections. Detection history already
    # records what Defender caught and where, which is forensic evidence even
    # after remediation.
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        Add-Result Threats 'Defender status' SKIPPED 'The Defender cmdlets are unavailable.' 'Repair the Defender platform before relying on scan evidence.'
        return
    }
    try { $status=Get-MpComputerStatus -ErrorAction Stop } catch {
        Add-Result Threats 'Defender status' FAILED $_.Exception.Message 'Repair the Defender platform before relying on scan evidence.'
        return
    }
    $ages=[System.Collections.Generic.List[string]]::new()
    # Defender reports "never" as 4294967295, the largest UInt32, which does not fit
    # in [int]. Read every age as a 64-bit number and name that value.
    $neverAge=[long][uint32]::MaxValue
    foreach ($pair in @(@{Name='QuickScanAge';Label='quick'},@{Name='FullScanAge';Label='full'})) {
        $value=Get-OptionalProperty $status $pair.Name $null
        if ($null -eq $value) { continue }
        $days=[long]$value
        if ($days -lt 0 -or $days -ge $neverAge) { $ages.Add("no $($pair.Label) scan has ever completed") }
        elseif ($days -ge 7) { $ages.Add("$($pair.Label) scan ${days}d old") }
    }
    $signatureAge=Get-OptionalProperty $status 'AntivirusSignatureAge' $null
    if ($null -ne $signatureAge) {
        $signatureDays=[long]$signatureAge
        if ($signatureDays -ge $neverAge) { $ages.Add('signatures have never been updated') }
        elseif ($signatureDays -ge 3) { $ages.Add("signatures ${signatureDays}d old") }
    }
    if ($ages.Count) {
        Add-Result Threats 'Scan and signature freshness' REVIEW ($ages -join '; ') 'Update security intelligence and complete a scan before the round ends; stale signatures are the usual reason a payload is never detected.'
    } else {
        $quickAge=Get-OptionalProperty $status 'QuickScanAge' $null
        $fullAge=Get-OptionalProperty $status 'FullScanAge' $null
        $sigAge=Get-OptionalProperty $status 'AntivirusSignatureAge' $null
        Add-Result Threats 'Scan and signature freshness' PASS "Quick scan age=$([string]$quickAge)d; full scan age=$([string]$fullAge)d; signature age=$([string]$sigAge)d." ''
    }
    $detections=@()
    try { $detections=@(Get-MpThreatDetection -ErrorAction Stop) } catch { }
    $threatNames=@{}
    try {
        foreach ($threat in @(Get-MpThreat -ErrorAction Stop)) {
            $id=[string](Get-OptionalProperty $threat 'ThreatID' '')
            if ($id) { $threatNames[$id]=[string](Get-OptionalProperty $threat 'ThreatName' '') }
        }
    } catch { }
    if ($detections.Count) {
        $sorted=@($detections | Sort-Object -Property @{Expression={Get-OptionalProperty $_ 'InitialDetectionTime' (Get-Date '1970-01-01')}} -Descending | Select-Object -First 8)
        $details=[System.Collections.Generic.List[string]]::new()
        foreach ($detection in $sorted) {
            $id=[string](Get-OptionalProperty $detection 'ThreatID' '')
            $name=if ($threatNames.ContainsKey($id)) { $threatNames[$id] } else { "threat id $id" }
            $resources=@(Get-OptionalProperty $detection 'Resources' @())
            $when=[string](Get-OptionalProperty $detection 'InitialDetectionTime' '')
            $details.Add("$when $name -> $($resources -join ', ')")
        }
        Add-Result Threats 'Defender detection history' REVIEW ($details -join '; ') 'This is evidence of what ran and where, even when remediation already succeeded. Record it, answer the related forensics question, and remove the source if it is still present.'
    } else {
        Add-Result Threats 'Defender detection history' PASS 'No Defender detection has ever been recorded on this image.' ''
    }
    $preference=$null
    try { $preference=Get-MpPreference -ErrorAction Stop } catch {
        Add-Result Threats 'Defender policy' REVIEW "Get-MpPreference failed: $($_.Exception.Message)" 'Repair the Defender platform before relying on policy evidence.'
    }
    if ($null -ne $preference) {
        $cfa=Get-OptionalProperty $preference 'EnableControlledFolderAccess' $null
        if ($null -ne $cfa) {
            if ([int]$cfa -eq 0) { Add-Result Threats 'Controlled folder access' REVIEW 'EnableControlledFolderAccess=0' 'Ransomware protection is off. Enable it only when the scenario does not require the blocked write paths.' }
            else { Add-Result Threats 'Controlled folder access' PASS "EnableControlledFolderAccess=$cfa" '' }
        }
        $asr=@(Get-OptionalProperty $preference 'AttackSurfaceReductionRules_Ids' @())
        $script:Inventory.AttackSurfaceReduction=[pscustomobject]@{RuleCount=$asr.Count}
        if ($asr.Count -eq 0) {
            Add-Result Threats 'Attack surface reduction rules' REVIEW 'No ASR rule is configured.' 'ASR rules are not scored directly but they block the script-host and Office behaviour most competition payloads rely on.'
        } else {
            Add-Result Threats 'Attack surface reduction rules' PASS "$($asr.Count) ASR rule(s) configured." ''
        }
    }
    if (-not $QuickScan) {
        Add-Result Threats 'On-demand scan' REVIEW 'No scan was requested (-QuickScan not supplied).' 'A quick scan costs several minutes; run one when the clock allows, and scan each folder named in the high-signal block.'
        return
    }
    $targets=@($script:SuspiciousPaths | Select-Object -First 5)
    if (-not $Apply -or $NonInteractive -or $WhatIfPreference) {
        Add-Result Threats 'On-demand scan' REVIEW "Scan targets: $(if ($targets.Count) { $targets -join ', ' } else { 'none recorded' })" 'Run the scan manually: Start-MpScan -ScanType QuickScan'
        return
    }
    $scope=if ($targets.Count) { "the $($targets.Count) flagged folder(s)" } else { 'the whole system' }
    if ((Read-YesNo "Start a Defender quick scan of $scope now? This can take several minutes") -ne 'Y') {
        Add-Result Threats 'On-demand scan' SKIPPED 'Scan was declined by the operator.' 'Run Start-MpScan -ScanType QuickScan before the round ends.'
        return
    }
    try {
        $started=Get-Date
        foreach ($target in $targets) { Start-MpScan -ScanPath $target -ScanType CustomScan -ErrorAction Stop }
        if (-not $targets.Count) { Start-MpScan -ScanType QuickScan -ErrorAction Stop }
        $elapsed=[int]((Get-Date)-$started).TotalSeconds
        $after=@()
        try { $after=@(Get-MpThreatDetection -ErrorAction Stop) } catch { }
        $new=@($after | Where-Object { $null -ne (Get-OptionalProperty $_ 'InitialDetectionTime' $null) -and [datetime](Get-OptionalProperty $_ 'InitialDetectionTime') -ge $started })
        Add-Result Threats 'On-demand scan' CHANGED "Completed in ${elapsed}s; new detections=$($new.Count)." 'Review any new detection, record the path, then remove the source with scenario approval.'
        Add-Ledger 'SCAN' 'Defender' "On-demand scan of $scope completed in ${elapsed}s; new detections=$($new.Count)."
    } catch {
        Add-Result Threats 'On-demand scan' FAILED $_.Exception.Message 'Run the scan interactively from Windows Security; a failed scan is not evidence that the image is clean.'
    }
}
function Invoke-VendorFolderSweep {
    # Opt-in net for a dropped binary that does not run yet. Bounded to avoid
    # blowing the round clock: three levels, executables only, signature first.
    if (-not $HuntVendorFolders) { return }
    $roots=@($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramData)
    $review=[System.Collections.Generic.List[string]]::new()
    $high=[System.Collections.Generic.List[string]]::new()
    $scanned=0
    foreach ($root in $roots) {
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -Depth 3 -File -Filter '*.exe' -ErrorAction SilentlyContinue)) {
            $scanned++
            if ($scanned -gt 1500) { break }
            $provenance=Get-FileProvenance $file.FullName
            if ($provenance.Severity -eq 'High') { $high.Add([pscustomobject]@{Path=$file.FullName;Text="$($file.FullName) [$([string]$provenance.Class)] $($provenance.Reason)"}) }
            elseif ($provenance.Severity -eq 'Review' -and $provenance.Class -ne 'Unregistered signed') { $review.Add($file.FullName) }
        }
    }
    if ($high.Count) {
        Add-Result Software 'Sweep: impersonating executables' REVIEW ((($high | Select-Object -First 10 | ForEach-Object { $_.Text }) -join '; ')) 'A file that claims a publisher it cannot prove, sitting in a vendor folder, is the exact pattern that defeats a folder allowlist. Verify with the vendor, then quarantine with scenario approval.'
        foreach ($item in $high) { Add-HighSignal 'SWEEP' $item.Path $item.Text 'Identify the owning product; remove only after evidence is recorded.' }
    }
    if ($review.Count) {
        Add-Result Software 'Sweep: executables without a publisher' REVIEW "$($review.Count) file(s) under Program Files or ProgramData have no verified publisher; first 10: $(($review | Select-Object -First 10) -join ', ')" 'Many legitimate installers drop helper binaries without embedded signatures. Treat this as a reading list, not a verdict.'
    }
    if (-not $high.Count -and -not $review.Count) {
        Add-Result Software 'Sweep: executables without a publisher' PASS "$scanned executable(s) scanned under Program Files and ProgramData; every one resolves to a servicing-owned or publisher-owned file." ''
    }
}
#endregion
#region v6 IIS and kept-share attestation
function Test-IisPresent {
    if (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) { return $true }
    if (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe')) { return $true }
    return $false
}
function Get-IisValue {
    param([string]$Filter,[string]$Name)
    try {
        $property=Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $Filter -Name $Name -ErrorAction Stop
        if ($null -eq $property) { return $null }
        return $property.Value
    } catch { return $null }
}
function Get-IisCollection {
    param([string]$Filter)
    try { return @(Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $Filter -Name '.' -ErrorAction Stop) } catch { return @() }
}
function Test-BroadWriteAccess {
    # A webshell only matters if someone can drop it. This answers "can an
    # ordinary authenticated user write here".
    param([string]$Path)
    try {
        $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($ace in @($acl.Access)) {
            if ([string]$ace.AccessControlType -ne 'Allow') { continue }
            $identity=[string]$ace.IdentityReference
            if ($identity -notmatch '(?i)(Everyone|BUILTIN\\Users|Authenticated Users|S-1-1-0$|S-1-5-11$|S-1-5-32-545$)') { continue }
            if ([string]$ace.FileSystemRights -match '(?i)(Write|Modify|FullControl|CreateFiles|AppendData)') { return $true }
        }
    } catch { }
    return $false
}
function Invoke-IisAudit {
    if (-not (Test-IisPresent)) {
        Add-Result IIS 'Web server role' SKIPPED 'IIS is not installed (no W3SVC service and no appcmd.exe).' 'Nothing to harden. If the README requires a web server, install the role before the round.'
        return
    }
    $script:Inventory.Iis=[ordered]@{}
    if (-not (Get-Module -Name WebAdministration -ListAvailable)) {
        Add-Result IIS 'WebAdministration module' FAILED 'IIS is present but the WebAdministration module is unavailable.' 'Install the IIS management tools or review the configuration in inetmgr.'
        return
    }
    Import-Module WebAdministration -ErrorAction Stop
    $sites=@(Get-Website -ErrorAction SilentlyContinue)
    $script:Inventory.Iis.Sites=@($sites | Select-Object Name,State,PhysicalPath,ApplicationPool)
    if (-not $sites.Count) { Add-Result IIS 'Web sites' REVIEW 'IIS is installed but no site is defined.' 'Confirm the README; an empty web server is usually a role that should be removed.' }
    else { Add-Result IIS 'Web sites' REVIEW ("Sites: " + (($sites | ForEach-Object { "$($_.Name) [$($_.State)] -> $($_.PhysicalPath)" }) -join '; ')) 'If the README does not require a web server, disable W3SVC through the IIS service decision instead of hardening it. If it does, keep every site and harden in place.' }
    # Directory browsing: safe to disable for every known site shape.
    $browse=Get-IisValue 'system.webServer/directoryBrowse' 'enabled'
    if ($null -eq $browse) {
        Add-Result IIS 'Directory browsing' REVIEW 'The setting could not be read at machine level.' 'Check inetmgr; directory browsing exposes the file tree of every site.'
    } else {
        Invoke-Setting IIS 'Directory browsing' {
            $value=Get-IisValue 'system.webServer/directoryBrowse' 'enabled'
            if ($null -eq $value) { throw 'Directory browsing could not be read.' }
            -not [bool]$value
        } {
            Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/directoryBrowse' -Name 'enabled' -Value $false -ErrorAction Stop
        } "Current=$browse; required=False." 'Directory browsing lists site contents to anonymous visitors.'
    }
    # WebDAV: absent module is the good state.
    $davModules=@(Get-WebGlobalModule -ErrorAction SilentlyContinue | Where-Object { [string](Get-OptionalProperty $_ 'Name' '') -match '(?i)webdav' })
    if (-not $davModules.Count) {
        Add-Result IIS 'WebDAV module' PASS 'The WebDAV module is not installed.' ''
    } else {
        Invoke-Setting IIS 'WebDAV authoring' {
            $value=Get-IisValue 'system.webServer/webdav/authoring' 'enabled'
            if ($null -eq $value) { return $true }
            -not [bool]$value
        } {
            Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/webdav/authoring' -Name 'enabled' -Value $false -ErrorAction Stop
        } "WebDAV modules present: $(($davModules | ForEach-Object { [string](Get-OptionalProperty $_ 'Name' '') }) -join ', ')." 'WebDAV turns a web server into a writable file share.'
    }
    # Dangerous verbs.
    $verbs=@(Get-IisCollection 'system.webServer/security/requestFiltering/verbs')
    $denied=@($verbs | Where-Object { -not [bool](Get-OptionalProperty $_ 'allowed' $true) } | ForEach-Object { [string](Get-OptionalProperty $_ 'verb' '') })
    $missingVerbs=@(@('TRACE','TRACK','DEBUG') | Where-Object { $denied -notcontains $_ })
    if (-not $missingVerbs.Count) {
        Add-Result IIS 'Request filtering verbs' PASS "Denied: $($denied -join ', ')" ''
    } else {
        Invoke-Setting IIS 'Request filtering verbs' {
            $current=@(Get-IisCollection 'system.webServer/security/requestFiltering/verbs')
            $currentDenied=@($current | Where-Object { -not [bool](Get-OptionalProperty $_ 'allowed' $true) } | ForEach-Object { [string](Get-OptionalProperty $_ 'verb' '') })
            @(@('TRACE','TRACK','DEBUG') | Where-Object { $currentDenied -notcontains $_ }).Count -eq 0
        } {
            # Flip an existing entry instead of adding a duplicate, which IIS rejects.
            $existingVerbs=@(Get-IisCollection 'system.webServer/security/requestFiltering/verbs')
            foreach ($verb in @('TRACE','TRACK','DEBUG')) {
                $entry=@($existingVerbs | Where-Object { [string](Get-OptionalProperty $_ 'verb' '') -ieq $verb })
                if ($entry.Count) {
                    if ([bool](Get-OptionalProperty $entry[0] 'allowed' $true)) {
                        $storedVerb=[string](Get-OptionalProperty $entry[0] 'verb' $verb)
                        Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/requestFiltering/verbs/add[@verb='$storedVerb']" -Name 'allowed' -Value $false -ErrorAction Stop
                    }
                } else {
                    Add-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering/verbs' -Name '.' -Value @{verb=$verb;allowed='false'} -ErrorAction Stop
                }
            }
        } "Missing deny entries: $($missingVerbs -join ', ')" 'TRACE and TRACK echo request content and enable cross-site tracing.'
    }
    # Version banner headers.
    $serverHeader=Get-IisValue 'system.webServer/security/requestFiltering' 'removeServerHeader'
    if ($null -eq $serverHeader) {
        Add-Result IIS 'Server header' REVIEW 'removeServerHeader is not supported on this build.' 'Use URL Rewrite to strip the Server header if the scenario scores banner disclosure.'
    } else {
        Invoke-Setting IIS 'Server header' { [bool](Get-IisValue 'system.webServer/security/requestFiltering' 'removeServerHeader') } {
            Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name 'removeServerHeader' -Value $true -ErrorAction Stop
        } "Current=$serverHeader; required=True." 'The Server header advertises the IIS version to every visitor.'
    }
    $customHeaders=@(Get-IisCollection 'system.webServer/httpProtocol/customHeaders')
    $poweredBy=@($customHeaders | Where-Object { [string](Get-OptionalProperty $_ 'name' '') -ieq 'X-Powered-By' })
    if (-not $poweredBy.Count) {
        Add-Result IIS 'X-Powered-By header' PASS 'The header is not set.' ''
    } else {
        Invoke-Setting IIS 'X-Powered-By header' {
            $current=@(Get-IisCollection 'system.webServer/httpProtocol/customHeaders')
            @($current | Where-Object { [string](Get-OptionalProperty $_ 'name' '') -ieq 'X-Powered-By' }).Count -eq 0
        } {
            Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/httpProtocol/customHeaders' -Name '.' -AtElement @{name='X-Powered-By'} -ErrorAction Stop
        } "Header entries: $($poweredBy.Count)" 'The header discloses the ASP.NET version.'
    }
    # Logging.
    $logEnabled=Get-IisValue 'system.applicationHost/sites/siteDefaults/logFile' 'enabled'
    if ($null -eq $logEnabled) {
        Add-Result IIS 'Request logging' REVIEW 'The logFile section could not be read.' 'Enable W3C logging in inetmgr; an unlogged web server produces no forensic evidence.'
    } else {
        Invoke-Setting IIS 'Request logging' { [bool](Get-IisValue 'system.applicationHost/sites/siteDefaults/logFile' 'enabled') } {
            Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults/logFile' -Name 'enabled' -Value $true -ErrorAction Stop
        } "Current=$logEnabled; required=True." 'W3C logs are the only record of what an attacker requested.'
    }
    # Application pools.
    $poolFindings=[System.Collections.Generic.List[string]]::new()
    # IIS:\AppPools comes from WebAdministration, which is already loaded; the
    # Get-IISAppPool cmdlet needs the separate IISAdministration module.
    $pools=@()
    try { $pools=@(Get-ChildItem -LiteralPath 'IIS:\AppPools' -ErrorAction Stop) } catch { $pools=@() }
    foreach ($pool in $pools) {
        $identity=[string](Get-OptionalProperty (Get-OptionalProperty $pool 'processModel' $null) 'identityType' '')
        $runtime=[string](Get-OptionalProperty $pool 'managedRuntimeVersion' '')
        if ($identity -and $identity -notmatch '(?i)^ApplicationPoolIdentity$') { $poolFindings.Add("$($pool.Name) runs as $identity") }
        if ($runtime -eq 'v2.0') { $poolFindings.Add("$($pool.Name) uses .NET $runtime") }
    }
    if ($poolFindings.Count) {
        Add-Result IIS 'Application pool identity' REVIEW (($poolFindings | Select-Object -First 8) -join '; ') 'ApplicationPoolIdentity is the least-privilege choice. A named or LocalSystem identity turns an application bug into a machine compromise.'
    } else {
        Add-Result IIS 'Application pool identity' PASS 'Every application pool uses ApplicationPoolIdentity and a supported runtime.' ''
    }
    # Bindings and TLS posture.
    $httpOnly=[System.Collections.Generic.List[string]]::new()
    foreach ($site in $sites) {
        $bindings=@()
        try { $bindings=@($site.Bindings.Collection) } catch { }
        $hasHttps=$false
        foreach ($binding in $bindings) {
            if ([string](Get-OptionalProperty $binding 'protocol' '') -ieq 'https') { $hasHttps=$true }
        }
        if ($bindings.Count -and -not $hasHttps) { $httpOnly.Add([string]$site.Name) }
    }
    if ($httpOnly.Count) {
        Add-Result IIS 'HTTPS bindings' REVIEW "Cleartext-only sites: $($httpOnly -join ', ')" 'Enforce HTTPS only when the scoring report or README expects it; on a plain-HTTP scenario a redirect can cost the site check.'
    } else {
        Add-Result IIS 'HTTPS bindings' PASS 'Every site with a binding has an HTTPS endpoint.' ''
    }
    $tls1=Get-RegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' 'Enabled'
    $tls11=Get-RegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' 'Enabled'
    if (($tls1.Exists -and [int]$tls1.Value -ne 0) -or ($tls11.Exists -and [int]$tls11.Value -ne 0)) {
        Add-Result IIS 'TLS protocol version' REVIEW "TLS1.0 enabled=$($tls1.Value); TLS1.1 enabled=$($tls11.Value)" 'Disable TLS 1.0 and 1.1 only after confirming the scoring client supports TLS 1.2; a failed handshake looks like a broken site.'
    } else {
        Add-Result IIS 'TLS protocol version' PASS 'TLS 1.0 and 1.1 are not explicitly enabled.' ''
    }
    # Webshell surface: script files in a folder that ordinary users can write.
    $scriptExtensions=@('.aspx','.asp','.ashx','.asmx','.ascx','.php','.jsp','.cgi','.pl','.cfm')
    $webshells=[System.Collections.Generic.List[string]]::new()
    $writableRoots=[System.Collections.Generic.List[string]]::new()
    foreach ($site in $sites) {
        $root=[string](Get-OptionalProperty $site 'PhysicalPath' '')
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root)) { continue }
        if (Test-BroadWriteAccess $root) { $writableRoots.Add([string]$site.Name) }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -Depth 3 -File -ErrorAction SilentlyContinue)) {
            if ($scriptExtensions -notcontains $file.Extension.ToLowerInvariant()) { continue }
            $provenance=Get-FileProvenance $file.FullName
            if ($provenance.Severity -eq 'High') { $webshells.Add("$($file.FullName) [$([string]$provenance.Class)]") }
            elseif (Test-BroadWriteAccess $file.DirectoryName) { $webshells.Add("$($file.FullName) [script in a broadly writable folder]") }
        }
    }
    if ($writableRoots.Count) {
        Add-Result IIS 'Writable site roots' REVIEW "Broad write access on: $($writableRoots -join ', ')" 'Remove write access for Everyone, Users, and Authenticated Users from the site root; that ACL is what makes a webshell possible.'
    }
    if ($webshells.Count) {
        Add-Result IIS 'Executable content in writable folders' REVIEW (($webshells | Select-Object -First 10) -join '; ') 'Script files that any authenticated user can replace are the standard IIS persistence path. Compare each against the site deployment and capture a hash before removing it.'
        foreach ($item in $webshells) { Add-HighSignal 'IIS' $item $item 'Verify against the site deployment; capture the hash first.' }
    } elseif ($sites.Count) {
        Add-Result IIS 'Executable content in writable folders' PASS 'No script file was found in a folder writable by Everyone, Users, or Authenticated Users.' ''
    }
    # Modules and handlers outside the IIS installation are live persistence.
    $moduleFindings=[System.Collections.Generic.List[string]]::new()
    foreach ($module in @(Get-WebGlobalModule -ErrorAction SilentlyContinue)) {
        $image=[string](Get-OptionalProperty $module 'Image' '')
        if ([string]::IsNullOrWhiteSpace($image)) { continue }
        if ($image -match '(?i)\\System32\\inetsrv\\') { continue }
        $moduleFindings.Add("$([string](Get-OptionalProperty $module 'Name' '')) -> $image [$((Format-Provenance (Get-FileProvenance $image)))]")
    }
    if ($moduleFindings.Count) {
        Add-Result IIS 'Global modules outside inetsrv' REVIEW (($moduleFindings | Select-Object -First 10) -join '; ') 'A native module loaded into every request is a durable backdoor. Confirm the vendor and remove unknown registrations with appcmd.'
        foreach ($item in $moduleFindings) { Add-HighSignal 'IIS-MODULE' $item $item 'Confirm the module owner; remove with appcmd clear module.' }
    } else {
        Add-Result IIS 'Global modules outside inetsrv' PASS 'Every global module image resolves inside System32\inetsrv.' ''
    }
    $isapiAllowed=[System.Collections.Generic.List[string]]::new()
    foreach ($entry in @(Get-IisCollection 'system.webServer/security/isapiCgiRestriction')) {
        if (-not [bool](Get-OptionalProperty $entry 'allowed' $false)) { continue }
        $path=[string](Get-OptionalProperty $entry 'path' '')
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if ($path -match '(?i)\\System32\\inetsrv\\') { continue }
        $isapiAllowed.Add($path)
    }
    if ($isapiAllowed.Count) {
        Add-Result IIS 'Allowed ISAPI/CGI extensions' REVIEW (($isapiAllowed | Select-Object -First 8) -join '; ') 'An allowed ISAPI filter outside inetsrv executes code inside the worker process. Confirm each one against the site deployment.'
        foreach ($item in $isapiAllowed) { Add-HighSignal 'IIS-ISAPI' $item $item 'Confirm the extension; deny it with appcmd if unauthorized.' }
    } else {
        Add-Result IIS 'Allowed ISAPI/CGI extensions' PASS 'No allowed ISAPI or CGI path exists outside System32\inetsrv.' ''
    }
}
function Invoke-KeptShareAttestation {
    # Runs only for shares that survived the keep decision. Every property is
    # read back, so "the share is kept" and "the share is hardened" are one block.
    if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) {
        Add-Result Shares 'Kept-share attestation' SKIPPED 'The SMB cmdlets are unavailable.' 'Review SMB hardening manually.'
        return
    }
    $shares=@()
    try { $shares=@(Get-SmbShare -IncludeHidden -ErrorAction Stop | Where-Object { -not [bool](Get-OptionalProperty $_ 'Special' $false) -and -not [string]::IsNullOrWhiteSpace([string](Get-OptionalProperty $_ 'Path' '')) }) } catch { }
    if (-not $shares.Count) {
        Add-Result Shares 'Kept-share attestation' PASS 'No ordinary SMB share remains, so there is no share surface to attest.' ''
        return
    }
    $attestation=[System.Collections.Generic.List[string]]::new()
    foreach ($share in $shares) {
        $name=[string]$share.Name
        $path=[string](Get-OptionalProperty $share 'Path' '')
        $encrypted=[bool](Get-OptionalProperty $share 'EncryptData' $false)
        $enumeration=[string](Get-OptionalProperty $share 'FolderEnumerationMode' '')
        if (-not (Test-Path -LiteralPath $path)) {
            $attestation.Add("$name MISSING PATH $path")
            continue
        }
        if (Test-ScenarioShare -Name $name -Path $path) {
            # AFA and CyberPatriot shares (and -ProtectedShareNames/-Paths) are reported, never changed.
            $attestation.Add("$name path=$path scenario-protected, not changed; encryption=$encrypted enumeration=$enumeration")
            continue
        }
        Invoke-Setting Shares "$name access-based enumeration" { [string](Get-OptionalProperty (Get-SmbShare -Name $name -ErrorAction Stop) 'FolderEnumerationMode' '') -ieq 'AccessBased' } {
            Set-SmbShare -Name $name -FolderEnumerationMode AccessBased -Force -ErrorAction Stop
        } "Current=$enumeration; required=AccessBased." 'Without ABE every user can enumerate every filename on the share.'
        if (-not $encrypted) {
            # Encryption is reported, not forced: an old client that cannot negotiate
            # SMB 3.x encryption loses access the moment this is switched on.
            if ($EncryptKeptShares) {
                Invoke-Setting Shares "$name SMB encryption" { [bool](Get-OptionalProperty (Get-SmbShare -Name $name -ErrorAction Stop) 'EncryptData' $false) } {
                    Set-SmbShare -Name $name -EncryptData $true -Force -ErrorAction Stop
                } "Current=$encrypted; required=True (-EncryptKeptShares)." 'SMB encryption protects the data in transit on a share that stays available.'
            } else {
                Add-Result Shares "$name SMB encryption" REVIEW "Current=False; -EncryptKeptShares was not supplied." 'Enable it with -EncryptKeptShares only after confirming every client can negotiate SMB 3.x encryption; an old client loses access.'
            }
        }
        $finding=Get-SharePermissionFindings $share
        $risky=@($finding.ShareRisky).Count + @($finding.NtfsExplicitRisky).Count
        $inherited=@($finding.NtfsInheritedRisky).Count
        $attestation.Add("$name path=$path encryption=$encrypted enumeration=$enumeration riskyAces=$risky inheritedRiskyAces=$inherited")
    }
    $server=Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    $signing=if ($server) { [bool](Get-OptionalProperty $server 'RequireSecuritySignature' $false) } else { $false }
    $smb1=if ($server) { [bool](Get-OptionalProperty $server 'EnableSMB1Protocol' $true) } else { $true }
    $guest=[bool](Get-OptionalProperty (Get-SmbClientConfiguration -ErrorAction Stop) 'EnableInsecureGuestLogons' $true)
    $serverOk=($signing -and -not $smb1 -and -not $guest)
    $status=if ($serverOk) { 'PASS' } else { 'REVIEW' }
    Add-Result Shares 'Kept-share attestation' $status ("signing=$signing smb1=$smb1 guestLogons=$guest | " + ($attestation -join ' | ')) 'This block is the proof that a retained share is hardened: signing on, SMB1 off, guest logons off, encryption on, ABE on, and no broad ACE at the share or NTFS root.'
    $nullLogon=Get-RegistryState 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess'
    if (-not ($nullLogon.Exists -and [int]$nullLogon.Value -eq 1)) {
        Add-Result SMB 'Restrict null session access' REVIEW "RestrictNullSessAccess exists=$($nullLogon.Exists); value=$($nullLogon.Value)" 'Set it to 1 unless the README requires anonymous share access.'
    }
    $inboundNtlm=Get-RegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'RestrictReceivingNTLMTraffic'
    if (-not $inboundNtlm.Exists) {
        Add-Result SMB 'Incoming NTLM restriction' REVIEW 'RestrictReceivingNTLMTraffic is not set.' 'Deny-all is the CIS value, but it breaks local-account SMB access. Decide from the scenario, not from the benchmark.'
    }
}
function Invoke-ProvenanceSelfTest {
    # Proves the classifier on the running host. Safe: writes only to TEMP.
    $root=Join-Path $env:TEMP ("CYPatProvenanceSelfTest-"+[guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -Path $root -ItemType Directory -Force -ErrorAction Stop | Out-Null
    $lines=[System.Collections.Generic.List[string]]::new()
    $ok=$true
    try {
        $osFile=Join-Path $env:SystemRoot 'System32\notepad.exe'
        if (Test-Path -LiteralPath $osFile) {
            $osProvenance=Get-FileProvenance $osFile
            $lines.Add("notepad.exe -> $([string]$osProvenance.Class) severity='$($osProvenance.Severity)'")
            if ($osProvenance.Severity -ne '' -or @('OS component','Microsoft signed') -notcontains $osProvenance.Class) { $ok=$false }
            $copy=Join-Path $root 'nvcontainer.exe'
            Copy-Item -LiteralPath $osFile -Destination $copy -Force -ErrorAction Stop
            $copyProvenance=Get-FileProvenance $copy
            $lines.Add("renamed copy -> $([string]$copyProvenance.Class) renamed=$($copyProvenance.Renamed)")
            if (-not $copyProvenance.Renamed) { $ok=$false }
        }
        $fake=Join-Path $root 'nvdisplay.container.exe'
        Set-Content -LiteralPath $fake -Value 'MZ placeholder, not a PE' -Encoding ASCII -ErrorAction Stop
        $fakeProvenance=Get-FileProvenance $fake
        $lines.Add("unsigned placeholder -> $([string]$fakeProvenance.Class) severity='$($fakeProvenance.Severity)'")
        # The classifier must never call a file with no identity trusted. It cannot
        # prove impersonation without a version resource, so 'Review' is the floor.
        if ([string]::IsNullOrEmpty([string]$fakeProvenance.Severity)) { $ok=$false }
        if (@('OS component','Microsoft signed','Installed product') -contains $fakeProvenance.Class) { $ok=$false }
        Add-Result Threats 'Provenance self-test' $(if ($ok) { 'PASS' } else { 'FAILED' }) ($lines -join '; ') 'A servicing-owned binary must classify as OS component or Microsoft signed, a renamed copy must be detected as renamed, and a file with no identity must never be reported as trusted.'
    } catch {
        Add-Result Threats 'Provenance self-test' FAILED $_.Exception.Message 'Run the self-test from an elevated prompt and check that fsutil.exe is available.'
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
function Test-QuarantineBlocked {
    # Why a file must not be quarantined, or '' when nothing forbids it.
    # C:\Windows\Temp is allowed; the rest of C:\Windows is not.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'the finding has no file path' }
    $systemRoot=([string]$env:SystemRoot).TrimEnd('\')
    $inWindowsTemp=(-not [string]::IsNullOrWhiteSpace($systemRoot)) -and $Path.StartsWith($systemRoot+'\Temp\',[StringComparison]::OrdinalIgnoreCase)
    $roots=[System.Collections.Generic.List[string]]::new()
    foreach ($root in @('C:\CyberPatriot','C:\AFA',$env:SystemRoot,(Join-Path $env:ProgramData 'CYPatV6'),(Join-Path ($env:SystemDrive + '\') 'findings'))) {
        if (-not [string]::IsNullOrWhiteSpace($root)) { $roots.Add([string]$root) }
    }
    foreach ($root in @($ProtectedSharePaths)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$root)) { $roots.Add([string]$root) }
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$script:RunDirectory)) { $roots.Add([string]$script:RunDirectory) }
    foreach ($root in $roots) {
        $trimmed=$root.Trim().TrimEnd('\')
        if (-not $trimmed) { continue }
        if ($systemRoot -and $trimmed -ieq $systemRoot -and $inWindowsTemp) { continue }
        if ($Path -ieq $trimmed -or $Path.StartsWith($trimmed+'\',[StringComparison]::OrdinalIgnoreCase)) { return "it lives inside a protected folder ($trimmed)" }
    }
    $required=Get-RequiredSoftwareOwner $Path
    if ($required) { return "it belongs to required software '$required' (-RequiredSoftware)" }
    if ($script:Inventory.Contains('Services')) {
        foreach ($service in @($script:Inventory.Services)) {
            $image=Resolve-ServiceImagePath ([string](Get-OptionalProperty $service 'PathName' ''))
            if ($image -and $image -ieq $Path) { return "it is the binary of service $([string](Get-OptionalProperty $service 'Name' ''))" }
        }
    }
    return ''
}
function Invoke-FileQuarantine {
    # The one copy-verify-delete path for a file the operator approved. Nothing is
    # deleted unless the copy in the private run folder hashes identically.
    param([string]$Path,[string]$Kind,[string]$Detail='')
    if ([string]::IsNullOrWhiteSpace($script:RunDirectory)) { throw 'The private run folder is unavailable; refusing to delete without a quarantine copy.' }
    $blocked=Test-QuarantineBlocked $Path
    if ($blocked) { throw "Refused because $blocked." }
    $hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    $running=@()
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        try { if ($process.Path -and $process.Path -ieq $Path) { $running+=$process } } catch { }
    }
    foreach ($process in $running) { Stop-Process -Id $process.Id -Force -ErrorAction Stop; Start-Sleep -Milliseconds 300 }
    $stamp=Get-Date -Format 'yyyy-MM-dd-HHmmss'
    $quarantineName="$stamp-$([guid]::NewGuid().ToString('N').Substring(0,6))-$([IO.Path]::GetFileName($Path)).quarantine"
    $quarantinePath=Join-Path (Join-Path $script:RunDirectory 'Quarantine') $quarantineName
    Copy-Item -LiteralPath $Path -Destination $quarantinePath -Force -ErrorAction Stop
    $copied=(Get-FileHash -LiteralPath $quarantinePath -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($copied -ne $hash) { throw 'Quarantine copy hash does not match the original.' }
    Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $Path) { throw 'The original file still exists after removal.' }
    $note=([string]$Detail -replace '[\r\n]+',' ')
    Write-PrivateLine 'Quarantine.txt' "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | QUARANTINED | $Kind | $Path | $hash | copy=$quarantineName | $note"
    Add-Ledger 'QUARANTINE' "File/$Path" "Kind=$Kind; SHA256=$hash; copy=$quarantineName"
    Write-Host "QUARANTINED $Path -> $quarantinePath" -ForegroundColor Yellow
    return [pscustomobject]@{Hash=$hash;QuarantinePath=$quarantinePath;Stopped=$running.Count}
}
function Invoke-HighSignalRemediation {
    # The only place a high-signal finding can become a change. Five finding kinds
    # qualify: a running process, an autorun target, a startup-folder item, a
    # scheduled-task action, and the opt-in vendor-folder sweep. Protected folders,
    # service binaries, and -RequiredSoftware folders are refused before anything
    # is asked. Each remaining file is shown with the reason it was flagged and
    # confirmed one at a time; Y copies it to the private run folder, verifies the
    # copy's hash, and only then deletes the original.
    $candidates=@($script:HighSignal | Where-Object { $_.Kind -in @('PROCESS','AUTORUN','STARTUP','TASK','SWEEP') })
    if (-not $candidates.Count) { return }
    if (-not $Apply -or $NonInteractive -or $WhatIfPreference) {
        Add-Result Backdoor 'Quarantine decisions' REVIEW "$($candidates.Count) high-signal file(s) were named and left untouched." 'Run interactively with -Apply to quarantine a confirmed file, or handle each one at the console after recording evidence.'
        return
    }
    $asked=@{}
    foreach ($candidate in $candidates) {
        $path=[string]$candidate.Target
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $key=$path.ToLowerInvariant()
        if ($asked.ContainsKey($key)) { continue }
        $asked[$key]=$true
        $label=[IO.Path]::GetFileName($path)
        $blocked=Test-QuarantineBlocked $path
        if ($blocked) {
            Add-Result Backdoor "Quarantine $label" REVIEW "$blocked; the file was not changed." 'Handle this through its owning component (service, driver, required application, or Windows servicing), not by deleting the file.'
            continue
        }
        $hash=''
        try { $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash }
        catch { Add-Result Backdoor "Quarantine $label" FAILED $_.Exception.Message 'The file could not be hashed; capture evidence manually.'; continue }
        $provenance=Get-FileProvenance $path
        Write-Host ''
        Write-Host "QUARANTINE CANDIDATE [$($candidate.Kind)] $path" -ForegroundColor Yellow
        Write-Host "  Why    : $(Format-Provenance $provenance)"
        if ($candidate.Detail) { Write-Host "  Found  : $($candidate.Detail)" }
        Write-Host "  SHA256 : $hash"
        if ($null -ne $provenance.Product) {
            Write-Host "  WARNING: this file is inside the install folder of '$($provenance.Product.Name)'. Deleting it breaks that program. Answer Y only if the README says that program must go." -ForegroundColor Red
        }
        $answer=Read-YesNo 'Quarantine this file? Y stops it if running, copies it to the private run folder, verifies the copy, then deletes the original'
        if ($answer -ne 'Y') {
            Add-Result Backdoor "Quarantine $label" SKIPPED "$($candidate.Kind) finding left unchanged by operator decision." 'Record the evidence path; a finding left in place must be explained in the report.'
            continue
        }
        try {
            $outcome=Invoke-FileQuarantine -Path $path -Kind ([string]$candidate.Kind) -Detail ([string]$candidate.Detail)
            Add-Result Backdoor "Quarantine $label" CHANGED "Process stopped if running; file copied to $($outcome.QuarantinePath), hash verified, and the original deleted." ''
        } catch {
            Add-Result Backdoor "Quarantine $label" FAILED $_.Exception.Message 'Stop the process and quarantine the file manually, or resolve the ACL/ownership problem and re-run.'
        }
    }
}
#endregion
#region v6.1 deep persistence and configuration integrity
function Get-RegistryValueText {
    param([string]$Path,[string]$Name)
    $state=Get-RegistryState $Path $Name
    if (-not $state.Exists) { return $null }
    if ($state.Value -is [array]) { return (@($state.Value) -join ';') }
    return [string]$state.Value
}
function Get-RegistryValueList {
    param([string]$Path,[string]$Name)
    $state=Get-RegistryState $Path $Name
    if (-not $state.Exists -or $null -eq $state.Value) { return @() }
    return @($state.Value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}
function Invoke-DefenderExclusionAudit {
    # Item 1. An exclusion is how malware keeps Defender quiet after it lands.
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Add-Result Threats 'Defender exclusions' SKIPPED 'The Defender cmdlets are unavailable.' 'Review exclusions in Windows Security: Virus & threat protection > Manage settings > Exclusions.'
        return
    }
    try { $preference=Get-MpPreference -ErrorAction Stop } catch {
        Add-Result Threats 'Defender exclusions' FAILED $_.Exception.Message 'Review exclusions in Windows Security; an unreadable configuration is not a clean one.'
        return
    }
    $pathExclusions=@(Get-OptionalProperty $preference 'ExclusionPath' @())
    $processExclusions=@(Get-OptionalProperty $preference 'ExclusionProcess' @())
    $extensionExclusions=@(Get-OptionalProperty $preference 'ExclusionExtension' @())
    $script:Inventory.DefenderExclusions=[pscustomobject]@{Path=@($pathExclusions);Process=@($processExclusions);Extension=@($extensionExclusions)}
    if (-not $pathExclusions.Count -and -not $processExclusions.Count -and -not $extensionExclusions.Count) {
        Add-Result Threats 'Defender exclusions' PASS 'No path, process, or extension exclusion is configured.' ''
        return
    }
    $details=[System.Collections.Generic.List[object]]::new()
    foreach ($entry in $pathExclusions) {
        $text=([string]$entry).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $expanded=[Environment]::ExpandEnvironmentVariables($text).TrimEnd('\')
        if ($expanded -match '^(?i)[A-Za-z]:$' -or $expanded -match '^(?i)[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|Users|ProgramData|)$') {
            $details.Add([pscustomobject]@{Kind='Path';Value=$text;Why='covers a whole root';Severity='High'}); continue
        }
        if (Test-UserWritableLocation ($expanded+'\')) { $details.Add([pscustomobject]@{Kind='Path';Value=$text;Why='user-writable path';Severity='High'}); continue }
        if (-not (Test-Path -LiteralPath $expanded)) { $details.Add([pscustomobject]@{Kind='Path';Value=$text;Why='path no longer exists';Severity='Review'}); continue }
        $details.Add([pscustomobject]@{Kind='Path';Value=$text;Why='scoped folder';Severity='Review'})
    }
    foreach ($entry in $extensionExclusions) {
        $text=([string]$entry).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        if ($text -match '^(?i)\.(exe|dll|scr|com|pif|cpl|ps1|bat|cmd|js|jse|vbs|vbe|hta|wsf|msi|jar)$') {
            $details.Add([pscustomobject]@{Kind='Extension';Value=$text;Why='directly executable type';Severity='High'})
        } else {
            $details.Add([pscustomobject]@{Kind='Extension';Value=$text;Why='file type';Severity='Review'})
        }
    }
    foreach ($entry in $processExclusions) {
        $text=([string]$entry).Trim()
        if ([string]::IsNullOrWhiteSpace($text)) { continue }
        $severity='Review'; $why='process name'
        if ($text -match '[\\/]') {
            $resolved=ConvertTo-ExecutablePath $text
            if ($resolved) {
                $provenance=Get-FileProvenance $resolved
                if ($provenance.Severity -eq 'High') { $severity='High'; $why="$(Format-Provenance $provenance)" }
                elseif (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { $why='path no longer exists' }
            }
        }
        $details.Add([pscustomobject]@{Kind='Process';Value=$text;Why=$why;Severity=$severity})
    }
    $high=@($details | Where-Object Severity -eq 'High')
    $review=@($details | Where-Object Severity -eq 'Review')
    if ($high.Count) {
        Add-Result Threats 'Defender exclusion defeats real-time protection' REVIEW (($high | ForEach-Object { "$($_.Kind) '$($_.Value)' ($($_.Why))" }) -join '; ') 'A whole-root, user-writable, executable-type, or unverifiable-process exclusion turns off detection for exactly the place a payload lands. Confirm it is not vendor-documented, then remove it.'
        foreach ($item in $high) { Add-HighSignal 'DEFENDER-EXCLUSION' "$($item.Kind):$($item.Value)" "Exclusion $($item.Value) ($($item.Why))" 'Remove the exclusion; it blinds real-time protection.' }
    }
    if ($review.Count) {
        Add-Result Threats 'Defender exclusions' REVIEW (($review | ForEach-Object { "$($_.Kind) '$($_.Value)' ($($_.Why))" }) -join '; ') 'Confirm each excluded folder or process belongs to a required application in the README. An unexplained exclusion is a finding even when it is narrow.'
    }
    if (-not $high.Count) { return }
    if (-not ($Apply -and -not $NonInteractive -and -not $WhatIfPreference)) {
        Add-Result Threats 'Defender exclusion removal' REVIEW "$($high.Count) exclusion(s) should be removed; no change was made." 'Run -Apply interactively, or remove them in Windows Security > Exclusions.'
        return
    }
    foreach ($item in $high) {
        try {
            switch ($item.Kind) {
                'Path' { Remove-MpPreference -ExclusionPath $item.Value -ErrorAction Stop }
                'Extension' { Remove-MpPreference -ExclusionExtension $item.Value -ErrorAction Stop }
                'Process' { Remove-MpPreference -ExclusionProcess $item.Value -ErrorAction Stop }
            }
            Add-Result Threats "Defender exclusion $($item.Value)" CHANGED 'Removed and logged.' ''
            Add-Ledger 'EXCLUSION' "$($item.Kind)/$($item.Value)" "Removed; reason=$($item.Why)"
        } catch {
            Add-Result Threats "Defender exclusion $($item.Value)" FAILED $_.Exception.Message 'Remove it manually in Windows Security.'
        }
    }
}
function Invoke-DllHijackAudit {
    # Item 2. A signed EXE loads an unsigned DLL from its own folder. No signature
    # check on the EXE would ever reveal this, and it is the sibling of the v5 hole.
    $names=@('version.dll','winmm.dll','wtsapi32.dll','userenv.dll','dbghelp.dll','d3d9.dll','dxgi.dll','dwmapi.dll','uxtheme.dll','propsys.dll','msimg32.dll','opengl32.dll','glu32.dll','winhttp.dll','wer.dll','profapi.dll','cryptbase.dll','ntmarta.dll','secur32.dll','sspicli.dll','dhcpcsvc.dll','dhcpcsvc6.dll','iphlpapi.dll','mswsock.dll','nlaapi.dll','rasadhlp.dll','schannel.dll','wkscli.dll','wldap32.dll','ws2_32.dll','wsnmp32.dll','thumbcache.dll','textshaping.dll','dsound.dll','dinput8.dll','xinput1_3.dll','xinput9_1_0.dll','msacm32.dll','avifil32.dll','comctl32.dll','comdlg32.dll','credui.dll','winsta.dll','wldp.dll','edputil.dll','pdh.dll','psapi.dll','dbgcore.dll','twinapi.dll','wlanapi.dll')
    $directories=[System.Collections.Generic.List[string]]::new()
    $seen=@{}
    $systemPrefix=([string]$env:SystemRoot).TrimEnd('\')+'\'
    if ($script:Inventory.Contains('Processes')) {
        foreach ($process in @($script:Inventory.Processes)) {
            $path=[string](Get-OptionalProperty $process 'ExecutablePath' '')
            if ([string]::IsNullOrWhiteSpace($path)) { continue }
            $directory=[IO.Path]::GetDirectoryName($path)
            if ([string]::IsNullOrWhiteSpace($directory)) { continue }
            if ($directory.StartsWith($systemPrefix,[StringComparison]::OrdinalIgnoreCase)) { continue }
            $key=$directory.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key]=$true
            $directories.Add($directory)
            if ($directories.Count -ge 120) { break }
        }
    }
    if ($script:Inventory.Contains('Services')) {
        foreach ($service in @($script:Inventory.Services)) {
            $image=Resolve-ServiceImagePath ([string](Get-OptionalProperty $service 'PathName' ''))
            if ([string]::IsNullOrWhiteSpace($image)) { continue }
            $directory=[IO.Path]::GetDirectoryName($image)
            if ([string]::IsNullOrWhiteSpace($directory)) { continue }
            if ($directory.StartsWith($systemPrefix,[StringComparison]::OrdinalIgnoreCase)) { continue }
            $key=$directory.ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key]=$true
            $directories.Add($directory)
            if ($directories.Count -ge 160) { break }
        }
    }
    if (-not $directories.Count) {
        Add-Result Persistence 'DLL search-order hijack' PASS 'No non-Windows application directory hosts a running process or service.' ''
        return
    }
    $high=[System.Collections.Generic.List[string]]::new()
    $review=[System.Collections.Generic.List[string]]::new()
    foreach ($directory in $directories) {
        foreach ($name in $names) {
            $candidate=Join-Path $directory $name
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
            $provenance=Get-FileProvenance $candidate
            if ($provenance.Severity -eq 'High') {
                $high.Add("$candidate [$(Format-Provenance $provenance)]")
                Add-HighSignal 'DLL-HIJACK' $candidate "$name planted beside an application [$([string]$provenance.Class)]" 'A hijackable DLL in an application folder loads into that process. Capture the hash, then quarantine with scenario approval.'
                Add-SuspiciousPath $candidate
            } else {
                $review.Add("$candidate [$([string]$provenance.Class)]")
            }
        }
    }
    if ($high.Count) {
        Add-Result Persistence 'DLL search-order hijack' REVIEW (($high | Select-Object -First 10) -join '; ') 'A well-known hijackable DLL name sitting in an application folder, with no verifiable publisher, is loaded by that application at start. This is how a signed EXE becomes a loader.'
    } elseif ($review.Count) {
        Add-Result Persistence 'DLL search-order hijack' REVIEW (($review | Select-Object -First 10) -join '; ') 'These names are commonly hijacked, but every copy here has a verifiable publisher. Confirm it matches the application vendor.'
    } else {
        Add-Result Persistence 'DLL search-order hijack' PASS "$($directories.Count) application folder(s) checked for 50 hijackable DLL names; none was planted." ''
    }
}
function Invoke-WinlogonLsaAudit {
    # Item 3. The registry surfaces that survive a service or startup-folder cleanup.
    $findings=[System.Collections.Generic.List[object]]::new()
    $winlogon='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    # Stock values: every Windows build ships VMApplet pointing at the
    # virtual-memory settings page, and Remote Desktop Session Hosts use AppSetup.
    $userinitDefault="$([string]$env:SystemRoot)\system32\userinit.exe,"
    $expectations=@(
        @{Name='Shell';Allowed=@('explorer.exe');Note='A replacement shell runs instead of Explorer at every logon.'},
        @{Name='Userinit';Allowed=@($userinitDefault,'C:\Windows\system32\userinit.exe,','userinit.exe,','userinit.exe');Note='Userinit runs before any user code and is a classic logon backdoor.'},
        @{Name='AppSetup';Allowed=@('','UsrLogon.Cmd');Note='AppSetup is only used by Remote Desktop Session Host (UsrLogon.Cmd).'},
        @{Name='GinaDLL';Allowed=@('');Note='A GINA DLL intercepts the logon credential path.'},
        @{Name='VmApplet';Allowed=@('','SystemPropertiesPerformance.exe /pagefile','rundll32 shell32,Control_RunDLL "sysdm.cpl"');Note='VmApplet normally opens the virtual-memory settings page.'}
    )
    foreach ($rule in $expectations) {
        $value=Get-RegistryValueText $winlogon $rule.Name
        if ($null -eq $value) { continue }
        $trimmed=($value.Trim() -replace '\s+',' ')
        if (@($rule.Allowed | Where-Object { $_ -ieq $trimmed }).Count) { continue }
        $findings.Add([pscustomobject]@{Label="Winlogon\$($rule.Name)";Value=$trimmed;Note=$rule.Note;Severity='High'})
    }
    $notify=Get-RegistryValueText $winlogon 'Notify'
    if (-not [string]::IsNullOrWhiteSpace($notify)) {
        $findings.Add([pscustomobject]@{Label='Winlogon\Notify';Value=$notify;Note='A Winlogon notification package runs inside the logon process.';Severity='High'})
    }
    $autoAdmin=Get-RegistryValueText $winlogon 'AutoAdminLogon'
    if ($autoAdmin -eq '1') {
        $findings.Add([pscustomobject]@{Label='Winlogon\AutoAdminLogon';Value='1';Note='The machine stores a logon credential and signs in without a human. Report the presence only; the password is never printed.';Severity='High'})
    }
    if ($null -ne (Get-RegistryValueText $winlogon 'DefaultPassword')) {
        $findings.Add([pscustomobject]@{Label='Winlogon\DefaultPassword';Value='(value present, not printed)';Note='A plain-text logon password is stored in the registry. Remove it after recording that it existed.';Severity='High'})
    }
    # AppInit_DLLs: 64-bit and 32-bit views.
    foreach ($path in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $appInit=Get-RegistryValueList $path 'AppInit_DLLs'
        if (-not $appInit.Count) { continue }
        $findings.Add([pscustomobject]@{Label="$path\AppInit_DLLs";Value=($appInit -join '; ');Note='AppInit_DLLs loads a DLL into every user-mode process that links user32.dll. It is empty on a stock image.';Severity='High'})
    }
    $lsa='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    foreach ($name in @('Security Packages','Authentication Packages','Notification Packages')) {
        $packages=Get-RegistryValueList $lsa $name
        $unexpected=@($packages | Where-Object { $_ -notmatch '(?i)^(msv1_0|kerberos|schannel|wdigest|tspkg|pku2u|negoexts|cloudap|livessp|dpapi|crashdmp|cic|scecli|rassfm|rassfm|winlogon|rpcexts|policymanager|davinci|AppContainer|Secur32|lsa)$' })
        if ($unexpected.Count) {
            $findings.Add([pscustomobject]@{Label="Lsa\$name";Value=($unexpected -join ', ');Note='An unexpected security or authentication package loads inside LSASS.';Severity='High'})
        }
    }
    $runAsPpl=Get-RegistryValueText $lsa 'RunAsPPL'
    if ($null -eq $runAsPpl -or [int]$runAsPpl -eq 0) {
        Add-Result Hardening 'LSA protection' REVIEW "RunAsPPL=$runAsPpl" 'RunAsPPL=1 needs a reboot and can break unsigned authentication packages. Enable only after confirming the scenario tolerates it.'
    } else {
        Add-Result Hardening 'LSA protection' PASS "RunAsPPL=$runAsPpl" ''
    }
    # Boot Execute.
    $bootExecute=Get-RegistryValueList 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'BootExecute'
    $extraBoot=@($bootExecute | Where-Object { $_ -notmatch '(?i)^autocheck\s+autochk\s+\*$' })
    if ($extraBoot.Count) {
        $findings.Add([pscustomobject]@{Label='Session Manager\BootExecute';Value=($extraBoot -join '; ');Note='A native program runs before the session manager starts.';Severity='High'})
    }
    # Netsh helper DLLs.
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NetSh') {
        try {
            $netsh=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NetSh' -ErrorAction Stop
            foreach ($property in @($netsh.PSObject.Properties)) {
                if ($property.Name -match '^PS') { continue }
                $value=[string]$property.Value
                if ([string]::IsNullOrWhiteSpace($value)) { continue }
                # Stock helpers are bare DLL names that resolve into System32 and are
                # Windows components; report only a helper that cannot prove that.
                $helperPath=[Environment]::ExpandEnvironmentVariables($value.Trim().Trim('"'))
                if (-not [IO.Path]::IsPathRooted($helperPath)) { $helperPath=Join-Path $env:SystemRoot (Join-Path 'System32' $helperPath) }
                $helperProvenance=Get-FileProvenance $helperPath
                if ([string]::IsNullOrEmpty([string]$helperProvenance.Severity) -and $helperProvenance.Class -ne 'Missing') { continue }
                $helperSeverity=if ($helperProvenance.Severity -eq 'High') { 'High' } else { 'Review' }
                $findings.Add([pscustomobject]@{Label="NetSh\$($property.Name)";Value="$value [$(Format-Provenance $helperProvenance)]";Note='A netsh helper DLL loads into every netsh invocation.';Severity=$helperSeverity})
            }
        } catch { }
    }
    # Print monitors.
    $monitorRoot='HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    if (Test-Path -LiteralPath $monitorRoot) {
        foreach ($key in @(Get-ChildItem -LiteralPath $monitorRoot -ErrorAction SilentlyContinue)) {
            $driver=Get-RegistryValueText $key.PSPath 'Driver'
            if ([string]::IsNullOrWhiteSpace($driver)) { continue }
            $resolved=Join-Path $env:SystemRoot (Join-Path 'System32' $driver)
            $provenance=Get-FileProvenance $resolved
            if ($provenance.Severity -eq 'High') {
                $findings.Add([pscustomobject]@{Label="Print monitor $($key.PSChildName)";Value="$driver [$(Format-Provenance $provenance)]";Note='A print monitor runs inside the spooler, which is a known local privilege-escalation path.';Severity='High'})
            }
        }
    }
    # W32Time providers.
    $timeRoot='HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'
    if (Test-Path -LiteralPath $timeRoot) {
        foreach ($key in @(Get-ChildItem -LiteralPath $timeRoot -ErrorAction SilentlyContinue)) {
            $dll=Get-RegistryValueText $key.PSPath 'DllName'
            if ([string]::IsNullOrWhiteSpace($dll)) { continue }
            $resolved=ConvertTo-ExecutablePath $dll
            if ([string]::IsNullOrWhiteSpace($resolved)) { continue }
            $provenance=Get-FileProvenance $resolved
            if ($provenance.Severity -eq 'High') {
                $findings.Add([pscustomobject]@{Label="Time provider $($key.PSChildName)";Value="$dll [$(Format-Provenance $provenance)]";Note='A time provider DLL runs inside the time service.';Severity='High'})
            }
        }
    }
    # Winsock namespace providers.
    $nsRoot='HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Namespace_Catalog5\Catalog_Entries'
    if (Test-Path -LiteralPath $nsRoot) {
        foreach ($key in @(Get-ChildItem -LiteralPath $nsRoot -ErrorAction SilentlyContinue)) {
            $library=Get-RegistryValueText $key.PSPath 'LibraryPath'
            if ([string]::IsNullOrWhiteSpace($library)) { continue }
            if ($library -match '(?i)\\System32\\') { continue }
            $findings.Add([pscustomobject]@{Label="Winsock namespace provider $($key.PSChildName)";Value=$library;Note='A Winsock provider DLL outside System32 intercepts name resolution.';Severity='High'})
        }
    }
    # Image File Execution Options, every entry rather than the four accessibility keys.
    $ifeoRoot='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (Test-Path -LiteralPath $ifeoRoot) {
        foreach ($key in @(Get-ChildItem -LiteralPath $ifeoRoot -ErrorAction SilentlyContinue)) {
            $debugger=Get-RegistryValueText $key.PSPath 'Debugger'
            if ([string]::IsNullOrWhiteSpace($debugger)) { continue }
            $resolved=ConvertTo-ExecutablePath $debugger
            $provenance=if ($resolved) { Get-FileProvenance $resolved } else { $null }
            $severity=if ($null -ne $provenance -and $provenance.Severity -eq 'High') { 'High' } else { 'Review' }
            $findings.Add([pscustomobject]@{Label="IFEO $($key.PSChildName)";Value="$debugger$(if ($provenance) { " [$(Format-Provenance $provenance)]" })";Note='An IFEO debugger replaces the launch of the named executable.';Severity=$severity})
        }
    }
    # SilentProcessExit.
    $speRoot='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    if (Test-Path -LiteralPath $speRoot) {
        foreach ($key in @(Get-ChildItem -LiteralPath $speRoot -ErrorAction SilentlyContinue)) {
            $monitor=Get-RegistryValueText $key.PSPath 'MonitoringProcess'
            if ([string]::IsNullOrWhiteSpace($monitor)) { continue }
            $findings.Add([pscustomobject]@{Label="SilentProcessExit $($key.PSChildName)";Value=$monitor;Note='A monitoring process launches when the named process exits.';Severity='High'})
        }
    }
    if ($findings.Count) {
        $high=@($findings | Where-Object Severity -eq 'High')
        $review=@($findings | Where-Object { $_.Severity -ne 'High' })
        if ($high.Count) {
            Add-Result Persistence 'Winlogon, LSA, and AppInit persistence' REVIEW (($high | ForEach-Object { "$($_.Label) = $($_.Value) ($($_.Note))" }) -join '; ') 'Each of these runs before or inside the logon path, so removing a startup shortcut does not remove it. Record the value and the target hash before restoring the expected value.'
            foreach ($item in $high) { Add-HighSignal 'LOGN-PATH' $item.Label "$($item.Label) = $($item.Value)" 'Restore the expected value only after the value and file hash are recorded.' }
        }
        if ($review.Count) {
            Add-Result Persistence 'Additional logon-path hooks' REVIEW (($review | ForEach-Object { "$($_.Label) = $($_.Value)" }) -join '; ') 'Confirm each one against the vendor list in the README.'
        }
    } else {
        Add-Result Persistence 'Winlogon, LSA, and AppInit persistence' PASS 'Winlogon, AppInit_DLLs, LSA packages, BootExecute, netsh helpers, print monitors, time providers, Winsock providers, IFEO, and SilentProcessExit all hold their default values.' ''
    }
}
function Invoke-RegLoad {
    # reg.exe reports failure on stderr, which Windows PowerShell 5.1 turns into a
    # terminating error under ErrorActionPreference=Stop. Judge it by exit code.
    param([string]$Mount,[string]$File)
    $ErrorActionPreference='Continue'
    try { $null=& reg.exe load $Mount $File 2>&1 } catch { return $false }
    return ($LASTEXITCODE -eq 0)
}
function Invoke-RegUnload {
    # Releases finalizable registry handles before each try; a hive left loaded
    # gives that user a temporary profile at the next sign-in.
    param([string]$Mount,[int]$Attempts=3)
    $ErrorActionPreference='Continue'
    for ($attempt=1; $attempt -le $Attempts; $attempt++) {
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
        try { $null=& reg.exe unload $Mount 2>&1 } catch { }
        if ($LASTEXITCODE -eq 0) { return $true }
        if ($attempt -lt $Attempts) { Start-Sleep -Milliseconds 700 }
    }
    return $false
}
function Invoke-PerUserHiveAudit {
    # Item 4. HKCU only covers the account running the script. Every other profile
    # has its own autoruns in an unloaded NTUSER.DAT. Each hive is loaded under
    # HKEY_USERS, read through the Registry:: provider, every key handle is closed,
    # and the unload is checked; a failed unload is reported with the fix.
    if (-not $script:Inventory.Contains('Accounts')) {
        Add-Result Persistence 'Per-user autoruns' SKIPPED 'The account inventory was not collected.' 'Review each profile NTUSER.DAT manually.'
        return
    }
    $usersRoot=Join-Path $env:SystemDrive 'Users'
    if (-not (Test-Path -LiteralPath $usersRoot)) { return }
    $currentProfile=''
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) { $currentProfile=$env:USERPROFILE.ToLowerInvariant() }
    $findings=[System.Collections.Generic.List[string]]::new()
    $unloadFailures=[System.Collections.Generic.List[string]]::new()
    $loadedCount=0
    $index=0
    foreach ($profileDir in @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($profileDir.Name -in @('Public','Default','Default User','All Users')) { continue }
        if ($profileDir.FullName.ToLowerInvariant() -eq $currentProfile) { continue }
        $hive=Join-Path $profileDir.FullName 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $hive)) { continue }
        $index++
        $mountName="CYPatAudit$index"
        $mount="HKU\$mountName"
        $providerRoot="Registry::HKEY_USERS\$mountName"
        # Clear a mount left behind by an interrupted earlier run.
        $null=Invoke-RegUnload -Mount $mount -Attempts 1
        if (-not (Invoke-RegLoad $mount $hive)) {
            $findings.Add("$($profileDir.Name): hive is in use (the user is signed in) and could not be loaded")
            continue
        }
        $loadedCount++
        $item=$null
        try {
            foreach ($sub in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run','SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')) {
                $path="$providerRoot\$sub"
                if (-not (Test-Path -LiteralPath $path)) { continue }
                $item=Get-Item -LiteralPath $path -ErrorAction Stop
                $values=[System.Collections.Generic.List[object]]::new()
                foreach ($valueName in @($item.GetValueNames())) {
                    if ([string]::IsNullOrWhiteSpace($valueName)) { continue }
                    $values.Add([pscustomobject]@{Name=$valueName;Command=[string]$item.GetValue($valueName)})
                }
                $item.Close()
                $item=$null
                foreach ($value in $values) {
                    $target=ConvertTo-ExecutablePath $value.Command
                    if ([string]::IsNullOrWhiteSpace($target)) {
                        $findings.Add("$($profileDir.Name): $sub\$($value.Name) -> command does not resolve to an absolute path")
                        continue
                    }
                    $provenance=Get-FileProvenance $target
                    if ($provenance.Severity -eq 'High') {
                        $findings.Add("$($profileDir.Name): $($value.Name) -> $target [$(Format-Provenance $provenance)]")
                        Add-HighSignal 'AUTORUN' $target "$($profileDir.Name) Run entry $($value.Name) [$([string]$provenance.Class)]" 'Disable the autorun through its owning product after recording evidence.'
                        Add-SuspiciousPath $target
                    } elseif ($provenance.Severity -eq 'Review') {
                        $findings.Add("$($profileDir.Name): $($value.Name) -> $target [$([string]$provenance.Class)]")
                    }
                }
            }
            $startupApproved="$providerRoot\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
            if (Test-Path -LiteralPath $startupApproved) {
                try {
                    $item=Get-Item -LiteralPath $startupApproved -ErrorAction Stop
                    $disabled=[System.Collections.Generic.List[string]]::new()
                    foreach ($valueName in @($item.GetValueNames())) {
                        $bytes=@($item.GetValue($valueName))
                        if ($bytes.Count -gt 0 -and (([int]$bytes[0] -band 1) -eq 1)) { $disabled.Add([string]$valueName) }
                    }
                    $item.Close()
                    $item=$null
                    if ($disabled.Count) { $findings.Add("$($profileDir.Name): disabled-but-present autoruns: $($disabled -join ', ')") }
                } catch { }
            }
        } catch {
            $findings.Add("$($profileDir.Name): hive read failed ($($_.Exception.Message))")
        } finally {
            if ($null -ne $item) {
                try { $item.Close() } catch { }
                $item=$null
            }
            if (-not (Invoke-RegUnload -Mount $mount)) { $unloadFailures.Add("$($profileDir.Name) ($mount)") }
        }
    }
    if ($unloadFailures.Count) {
        Add-Result Persistence 'Per-user hive unload' FAILED "These hives are still loaded: $($unloadFailures -join ', ')." 'Close other tools, then run reg unload <mount> for each one from an elevated prompt (or restart) before that user signs in; a loaded hive gives the user a temporary profile.'
    }
    if ($findings.Count) {
        Add-Result Persistence 'Per-user autoruns' REVIEW (($findings | Select-Object -First 15) -join '; ') "Loaded $loadedCount offline profile hive(s). A per-user autorun runs when that account signs in and is invisible to a machine-wide scan."
    } else {
        Add-Result Persistence 'Per-user autoruns' PASS "Loaded $loadedCount offline profile hive(s); no per-user autorun or disabled autorun entry was found." ''
    }
}
function Invoke-CertificateTrustAudit {
    # Item 5. A rogue root CA makes every forged signature look valid.
    $knownCaTokens=@('DigiCert','Baltimore','Microsoft','GlobalSign','Entrust','Go Daddy','GoDaddy','Sectigo','COMODO','USERTrust','AddTrust','VeriSign','Thawte','GeoTrust','Starfield','Amazon','Google','ISRG','Let''s Encrypt','Certum','QuoVadis','SecureTrust','Trustwave','Network Solutions','Symantec','AAA Certificate Services','SSL.com','Actalis','Buypass','D-TRUST','SwissSign','TWCA','HARICA','IdenTrust','AC Camerfirma','Chunghwa','Hongkong Post','Microsec','NetLock','Security Communication','TeliaSonera','T-Systems','Staat der Nederlanden','e-Szigno','Certigna','E-Tugra','OISTE','Firmaprofesional','ANF','Hellenic Academic','GLOBALTRUST','certSIGN','TrustCor','emSign','vTrus','Certainly','CommScope','WI-SUN','Agencia Catalana','Autoridad de Certificacion','CFCA','China Financial','SHECA','UniTrust','UCA','BJCA','iTrusChina','Telia','Sonera','SK ID','KISA','Government Root')
    $withKey=[System.Collections.Generic.List[string]]::new()
    $unknown=[System.Collections.Generic.List[string]]::new()
    $total=0
    foreach ($store in @('Cert:\LocalMachine\Root','Cert:\CurrentUser\Root')) {
        try { $certs=@(Get-ChildItem -Path $store -ErrorAction Stop) } catch { continue }
        foreach ($cert in $certs) {
            $total++
            $subject=[string]$cert.Subject
            $issuer=[string]$cert.Issuer
            $thumb=[string]$cert.Thumbprint
            if ($cert.HasPrivateKey) {
                $withKey.Add("$subject [$store] thumbprint=$thumb expires=$($cert.NotAfter.ToString('yyyy-MM-dd'))")
                continue
            }
            $matched=$false
            foreach ($token in $knownCaTokens) { if ($subject -match [regex]::Escape($token)) { $matched=$true; break } }
            if (-not $matched -and $subject -eq $issuer) {
                $unknown.Add("$subject [$store] expires=$($cert.NotAfter.ToString('yyyy-MM-dd'))")
            }
        }
    }
    $script:Inventory.CertificateRoots=[pscustomobject]@{Total=$total;WithPrivateKey=@($withKey);Unrecognised=@($unknown)}
    if ($withKey.Count) {
        Add-Result Certificates 'Root CA with an exportable private key' REVIEW (($withKey | Select-Object -First 8) -join '; ') 'A trusted root that owns a private key can sign anything and be trusted by this machine. A real public CA never leaves its key on a client. Record the thumbprint, then remove it after the forensics answers are submitted.'
        foreach ($item in $withKey) { Add-HighSignal 'ROOT-CA' $item 'A trusted root holding a private key is a planted CA.' 'Export the certificate as evidence, then delete it from the Root store.' }
    } else {
        Add-Result Certificates 'Root CA with an exportable private key' PASS "Checked $total trusted root certificate(s) in the machine and current-user stores; none holds a private key." ''
    }
    if ($unknown.Count) {
        Add-Result Certificates 'Unrecognised trusted root' REVIEW (($unknown | Select-Object -First 10) -join '; ') 'These self-signed roots do not match a known public CA. Some are legitimate enterprise roots; confirm against the README before removing one.'
    } else {
        Add-Result Certificates 'Unrecognised trusted root' PASS "Every self-signed root in the trusted store matches a known public CA name ($total certificate(s) checked)." ''
    }
}
function Invoke-CredentialExposureAudit {
    # Item 9. Stored credentials and install-elevation paths that survive cleanup.
    $findings=[System.Collections.Generic.List[string]]::new()
    foreach ($scope in @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer')) {
        $value=Get-RegistryValueText $scope 'AlwaysInstallElevated'
        if ($value -eq '1') {
            $findings.Add("AlwaysInstallElevated=1 at $scope (any user can install an MSI with SYSTEM rights)")
            Add-HighSignal 'PRIVESC' $scope 'AlwaysInstallElevated=1' 'Set it to 0 in both the machine and user policy hives.'
        }
    }
    $winlogon='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ($null -ne (Get-RegistryValueText $winlogon 'DefaultPassword')) { $findings.Add('Winlogon\DefaultPassword is present (value not printed)') }
    if ((Get-RegistryValueText $winlogon 'AutoAdminLogon') -eq '1') { $findings.Add('Winlogon\AutoAdminLogon=1 (stored credential, automatic sign-in)') }
    $profilePaths=@()
    if ($null -ne $PROFILE) { $profilePaths=@($PROFILE.AllUsersAllHosts,$PROFILE.AllUsersCurrentHost,$PROFILE.CurrentUserAllHosts,$PROFILE.CurrentUserCurrentHost) }
    foreach ($profilePath in $profilePaths) {
        if ([string]::IsNullOrWhiteSpace($profilePath)) { continue }
        if (Test-Path -LiteralPath $profilePath -PathType Leaf) {
            $findings.Add("PowerShell profile exists: $profilePath")
        }
    }
    $unattendCandidates=@(
        (Join-Path $env:SystemDrive 'unattend.xml'),
        (Join-Path $env:SystemRoot 'Panther\Unattend.xml'),
        (Join-Path $env:SystemRoot 'Panther\Unattend\Unattend.xml'),
        (Join-Path $env:SystemRoot 'System32\Sysprep\unattend.xml'),
        (Join-Path $env:SystemRoot 'System32\Sysprep\Autounattend.xml')
    )
    foreach ($candidate in $unattendCandidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $findings.Add("Answer file present: $candidate (may contain a plain-text password)") }
    }
    try {
        foreach ($extra in @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Panther') -Filter 'Unattend*.xml' -File -ErrorAction SilentlyContinue)) {
            if ($unattendCandidates -notcontains $extra.FullName) { $findings.Add("Answer file present: $($extra.FullName)") }
        }
    } catch { }
    if ($findings.Count) {
        Add-Result Credentials 'Stored credential and elevation paths' REVIEW (($findings | Select-Object -First 12) -join '; ') 'Each item either stores a credential in clear text or lets an ordinary user gain SYSTEM. Record it, answer any related forensics question, then remove the answer file or set the policy to 0.'
    } else {
        Add-Result Credentials 'Stored credential and elevation paths' PASS 'No AlwaysInstallElevated policy, stored Winlogon password, PowerShell profile, or unattend answer file was found.' ''
    }
}
#endregion
#region v6.2 forensics, network pivots, and port attribution
function Get-FileSha256 {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return '' }
}
function Get-RecentEventRecord {
    # Returns matching records, newest first. An empty result means the query ran
    # and found nothing; an unreadable log is reported by the caller's ListLog probe.
    param([string]$LogName,[int[]]$Id,[int]$MaxEvents=25)
    $out=[System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrWhiteSpace($LogName)) { return @() }
    foreach ($eventId in @($Id)) {
        try { $records=@(Get-WinEvent -FilterHashtable @{LogName=$LogName;Id=$eventId} -MaxEvents $MaxEvents -ErrorAction Stop) }
        catch { continue }
        foreach ($record in $records) {
            $text=''
            try { $text=(([string]$record.Message) -replace '\s+',' ').Trim() } catch { $text='' }
            if ($text.Length -gt 320) { $text=$text.Substring(0,320)+'...' }
            $out.Add([pscustomobject]@{Log=$LogName;Id=[int]$eventId;Time=$record.TimeCreated;Source=[string]$record.ProviderName;Text=$text})
        }
    }
    return @($out | Sort-Object Time -Descending)
}
function Invoke-EventLogForensics {
    # Item 6. The event log records what ran before this script. A cleared log is a
    # finding in itself, so the record counts are reported even on a clean image.
    $securityConfig=$null
    try { $securityConfig=Get-WinEvent -ListLog Security -ErrorAction Stop } catch { }
    $securityReadable=($null -ne $securityConfig)
    $securityRecords=0
    if ($securityReadable) { $securityRecords=[int](Get-OptionalProperty $securityConfig 'RecordCount' -1) }
    $systemConfig=$null
    try { $systemConfig=Get-WinEvent -ListLog System -ErrorAction Stop } catch { }
    $systemReadable=($null -ne $systemConfig)
    $systemRecords=0
    if ($systemReadable) { $systemRecords=[int](Get-OptionalProperty $systemConfig 'RecordCount' -1) }
    $cleared=@()
    $legacyCleared=@()
    $serviceInstalls=@()
    $serviceStartChanges=@()
    $taskCreates=@()
    $accountCreates=@()
    if ($securityReadable) {
        $cleared=@(Get-RecentEventRecord 'Security' @(1102) 10)
        $legacyCleared=@(Get-RecentEventRecord 'Security' @(104) 10)
        $taskCreates=@(Get-RecentEventRecord 'Security' @(4698) 20)
        $accountCreates=@(Get-RecentEventRecord 'Security' @(4720) 20)
    }
    if ($systemReadable) {
        $serviceInstalls=@(Get-RecentEventRecord 'System' @(7045) 25)
        $serviceStartChanges=@(Get-RecentEventRecord 'System' @(7040) 25)
    }
    $script:Inventory.EventLogForensics=[pscustomobject]@{
        SecurityReadable=$securityReadable;SecurityRecords=$securityRecords;SystemReadable=$systemReadable;SystemRecords=$systemRecords
        Cleared=@($cleared);LegacyCleared=@($legacyCleared);ServiceInstalls=@($serviceInstalls)
        ServiceStartChanges=@($serviceStartChanges);TaskCreates=@($taskCreates);AccountCreates=@($accountCreates)
    }
    if (-not $securityReadable -and -not $systemReadable) {
        Add-Result Forensics 'Event log history' FAILED 'Neither the Security nor the System log could be read.' 'Run from an elevated console. An unreadable log is not a clean log; inspect it in Event Viewer before answering forensics questions.'
        return
    }
    $logLines=[System.Collections.Generic.List[string]]::new()
    $logLines.Add("Security log: readable=$securityReadable records=$securityRecords")
    $logLines.Add("System log: readable=$systemReadable records=$systemRecords")
    if ($securityReadable -and $securityRecords -eq 0) {
        Add-Result Forensics 'Security log is empty' REVIEW 'The Security log exists but holds zero records on a machine that has been used.' 'A cleared log that has not repopulated looks exactly like this. Check 1102 in the System/archive logs and record it as evidence before rebuilding auditing.'
    }
    foreach ($entry in $cleared) {
        $actor=''
        if ($entry.Text -match '(?i)Account Name:\s*(\S+)') { $actor=$Matches[1] }
        $detail="1102 at $($entry.Time.ToString('yyyy-MM-dd HH:mm:ss')) by '$actor' ($($entry.Text))"
        $logLines.Add($detail)
        Add-HighSignal 'LOG-CLEARED' "1102 $($entry.Time.ToString('o'))" $detail 'A cleared audit log destroys the record of everything that ran. Preserve the log file, note the account, and answer any related forensics question before changing anything.'
    }
    foreach ($entry in $legacyCleared) {
        $detail="Legacy event 104 at $($entry.Time.ToString('yyyy-MM-dd HH:mm:ss')) ($($entry.Text))"
        $logLines.Add($detail)
        Add-HighSignal 'LOG-CLEARED' "104 $($entry.Time.ToString('o'))" $detail 'Event 104 is the pre-Vista log-clear record. Treat it the same as 1102.'
    }
    $suspiciousInstall=[System.Collections.Generic.List[object]]::new()
    foreach ($entry in $serviceInstalls) {
        $serviceName=''; $serviceFile=''
        if ($entry.Text -match '(?i)Service Name:\s*(.+?)\s+Service File Name:\s*(.+?)(\s+Service Type:|\s+Service Start Type:|$)') {
            $serviceName=$Matches[1].Trim(); $serviceFile=$Matches[2].Trim()
        }
        $summary="7045 $($entry.Time.ToString('yyyy-MM-dd HH:mm:ss')) service '$serviceName' file '$serviceFile'"
        $logLines.Add($summary)
        if (-not [string]::IsNullOrWhiteSpace($serviceFile)) {
            $resolved=Resolve-ServiceImagePath $serviceFile
            if ([string]::IsNullOrWhiteSpace($resolved)) { $resolved=(ConvertTo-ExecutablePath $serviceFile) }
            $severity='Review'
            $why='installed after the image was built'
            if (-not [string]::IsNullOrWhiteSpace($resolved)) {
                if (Test-UserWritableLocation ($resolved)) { $severity='High'; $why='service binary sits in a user-writable path' }
                $provenance=Get-FileProvenance $resolved
                if ($provenance.Severity -eq 'High') { $severity='High'; $why="service binary cannot prove its publisher [$([string]$provenance.Class)]" }
            }
            if ($severity -eq 'High') {
                $suspiciousInstall.Add([pscustomobject]@{Name=$serviceName;File=$serviceFile;Time=$entry.Time;Why=$why})
                Add-HighSignal 'SERVICE-INSTALL' $serviceName "$summary ($why)" 'A service installed from a writable or unverifiable path is the strongest persistence signal in the log. Record the hash, then disable it only with scenario approval.'
            }
        }
    }
    foreach ($entry in $serviceStartChanges) {
        $logLines.Add("7040 $($entry.Time.ToString('yyyy-MM-dd HH:mm:ss')) $($entry.Text)")
    }
    # Task creations are listed, not raised: Windows and installers create tasks all
    # the time, and the scheduled-task audit already judges every task that exists.
    foreach ($entry in $taskCreates) {
        $taskName=''
        if ($entry.Text -match '(?i)Task Name:\s*(\S+)') { $taskName=$Matches[1] }
        $logLines.Add("4698 $($entry.Time.ToString('yyyy-MM-dd HH:mm:ss')) task '$taskName'")
    }
    # The new account's name follows "New Account: ... Account Name:" in event 4720.
    # Only an account outside the supplied allowlists is a lead; without the lists
    # every account the image builder created would appear here.
    foreach ($entry in $accountCreates) {
        $newAccount=''
        if ($entry.Text -match '(?i)New Account:\s*Security ID:\s*\S+\s*Account Name:\s*(\S+)') { $newAccount=$Matches[1] }
        $logLines.Add("4720 $($entry.Time.ToString('yyyy-MM-dd HH:mm:ss')) account '$newAccount'")
        if (-not [string]::IsNullOrWhiteSpace($newAccount) -and ($script:HasUserAllowlist -or $script:HasAdminAllowlist) -and $newAccount -notin $AuthorizedUsers -and $newAccount -notin $AuthorizedAdministrators) {
            Add-HighSignal 'ACCOUNT-CREATED' $newAccount "An account that is not in -AuthorizedUsers or -AuthorizedAdministrators was created at $($entry.Time.ToString('yyyy-MM-dd HH:mm:ss')): $newAccount" 'Confirm the account against the README; remove it with -RemoveUsers if it is unauthorized.'
        }
    }
    $summaryText=($logLines | Select-Object -First 18) -join '; '
    if ($suspiciousInstall.Count) {
        Add-Result Forensics 'Event log history' REVIEW $summaryText "$($suspiciousInstall.Count) service installation(s) came from a writable or unverifiable path. Service install events survive a cleanup of the service itself, so record the event before removing anything."
    } else {
        Add-Result Forensics 'Event log history' REVIEW $summaryText 'Review the listed log-clear, service-install, task-create, and account-create events against the README. Event history is evidence: answer forensics questions before deleting or altering the objects they name.'
    }
}
function ConvertFrom-Rot13 {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $chars=[char[]]$Text.ToCharArray()
    for ($i=0; $i -lt $chars.Length; $i++) {
        $code=[int]$chars[$i]
        if ($code -ge 97 -and $code -le 122) { $chars[$i]=[char]((($code-97+13)%26)+97) }
        elseif ($code -ge 65 -and $code -le 90) { $chars[$i]=[char]((($code-65+13)%26)+65) }
    }
    return (-join $chars)
}
function Get-AmcacheEntries {
    # Item 7 helper. Amcache records applications that executed even when the
    # Prefetch file is gone. Windows usually keeps Amcache.hve open, so a plain copy
    # can fail; the section then reports zero records instead of guessing.
    param([int]$MaxEntries=4000)
    $result=[System.Collections.Generic.List[object]]::new()
    $source=Join-Path $env:SystemRoot 'AppCompat\Programs\Amcache.hve'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { return @() }
    $temp=Join-Path ([IO.Path]::GetTempPath()) ("cypat-amcache-"+[guid]::NewGuid().ToString('N')+'.hve')
    try { Copy-Item -LiteralPath $source -Destination $temp -Force -ErrorAction Stop } catch { return @() }
    $mount='HKLM\CYPatAmcacheAudit'
    $null=Invoke-RegUnload -Mount $mount -Attempts 1
    if (-not (Invoke-RegLoad $mount $temp)) {
        Remove-Item -Path "$temp*" -Force -ErrorAction SilentlyContinue
        return @()
    }
    try {
        $root='Registry::HKEY_LOCAL_MACHINE\CYPatAmcacheAudit\Root\InventoryApplicationFile'
        if (Test-Path -LiteralPath $root) {
            foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                try {
                    if ($result.Count -ge $MaxEntries) { continue }
                    $path=[string]$key.GetValue('LowerCaseLongPath')
                    if ([string]::IsNullOrWhiteSpace($path)) { continue }
                    $result.Add([pscustomobject]@{Path=$path;Publisher=[string]$key.GetValue('Publisher');Version=[string]$key.GetValue('Version')})
                } finally {
                    $key.Close()
                }
            }
        }
    } catch { } finally {
        $null=Invoke-RegUnload -Mount $mount
        Remove-Item -Path "$temp*" -Force -ErrorAction SilentlyContinue
    }
    return @($result)
}
function Get-UserAssistRecords {
    param([int]$MaxEntries=120)
    $records=[System.Collections.Generic.List[object]]::new()
    $root='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    if (-not (Test-Path -LiteralPath $root)) { return @() }
    foreach ($guidKey in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        $countKey=Join-Path $guidKey.PSPath 'Count'
        if (-not (Test-Path -LiteralPath $countKey)) { continue }
        try { $item=Get-Item -LiteralPath $countKey -ErrorAction Stop } catch { continue }
        foreach ($valueName in @($item.GetValueNames())) {
            if ($records.Count -ge $MaxEntries) { break }
            if ([string]::IsNullOrWhiteSpace($valueName) -or $valueName -eq 'UEME_CTLSESSION') { continue }
            $decoded=ConvertFrom-Rot13 $valueName
            $runCount=0
            $lastRun=$null
            try {
                $bytes=@($item.GetValue($valueName))
                if ($bytes.Count -ge 8) { $runCount=[BitConverter]::ToInt32([byte[]]$bytes,4) }
                if ($bytes.Count -ge 68) {
                    $fileTime=[BitConverter]::ToInt64([byte[]]$bytes,60)
                    if ($fileTime -gt 0) { $lastRun=[DateTime]::FromFileTimeUtc($fileTime).ToLocalTime() }
                }
            } catch { }
            $records.Add([pscustomobject]@{Name=$decoded;RunCount=$runCount;LastRun=$lastRun;Store=$guidKey.PSChildName})
        }
    }
    return @($records | Sort-Object LastRun -Descending)
}
function Get-BamRecords {
    param([int]$MaxEntries=80)
    $records=[System.Collections.Generic.List[object]]::new()
    $roots=@(
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($sidKey in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $account=$sidKey.PSChildName
            try { $account=([Security.Principal.SecurityIdentifier]$sidKey.PSChildName).Translate([Security.Principal.NTAccount]).Value } catch { }
            try { $item=Get-Item -LiteralPath $sidKey.PSPath -ErrorAction Stop } catch { continue }
            foreach ($valueName in @($item.GetValueNames())) {
                if ($records.Count -ge $MaxEntries) { break }
                if ([string]::IsNullOrWhiteSpace($valueName)) { continue }
                $lastRun=$null
                try {
                    $bytes=@($item.GetValue($valueName))
                    if ($bytes.Count -ge 8) {
                        $fileTime=[BitConverter]::ToInt64([byte[]]$bytes,0)
                        if ($fileTime -gt 0 -and $fileTime -lt 2650467743999999999) { $lastRun=[DateTime]::FromFileTimeUtc($fileTime).ToLocalTime() }
                    }
                } catch { }
                $records.Add([pscustomobject]@{Account=$account;Path=$valueName;LastRun=$lastRun})
            }
        }
    }
    return @($records | Sort-Object LastRun -Descending)
}
function Invoke-ExecutionArtifactAudit {
    # Item 7. Prefetch, RunMRU, UserAssist, BAM, and Amcache answer "what ran here"
    # after a binary is deleted. Every source is read; none is modified.
    $prefetch=@()
    $prefetchDir=Join-Path $env:SystemRoot 'Prefetch'
    if (Test-Path -LiteralPath $prefetchDir) {
        $prefetch=@(Get-ChildItem -LiteralPath $prefetchDir -Filter '*.pf' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    }
    $prefetchNames=@($prefetch | ForEach-Object { (($_.BaseName -replace '-[0-9A-Fa-f]{8}$','') -replace '(?i)\.(exe|com|scr|pif)$','').ToUpperInvariant() })
    $prefetchEnabled=''
    $prefetchPolicy=Get-RegistryValueText 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' 'EnablePrefetch'
    if ($null -ne $prefetchPolicy) { $prefetchEnabled=$prefetchPolicy }
    $runMru=[System.Collections.Generic.List[string]]::new()
    $runMruPath='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
    if (Test-Path -LiteralPath $runMruPath) {
        try {
            $item=Get-Item -LiteralPath $runMruPath -ErrorAction Stop
            $order=Get-RegistryValueText $runMruPath 'MRUList'
            $sequence=@()
            if (-not [string]::IsNullOrWhiteSpace($order)) { $sequence=@($order.ToCharArray() | ForEach-Object { [string]$_ }) }
            foreach ($letter in $sequence) {
                $value=[string]$item.GetValue($letter)
                if ([string]::IsNullOrWhiteSpace($value)) { continue }
                $command=($value -replace '\\1$','').Trim()
                if ([string]::IsNullOrWhiteSpace($command)) { continue }
                $runMru.Add($command)
            }
        } catch { }
    }
    $userAssist=@(Get-UserAssistRecords)
    $bam=@(Get-BamRecords)
    $amcache=@(Get-AmcacheEntries)
    $script:Inventory.ExecutionArtifacts=[pscustomobject]@{
        PrefetchCount=$prefetch.Count;PrefetchEnabled=$prefetchEnabled;Prefetch=@($prefetch | Select-Object -First 60 Name,LastWriteTime,Length)
        RunMru=@($runMru);UserAssist=@($userAssist);Bam=@($bam);AmcacheCount=$amcache.Count
    }
    # WMIC and VSSADMIN are left out: Windows and installers run them routinely.
    $credentialTools=@('MIMIKATZ','PWDUMP','PROCDUMP','LAZAGNE','GSECDUMP','CACHEDUMP','WCE','PSEXEC','NC','NCAT','NETCAT','CRYPTCAT','PLINK','RCLONE','NTDSUTIL','SECRETSDUMP')
    foreach ($name in $prefetchNames) {
        if ($credentialTools -notcontains $name) { continue }
        Add-HighSignal 'EXECUTION' $name "Prefetch record for $name.exe exists in $prefetchDir" 'A credential-dumping or lateral-movement tool executed on this image. Capture the .pf file and the tool itself as evidence before deleting either.'
    }
    $amcacheSuspicious=[System.Collections.Generic.List[string]]::new()
    $checked=0
    foreach ($entry in $amcache) {
        if ($checked -ge 120) { break }
        $path=[string]$entry.Path
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        if ($path.StartsWith(([string]$env:SystemRoot),[StringComparison]::OrdinalIgnoreCase)) { continue }
        $extension=[IO.Path]::GetExtension($path)
        if (@('.exe','.dll','.scr','.sys','.ps1','.bat','.cmd','.js','.vbs') -notcontains $extension.ToLowerInvariant()) { continue }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $checked++
        $provenance=Get-FileProvenance $path
        if ($provenance.Severity -eq 'High') {
            $amcacheSuspicious.Add("$path [$(Format-Provenance $provenance)]")
            Add-HighSignal 'EXECUTION' $path "Amcache records execution: $path [$([string]$provenance.Class)]" 'Amcache proves the file ran even if Prefetch is gone. Capture the file and hash before changing it.'
        }
    }
    $detail=[System.Collections.Generic.List[string]]::new()
    $detail.Add("Prefetch: $($prefetch.Count) record(s), EnablePrefetch=$prefetchEnabled")
    if ($prefetch.Count) {
        $detail.Add('Most recent: '+(($prefetch | Select-Object -First 8 | ForEach-Object { "$($_.BaseName)@$($_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))" }) -join ', '))
    }
    if ($runMru.Count) { $detail.Add('RunMRU: '+(($runMru | Select-Object -First 8) -join ' | ')) }
    if ($userAssist.Count) { $detail.Add('UserAssist: '+(($userAssist | Select-Object -First 6 | ForEach-Object { "$($_.Name) x$($_.RunCount)" }) -join ', ')) }
    if ($bam.Count) { $detail.Add('BAM: '+(($bam | Select-Object -First 6 | ForEach-Object { "$($_.Path)@$($_.LastRun)" }) -join ', ')) }
    $detail.Add("Amcache: $($amcache.Count) application record(s)")
    $evidence=($detail -join '; ')
    if ($amcacheSuspicious.Count) {
        Add-Result Forensics 'Execution artifacts' REVIEW ($evidence+'; suspicious: '+(($amcacheSuspicious | Select-Object -First 6) -join '; ')) 'Amcache names files that cannot prove their origin. Record the path and hash, then answer any forensics question that references them.'
    } else {
        Add-Result Forensics 'Execution artifacts' REVIEW $evidence 'Prefetch, RunMRU, UserAssist, BAM, and Amcache are execution evidence. Use them to answer "what ran" questions; do not clear them as part of cleanup.'
    }
    # Windows Server ships with Prefetch turned off, so an empty Prefetch folder is
    # only a lead on a Windows client.
    $isServerSku=($os.ProductType -ne 1)
    if ($prefetch.Count -eq 0) {
        if ($isServerSku) {
            Add-Result Forensics 'Prefetch availability' SKIPPED "Windows Server disables Prefetch by default (EnablePrefetch=$prefetchEnabled), so no .pf history is expected." 'Use Amcache, BAM, and the event logs for execution history on a server.'
        } else {
            Add-Result Forensics 'Prefetch availability' REVIEW "EnablePrefetch=$prefetchEnabled and no .pf file was found in $prefetchDir." 'Prefetch is either disabled or was cleared. A disabled or emptied Prefetch store removes the easiest execution history, so record its state before remediation.'
        }
    } elseif ($prefetchEnabled -eq '0' -and -not $isServerSku) {
        Add-Result Forensics 'Prefetch disabled' REVIEW "EnablePrefetch=0 with $($prefetch.Count) leftover record(s)." 'Disabling Prefetch hides future execution history. Re-enable it only if the README does not require the current setting.'
    }
}
function Get-PortProxyRecords {
    $records=[System.Collections.Generic.List[object]]::new()
    $map=@{
        'v4tov4\tcp'='IPv4 to IPv4 TCP';'v4tov4\udp'='IPv4 to IPv4 UDP'
        'v4tov6\tcp'='IPv4 to IPv6 TCP';'v4tov6\udp'='IPv4 to IPv6 UDP'
        'v6tov4\tcp'='IPv6 to IPv4 TCP';'v6tov4\udp'='IPv6 to IPv4 UDP'
        'v6tov6\tcp'='IPv6 to IPv6 TCP';'v6tov6\udp'='IPv6 to IPv6 UDP'
    }
    foreach ($key in $map.Keys) {
        $path="HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\$key"
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try { $item=Get-Item -LiteralPath $path -ErrorAction Stop } catch { continue }
        foreach ($name in @($item.GetValueNames())) {
            $target=''
            try { $target=[string]$item.GetValue($name) } catch { $target='' }
            if ([string]::IsNullOrWhiteSpace($target)) { continue }
            $records.Add([pscustomobject]@{Mode=$map[$key];Listen=$name;Forward=$target})
        }
    }
    return @($records)
}
function Invoke-NetworkPivotAudit {
    # Item 8. A pivot is any rule that sends traffic somewhere the README does not
    # describe: port proxy, persistent route, hosts override, proxy, or trusted site.
    $findings=[System.Collections.Generic.List[string]]::new()
    $proxies=@(Get-PortProxyRecords)
    foreach ($proxy in $proxies) {
        $findings.Add("portproxy [$($proxy.Mode)] $($proxy.Listen) -> $($proxy.Forward)")
        Add-HighSignal 'PORT-PROXY' "$($proxy.Listen) -> $($proxy.Forward)" "A netsh portproxy entry forwards $($proxy.Listen) to $($proxy.Forward)." 'A port proxy turns this host into a relay. Record the endpoints, then remove the entry with netsh interface portproxy delete after confirming it is not README-required.'
    }
    $routes=@()
    try { $routes=@(Get-NetRoute -PolicyStore PersistentStore -ErrorAction SilentlyContinue) } catch { $routes=@() }
    foreach ($route in $routes) {
        # A static IP address stores its default gateway as a persistent route.
        if ([string]$route.DestinationPrefix -in @('0.0.0.0/0','::/0')) { continue }
        $findings.Add("persistent route $($route.DestinationPrefix) -> $($route.NextHop) on $($route.InterfaceAlias)")
        Add-HighSignal 'ROUTE' "$($route.DestinationPrefix) -> $($route.NextHop)" "A persistent route was added for $($route.DestinationPrefix) via $($route.NextHop)." 'Compare the route against the README network diagram. An unexplained persistent route is a pivot that survives a reboot.'
    }
    $hostsPath=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hostsExtra=[System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $hostsPath -PathType Leaf) {
        try {
            foreach ($line in @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop)) {
                $text=$line.Trim()
                if ([string]::IsNullOrWhiteSpace($text) -or $text.StartsWith('#')) { continue }
                if ($text -match '^(?i)\s*127\.0\.0\.1\s+localhost\s*$') { continue }
                if ($text -match '^(?i)\s*::1\s+localhost\s*$') { continue }
                $hostsExtra.Add($text)
            }
        } catch { }
    }
    foreach ($entry in $hostsExtra) {
        $findings.Add("hosts override: $entry")
        Add-HighSignal 'HOSTS' $entry "The hosts file maps $entry." 'A hosts entry redirects a name the image trusts. Record the line, then restore the default hosts file after answering any forensics question.'
    }
    $proxySettings=[System.Collections.Generic.List[string]]::new()
    foreach ($scope in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings')) {
        if (-not (Test-Path -LiteralPath $scope)) { continue }
        $enabled=Get-RegistryValueText $scope 'ProxyEnable'
        $server=Get-RegistryValueText $scope 'ProxyServer'
        $autoConfig=Get-RegistryValueText $scope 'AutoConfigURL'
        if ($enabled -eq '1' -or -not [string]::IsNullOrWhiteSpace($server)) { $proxySettings.Add("$scope ProxyEnable=$enabled ProxyServer=$server") }
        if (-not [string]::IsNullOrWhiteSpace($autoConfig)) { $proxySettings.Add("$scope AutoConfigURL=$autoConfig") }
    }
    foreach ($entry in $proxySettings) { $findings.Add("proxy: $entry") }
    $zoneRoot='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains'
    $trustedSites=[System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $zoneRoot) {
        foreach ($domainKey in @(Get-ChildItem -LiteralPath $zoneRoot -ErrorAction SilentlyContinue)) {
            foreach ($schemeKey in @(Get-ChildItem -LiteralPath $domainKey.PSPath -ErrorAction SilentlyContinue)) {
                $value=Get-RegistryValueText $schemeKey.PSPath $schemeKey.PSChildName
                if ($null -eq $value) { continue }
                if ($value -eq '2' -or $value -eq '1') { $trustedSites.Add("$($domainKey.PSChildName) ($($schemeKey.PSChildName)=$value)") }
            }
        }
    }
    foreach ($entry in $trustedSites) { $findings.Add("trusted/intranet site: $entry") }
    $script:Inventory.NetworkPivots=[pscustomobject]@{PortProxy=@($proxies);PersistentRoutes=@($routes);HostsOverrides=@($hostsExtra);Proxy=@($proxySettings);TrustedSites=@($trustedSites)}
    if ($findings.Count) {
        Add-Result Network 'Network pivots and redirection' REVIEW (($findings | Select-Object -First 14) -join '; ') 'Each entry moves traffic outside the path the README describes. Record it, answer any related forensics question, then remove the entry only after confirming it is not a required part of the scenario.'
    } else {
        Add-Result Network 'Network pivots and redirection' PASS 'No port proxy, persistent route, hosts override, proxy, or trusted-site entry was found.' ''
    }
}
function ConvertTo-ProcessBaseName {
    # Win32_Process.Name carries the .exe suffix; owner patterns below do not.
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    return ($Name.Trim() -replace '(?i)\.exe$','')
}
function Get-PortCatalog {
    # Named ports. Title is what the operator sees. Need is the README requirement
    # that makes the port expected (see Get-PortNeedMap); 'Core' is always expected,
    # 'DC' is expected on a domain controller, and an empty Need means nothing on a
    # competition image should listen there. Owners is the usual process, without
    # .exe. This explains a port; it is not an allowlist.
    if ($null -ne $script:PortCatalog) { return $script:PortCatalog }
    $web='^(System|w3wp|inetinfo|httpd|nginx|apache|php-cgi|node|java|javaw|tomcat\d*|python|pythonw)$'
    $vnc='^(tvnserver|winvnc|uvnc_service|vncserver|vncserver-x11-serviced)$'
    $ftp='^(svchost|inetinfo|filezilla.*)$'
    $rows=@(
        @('tcp',7,'Echo','SimpleTCP','^(tcpsvcs)$','Legacy Simple TCP/IP test service; nothing on the image should need it.'),
        @('tcp',9,'Discard','SimpleTCP','^(tcpsvcs)$','Legacy Simple TCP/IP test service; nothing on the image should need it.'),
        @('tcp',13,'Daytime','SimpleTCP','^(tcpsvcs)$','Legacy Simple TCP/IP test service; nothing on the image should need it.'),
        @('tcp',17,'Quote of the Day','SimpleTCP','^(tcpsvcs)$','Legacy Simple TCP/IP test service; nothing on the image should need it.'),
        @('tcp',19,'Chargen','SimpleTCP','^(tcpsvcs)$','Legacy test service that can be abused for traffic amplification.'),
        @('tcp',20,'FTP data','FTP',$ftp,'Cleartext file transfer.'),
        @('tcp',21,'FTP','FTP',$ftp,'Cleartext file transfer; anonymous logons are common.'),
        @('tcp',22,'SSH','SSH','^(sshd)$','Remote shell access to this machine.'),
        @('tcp',23,'Telnet','Telnet','^(tlntsvr)$','Cleartext remote shell; passwords cross the network unencrypted.'),
        @('tcp',25,'SMTP','SMTP','^(inetinfo|smtpsvc|edgetransport|msexchangefrontendtransport|hmailserver)$','Mail relay; an open relay sends mail for anyone.'),
        @('tcp',53,'DNS','DNS','^(dns)$','Name server.'),
        @('tcp',79,'Finger','','','Legacy user-information service that leaks account names.'),
        @('tcp',80,'HTTP','Web',$web,'Web server.'),
        @('tcp',88,'Kerberos','DC','^(lsass)$','Domain controller authentication.'),
        @('tcp',110,'POP3','Mail','','Cleartext mail retrieval.'),
        @('tcp',111,'RPC portmapper','NFS','','Unix RPC portmapper used by NFS.'),
        @('tcp',135,'RPC endpoint mapper','Core','^(svchost)$','Windows RPC.'),
        @('tcp',139,'NetBIOS session','Core','^(System)$','Legacy Windows file sharing.'),
        @('tcp',143,'IMAP','Mail','','Cleartext mail retrieval.'),
        @('tcp',389,'LDAP','DC','^(lsass)$','Directory service.'),
        @('tcp',443,'HTTPS','Web',$web,'Web server over TLS.'),
        @('tcp',445,'SMB','SMB','^(System)$','Windows file and printer sharing.'),
        @('tcp',464,'Kerberos password change','DC','^(lsass)$','Domain controller password service.'),
        @('tcp',465,'SMTP over TLS','SMTP','','Mail submission.'),
        @('tcp',512,'rexec','','','Legacy Unix remote execution that sends passwords in cleartext.'),
        @('tcp',513,'rlogin','','','Legacy Unix remote login that trusts hosts by name.'),
        @('tcp',514,'rsh','','','Legacy Unix remote shell with no password.'),
        @('tcp',515,'LPD printing','Print','','Line printer daemon.'),
        @('tcp',587,'SMTP submission','SMTP','','Mail submission.'),
        @('tcp',593,'RPC over HTTP','Core','^(svchost|System)$','Windows RPC over HTTP.'),
        @('tcp',636,'LDAPS','DC','^(lsass)$','Directory service over TLS.'),
        @('tcp',873,'rsync','','','File synchronisation daemon, often unauthenticated.'),
        @('tcp',990,'FTPS','FTP',$ftp,'FTP over TLS.'),
        @('tcp',993,'IMAPS','Mail','','Mail retrieval over TLS.'),
        @('tcp',995,'POP3S','Mail','','Mail retrieval over TLS.'),
        @('tcp',1080,'SOCKS proxy','','','Proxy that relays other machines'' traffic through this one.'),
        @('tcp',1337,'Backdoor port 1337','','','Frequently used by backdoors and reverse shells.'),
        @('tcp',1433,'SQL Server','SQL','^(sqlservr)$','Database server.'),
        @('tcp',1434,'SQL Server admin connection','SQL','^(sqlservr)$','Database administrator connection.'),
        @('tcp',1521,'Oracle database','Oracle','^(tnslsnr)$','Database listener.'),
        @('tcp',1723,'PPTP VPN','VPN','^(System|svchost)$','Legacy VPN with weak encryption.'),
        @('tcp',2049,'NFS','NFS','^(System)$','Network file system.'),
        @('tcp',2179,'Hyper-V VM connect','HyperV','^(vmms)$','Hyper-V console access.'),
        @('tcp',2869,'UPnP device host','Core','^(System)$','Windows device discovery.'),
        @('tcp',3268,'Global Catalog','DC','^(lsass)$','Domain controller directory search.'),
        @('tcp',3269,'Global Catalog over TLS','DC','^(lsass)$','Domain controller directory search.'),
        @('tcp',3306,'MySQL','MySQL','^(mysqld|mariadbd)$','Database server.'),
        @('tcp',3389,'RDP','RDP','^(svchost)$','Remote Desktop.'),
        @('tcp',4444,'Backdoor port 4444','','','Default port of Metasploit handlers and many reverse shells.'),
        @('tcp',4899,'Radmin','','','Remote-control tool often used as a backdoor.'),
        @('tcp',5040,'Connected Devices Platform','Core','^(svchost)$','Windows device sync.'),
        @('tcp',5357,'WSD API','Core','^(System)$','Windows network discovery for devices.'),
        @('tcp',5432,'PostgreSQL','PostgreSQL','^(postgres)$','Database server.'),
        @('tcp',5555,'Backdoor port 5555','','','Used by remote-access trojans and debug bridges.'),
        @('tcp',5800,'VNC over HTTP','VNC',$vnc,'Remote desktop viewer.'),
        @('tcp',5900,'VNC','VNC',$vnc,'Remote desktop control that is often weakly protected.'),
        @('tcp',5901,'VNC','VNC',$vnc,'Remote desktop control that is often weakly protected.'),
        @('tcp',5902,'VNC','VNC',$vnc,'Remote desktop control that is often weakly protected.'),
        @('tcp',5938,'TeamViewer','TeamViewer','^(teamviewer_service|teamviewer)$','Remote-control tool.'),
        @('tcp',5985,'WinRM','WinRM','^(System|svchost)$','PowerShell remoting over HTTP.'),
        @('tcp',5986,'WinRM over HTTPS','WinRM','^(System|svchost)$','PowerShell remoting over HTTPS.'),
        @('tcp',6379,'Redis','','','In-memory database that is unauthenticated by default.'),
        @('tcp',6666,'Backdoor port 6666','','','Used by backdoors and IRC bots.'),
        @('tcp',6667,'IRC','','','IRC, a classic botnet command channel.'),
        @('tcp',7070,'AnyDesk direct','AnyDesk','^(anydesk)$','Remote-control tool.'),
        @('tcp',7680,'Delivery Optimization','Core','^(svchost)$','Windows Update peer sharing.'),
        @('tcp',8080,'HTTP alternate','Web',$web,'Web server on an alternate port.'),
        @('tcp',8443,'HTTPS alternate','Web',$web,'Web server on an alternate port.'),
        @('tcp',9100,'Raw printing','Print','','Printer port.'),
        @('tcp',9200,'Elasticsearch','','','Search database that is unauthenticated by default.'),
        @('tcp',9389,'AD Web Services','DC','^(microsoft\.activedirectory\.webservices)$','Active Directory PowerShell endpoint.'),
        @('tcp',11211,'memcached','','','Cache server that is unauthenticated by default.'),
        @('tcp',12345,'NetBus','','','Default port of the NetBus remote-control trojan.'),
        @('tcp',20034,'NetBus Pro','','','Default port of the NetBus Pro trojan.'),
        @('tcp',27017,'MongoDB','','','Database that is often left unauthenticated.'),
        @('tcp',31337,'Back Orifice','','','Classic backdoor port.'),
        @('tcp',47001,'WinRM listener','WinRM','^(System)$','WinRM management listener.'),
        @('udp',53,'DNS','DNS','^(dns)$','Name server.'),
        @('udp',67,'DHCP server','DHCP','^(svchost)$','Hands out IP addresses.'),
        @('udp',68,'DHCP client','Core','^(svchost)$','Receives this machine''s IP address.'),
        @('udp',69,'TFTP','TFTP','^(svchost|tftpd.*)$','Unauthenticated file transfer.'),
        @('udp',88,'Kerberos','DC','^(lsass)$','Domain controller authentication.'),
        @('udp',123,'NTP','Core','^(svchost)$','Time synchronisation.'),
        @('udp',137,'NetBIOS name service','Core','^(System)$','Legacy name resolution.'),
        @('udp',138,'NetBIOS datagram','Core','^(System)$','Legacy network browsing.'),
        @('udp',161,'SNMP','SNMP','^(snmp)$','Device monitoring; default community strings leak configuration.'),
        @('udp',162,'SNMP trap','SNMP','^(snmptrap)$','Monitoring traps.'),
        @('udp',389,'LDAP (CLDAP)','DC','^(lsass)$','Domain controller locator.'),
        @('udp',464,'Kerberos password change','DC','^(lsass)$','Domain controller password service.'),
        @('udp',500,'IPsec IKE','Core','^(svchost)$','IPsec key exchange.'),
        @('udp',514,'Syslog','','','Log receiver.'),
        @('udp',1434,'SQL Server Browser','SQL','^(sqlbrowser)$','Advertises SQL Server instances.'),
        @('udp',1701,'L2TP VPN','VPN','^(System|svchost)$','VPN tunnel.'),
        @('udp',1900,'SSDP','Core','^(svchost)$','Device discovery.'),
        @('udp',3389,'RDP (UDP)','RDP','^(svchost)$','Remote Desktop.'),
        @('udp',3702,'WS-Discovery','Core','^(svchost|dashost)$','Device discovery.'),
        @('udp',4500,'IPsec NAT-T','Core','^(svchost)$','IPsec through NAT.'),
        @('udp',5353,'mDNS','Core','^(svchost|chrome|msedge|firefox|System)$','Multicast name resolution.'),
        @('udp',5355,'LLMNR','Core','^(svchost)$','Multicast name resolution.')
    )
    $catalog=@{}
    foreach ($row in $rows) {
        $catalog["$($row[0])/$($row[1])"]=@{Title=[string]$row[2];Need=[string]$row[3];Owners=[string]$row[4];Risk=[string]$row[5];Risky=([string]$row[3] -eq '')}
    }
    $script:PortCatalog=$catalog
    return $catalog
}
function Get-PortNeedMap {
    # Need -> the -RequiredServices alias (Logical), the service names whose Y/N
    # answer or protection decides it, and extra decision keys (RDP has its own).
    return @{
        SSH=@{Logical='SSH';Services=@('sshd');Decisions=@()}
        FTP=@{Logical='FTP';Services=@('FTPSVC','filezilla-server','FileZilla Server');Decisions=@()}
        Telnet=@{Logical='';Services=@('TlntSvr');Decisions=@()}
        SMTP=@{Logical='SMTP';Services=@('SMTPSVC','MSExchangeFrontEndTransport','MSExchangeTransport','hMailServer');Decisions=@()}
        Mail=@{Logical='';Services=@('MSExchangeIMAP4','MSExchangePOP3','hMailServer');Decisions=@()}
        DNS=@{Logical='DNS';Services=@('DNS');Decisions=@()}
        DHCP=@{Logical='DHCP';Services=@('DHCPServer');Decisions=@()}
        Web=@{Logical='IIS';Services=@('W3SVC','WAS','Apache2.4','Apache2.2','nginx','Tomcat9','Tomcat10');Decisions=@()}
        RDP=@{Logical='RDP';Services=@('TermService');Decisions=@('RDP')}
        SMB=@{Logical='SMB';Services=@('LanmanServer');Decisions=@();Optional=$true}
        WinRM=@{Logical='WinRM';Services=@('WinRM');Decisions=@()}
        Print=@{Logical='Print';Services=@('Spooler','LPDSVC');Decisions=@()}
        SNMP=@{Logical='';Services=@('SNMP','SNMPTRAP');Decisions=@()}
        SimpleTCP=@{Logical='';Services=@('simptcp');Decisions=@()}
        VPN=@{Logical='';Services=@('RemoteAccess');Decisions=@()}
        TFTP=@{Logical='';Services=@('tftpd','WDSServer');Decisions=@()}
        SQL=@{Logical='';Services=@('MSSQLSERVER','MSSQL$SQLEXPRESS','SQLBrowser');Decisions=@()}
        MySQL=@{Logical='';Services=@('MySQL','MySQL80','MySQL57','MariaDB');Decisions=@()}
        PostgreSQL=@{Logical='';Services=@('postgresql-x64-14','postgresql-x64-15','postgresql-x64-16','postgresql-x64-17');Decisions=@()}
        Oracle=@{Logical='';Services=@('OracleServiceXE','OracleOraDB21Home1TNSListener');Decisions=@()}
        HyperV=@{Logical='';Services=@('vmms');Decisions=@()}
        NFS=@{Logical='';Services=@('NfsService','NfsServer');Decisions=@()}
        VNC=@{Logical='';Services=@('tvnserver','uvnc_service','vncserver');Decisions=@()}
        TeamViewer=@{Logical='';Services=@('TeamViewer');Decisions=@()}
        AnyDesk=@{Logical='';Services=@('AnyDesk');Decisions=@()}
    }
}
function Get-PortNeedState {
    # Core, Role, Required, Kept, TurnedOff, Optional, or Unknown for one Need.
    param([string]$Need)
    if ($Need -eq 'Core') { return 'Core' }
    if ($Need -eq 'DC') { if ($script:IsDomainController) { return 'Role' } else { return 'Unknown' } }
    if ([string]::IsNullOrWhiteSpace($Need)) { return 'Unknown' }
    $map=Get-PortNeedMap
    if (-not $map.ContainsKey($Need)) { return 'Unknown' }
    $definition=$map[$Need]
    $logical=[string]$definition['Logical']
    if ($logical -and $script:RequiredLogical.ContainsKey($logical)) { return 'Required' }
    $kept=$false
    $off=$false
    foreach ($serviceName in @($definition['Services'])) {
        if (Test-ServiceProtected $serviceName) { return 'Required' }
        if ($script:ServiceDecisions.Contains($serviceName)) {
            $decision=[string]$script:ServiceDecisions[$serviceName]
            if ($decision -eq 'Y') { $kept=$true } elseif ($decision -eq 'N') { $off=$true }
        }
    }
    foreach ($decisionKey in @($definition['Decisions'])) {
        if ($script:ServiceDecisions.Contains($decisionKey)) {
            $decision=[string]$script:ServiceDecisions[$decisionKey]
            if ($decision -eq 'Y') { $kept=$true } elseif ($decision -eq 'N') { $off=$true }
        }
    }
    if ($kept) { return 'Kept' }
    if ($off) { return 'TurnedOff' }
    if ($definition.ContainsKey('Optional') -and [bool]$definition['Optional']) { return 'Optional' }
    return 'Unknown'
}
function Get-PortAcknowledgment {
    param([string]$Key)
    $path='HKLM:\SOFTWARE\CYPatV6\PortAcknowledgments'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { $item=Get-Item -LiteralPath $path -ErrorAction Stop } catch { return $null }
    try {
        $raw=$item.GetValue($Key)
        if ($null -eq $raw) { return $null }
        return [string]$raw
    } catch { return $null }
}
function Set-PortAcknowledgment {
    param([string]$Key,[string]$Owner,[string]$Note)
    $path='HKLM:\SOFTWARE\CYPatV6\PortAcknowledgments'
    try {
        if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
        $value="$Owner|$((Get-Date).ToString('o'))|$Note"
        New-ItemProperty -Path $path -Name $Key -Value $value -PropertyType String -Force -ErrorAction Stop | Out-Null
        return $true
    } catch { return $false }
}
function Get-PortAttributionRecords {
    # Item 10. Every listening socket is tied to its process, owning service(s),
    # and provenance, then named from the port catalog and judged against what the
    # README settings say is needed: -RequiredServices, the service Y/N answers,
    # -AllowedPorts, and earlier keep decisions.
    $catalog=Get-PortCatalog
    $processById=@{}
    if ($script:Inventory.Contains('Processes')) {
        foreach ($process in @($script:Inventory.Processes)) { $processById[[int]$process.ProcessId]=$process }
    }
    $serviceByPid=@{}
    try {
        foreach ($service in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
            $servicePid=[int](Get-OptionalProperty $service 'ProcessId' 0)
            if ($servicePid -le 0) { continue }
            if (-not $serviceByPid.ContainsKey($servicePid)) { $serviceByPid[$servicePid]=[System.Collections.Generic.List[object]]::new() }
            $serviceByPid[$servicePid].Add($service)
        }
    } catch { }
    # Processes that host Windows RPC endpoints on the dynamic range.
    $windowsHosts=@('system','svchost','lsass','wininit','services','spoolsv','dns','dfsrs','ismserv','ntfrs','certsrv','msdtc')
    $stateText=@{Core='a core Windows service';Role='required by the domain controller role';Required='required by -RequiredServices';Kept='kept by the operator in this run';Optional='Windows file sharing, with no README requirement recorded'}
    $endpoints=[System.Collections.Generic.List[object]]::new()
    $tcp=@()
    try { $tcp=@(Get-NetTCPConnection -State Listen -ErrorAction Stop) } catch {
        try { $tcp=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) } catch { $tcp=@() }
    }
    foreach ($listener in $tcp) { $endpoints.Add([pscustomobject]@{Protocol='tcp';Address=[string]$listener.LocalAddress;Port=[int]$listener.LocalPort;PID=[int]$listener.OwningProcess}) }
    try {
        foreach ($endpoint in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) { $endpoints.Add([pscustomobject]@{Protocol='udp';Address=[string]$endpoint.LocalAddress;Port=[int]$endpoint.LocalPort;PID=[int]$endpoint.OwningProcess}) }
    } catch { }
    $records=[System.Collections.Generic.List[object]]::new()
    foreach ($endpoint in $endpoints) {
        $protocol=[string]$endpoint.Protocol
        $port=[int]$endpoint.Port
        $address=[string]$endpoint.Address
        $pidValue=[int]$endpoint.PID
        $processName=''
        $processPath=''
        if ($processById.ContainsKey($pidValue)) {
            $processName=[string](Get-OptionalProperty $processById[$pidValue] 'Name' '')
            $processPath=[string](Get-OptionalProperty $processById[$pidValue] 'ExecutablePath' '')
        }
        if ($pidValue -eq 4) { $processName='System' }
        if ($pidValue -eq 0) { $processName='Idle' }
        $owner=ConvertTo-ProcessBaseName $processName
        $ownerText=if ($processName) { $processName } else { '(no owning process)' }
        $class=''
        $severity=''
        if (-not [string]::IsNullOrWhiteSpace($processPath)) {
            $provenance=Get-FileProvenance $processPath
            $class=[string]$provenance.Class
            $severity=[string]$provenance.Severity
        }
        $services=@()
        if ($serviceByPid.ContainsKey($pidValue)) { $services=@($serviceByPid[$pidValue]) }
        $serviceNames=@($services | ForEach-Object { [string]$_.Name })
        $serviceState=''
        $serviceStartMode=''
        if ($services.Count -eq 1) {
            $serviceState=[string]$services[0].State
            $serviceStartMode=[string]$services[0].StartMode
        } elseif ($services.Count -gt 1) {
            $serviceState='shared process'
            $serviceStartMode='shared process'
        }
        $scope='Specific address'
        if ($address -eq '0.0.0.0' -or $address -eq '::') { $scope='All interfaces' }
        elseif ($address -like '127.*' -or $address -eq '::1') { $scope='Loopback only' }
        $protocolLabel=$protocol.ToUpperInvariant()
        $entry=$null
        if ($catalog.ContainsKey("$protocol/$port")) { $entry=$catalog["$protocol/$port"] }
        $title=''
        $label="$protocolLabel $port"
        if ($null -ne $entry) {
            $title=[string]$entry['Title']
            $label="$title ($protocolLabel $port)"
        }
        $acknowledged=Get-PortAcknowledgment "${protocol}:$port"
        $declared=(@($script:AllowedPortList) -contains "$protocol/$port") -or (@($script:AllowedPortList) -contains [string]$port)
        $trustedBinary=(-not [string]::IsNullOrWhiteSpace($processPath)) -and [string]::IsNullOrEmpty($severity) -and $class -ne 'Missing'
        $verdict='Undeclared'
        $detail='No documented service answers on this port.'
        $risky=$false
        $ownerMismatch=$false
        if ($null -ne $acknowledged) {
            $verdict='Acknowledged'
            $detail="Kept earlier by the operator: $acknowledged"
        } elseif ($declared) {
            $verdict='Declared'
            $detail='Declared with -AllowedPorts.'
        } elseif ($null -ne $entry) {
            $need=[string]$entry['Need']
            $owners=[string]$entry['Owners']
            $usual=if ($owners) { ($owners -replace '^\^\(|\)\$$','') -replace '\|',' or ' } else { '' }
            $ownerMatches=$true
            if ($owners) { $ownerMatches=($owner -match $owners) }
            $risky=[bool]$entry['Risky']
            $state=Get-PortNeedState $need
            if ($state -in @('Core','Role','Required','Kept','Optional')) {
                if ($ownerMatches) {
                    $verdict='Expected'
                    $detail="$title is $($stateText[$state])."
                } else {
                    $verdict='Unexpected'
                    $ownerMismatch=$true
                    $detail="$title normally comes from $usual, but $ownerText owns this port."
                }
            } elseif ($state -eq 'TurnedOff') {
                $verdict='Unexpected'
                $detail="$title was turned off in this run, yet $protocolLabel $port is still listening ($ownerText)."
                if (-not $ownerMatches) { $ownerMismatch=$true }
            } else {
                $verdict='Unexpected'
                if ($risky) {
                    $detail="${title}: $([string]$entry['Risk'])"
                } else {
                    $detail="$title is listening, but nothing says $need is needed: it is not in -RequiredServices, was not kept in a service question, and is not in -AllowedPorts. $([string]$entry['Risk'])"
                }
                if (-not $ownerMatches) {
                    $ownerMismatch=$true
                    $detail+=" It is answered by $ownerText, not $usual."
                }
            }
        } else {
            $dynamic=($port -ge 49152 -and $port -le 65535)
            $windowsHost=$windowsHosts -contains $owner.ToLowerInvariant()
            $hostTrusted=$windowsHost -and ([string]::IsNullOrWhiteSpace($processPath) -or [string]::IsNullOrEmpty($severity))
            if ($protocol -eq 'tcp' -and $dynamic -and $hostTrusted) {
                $verdict='Expected'
                $detail="Windows dynamic RPC endpoint of $ownerText."
            } elseif ($protocol -eq 'udp' -and $hostTrusted) {
                $verdict='Expected'
                $detail="UDP socket of the Windows service host $ownerText."
            } elseif ($protocol -eq 'udp' -and $dynamic -and $trustedBinary) {
                $verdict='Expected'
                $detail="Ephemeral UDP socket of $ownerText, a program with a verified origin."
            }
        }
        $records.Add([pscustomobject]@{
            Protocol=$protocol;Address=$address;Port=$port;Scope=$scope;PID=$pidValue
            Process=$ownerText;Path=$processPath;Class=$class;Severity=$severity
            Service=($serviceNames -join ',');ServiceState=$serviceState;ServiceStartMode=$serviceStartMode
            Title=$title;Label=$label;Expected=$title;Verdict=$verdict;Detail=$detail
            Risky=$risky;OwnerMismatch=$ownerMismatch
        })
    }
    return @($records | Sort-Object Protocol,Port)
}
function Wait-PortClosed {
    param([string]$Protocol,[int]$Port,[int]$Seconds=5)
    for ($attempt=0; $attempt -lt ($Seconds*2); $attempt++) {
        $open=@()
        try {
            if ($Protocol -eq 'udp') { $open=@(Get-NetUDPEndpoint -LocalPort $Port -ErrorAction SilentlyContinue) }
            else { $open=@(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) }
        } catch { $open=@() }
        if (-not $open.Count) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}
function Stop-AttributedListener {
    # Closes one confirmed listener. A service is stopped only when it is the only
    # service in its process, is not required or core to Windows, and has no
    # running dependents; it is disabled only after the port is proven closed, and
    # started again if the port stays open. A standalone process is stopped only
    # when it is not a Windows system process.
    param($Record)
    $port=[int]$Record.Port
    $protocol=[string]$Record.Protocol
    $label=[string]$Record.Label
    $corePorts=@(53,88,123,135,137,138,139,389,445,464,636,3268,3269,3389,5985,5986,47001)
    if ($protocol -eq 'tcp' -and $corePorts -contains $port) {
        return [pscustomobject]@{Status='Refused';Message="$label is a core identity, administration, or file-sharing port. Turn its service off with its own question (RDP, SMB, WinRM, DNS) instead of the port prompt."}
    }
    $requiredOwner=Get-RequiredSoftwareOwner ([string]$Record.Path)
    if ($requiredOwner) {
        return [pscustomobject]@{Status='Refused';Message="The listening program belongs to required software '$requiredOwner' (-RequiredSoftware)."}
    }
    $criticalServices=@('RpcSs','RpcEptMapper','DcomLaunch','EventLog','Schedule','Dhcp','Dnscache','nsi','LSM','SamSs','KeyIso','VaultSvc','Netlogon','NTDS','Kdc','DFSR','IsmServ','NtFrs','W32Time','Winmgmt','gpsvc','ProfSvc','SENS','Appinfo','CryptSvc','PlugPlay','Power','BFE','MpsSvc','WinDefend','WdNisSvc','PolicyAgent','IKEEXT','iphlpsvc','LanmanWorkstation','LanmanServer','TermService','SessionEnv','UmRdpService','WinRM','EventSystem','NlaSvc','netprofm','Wcmsvc','BrokerInfrastructure','SystemEventsBroker','CoreMessagingRegistrar','TimeBrokerSvc','StateRepository','UserManager','DNS','DHCPServer','CertSvc','ADWS','Wecsvc','WinHttpAutoProxySvc','lmhosts')
    $criticalProcesses=@('system','idle','registry','smss','csrss','wininit','winlogon','services','lsass','svchost','spoolsv','dwm','fontdrvhost','msmpeng','nissrv','securityhealthservice','memory compression')
    $serviceNames=@()
    if (-not [string]::IsNullOrWhiteSpace([string]$Record.Service)) { $serviceNames=@(([string]$Record.Service) -split ',' | Where-Object { $_ }) }
    if ($serviceNames.Count -gt 1) {
        return [pscustomobject]@{Status='Refused';Message="PID $($Record.PID) hosts $($serviceNames.Count) services ($($serviceNames -join ', ')). Stopping one of them may not close $label and can break the others. Find the right service with 'netstat -anob' and turn it off by name."}
    }
    if ($serviceNames.Count -eq 1) {
        $name=$serviceNames[0]
        if (Test-ServiceProtected $name) {
            return [pscustomobject]@{Status='Refused';Message="Service '$name' is required by the scenario and stays running. Closing $label would break it."}
        }
        if ($criticalServices -contains $name) {
            return [pscustomobject]@{Status='Refused';Message="Service '$name' is a core Windows service. Closing $label this way would break Windows, so it was left running."}
        }
        $service=Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $service) { return [pscustomobject]@{Status='Refused';Message="Service '$name' no longer exists."} }
        $dependents=@($service.DependentServices | Where-Object { [string]$_.Status -eq 'Running' })
        if ($dependents.Count) {
            return [pscustomobject]@{Status='Refused';Message="Running services depend on '$name': $(($dependents | ForEach-Object { $_.Name }) -join ', '). Review them at the console first."}
        }
        $previousStart=Get-ServiceStartMode $service
        try {
            Stop-Service -Name $name -Force -ErrorAction Stop
            if (-not (Wait-PortClosed $protocol $port 6)) {
                # The port belongs to something else: put the service back as it was.
                try { Start-Service -Name $name -ErrorAction Stop } catch { }
                return [pscustomobject]@{Status='Failed';Message="Service '$name' stopped, but $label stayed open, so another process owns it. The service was started again and left at start mode $previousStart."}
            }
            Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
            $mode=Get-ServiceStartMode (Get-Service -Name $name -ErrorAction Stop)
            return [pscustomobject]@{Status='Changed';Message="Service '$name' stopped and set to $mode (was $previousStart); $label is closed."}
        } catch {
            return [pscustomobject]@{Status='Failed';Message=$_.Exception.Message}
        }
    }
    $pidValue=[int]$Record.PID
    $base=(ConvertTo-ProcessBaseName ([string]$Record.Process)).ToLowerInvariant()
    if ($pidValue -le 4 -or $criticalProcesses -contains $base) {
        return [pscustomobject]@{Status='Refused';Message="$label belongs to $($Record.Process), a Windows process that must not be stopped. Turn the feature off through its own setting."}
    }
    $process=Get-Process -Id $pidValue -ErrorAction SilentlyContinue
    if ($null -eq $process) { return [pscustomobject]@{Status='Failed';Message="PID $pidValue is gone; the port may already be closed."} }
    $currentPath=''
    try { $currentPath=[string]$process.Path } catch { $currentPath='' }
    if (-not [string]::IsNullOrWhiteSpace($currentPath) -and -not [string]::IsNullOrWhiteSpace([string]$Record.Path)) {
        if ($currentPath -ine [string]$Record.Path) { return [pscustomobject]@{Status='Refused';Message='The PID now belongs to a different executable; refusing to stop it.'} }
    }
    try {
        Stop-Process -Id $pidValue -Force -ErrorAction Stop
        if (-not (Wait-PortClosed $protocol $port 4)) { return [pscustomobject]@{Status='Failed';Message="Process stopped, but $label is still listening."} }
        return [pscustomobject]@{Status='Changed';Message="Process $($Record.Process) PID $pidValue stopped; $label is closed. Its file was not deleted, so it runs again at the next start unless its autorun, task, or service is removed too."}
    } catch {
        return [pscustomobject]@{Status='Failed';Message=$_.Exception.Message}
    }
}
function Invoke-PortAttribution {
    $records=@(Get-PortAttributionRecords)
    $script:Inventory.Ports=@($records)
    if (-not $records.Count) {
        Add-Result Network 'Listening-port attribution' SKIPPED 'No listening socket could be enumerated.' 'Run netstat -anob from an elevated console to list listeners manually.'
        return
    }
    # One entry per protocol/port. Unexpected named services first, then unknown ports.
    $reachable=@($records | Where-Object { $_.Scope -ne 'Loopback only' })
    $seenPorts=@{}
    $flaggedList=[System.Collections.Generic.List[object]]::new()
    foreach ($record in @($reachable | Where-Object { $_.Verdict -eq 'Unexpected' }) + @($reachable | Where-Object { $_.Verdict -eq 'Undeclared' })) {
        $key="$($record.Protocol)/$($record.Port)"
        if ($seenPorts.ContainsKey($key)) { continue }
        $seenPorts[$key]=$true
        $flaggedList.Add($record)
    }
    $flagged=@($flaggedList)
    $unexpected=@($flagged | Where-Object { $_.Verdict -eq 'Unexpected' })
    $undeclared=@($flagged | Where-Object { $_.Verdict -eq 'Undeclared' })
    $loopbackFlagged=@($records | Where-Object { $_.Scope -eq 'Loopback only' -and $_.Verdict -in @('Unexpected','Undeclared') })
    $expectedCount=@($records | Where-Object { $_.Verdict -eq 'Expected' }).Count
    $declaredCount=@($records | Where-Object { $_.Verdict -eq 'Declared' }).Count
    $acknowledgedCount=@($records | Where-Object { $_.Verdict -eq 'Acknowledged' }).Count
    $summary=[System.Collections.Generic.List[string]]::new()
    $summary.Add("$($records.Count) socket(s): $expectedCount expected, $declaredCount declared, $acknowledgedCount kept earlier, $($unexpected.Count) unexpected service(s), $($undeclared.Count) undeclared")
    foreach ($record in $flagged) {
        $serviceText=if ($record.Service) { " service=$($record.Service)" } else { '' }
        $classText=if ($record.Class) { " [$($record.Class)]" } else { '' }
        $summary.Add("$($record.Label) on $($record.Address) <- $($record.Process) PID=$($record.PID)$serviceText${classText}: $($record.Detail)")
    }
    # Name every open port so the report reads like netstat with titles.
    $namedSeen=@{}
    $named=[System.Collections.Generic.List[string]]::new()
    foreach ($record in @($reachable | Where-Object { $_.Title -and -not ($_.Protocol -eq 'udp' -and $_.Verdict -eq 'Expected') })) {
        $key="$($record.Protocol)/$($record.Port)"
        if ($namedSeen.ContainsKey($key)) { continue }
        $namedSeen[$key]=$true
        $named.Add("$($record.Label) [$($record.Verdict)]")
    }
    if ($named.Count) {
        $namedStatus=if ($unexpected.Count) { 'REVIEW' } else { 'PASS' }
        Add-Result Network 'Named open ports' $namedStatus ($named -join '; ') 'Every named port should be one the README needs. Unexpected ones are listed separately below with the reason.'
    }
    foreach ($record in $unexpected) {
        $serviceText=if ($record.Service) { "; service $($record.Service) ($($record.ServiceState))" } else { '' }
        $pathText=if ($record.Path) { "; $($record.Path)" } else { '' }
        Add-Result Network "Open port: $($record.Label)" REVIEW "$($record.Detail) Owner: $($record.Process) PID=$($record.PID)$serviceText$pathText." 'If the README does not need this service, answer N at its port prompt or turn the service off; if it does, add it to -RequiredServices or -AllowedPorts and re-run.'
        if ($record.Risky -or $record.OwnerMismatch) {
            Add-HighSignal 'LISTENER' "$($record.Label)|$($record.Path)" "$($record.Detail) Owner: $($record.Process) PID=$($record.PID)." 'Record the owner and hash, answer any forensics question, then close the port and remove whatever starts it.'
        }
    }
    foreach ($record in @($flagged | Where-Object { $_.Severity -eq 'High' })) {
        Add-HighSignal 'LISTENER' "$($record.Label)|$($record.Path)" "$($record.Process) PID=$($record.PID) listens on $($record.Address):$($record.Port) [$($record.Class)]" 'A listener whose binary cannot prove its origin is a remote-control channel. Record the hash, close the port, then quarantine the file with scenario approval.'
    }
    if ($flagged.Count) {
        Add-Result Network 'Listening-port attribution' REVIEW (($summary | Select-Object -First 16) -join '; ') 'Each flagged socket is attributed to its process, service, and provenance. Keep it only if the README or the operator can name why it listens; otherwise close it at the Y/N prompt.'
    } else {
        Add-Result Network 'Listening-port attribution' PASS (($summary | Select-Object -First 4) -join '; ') ''
    }
    if ($loopbackFlagged.Count) {
        Add-Result Network 'Loopback-only listeners' REVIEW (($loopbackFlagged | ForEach-Object { "$($_.Label) $($_.Process) PID=$($_.PID)" }) -join '; ') 'A loopback listener is not reachable off the host, but it can still be a local proxy or a post-exploitation channel. Confirm the owner.'
    }
    if (-not $Apply -or $NonInteractive -or $WhatIfPreference) {
        if ($flagged.Count) {
            Add-Result Network 'Port allow/disable decisions' REVIEW "$($flagged.Count) flagged socket(s) were reported and left unchanged." 'Re-run interactively with -Apply to answer Y (keep and record) or N (close) for each port, or declare README ports with -AllowedPorts.'
        }
        return
    }
    $index=0
    foreach ($record in $flagged) {
        $index++
        if ($index -gt 20) { Add-Result Network 'Port decisions' REVIEW 'The interactive port review stopped after 20 sockets.' 'Re-run to continue, or record the remaining ports with -AllowedPorts.'; break }
        $heading=if ($record.Verdict -eq 'Unexpected') { "UNEXPECTED $($record.Label)" } else { "UNDECLARED LISTENER $($record.Label)" }
        Write-Host ''
        Write-Host "$heading ($index/$($flagged.Count))" -ForegroundColor Yellow
        Write-Host "  Why     : $($record.Detail)"
        Write-Host "  Address : $($record.Address) ($($record.Scope))"
        Write-Host "  Process : $($record.Process) PID=$($record.PID)"
        if ($record.Path) { Write-Host "  Path    : $($record.Path)" }
        if ($record.Class) { Write-Host "  Origin  : $($record.Class) [severity=$($record.Severity)]" }
        if ($record.Service) { Write-Host "  Service : $($record.Service) state=$($record.ServiceState) start=$($record.ServiceStartMode)" }
        if ($record.Path -and (Test-Path -LiteralPath $record.Path -PathType Leaf)) {
            Write-Host "  SHA256  : $(Get-FileSha256 $record.Path)"
        }
        $answer=Read-YesNo "Keep $($record.Label) open? Y keeps it and records the decision; N closes it"
        if ($answer -eq 'Y') {
            $owner="$($record.Process) PID=$($record.PID)"
            $ok=Set-PortAcknowledgment "$($record.Protocol):$($record.Port)" $owner 'Kept by operator during port attribution.'
            $pathNote=if ($record.Path) { " ($($record.Path))" } else { '' }
            if ($ok) {
                Add-Result Network "Port $($record.Label)" PASS "Kept and recorded: $owner$pathNote" ''
            } else {
                Add-Result Network "Port $($record.Label)" REVIEW 'The decision could not be written to HKLM:\SOFTWARE\CYPatV6\PortAcknowledgments.' 'Record the decision in the run notes manually.'
            }
            continue
        }
        if ($answer -eq 'N') {
            if ($record.Protocol -eq 'udp') {
                Add-Result Network "Port $($record.Label)" REVIEW "Operator asked to close $($record.Process) PID=$($record.PID); UDP sockets are not closed automatically." 'Stop the owning service or process manually after recording evidence.'
                continue
            }
            $confirmation=Read-YesNo "Confirm closing $($record.Label)"
            if ($confirmation -ne 'Y') {
                Add-Result Network "Port $($record.Label)" SKIPPED 'Close was not confirmed; the listener was left running.' 'Record why the listener stays.'
                continue
            }
            $outcome=Stop-AttributedListener $record
            switch ($outcome.Status) {
                'Changed' {
                    Add-Result Network "Port $($record.Label)" CHANGED $outcome.Message ''
                    Add-Ledger 'PORT' "$($record.Protocol)/$($record.Port)" "$($outcome.Message); owner=$($record.Process) PID=$($record.PID); path=$($record.Path)"
                }
                'Refused' { Add-Result Network "Port $($record.Label)" REVIEW $outcome.Message 'Treat this as a scenario decision; nothing was changed.' }
                default { Add-Result Network "Port $($record.Label)" FAILED $outcome.Message 'Close it manually and verify with Get-NetTCPConnection.' }
            }
            continue
        }
        Add-Result Network "Port $($record.Label)" SKIPPED 'No valid Y/N answer; the listener was left running.' 'Record the decision in the run notes.'
    }
}
#endregion
#region v6.3 README-driven checks
# Every check here starts from a name the operator copied out of the image
# README. Nothing is guessed: a program, account, or file type that is not named
# on the command line is never removed by this region.
function Read-Choice {
    param([string]$Prompt,[string[]]$Choices)
    if ($NonInteractive) { return $null }
    $answer=(Read-Host "$Prompt [$($Choices -join '/')]").Trim().ToUpperInvariant()
    if ($Choices -contains $answer) { return $answer }
    Write-Warning 'No valid answer was received; nothing was changed.'
    return $null
}
function Test-ApplicationNameMatch {
    # Exact, wildcard, or whole-word match of a README name against a DisplayName:
    # 'Firefox' matches 'Mozilla Firefox (x64 en-US)', 'GIMP' matches 'GIMP 2.10.36'.
    param([string]$Name,[string]$DisplayName)
    $needle=([string]$Name).Trim()
    if (-not $needle -or [string]::IsNullOrWhiteSpace($DisplayName)) { return $false }
    if ([WildcardPattern]::ContainsWildcardCharacters($needle)) { return ($DisplayName -like $needle) }
    if ($DisplayName -ieq $needle) { return $true }
    return ($DisplayName -match ('(?i)(^|[^a-z0-9])'+[regex]::Escape($needle)+'([^a-z0-9]|$)'))
}
function Find-InstalledApplication {
    # Uninstall entries (machine 64-bit, machine 32-bit, and the current user)
    # whose DisplayName matches a README name.
    param([string]$Name)
    $results=[System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrWhiteSpace($Name)) { return @() }
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $scope='Machine'
        if ($root -like 'HKCU:*') { $scope='Current user' } elseif ($root -like '*WOW6432Node*') { $scope='Machine (32-bit)' }
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $item=$null
            try { $item=Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop } catch { continue }
            $display=[string](Get-OptionalProperty $item 'DisplayName' '')
            if (-not (Test-ApplicationNameMatch $Name $display)) { continue }
            $results.Add([pscustomobject]@{
                Name=$display
                Version=[string](Get-OptionalProperty $item 'DisplayVersion' '')
                Publisher=[string](Get-OptionalProperty $item 'Publisher' '')
                InstallLocation=[string](Get-OptionalProperty $item 'InstallLocation' '')
                DisplayIcon=[string](Get-OptionalProperty $item 'DisplayIcon' '')
                UninstallString=[string](Get-OptionalProperty $item 'UninstallString' '')
                QuietUninstallString=[string](Get-OptionalProperty $item 'QuietUninstallString' '')
                KeyPath=[string]$key.PSPath
                Scope=$scope
            })
        }
    }
    return @($results)
}
function Get-ApplicationFolder {
    # Where the product lives: InstallLocation, else the folder of its DisplayIcon,
    # else the folder of a non-MSI uninstaller.
    param($Entry)
    $candidates=[System.Collections.Generic.List[string]]::new()
    $location=([string]$Entry.InstallLocation).Trim().Trim('"').TrimEnd('\')
    if ($location) { $candidates.Add([Environment]::ExpandEnvironmentVariables($location)) }
    $icon=([string]$Entry.DisplayIcon).Trim()
    if ($icon) {
        $iconPath=[Environment]::ExpandEnvironmentVariables((($icon -replace ',\s*-?\d+$','').Trim().Trim('"')))
        $installerCache=(Join-Path ([string]$env:SystemRoot) 'Installer')+'\'
        if ($iconPath -and [IO.Path]::IsPathRooted($iconPath) -and -not $iconPath.StartsWith($installerCache,[StringComparison]::OrdinalIgnoreCase)) {
            $iconFolder=[IO.Path]::GetDirectoryName($iconPath)
            if ($iconFolder) { $candidates.Add($iconFolder) }
        }
    }
    $uninstall=[string]$Entry.UninstallString
    if ($uninstall -and $uninstall -notmatch '(?i)msiexec') {
        $uninstallPath=ConvertTo-ExecutablePath $uninstall
        if ($uninstallPath) {
            $uninstallFolder=[IO.Path]::GetDirectoryName($uninstallPath)
            if ($uninstallFolder) { $candidates.Add($uninstallFolder) }
        }
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Container)) { return $candidate }
    }
    if ($candidates.Count) { return [string]$candidates[0] }
    return ''
}
function Get-RequiredSoftwareOwner {
    # The -RequiredSoftware program whose install folder contains this path, or ''.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    foreach ($entry in $script:RequiredSoftwareRoots) {
        $root=([string]$entry.Root).TrimEnd('\')
        if (-not $root) { continue }
        if ($Path -ieq $root -or $Path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) { return [string]$entry.Name }
    }
    return ''
}
function Invoke-RequiredSoftwareAudit {
    # R4. The "required software moved or missing" penalty: each README program must
    # be installed, machine-wide, at its default location. Its folder is then kept
    # out of quarantine, port closing, package removal, and the prohibited-file scan.
    $names=@($RequiredSoftware | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -Unique)
    # Optional: the README's list changes every round, so names are typed on the
    # command line for that run and nothing is stored in the script.
    if (-not $names.Count) { return }
    $defaultRoots=@(@($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramW6432) | Where-Object { $_ } | ForEach-Object { ([string]$_).TrimEnd('\') } | Select-Object -Unique)
    foreach ($name in $names) {
        $entries=@(Find-InstalledApplication $name)
        if (-not $entries.Count) {
            Add-Result Software "Required software/$name" FAILED "No installed program matches '$name' (machine and current-user uninstall entries were checked)." 'Reinstall it from its official installer at the default location, or correct the name to match Apps & Features.'
            continue
        }
        foreach ($entry in $entries) {
            $label=[string]$entry.Name
            if ($entry.Version) { $label+=" $($entry.Version)" }
            $folder=Get-ApplicationFolder $entry
            if (-not $folder) {
                Add-Result Software "Required software/$name" REVIEW "$label is registered but does not record where it is installed." 'Open the program once and confirm its folder is the default install location.'
                continue
            }
            if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
                Add-Result Software "Required software/$name" FAILED "$label is registered at $folder, but that folder does not exist." 'Reinstall it at the default location; a moved or deleted program is scored as missing.'
                continue
            }
            $script:RequiredSoftwareRoots.Add([pscustomobject]@{Name=[string]$entry.Name;Root=$folder})
            $hasProgram=@(Get-ChildItem -LiteralPath $folder -Filter '*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 1).Count -gt 0
            if (-not $hasProgram) {
                foreach ($child in @(Get-ChildItem -LiteralPath $folder -Directory -ErrorAction SilentlyContinue | Select-Object -First 8)) {
                    if (@(Get-ChildItem -LiteralPath $child.FullName -Filter '*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 1).Count) { $hasProgram=$true; break }
                }
            }
            $underDefault=$false
            foreach ($root in $defaultRoots) {
                if ($folder.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) { $underDefault=$true; break }
            }
            if ($entry.Scope -eq 'Current user' -or $folder -match '(?i)\\Users\\[^\\]+\\') {
                Add-Result Software "Required software/$name" REVIEW "$label is installed for one user at $folder, not machine-wide under Program Files." 'If the README expects the normal machine-wide install, reinstall it with the official installer for all users. Do not move the folder by hand.'
            } elseif (-not $underDefault) {
                Add-Result Software "Required software/$name" REVIEW "$label is installed at $folder, outside Program Files." 'Confirm this is the product''s default location. A program installed or moved anywhere else is scored as not installed at the default location.'
            } elseif (-not $hasProgram) {
                Add-Result Software "Required software/$name" REVIEW "$label is registered at $folder, but no program file was found there." 'Launch it once to confirm it still works; reinstall it at the default location if it does not.'
            } else {
                Add-Result Software "Required software/$name" PASS "$label is installed at its default location ($folder)." ''
            }
        }
    }
}
function Get-LocalAccountGroupNames {
    param($User)
    $names=[System.Collections.Generic.List[string]]::new()
    $sid=[string]$User.SID.Value
    foreach ($group in @(Get-LocalGroup -ErrorAction SilentlyContinue)) {
        try {
            foreach ($member in @(Get-LocalGroupMember -Group $group -ErrorAction Stop)) {
                if ([string]$member.SID.Value -eq $sid) { $names.Add([string]$group.Name); break }
            }
        } catch { }
    }
    return @($names)
}
function Get-LocalAccountProfilePath {
    param([string]$Sid)
    if ($Sid -notmatch '^S-1-[0-9-]+$') { return '' }
    try {
        $profileEntry=@(Get-CimInstance Win32_UserProfile -Filter "SID='$Sid'" -ErrorAction Stop | Select-Object -First 1)
        if ($profileEntry.Count) { return [string]$profileEntry[0].LocalPath }
    } catch { }
    return ''
}
function Invoke-NamedAccountRemoval {
    # R1. Removes only accounts named with -RemoveUsers (the README's unauthorized or
    # terminated users), one Y/N at a time. The profile folder is never deleted; the
    # script checks it still exists afterwards and records that in the ledger,
    # because deleting it is a separate scored penalty.
    $names=@($RemoveUsers | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $names.Count) { return }
    if ($script:IsDomainController) {
        Add-Result Accounts 'Named account removal' REVIEW 'Domain controller detected; -RemoveUsers only handles local accounts.' 'Remove domain accounts in Active Directory Users and Computers after checking the README.'
        return
    }
    $currentSid=[string]([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    foreach ($name in $names) {
        if ([WildcardPattern]::ContainsWildcardCharacters($name)) {
            Add-Result Accounts "Remove user/$name" FAILED '-RemoveUsers takes exact account names, not patterns.' 'Copy each name exactly from the README.'
            continue
        }
        $user=Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $user) {
            Add-Result Accounts "Remove user/$name" PASS 'No local account has this name (already removed or never present).' ''
            continue
        }
        $sid=[string]$user.SID.Value
        if ($sid -match '-(500|501|503|504)$') {
            Add-Result Accounts "Remove user/$name" REVIEW 'This is a built-in account; it was not deleted.' 'Disable a built-in account instead of deleting it.'
            continue
        }
        if ($sid -eq $currentSid) {
            Add-Result Accounts "Remove user/$name" REVIEW 'This is the account running the script; it was not deleted.' 'Sign in as another administrator if this account really must go.'
            continue
        }
        if ($name -in $AuthorizedUsers -or $name -in $AuthorizedAdministrators) {
            Add-Result Accounts "Remove user/$name" FAILED 'The account is also listed in -AuthorizedUsers or -AuthorizedAdministrators; nothing was changed.' 'Fix the conflicting lists against the README and re-run.'
            continue
        }
        if ($name -in $ResetPasswords) {
            Add-Result Accounts "Remove user/$name" FAILED 'The account is also listed in -ResetPasswords; nothing was changed.' 'Decide from the README whether the account goes or stays, and list it once.'
            continue
        }
        $groups=@(Get-LocalAccountGroupNames $user)
        $profilePath=Get-LocalAccountProfilePath $sid
        $profileExisted=(-not [string]::IsNullOrWhiteSpace($profilePath)) -and (Test-Path -LiteralPath $profilePath)
        $groupText=if ($groups.Count) { $groups -join ', ' } else { '(none)' }
        $profileText=if ($profilePath) { $profilePath } else { '(no profile)' }
        $evidence="Enabled=$($user.Enabled); last logon=$($user.LastLogon); groups=$groupText; profile=$profileText"
        if (-not $Apply) {
            Add-Result Accounts "Remove user/$name" REVIEW "Would remove this account. $evidence" 'Run with -Apply interactively and answer Y to remove it; the profile folder is kept.'
            continue
        }
        if ($WhatIfPreference) {
            Add-Result Accounts "Remove user/$name" SKIPPED "Change suppressed by -WhatIf. $evidence" ''
            continue
        }
        if ($NonInteractive) {
            Add-Result Accounts "Remove user/$name" REVIEW "NonInteractive mode will not remove an account. $evidence" 'Run interactively and answer Y, or remove it in lusrmgr.msc.'
            continue
        }
        Write-Host ''
        Write-Host "REMOVE ACCOUNT $name" -ForegroundColor Yellow
        Write-Host "  $evidence"
        $choice=Read-YesNo "Remove local account $name? Its profile folder is kept. Y removes the account; N keeps it"
        if ($choice -ne 'Y') {
            Add-Result Accounts "Remove user/$name" SKIPPED "Kept by operator decision. $evidence" 'Remove it later only if the README names it as unauthorized.'
            continue
        }
        try {
            Remove-LocalUser -SID $user.SID -ErrorAction Stop
            $after=Get-LocalUser -SID $user.SID -ErrorAction SilentlyContinue
            if ($null -ne $after) { throw 'The account still exists after removal.' }
            if ($profileExisted -and -not (Test-Path -LiteralPath $profilePath)) {
                Add-Result Accounts "Remove user/$name" FAILED "The account was removed, but the profile folder $profilePath is gone." 'Restore the folder from the VM snapshot; a removed user directory is a separate penalty.'
                continue
            }
            $kept=if ($profileExisted) { "profile folder kept at $profilePath" } else { 'the account had no profile folder' }
            Add-Ledger 'ACCOUNT' "Account/$name" "Removed local account (SID $sid); $kept."
            Add-Result Accounts "Remove user/$name" CHANGED "Account removed; $kept." ''
            Write-Host "Removed account $name; $kept." -ForegroundColor Green
        } catch {
            Add-Result Accounts "Remove user/$name" FAILED $_.Exception.Message 'Remove it in lusrmgr.msc. Never delete the profile folder.'
        }
    }
}
function Invoke-NamedPasswordReset {
    # R8. A new generated password for each account named with -ResetPasswords (the
    # README's "insecure password" users), confirmed once, verified with a real
    # logon where the account is enabled, and recorded in Changed-Passwords.txt.
    $names=@($ResetPasswords | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $names.Count) { return }
    if ($script:IsDomainController) {
        Add-Result Accounts 'Named password resets' SKIPPED 'Domain controller detected; -ResetPasswords only handles local accounts.' 'Reset domain passwords in Active Directory Users and Computers.'
        return
    }
    $exempt=@($PasswordExemptUsers | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    $targets=[System.Collections.Generic.List[object]]::new()
    foreach ($name in $names) {
        $user=Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $user) {
            Add-Result Accounts "Reset password/$name" FAILED 'No local account has this name.' 'Check the spelling against the README.'
            continue
        }
        if ([string]$user.SID.Value -match '-(501|503|504)$') {
            Add-Result Accounts "Reset password/$name" REVIEW 'This built-in account should stay disabled rather than get a password.' ''
            continue
        }
        if ($name -in $exempt) {
            Add-Result Accounts "Reset password/$name" SKIPPED 'Excluded by -PasswordExemptUsers.' ''
            continue
        }
        if ($name -in $RemoveUsers) {
            Add-Result Accounts "Reset password/$name" FAILED 'The account is also listed in -RemoveUsers; nothing was changed.' 'Decide from the README whether the account goes or stays, and list it once.'
            continue
        }
        if ($script:ResetPasswordAccounts.ContainsKey([string]$user.Name)) {
            Add-Result Accounts "Reset password/$name" SKIPPED 'A generated password was already applied earlier in this run.' ''
            continue
        }
        $targets.Add($user)
    }
    if (-not $targets.Count) { return }
    $targetNames=(@($targets | ForEach-Object { [string]$_.Name }) -join ', ')
    if (-not $Apply) {
        Add-Result Accounts 'Named password resets' REVIEW "Would set a new generated password for: $targetNames." 'Run with -Apply interactively and answer Y.'
        return
    }
    if ($WhatIfPreference) {
        Add-Result Accounts 'Named password resets' SKIPPED "Change suppressed by -WhatIf; targets: $targetNames." ''
        return
    }
    if ($NonInteractive) {
        Add-Result Accounts 'Named password resets' REVIEW "NonInteractive mode cannot confirm password resets. Targets: $targetNames." 'Run interactively and answer Y, or reset them manually.'
        return
    }
    if ([string]::IsNullOrWhiteSpace($script:RunDirectory)) {
        Add-Result Accounts 'Named password resets' FAILED 'The private run folder is unavailable; refusing to reset passwords without a durable record.' 'Fix the run-folder path or pass -RunRoot to a writable folder, then re-run.'
        return
    }
    $choice=Read-YesNo "Set a new generated password for $($targets.Count) README-named account(s): $targetNames? Y resets them; N skips"
    if ($choice -ne 'Y') {
        Add-Result Accounts 'Named password resets' SKIPPED "Operator did not approve the resets. Targets: $targetNames." 'Run again and answer Y, or reset them manually.'
        return
    }
    $minimumLength=Get-EffectiveMinimumPasswordLength
    $passwordLength=[Math]::Max($GeneratedPasswordLength,$minimumLength)
    foreach ($user in $targets) {
        $name=[string]$user.Name
        $enabled=[bool]$user.Enabled
        $password=$null
        try {
            $password=New-ComplexPassword $passwordLength
            $method=Set-LocalAccountPassword -Name $name -Password $password -CanVerify:$enabled
            $flagMethod=$null
            try { $flagMethod=Set-LocalPasswordRequired -Name $name }
            catch { Add-Result Accounts "Reset password/$name flag" REVIEW $_.Exception.Message ("The password was set, but the password-not-required flag could not be cleared. " + (Get-ManualPasswordHelp -Name $name)) }
            try { Set-LocalUser -Name $name -PasswordNeverExpires $false -ErrorAction Stop }
            catch { Add-Result Accounts "Reset password/$name expiry" REVIEW $_.Exception.Message 'The password was set, but the "password never expires" flag could not be cleared. Clear it manually if the account policy requires it.' }
            $after=Get-LocalUser -Name $name -ErrorAction Stop
            $afterState=Get-PasswordState $after
            $stamp=Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Write-Host "NEW PASSWORD for $name : $password" -ForegroundColor Yellow
            try { Write-PrivateLine 'Changed-Passwords.txt' "$stamp | $name | $password" }
            catch { Add-Result Accounts "Reset password/$name record" FAILED $_.Exception.Message 'The password was set but could not be written to the private run folder. Record it manually.' }
            $flagDetail=if ($flagMethod) { " PasswordRequired cleared via $flagMethod." } else { '' }
            Add-Ledger 'PASSWORD' "Account/$name" "Named reset (-ResetPasswords): generated and set a password via $method.$flagDetail"
            if ($enabled) { $verification=Test-AppliedPassword -Name $name -Password $password -Enabled $true }
            else { $verification=[pscustomobject]@{Verified=(-not $afterState.Passwordless);Evidence='Account is disabled; the password flags were read back instead of a logon.'} }
            if ($verification.Verified) {
                Add-Result Accounts "Reset password/$name" CHANGED "New password applied via $method and verified ($($verification.Evidence)). Saved in the private run folder.$flagDetail" ''
                $script:ResetPasswordAccounts[$name]=$true
            } else {
                Add-Result Accounts "Reset password/$name" REVIEW "The password was applied at $stamp but verification failed ($($verification.Evidence)). The candidate is in Changed-Passwords.txt." ("Reset the account with the saved password. " + (Get-ManualPasswordHelp -Name $name))
            }
        } catch {
            Add-Result Accounts "Reset password/$name" FAILED $_.Exception.Message ("The automatic reset failed. " + (Get-ManualPasswordHelp -Name $name -MultiLine))
        } finally {
            $password=$null
        }
    }
}
function Get-UninstallCommand {
    # MSI products are removed silently through msiexec. Other products use their
    # QuietUninstallString when they publish one, Inno Setup uninstallers get their
    # documented silent switches, and anything else opens its own uninstaller.
    param($Entry)
    $quiet=[string]$Entry.QuietUninstallString
    $normal=[string]$Entry.UninstallString
    $guid=''
    foreach ($text in @($normal,$quiet)) {
        if ($text -match '(?i)msiexec(\.exe)?\s.*?(\{[0-9A-F-]{36}\})') { $guid=$Matches[2]; break }
    }
    if ($guid) {
        $msi=Join-Path ([string]$env:SystemRoot) 'System32\msiexec.exe'
        return [pscustomobject]@{FilePath=$msi;Arguments="/x $guid /qn /norestart";Silent=$true;Display="msiexec /x $guid /qn /norestart"}
    }
    $source=$normal
    $silent=$false
    if (-not [string]::IsNullOrWhiteSpace($quiet)) { $source=$quiet; $silent=$true }
    if ([string]::IsNullOrWhiteSpace($source)) { return [pscustomobject]@{FilePath='';Arguments='';Silent=$false;Display='(none)'} }
    $text=[Environment]::ExpandEnvironmentVariables($source.Trim())
    $file=''
    $arguments=''
    if ($text.StartsWith('"')) {
        $end=$text.IndexOf('"',1)
        if ($end -gt 1) { $file=$text.Substring(1,$end-1); $arguments=$text.Substring($end+1).Trim() }
    } elseif ($text -match '(?i)^(.+?\.exe)(\s+(.*))?$') {
        $file=$Matches[1]
        $arguments=[string]$Matches[3]
    } else {
        $file=$text
    }
    if (-not $silent -and [IO.Path]::GetFileName($file) -match '(?i)^unins\d+\.exe$') {
        $arguments=("$arguments /VERYSILENT /SUPPRESSMSGBOXES /NORESTART").Trim()
        $silent=$true
    }
    return [pscustomobject]@{FilePath=$file;Arguments=$arguments.Trim();Silent=$silent;Display=("$file $arguments").Trim()}
}
function Invoke-PackageRemoval {
    # R3. Uninstalls only programs named with -RemovePackages (the README's
    # prohibited software), one Y/N per match, through the product's own uninstall
    # entry. A name that also matches -RequiredSoftware is refused.
    $names=@($RemovePackages | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $names.Count) { return }
    foreach ($name in $names) {
        $entries=@(Find-InstalledApplication $name)
        if (-not $entries.Count) {
            Add-Result Software "Remove package/$name" PASS "No installed program matches '$name'." ''
            continue
        }
        foreach ($entry in $entries) {
            $label=[string]$entry.Name
            if ($entry.Version) { $label+=" $($entry.Version)" }
            $conflict=@($RequiredSoftware | Where-Object { $_ -and (Test-ApplicationNameMatch ([string]$_) ([string]$entry.Name)) })
            if ($conflict.Count) {
                Add-Result Software "Remove package/$name" REVIEW "$label also matches -RequiredSoftware '$($conflict -join ', ')'; it was not removed." 'Check the README: required software must stay installed at its default location.'
                continue
            }
            $command=Get-UninstallCommand $entry
            $folder=Get-ApplicationFolder $entry
            $evidence="Publisher=$($entry.Publisher); folder=$folder; scope=$($entry.Scope); uninstaller=$($command.Display)"
            if (-not $command.FilePath) {
                Add-Result Software "Remove package/$name" REVIEW "$label has no usable uninstall command. $evidence" 'Remove it from Settings > Apps, then re-run -AuditOnly.'
                continue
            }
            if (-not $Apply) {
                Add-Result Software "Remove package/$name" REVIEW "Would uninstall $label. $evidence" 'Run with -Apply interactively and answer Y.'
                continue
            }
            if ($WhatIfPreference) {
                Add-Result Software "Remove package/$name" SKIPPED "Change suppressed by -WhatIf. $evidence" ''
                continue
            }
            if ($NonInteractive) {
                Add-Result Software "Remove package/$name" REVIEW "NonInteractive mode will not uninstall software. $evidence" 'Run interactively and answer Y, or remove it from Settings > Apps.'
                continue
            }
            $how=if ($command.Silent) { 'silently' } else { 'with its own uninstaller window (follow its prompts)' }
            Write-Host ''
            Write-Host "UNINSTALL $label" -ForegroundColor Yellow
            Write-Host "  $evidence"
            $choice=Read-YesNo "Uninstall $label $how? Answer forensics questions about it first. Y uninstalls; N keeps it"
            if ($choice -ne 'Y') {
                Add-Result Software "Remove package/$name" SKIPPED "$label was kept by operator decision." ''
                continue
            }
            $outcome=Invoke-UninstallEntry -Entry $entry -Label $label -Command $command
            Add-Result Software "Remove package/$name" $outcome.Status $outcome.Evidence $outcome.Recommendation
        }
    }
}
function Invoke-ProhibitedFileAudit {
    # R2. Finds files with the extensions named in -ProhibitedExtensions (the README's
    # prohibited media or tools) under user folders, inetpub, Temp, and ProgramData,
    # then offers each one for quarantine. Off unless the parameter is supplied.
    $extensions=@($ProhibitedExtensions | ForEach-Object { ([string]$_).Trim().TrimStart('*').TrimStart('.').ToLowerInvariant() } | Where-Object { $_ -match '^[a-z0-9]{1,12}$' } | Select-Object -Unique)
    if (-not $extensions.Count) { return }
    $wanted=@{}
    foreach ($extension in $extensions) { $wanted[".$extension"]=$true }
    $roots=@(@((Join-Path $env:SystemDrive 'Users'),(Join-Path $env:SystemDrive 'inetpub'),(Join-Path $env:SystemDrive 'Temp'),$env:ProgramData) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | Select-Object -Unique)
    $skipFragments=@('\AppData\Local\Microsoft\','\AppData\Local\Packages\','\AppData\Roaming\Microsoft\Windows\Themes\','\ProgramData\Microsoft\','\ProgramData\Package Cache\','\ProgramData\CYPatV6\','\Users\All Users\','\Users\Default User\')
    $found=[System.Collections.Generic.List[object]]::new()
    $limit=400
    foreach ($root in $roots) {
        if ($found.Count -ge $limit) { break }
        $hits=@(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $wanted.ContainsKey($_.Extension.ToLowerInvariant()) } | Select-Object -First ($limit - $found.Count))
        foreach ($file in $hits) {
            $full=[string]$file.FullName
            $skip=$false
            foreach ($fragment in $skipFragments) { if ($full.IndexOf($fragment,[StringComparison]::OrdinalIgnoreCase) -ge 0) { $skip=$true; break } }
            if ($skip) { continue }
            if (Test-QuarantineBlocked $full) { continue }
            $found.Add($file)
        }
    }
    $extensionText='.'+($extensions -join ', .')
    $script:Inventory.ProhibitedFiles=@($found | ForEach-Object { [pscustomobject]@{Path=$_.FullName;Size=$_.Length;LastWrite=$_.LastWriteTime} })
    if (-not $found.Count) {
        Add-Result Forensics 'Prohibited files' PASS "No $extensionText file was found under $($roots -join ', ')." ''
        return
    }
    $listing=@($found | Select-Object -First 25 | ForEach-Object { "$($_.FullName) ($([Math]::Round($_.Length/1MB,1)) MB, $($_.LastWriteTime.ToString('yyyy-MM-dd')))" })
    Add-Result Forensics 'Prohibited files' REVIEW "$($found.Count) $extensionText file(s): $($listing -join '; ')" 'Answer every forensics question first; a question can be about one of these files. Then quarantine only what the README prohibits.'
    if (-not $Apply -or $NonInteractive -or $WhatIfPreference) { return }
    $asked=0
    foreach ($file in $found) {
        if ($asked -ge 60) {
            Add-Result Forensics 'Prohibited file decisions' REVIEW 'The interactive file review stopped after 60 files.' 'Re-run to continue with the rest of the list.'
            break
        }
        $asked++
        $full=[string]$file.FullName
        if ($file.Length -gt 524288000) {
            Add-Result Forensics "Prohibited file $($file.Name)" REVIEW "$full is larger than 500 MB, so it was not copied." 'Remove it by hand after recording the path.'
            continue
        }
        $owner='unknown'
        try { $owner=[string](Get-Acl -LiteralPath $full -ErrorAction Stop).Owner } catch { $owner='unknown' }
        Write-Host ''
        Write-Host "PROHIBITED FILE ($asked/$($found.Count)) $full" -ForegroundColor Yellow
        Write-Host "  $([Math]::Round($file.Length/1MB,2)) MB, last written $($file.LastWriteTime.ToString('yyyy-MM-dd HH:mm')), owner $owner"
        $answer=Read-YesNo 'Quarantine it? Y copies it to the private run folder, verifies the copy, then deletes the original; N keeps it'
        if ($answer -ne 'Y') {
            Add-Result Forensics "Prohibited file $($file.Name)" SKIPPED "$full was kept by operator decision." ''
            continue
        }
        try {
            $outcome=Invoke-FileQuarantine -Path $full -Kind 'PROHIBITED' -Detail "extension $($file.Extension)"
            Add-Result Forensics "Prohibited file $($file.Name)" CHANGED "Copied to $($outcome.QuarantinePath), hash verified, and the original deleted." ''
        } catch {
            Add-Result Forensics "Prohibited file $($file.Name)" FAILED $_.Exception.Message 'Remove it by hand after recording the path.'
        }
    }
}
#region Shared uninstall helper
function Invoke-UninstallEntry {
    # Runs one product's own uninstaller and proves its uninstall entry is gone.
    # The caller asks the operator first. Returns Status (CHANGED, REVIEW, or
    # FAILED), Evidence, and Recommendation for the caller's result row.
    param($Entry,[string]$Label,$Command)
    try {
        $startArguments=@{FilePath=[string]$Command.FilePath;Wait=$true;PassThru=$true;ErrorAction='Stop'}
        if (-not [string]::IsNullOrWhiteSpace([string]$Command.Arguments)) { $startArguments['ArgumentList']=[string]$Command.Arguments }
        $process=Start-Process @startArguments
        $exitCode=[int]$process.ExitCode
        $removed=$false
        for ($waited=0; $waited -le 45; $waited+=3) {
            if (-not (Test-Path -LiteralPath $Entry.KeyPath)) { $removed=$true; break }
            Start-Sleep -Seconds 3
        }
        if ($removed) {
            Add-Ledger 'UNINSTALL' "Package/$Label" "Uninstalled with: $($Command.Display); exit code $exitCode."
            return [pscustomobject]@{Status='CHANGED';Evidence="$Label was uninstalled (exit code $exitCode).";Recommendation=''}
        }
        return [pscustomobject]@{Status='REVIEW';Evidence="The uninstaller finished (exit code $exitCode), but $Label is still registered.";Recommendation='Finish the removal in Settings > Apps, then re-run -AuditOnly. A restart may be required.'}
    } catch {
        return [pscustomobject]@{Status='FAILED';Evidence=$_.Exception.Message;Recommendation='Remove it from Settings > Apps.'}
    }
}
#endregion
#region Deep hardening (round 3)
function Set-DeepRegistryRange {
    # "This value or stronger": a value inside Minimum..Maximum is kept; a missing
    # or out-of-range value is set to Default.
    param([string]$Category,[string]$Path,[string]$Name,[int]$Minimum,[int]$Maximum,[int]$Default,[string]$Type='DWord')
    $state=Get-RegistryState $Path $Name
    $currentText=if ($state.Exists) { [string]$state.Value } else { 'not set' }
    Invoke-Setting $Category "$Path\$Name" {
        $current=Get-RegistryState $Path $Name
        if (-not $current.Exists) { return $false }
        $number=0
        return ([int]::TryParse([string]$current.Value,[ref]$number) -and $number -ge $Minimum -and $number -le $Maximum)
    } {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        $newValue=if ($Type -eq 'String') { [string]$Default } else { $Default }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $newValue -PropertyType $Type -Force -ErrorAction Stop | Out-Null
    } "Current=$currentText; required $Minimum to $Maximum." "Set $Name to $Default, or keep a value from $Minimum to $Maximum."
}
function Set-DeepEmptyMultiString {
    # A list that must be empty, such as the pipes and shares anonymous users may
    # open. A missing value counts as empty.
    param([string]$Category,[string]$Path,[string]$Name)
    $state=Get-RegistryState $Path $Name
    $currentText=if ($state.Exists) { (@($state.Value) -join ', ') } else { 'not set' }
    if (-not $currentText) { $currentText='empty' }
    Invoke-Setting $Category "$Path\$Name" {
        $current=Get-RegistryState $Path $Name
        if (-not $current.Exists) { return $true }
        return (@(@($current.Value) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -eq 0)
    } {
        $nativePath=$Path -replace '^HKLM:\\','HKEY_LOCAL_MACHINE\'
        [Microsoft.Win32.Registry]::SetValue($nativePath,$Name,[string[]]@(),[Microsoft.Win32.RegistryValueKind]::MultiString)
    } "Current=$currentText; required: empty." "Clear $Name so anonymous users cannot open any pipe or share."
}
function Invoke-DeepSecurityOptions {
    # Security Options and administrative-template values from the CIS Level 1 and
    # Microsoft security baselines that the main registry audit does not cover.
    # Every one is a registry value with no service impact, so it is applied and
    # read back automatically. Range values keep a stronger existing setting.
    $lsa='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $sessionManager='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $system='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $server='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $workstation='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $netlogon='HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $winlogon='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $windowsSystem='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    $terminal='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $winrm='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM'
    $printers='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
    $recovery='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole'
    foreach ($setting in @(
        @('Security options',"$lsa\MSV1_0",'allownullsessionfallback',0),
        @('Security options',$lsa,'UseMachineId',1),
        @('Security options',"$lsa\pku2u",'AllowOnlineID',0),
        @('Security options',$lsa,'CrashOnAuditFail',0),
        @('Security options',$lsa,'ForceGuest',0),
        @('Security options',$sessionManager,'ProtectionMode',1),
        @('Security options',"$sessionManager\Kernel",'ObCaseInsensitive',1),
        @('Security options',$sessionManager,'SafeDllSearchMode',1),
        @('Security options',"$sessionManager\Kernel",'DisableExceptionChainValidation',0),
        @('Credential protection','HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential',0),
        @('Credential protection','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters','AllowEncryptionOracle',0),
        @('Credential protection','HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation','AllowProtectedCreds',1),
        @('SMB',$workstation,'EnablePlainTextPassword',0),
        @('SMB',$workstation,'EnableSecuritySignature',1),
        @('SMB',$server,'EnableSecuritySignature',1),
        @('SMB',$server,'enableforcedlogoff',1),
        @('SMB','HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation','AllowInsecureGuestAuth',0),
        @('Domain member',$netlogon,'RequireSignOrSeal',1),
        @('Domain member',$netlogon,'SealSecureChannel',1),
        @('Domain member',$netlogon,'SignSecureChannel',1),
        @('Domain member',$netlogon,'RequireStrongKey',1),
        @('Domain member',$netlogon,'DisablePasswordChange',0),
        @('UAC',$system,'FilterAdministratorToken',1),
        @('UAC',$system,'ConsentPromptBehaviorUser',0),
        @('UAC',$system,'EnableInstallerDetection',1),
        @('UAC',$system,'EnableVirtualization',1),
        @('Logon',$system,'DisableAutomaticRestartSignOn',1),
        @('Logon',$system,'ShutdownWithoutLogon',0),
        @('Accounts',$system,'NoConnectedUser',3),
        @('Logon',$windowsSystem,'DontDisplayNetworkSelectionUI',1),
        @('Logon',$windowsSystem,'EnumerateLocalUsers',0),
        @('Logon',$windowsSystem,'DisableLockScreenAppNotifications',1),
        @('Logon',$windowsSystem,'AllowDomainPINLogon',0),
        @('Recovery console',$recovery,'SecurityLevel',0),
        @('Recovery console',$recovery,'SetCommand',0),
        @('Network','HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters','DisableIPSourceRouting',2),
        @('Network','HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters','DisableIPSourceRouting',2),
        @('Network','HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters','EnableICMPRedirect',0),
        @('Network','HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters','NoNameReleaseOnDemand',1),
        @('Boot','HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch','DriverLoadPolicy',3),
        @('Explorer','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoWebServices',1),
        @('Installer','HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','EnableUserControl',0),
        @('Installer','HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','SafeForScripting',0),
        @('Printing',$printers,'DisableWebPnPDownload',1),
        @('Printing',$printers,'DisableHTTPPrinting',1),
        @('Printing',"$printers\PointAndPrint",'RestrictDriverInstallationToAdministrators',1),
        @('PowerShell','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','EnableScriptBlockLogging',1),
        @('WinRM',"$winrm\Service",'AllowBasic',0),
        @('WinRM',"$winrm\Service",'AllowUnencryptedTraffic',0),
        @('WinRM',"$winrm\Service",'DisableRunAs',1),
        @('WinRM',"$winrm\Client",'AllowBasic',0),
        @('WinRM',"$winrm\Client",'AllowUnencryptedTraffic',0),
        @('WinRM',"$winrm\Client",'AllowDigest',0),
        @('RDP',$terminal,'DisablePasswordSaving',1),
        @('RDP',$terminal,'fDisableCdm',1),
        @('Remote access',$terminal,'fAllowUnsolicited',0)
    )) { Set-RegistryBaseline $setting[0] $setting[1] $setting[2] $setting[3] }
    Set-DeepRegistryRange 'SMB' $server 'autodisconnect' 1 15 15
    Set-DeepRegistryRange 'SMB' $server 'SmbServerNameHardeningLevel' 1 2 1
    Set-DeepRegistryRange 'Domain member' $netlogon 'MaximumPasswordAge' 1 30 30
    Set-DeepRegistryRange 'Security options' 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' 1 2 1
    Set-DeepRegistryRange 'Logon' $winlogon 'PasswordExpiryWarning' 5 14 14
    Set-DeepRegistryRange 'Logon' $winlogon 'ScRemoveOption' 1 3 1 -Type String
    Set-DeepRegistryRange 'Logon' $winlogon 'ScreenSaverGracePeriod' 0 5 5 -Type String
    Set-DeepRegistryRange 'Event logs' 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security' 'WarningLevel' 1 90 90
    if ($script:IsDomainController) {
        Add-Result 'Security options' 'Anonymous pipes, shares, and remote SAM' SKIPPED 'Domain controllers need their own values (netlogon, samr, lsarpc); left to the domain policy.' ''
    } else {
        Set-DeepEmptyMultiString 'Security options' $server 'NullSessionPipes'
        Set-DeepEmptyMultiString 'Security options' $server 'NullSessionShares'
        Set-RegistryBaseline 'Security options' $lsa 'RestrictRemoteSAM' 'O:BAG:BAD:(A;;RC;;;BA)' -Type String
    }
    # Logon banner: an existing caption and text (the README's own banner) are kept.
    $caption=Get-RegistryState $system 'LegalNoticeCaption'
    $text=Get-RegistryState $system 'LegalNoticeText'
    $hasCaption=$caption.Exists -and -not [string]::IsNullOrWhiteSpace([string]$caption.Value)
    $hasText=$text.Exists -and -not [string]::IsNullOrWhiteSpace([string]$text.Value)
    Invoke-Setting 'Logon' 'Logon banner' {
        $nowCaption=Get-RegistryState $system 'LegalNoticeCaption'
        $nowText=Get-RegistryState $system 'LegalNoticeText'
        ($nowCaption.Exists -and -not [string]::IsNullOrWhiteSpace([string]$nowCaption.Value)) -and ($nowText.Exists -and -not [string]::IsNullOrWhiteSpace([string]$nowText.Value))
    } {
        if (-not (Test-Path -LiteralPath $system)) { New-Item -Path $system -Force -ErrorAction Stop | Out-Null }
        if (-not $hasCaption) { New-ItemProperty -LiteralPath $system -Name 'LegalNoticeCaption' -Value 'Authorized use only' -PropertyType String -Force -ErrorAction Stop | Out-Null }
        if (-not $hasText) { New-ItemProperty -LiteralPath $system -Name 'LegalNoticeText' -Value 'This computer is for authorized users only. Activity may be monitored and reported. Log off now if you are not an authorized user.' -PropertyType String -Force -ErrorAction Stop | Out-Null }
    } "Caption set=$hasCaption; text set=$hasText. A logon banner title and message are required." 'Set Interactive logon: Message title and Message text. An existing banner is kept.'
}
function ConvertTo-DeepPrincipalKey {
    # A user-right principal as an upper-case SID when it can be resolved.
    param([string]$Principal)
    $value=([string]$Principal).Trim().TrimStart('*')
    if (-not $value) { return '' }
    if ($value -match '^(?i)S-1-[0-9-]+$') { return $value.ToUpperInvariant() }
    try {
        $sid=(New-Object System.Security.Principal.NTAccount($value)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($sid) { return ([string]$sid).ToUpperInvariant() }
    } catch { }
    return $value
}
function Format-DeepPrincipals {
    param([string[]]$Keys)
    $names=[System.Collections.Generic.List[string]]::new()
    foreach ($key in @($Keys)) {
        if (-not $key) { continue }
        $name=$key
        if ($key -match '^S-1-') {
            try { $name=(New-Object System.Security.Principal.SecurityIdentifier($key)).Translate([System.Security.Principal.NTAccount]).Value } catch { $name=$key }
        }
        $names.Add([string]$name)
    }
    if (-not $names.Count) { return 'no one' }
    return ($names -join ', ')
}
function Get-DeepRightKeys {
    param($Policy,[string]$Right)
    $keys=[System.Collections.Generic.List[string]]::new()
    if ($null -eq $Policy -or -not $Policy.ContainsKey('Privilege Rights')) { return @() }
    foreach ($principal in @(Get-UserRightPrincipals $Policy['Privilege Rights'] $Right)) {
        $key=ConvertTo-DeepPrincipalKey $principal
        if ($key -and -not $keys.Contains($key)) { $keys.Add($key) }
    }
    return @($keys)
}
function Get-DeepRightTarget {
    # The principals a right should hold, worked out from what it holds now.
    param([string[]]$Current,[string]$Mode,[bool]$AddGuests)
    $current=@($Current | Where-Object { $_ })
    switch ($Mode) {
        'Nobody' { return @() }
        'Administrators' { return @('S-1-5-32-544') }
        'NoAnonymous' {
            return @($current | Where-Object { @('S-1-1-0','S-1-5-7','S-1-5-32-546') -notcontains $_ -and $_ -notmatch '^S-1-5-21-[0-9-]+-501$' })
        }
        'DenyGuests' {
            $list=@($current | Where-Object { @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-544') -notcontains $_ })
            if ($AddGuests -and $list -notcontains 'S-1-5-32-546') { $list+='S-1-5-32-546' }
            return $list
        }
    }
    return $current
}
function Invoke-DeepUserRights {
    # The User Rights Assignment table from the CIS Level 1 member-server baseline:
    #   * rights no one should hold (act as part of the OS, create a token, ...);
    #   * rights only Administrators should hold (debug programs, load drivers,
    #     back up and restore files, force remote shutdown, ...);
    #   * Everyone, Anonymous Logon, Guests, and the Guest account removed from
    #     every other right (bypass traverse checking keeps its Everyone default);
    #   * Guests added to the five deny-logon rights, and Everyone, Users,
    #     Authenticated Users, and Administrators removed from them so nobody
    #     who belongs is locked out.
    # Logon-as-a-service and batch rights keep their service accounts. One secedit
    # template applies every change and each right is read back. Domain
    # controllers are left to the domain policy.
    if ($script:IsDomainController) {
        Add-Result 'User rights' 'User rights table' SKIPPED 'Domain controllers use the Default Domain Controllers Policy; nothing was changed.' 'Review user rights in the domain controller GPO.'
        return
    }
    $labels=[ordered]@{
        SeTcbPrivilege='Act as part of the operating system'
        SeCreateTokenPrivilege='Create a token object'
        SeCreatePermanentPrivilege='Create permanent shared objects'
        SeTrustedCredManAccessPrivilege='Access Credential Manager as a trusted caller'
        SeRelabelPrivilege='Modify an object label'
        SeLockMemoryPrivilege='Lock pages in memory'
        SeEnableDelegationPrivilege='Enable accounts to be trusted for delegation'
        SeDebugPrivilege='Debug programs'
        SeLoadDriverPrivilege='Load and unload device drivers'
        SeBackupPrivilege='Back up files and directories'
        SeRestorePrivilege='Restore files and directories'
        SeRemoteShutdownPrivilege='Force shutdown from a remote system'
        SeSystemEnvironmentPrivilege='Modify firmware environment values'
        SeManageVolumePrivilege='Perform volume maintenance tasks'
        SeProfileSingleProcessPrivilege='Profile single process'
        SeInteractiveLogonRight='Allow log on locally'
        SeRemoteInteractiveLogonRight='Allow log on through Remote Desktop Services'
        SeBatchLogonRight='Log on as a batch job'
        SeServiceLogonRight='Log on as a service'
        SeShutdownPrivilege='Shut down the system'
        SeSystemtimePrivilege='Change the system time'
        SeTimeZonePrivilege='Change the time zone'
        SeUndockPrivilege='Remove computer from docking station'
        SeIncreaseQuotaPrivilege='Adjust memory quotas for a process'
        SeAssignPrimaryTokenPrivilege='Replace a process level token'
        SeAuditPrivilege='Generate security audits'
        SeImpersonatePrivilege='Impersonate a client after authentication'
        SeCreateGlobalPrivilege='Create global objects'
        SeCreatePagefilePrivilege='Create a pagefile'
        SeSystemProfilePrivilege='Profile system performance'
        SeCreateSymbolicLinkPrivilege='Create symbolic links'
        SeIncreaseBasePriorityPrivilege='Increase scheduling priority'
        SeIncreaseWorkingSetPrivilege='Increase a process working set'
        SeDenyNetworkLogonRight='Deny access to this computer from the network'
        SeDenyInteractiveLogonRight='Deny log on locally'
        SeDenyRemoteInteractiveLogonRight='Deny log on through Remote Desktop Services'
        SeDenyBatchLogonRight='Deny log on as a batch job'
        SeDenyServiceLogonRight='Deny log on as a service'
    }
    $modes=@{}
    foreach ($right in @('SeTcbPrivilege','SeCreateTokenPrivilege','SeCreatePermanentPrivilege','SeTrustedCredManAccessPrivilege','SeRelabelPrivilege','SeLockMemoryPrivilege','SeEnableDelegationPrivilege')) { $modes[$right]='Nobody' }
    foreach ($right in @('SeDebugPrivilege','SeLoadDriverPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeRemoteShutdownPrivilege','SeSystemEnvironmentPrivilege','SeManageVolumePrivilege','SeProfileSingleProcessPrivilege')) { $modes[$right]='Administrators' }
    foreach ($right in @('SeDenyNetworkLogonRight','SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight','SeDenyBatchLogonRight','SeDenyServiceLogonRight')) { $modes[$right]='DenyGuests' }
    foreach ($right in @($labels.Keys)) { if (-not $modes.ContainsKey($right)) { $modes[$right]='NoAnonymous' } }
    # Guests is added to the deny rights only when nobody but the built-in Guest
    # account is in it; otherwise a real user would be locked out.
    $addGuests=$true
    $guestMembers=@()
    try {
        $guestMembers=@(Get-LocalGroupMember -SID 'S-1-5-32-546' -ErrorAction Stop | Where-Object { [string]$_.SID.Value -notmatch '^S-1-5-21-[0-9-]+-501$' } | ForEach-Object { [string]$_.Name })
    } catch { $guestMembers=@('(membership could not be read)') }
    if ($guestMembers.Count) {
        $addGuests=$false
        Add-Result 'User rights' 'Guests in deny rights' REVIEW "The Guests group has other members: $($guestMembers -join ', '). Guests was not added to the deny-logon rights so they are not locked out." 'Remove unauthorized members from Guests, then run the script again.'
    }
    try { $policy=Get-SecurityPolicy } catch {
        Add-Result 'User rights' 'User rights table' FAILED "Unable to read the current rights: $($_.Exception.Message)" 'Review user rights in secpol.msc.'
        return
    }
    $plans=[ordered]@{}
    $correct=[System.Collections.Generic.List[string]]::new()
    foreach ($right in @($labels.Keys)) {
        $current=@(Get-DeepRightKeys $policy $right)
        $target=@(Get-DeepRightTarget -Current $current -Mode $modes[$right] -AddGuests $addGuests)
        $currentText=(@($current | Sort-Object) -join ',')
        $targetText=(@($target | Sort-Object) -join ',')
        if ($currentText -ieq $targetText) { $correct.Add($labels[$right]); continue }
        $plans[$right]=[pscustomobject]@{Right=$right;Label=$labels[$right];Current=$current;Target=$target}
    }
    if ($correct.Count) { Add-Result 'User rights' 'User rights already correct' PASS "$($correct.Count) right(s): $($correct -join '; ')." '' }
    if (-not $plans.Count) { return }
    if ($script:IsDomainJoined) {
        Add-Result 'User rights' 'Domain policy may control user rights' REVIEW 'Local user rights were updated, but a domain GPO that defines the same rights wins.' 'Check gpresult /h for user rights set by the domain.'
    }
    if (-not $Apply -or $WhatIfPreference) {
        foreach ($plan in $plans.Values) {
            Add-Result 'User rights' "$($plan.Label) ($($plan.Right))" REVIEW "Now: $(Format-DeepPrincipals $plan.Current). Should be: $(Format-DeepPrincipals $plan.Target)." 'Run with -Apply to set it.'
        }
        return
    }
    $prefix=Join-Path ([IO.Path]::GetTempPath()) ('CYPat-rights-' + [guid]::NewGuid().ToString('N'))
    $applyError=''
    try {
        $lines=[System.Collections.Generic.List[string]]::new()
        foreach ($line in @('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[Privilege Rights]')) { $lines.Add($line) }
        foreach ($plan in $plans.Values) {
            $values=@($plan.Target | ForEach-Object { if ($_ -match '^S-1-') { "*$_" } else { [string]$_ } })
            $lines.Add("$($plan.Right) = $($values -join ',')")
        }
        $lines | Set-Content -LiteralPath "$prefix.inf" -Encoding Unicode -ErrorAction Stop
        Invoke-Native 'secedit.exe' @('/validate',"$prefix.inf") | Out-Null
        Invoke-Native 'secedit.exe' @('/configure','/db',"$prefix.sdb",'/cfg',"$prefix.inf",'/areas','USER_RIGHTS','/log',"$prefix.log",'/quiet') | Out-Null
    } catch {
        $applyError=$_.Exception.Message
    } finally {
        foreach ($file in @("$prefix.inf","$prefix.sdb","$prefix.log","$prefix.jfm","$prefix.sdb.jfm")) {
            if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue }
        }
    }
    $after=$null
    try { $after=Get-SecurityPolicy } catch { if (-not $applyError) { $applyError="Readback failed: $($_.Exception.Message)" } }
    foreach ($plan in $plans.Values) {
        $item="$($plan.Label) ($($plan.Right))"
        if ($null -eq $after) {
            Add-Result 'User rights' $item FAILED $applyError 'Set this right in secpol.msc > Local Policies > User Rights Assignment.'
            continue
        }
        $now=@(Get-DeepRightKeys $after $plan.Right)
        if ((@($now | Sort-Object) -join ',') -ieq (@($plan.Target | Sort-Object) -join ',')) {
            Add-Result 'User rights' $item CHANGED "Was: $(Format-DeepPrincipals $plan.Current). Now: $(Format-DeepPrincipals $now)." ''
            Add-Ledger 'USER RIGHT' $plan.Right "Previous: $(Format-DeepPrincipals $plan.Current); new: $(Format-DeepPrincipals $now)"
        } else {
            $why=if ($applyError) { "$applyError " } else { '' }
            Add-Result 'User rights' $item FAILED "${why}Readback: $(Format-DeepPrincipals $now). Wanted: $(Format-DeepPrincipals $plan.Target)." 'Set this right in secpol.msc > Local Policies > User Rights Assignment, or check the governing GPO.'
        }
    }
}
function Invoke-DeepSystemAccess {
    # Network access: Allow anonymous SID/Name translation = Disabled, and Network
    # security: Force logoff when logon hours expire = Enabled. Both live in the
    # [System Access] part of the local security policy.
    if ($script:IsDomainController) {
        Add-Result 'Security options' 'Anonymous SID/name translation and forced logoff' SKIPPED 'Domain controllers take these from the domain policy.' ''
        return
    }
    $wanted=[ordered]@{LSAAnonymousNameLookup='0';ForceLogoffWhenHourExpire='1'}
    $current='unreadable'
    try {
        $policy=Get-SecurityPolicy
        $current=(@($wanted.Keys | ForEach-Object { "$_=$(if ($policy['System Access'].ContainsKey($_)) { [string]$policy['System Access'][$_] } else { 'not set' })" }) -join '; ')
    } catch { $current="unreadable: $($_.Exception.Message)" }
    Invoke-Setting 'Security options' 'Anonymous SID/name translation off and forced logoff on' {
        $policy=Get-SecurityPolicy
        foreach ($key in $wanted.Keys) {
            if (-not $policy['System Access'].ContainsKey($key) -or ([string]$policy['System Access'][$key]).Trim() -ne $wanted[$key]) { return $false }
        }
        return $true
    } {
        $prefix=Join-Path ([IO.Path]::GetTempPath()) ('CYPat-access-' + [guid]::NewGuid().ToString('N'))
        try {
            $lines=@('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1','[System Access]')
            foreach ($key in $wanted.Keys) { $lines+="$key = $($wanted[$key])" }
            $lines | Set-Content -LiteralPath "$prefix.inf" -Encoding Unicode -ErrorAction Stop
            Invoke-Native 'secedit.exe' @('/configure','/db',"$prefix.sdb",'/cfg',"$prefix.inf",'/areas','SECURITYPOLICY','/log',"$prefix.log",'/quiet') | Out-Null
        } finally {
            foreach ($file in @("$prefix.inf","$prefix.sdb","$prefix.log","$prefix.jfm","$prefix.sdb.jfm")) {
                if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue }
            }
        }
    } "Current: $current. Required: LSAAnonymousNameLookup=0, ForceLogoffWhenHourExpire=1." 'Set both in secpol.msc > Local Policies > Security Options.'
}
function Invoke-DeepDefenderPolicy {
    # A planted Group Policy value switches Defender off whatever Set-MpPreference
    # says, so every value that disables protection must be missing or 0. Each one
    # found is set to 0 and read back. Then potentially unwanted app blocking,
    # cloud protection, sample submission, network protection, and archive,
    # e-mail, and removable-drive scanning are turned on.
    $root='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $found=0
    foreach ($check in @(
        @($root,'DisableAntiSpyware'),@($root,'DisableAntiVirus'),@($root,'DisableRoutinelyTakingAction'),
        @("$root\Real-Time Protection",'DisableRealtimeMonitoring'),@("$root\Real-Time Protection",'DisableBehaviorMonitoring'),
        @("$root\Real-Time Protection",'DisableOnAccessProtection'),@("$root\Real-Time Protection",'DisableScanOnRealtimeEnable'),
        @("$root\Real-Time Protection",'DisableIOAVProtection'),@("$root\Real-Time Protection",'DisableScriptScanning'),
        @("$root\Scan",'DisableArchiveScanning'),@("$root\Scan",'DisableRemovableDriveScanning'),@("$root\Scan",'DisableEmailScanning')
    )) {
        $state=Get-RegistryState $check[0] $check[1]
        if (-not $state.Exists) { continue }
        $found++
        Set-RegistryBaseline Defender $check[0] $check[1] 0
    }
    $spynet=Get-RegistryState "$root\Spynet" 'SpynetReporting'
    if ($spynet.Exists) { $found++; Set-DeepRegistryRange Defender "$root\Spynet" 'SpynetReporting' 1 2 2 }
    $consent=Get-RegistryState "$root\Spynet" 'SubmitSamplesConsent'
    if ($consent.Exists -and [string]$consent.Value -eq '2') { $found++; Set-RegistryBaseline Defender "$root\Spynet" 'SubmitSamplesConsent' 1 }
    if (-not $found) { Add-Result Defender 'Defender policy overrides' PASS 'No Group Policy value turns Defender protection off.' '' }
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) {
        Add-Result Defender 'Defender protection features' SKIPPED 'The Defender cmdlets are unavailable.' ''
        return
    }
    $status=$null
    try { $status=Get-MpComputerStatus -ErrorAction Stop } catch { $status=$null }
    if ($null -ne $status -and [string](Get-OptionalProperty $status 'AMRunningMode' '') -match 'Passive|EDR') {
        Add-Result Defender 'Defender protection features' SKIPPED 'Defender runs in passive mode behind another antivirus.' ''
        return
    }
    $setParameters=@{}
    try { $setParameters=(Get-Command Set-MpPreference -ErrorAction Stop).Parameters } catch { $setParameters=@{} }
    $features=@(
        @{Name='PUAProtection';Value='Enabled';Expected=@('1');Label='Block potentially unwanted apps'},
        @{Name='MAPSReporting';Value='Advanced';Expected=@('1','2');Label='Cloud-delivered protection'},
        @{Name='SubmitSamplesConsent';Value='SendSafeSamples';Expected=@('1','3');Label='Automatic sample submission'},
        @{Name='DisableArchiveScanning';Value=$false;Expected=@('False');Label='Scan archive files'},
        @{Name='DisableEmailScanning';Value=$false;Expected=@('False');Label='Scan e-mail'},
        @{Name='DisableRemovableDriveScanning';Value=$false;Expected=@('False');Label='Scan removable drives'},
        @{Name='DisableBlockAtFirstSeen';Value=$false;Expected=@('False');Label='Block at first sight'}
    )
    if ($os.ProductType -ne 1 -and $setParameters.ContainsKey('AllowNetworkProtectionOnWinServer')) {
        $features+=@{Name='AllowNetworkProtectionOnWinServer';Value=$true;Expected=@('True');Label='Allow network protection on Windows Server'}
    }
    $features+=@{Name='EnableNetworkProtection';Value='Enabled';Expected=@('1');Label='Network protection'}
    foreach ($feature in $features) {
        $featureName=[string]$feature.Name
        if (-not $setParameters.ContainsKey($featureName)) { continue }
        $before=''
        try { $before=[string](Get-OptionalProperty (Get-MpPreference -ErrorAction Stop) $featureName '') } catch { $before='unreadable' }
        Invoke-Setting Defender $feature.Label {
            $value=[string](Get-OptionalProperty (Get-MpPreference -ErrorAction Stop) $featureName '')
            @($feature.Expected) -contains $value
        } {
            $arguments=@{ErrorAction='Stop'}
            $arguments[$featureName]=$feature.Value
            Set-MpPreference @arguments
        } "$featureName=$before; required $(@($feature.Expected) -join ' or ')." "Turn on $($feature.Label) in Windows Security, or check for a Defender policy or Tamper Protection that blocks it."
    }
}
function Invoke-DeepAutoLogon {
    # Automatic logon keeps a password in plain text in the registry. Turning it
    # off and deleting the stored password is one Y/N question.
    $winlogon='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $auto=Get-RegistryState $winlogon 'AutoAdminLogon'
    $stored=Get-RegistryState $winlogon 'DefaultPassword'
    $on=$auto.Exists -and ([string]$auto.Value).Trim() -eq '1'
    if (-not $on -and -not $stored.Exists) {
        Add-Result Logon 'Automatic logon' PASS 'Automatic logon is off and no password is stored in the registry.' ''
        return
    }
    $user=Get-RegistryState $winlogon 'DefaultUserName'
    $who=if ($user.Exists -and [string]$user.Value) { [string]$user.Value } else { 'unknown' }
    $evidence="AutoAdminLogon=$(if ($auto.Exists) { [string]$auto.Value } else { 'not set' }); stored password present=$($stored.Exists); account=$who. The password itself is not shown."
    if (-not $Apply -or $NonInteractive -or $WhatIfPreference) {
        Add-Result Logon 'Automatic logon' REVIEW $evidence 'Run with -Apply interactively and answer Y to turn automatic logon off and delete the stored password.'
        return
    }
    $answer=Read-YesNo "Automatic logon for $who is on or its password is stored in the registry. Turn automatic logon off and delete the stored password? Y turns it off; N keeps it"
    if ($answer -ne 'Y') {
        $status=if ($answer -eq 'N') { 'SKIPPED' } else { 'REVIEW' }
        Add-Result Logon 'Automatic logon' $status "$evidence Left unchanged by operator decision." 'Turn it off unless the README requires automatic logon.'
        return
    }
    try {
        New-ItemProperty -LiteralPath $winlogon -Name 'AutoAdminLogon' -Value '0' -PropertyType String -Force -ErrorAction Stop | Out-Null
        if ($stored.Exists) { Remove-ItemProperty -LiteralPath $winlogon -Name 'DefaultPassword' -ErrorAction Stop }
        $afterAuto=Get-RegistryState $winlogon 'AutoAdminLogon'
        $afterStored=Get-RegistryState $winlogon 'DefaultPassword'
        if ([string]$afterAuto.Value -ne '0' -or $afterStored.Exists) { throw 'Readback still shows automatic logon or a stored password.' }
        Add-Result Logon 'Automatic logon' CHANGED "Automatic logon for $who was turned off and the stored password was deleted." ''
        Add-Ledger 'LOGON' 'AutoAdminLogon' "Turned off for $who; DefaultPassword deleted."
    } catch {
        Add-Result Logon 'Automatic logon' FAILED $_.Exception.Message 'Set AutoAdminLogon to 0 and delete DefaultPassword under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon.'
    }
}
function Invoke-DeepPowerShellV2 {
    # The PowerShell 2.0 engine skips script block logging and AMSI, which is why
    # attackers downgrade to it. Removing it is one Y/N question; scripts keep
    # running on PowerShell 5.1.
    $kind=''
    $installed=$false
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        try {
            $feature=Get-WindowsFeature -Name 'PowerShell-V2' -ErrorAction Stop
            if ($null -ne $feature) { $kind='Server'; $installed=[bool]$feature.Installed }
        } catch { $kind='' }
    }
    if (-not $kind -and (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue)) {
        try {
            $optional=Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction Stop
            if ($null -ne $optional) { $kind='Client'; $installed=([string]$optional.State -eq 'Enabled') }
        } catch { $kind='' }
    }
    if (-not $kind) {
        Add-Result PowerShell 'PowerShell 2.0 engine' SKIPPED 'The Windows feature list could not be read.' 'Check Windows Features for Windows PowerShell 2.0.'
        return
    }
    if (-not $installed) {
        Add-Result PowerShell 'PowerShell 2.0 engine' PASS 'The PowerShell 2.0 engine is not installed.' ''
        return
    }
    if (-not $Apply -or $NonInteractive -or $WhatIfPreference) {
        Add-Result PowerShell 'PowerShell 2.0 engine' REVIEW 'The PowerShell 2.0 engine is installed; attackers use it to avoid logging.' 'Run with -Apply interactively and answer Y to remove it.'
        return
    }
    $answer=Read-YesNo 'Remove the Windows PowerShell 2.0 engine? Y removes it (scripts keep using PowerShell 5.1); N keeps it'
    if ($answer -ne 'Y') {
        $status=if ($answer -eq 'N') { 'SKIPPED' } else { 'REVIEW' }
        Add-Result PowerShell 'PowerShell 2.0 engine' $status 'Left installed by operator decision.' 'Remove it unless the README requires PowerShell 2.0.'
        return
    }
    try {
        $restart=''
        if ($kind -eq 'Server') {
            $outcome=Uninstall-WindowsFeature -Name 'PowerShell-V2' -ErrorAction Stop
            $restart=[string](Get-OptionalProperty $outcome 'RestartNeeded' '')
            $gone=-not [bool](Get-WindowsFeature -Name 'PowerShell-V2' -ErrorAction Stop).Installed
        } else {
            $outcome=Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -ErrorAction Stop
            $restart=[string](Get-OptionalProperty $outcome 'RestartNeeded' '')
            $gone=@('Disabled','DisablePending') -contains [string](Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction Stop).State
        }
        if (-not $gone) { throw 'The feature still reads back as installed.' }
        $note=if ($restart -match '^(?i)(yes|true)$') { ' A restart finishes the removal; the script does not restart the computer.' } else { '' }
        Add-Result PowerShell 'PowerShell 2.0 engine' CHANGED "The PowerShell 2.0 engine was removed.$note" ''
        Add-Ledger 'FEATURE' 'PowerShell 2.0 engine' "Removed after the operator answered Y.$note"
    } catch {
        Add-Result PowerShell 'PowerShell 2.0 engine' FAILED $_.Exception.Message 'Remove Windows PowerShell 2.0 in Server Manager or Windows Features.'
    }
}
#endregion
function Invoke-UpdateFreshnessAudit {
    # R5. "The majority of Windows updates are installed" and "<browser> has been
    # updated" are scored. Nothing is downloaded; this reports how old the newest
    # installed update and each browser's program file are.
    $hotfixes=@()
    try { $hotfixes=@(Get-HotFix -ErrorAction Stop | Where-Object { $null -ne $_.InstalledOn } | Sort-Object InstalledOn -Descending) } catch { $hotfixes=@() }
    if (-not $hotfixes.Count) {
        Add-Result Updates 'Windows update freshness' REVIEW 'No installed update reports an install date.' 'Open Settings > Windows Update and install the quality updates the README allows; feature upgrades are usually not wanted.'
    } else {
        $newest=$hotfixes[0]
        $installedOn=[datetime]$newest.InstalledOn
        $age=[int]((Get-Date)-$installedOn).TotalDays
        $text="Newest update $($newest.HotFixID) was installed $($installedOn.ToString('yyyy-MM-dd')) ($age day(s) ago); $($hotfixes.Count) dated update(s) are installed."
        if ($age -gt 45) {
            Add-Result Updates 'Windows update freshness' REVIEW $text 'The image is more than 45 days behind. Install the quality updates the README allows from Settings > Windows Update.'
        } else {
            Add-Result Updates 'Windows update freshness' PASS $text ''
        }
    }
    $browsers=@()
    if ($script:Inventory.Contains('Browsers')) { $browsers=@($script:Inventory['Browsers']) }
    foreach ($browser in $browsers) {
        $browserName=[string](Get-OptionalProperty $browser 'Name' '')
        foreach ($executable in @(Get-OptionalProperty $browser 'Executables' @())) {
            if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { continue }
            $file=Get-Item -LiteralPath $executable -ErrorAction SilentlyContinue
            if ($null -eq $file) { continue }
            $version=''
            try { $version=[string]$file.VersionInfo.ProductVersion } catch { $version='' }
            $fileAge=[int]((Get-Date)-$file.LastWriteTime).TotalDays
            $text="$browserName $version at $executable; the program file is dated $($file.LastWriteTime.ToString('yyyy-MM-dd')) ($fileAge day(s) old)."
            if ($fileAge -gt 60) {
                Add-Result Updates "$browserName freshness" REVIEW $text "Update $browserName with its own updater or official installer if the README allows; a browser update is commonly scored."
            } else {
                Add-Result Updates "$browserName freshness" PASS $text ''
            }
        }
    }
}
#endregion
function Get-ScheduledTaskActionData {
    param($Task)
    $paths = [System.Collections.Generic.List[string]]::new()
    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($action in @(Get-OptionalProperty $Task 'Actions' @())) {
        if ($null -eq $action) { continue }
        $execute = [string](Get-OptionalProperty $action 'Execute' '')
        if ($execute) { $paths.Add($execute) }
        $argument = [string](Get-OptionalProperty $action 'Arguments' '')
        if ($argument) { $arguments.Add($argument) }
    }
    return [pscustomobject]@{ Paths=@($paths); Arguments=@($arguments) }
}
function Get-ScheduledTaskRisk {
    param($Task)
    $name = [string](Get-OptionalProperty $Task 'TaskName' '')
    $path = [string](Get-OptionalProperty $Task 'TaskPath' '')
    $fullName = "$path$name"
    $reasons = [System.Collections.Generic.List[string]]::new()
    $risk = 'Info'
    $actionData = Get-ScheduledTaskActionData $Task
    $actionText = (@($actionData.Paths) -join '; ')
    $argumentText = (@($actionData.Arguments) -join ' ')
    if ($fullName -match '(?i)backup[_\-\s]?plan') {
        $reasons.Add('Task name matches the known irregular pattern backup_plan.')
        $risk = 'High'
    } elseif ($name -match '(?i)(^|[_\-\s])(payload|backdoor|malware|persist|persistence|evil|hack|keylog|mimikatz|netcat|nc)([_\-\s]|$)') {
        $reasons.Add('Task name contains a suspicious persistence or intrusion tool token.')
        $risk = 'High'
    }
    if ($actionText -match '(?i)(\\Users\\|\\Temp\\|\\AppData\\|\\ProgramData\\|\\Downloads\\|\\Public\\)') {
        $reasons.Add('Task action executable is in a user-writable location.')
        $risk = 'High'
    }
    # v6: a task whose own action binary cannot prove its origin is a persistence
    # lead regardless of its name or folder. v5 never looked at the signature.
    foreach ($actionPath in @($actionData.Paths)) {
        $resolved=ConvertTo-ExecutablePath ([string]$actionPath)
        if ([string]::IsNullOrWhiteSpace($resolved)) { continue }
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { continue }
        $provenance=Get-FileProvenance $resolved
        if ($provenance.Severity -eq 'High') {
            $reasons.Add("Action binary has no verifiable origin ($([string]$provenance.Class)): $($provenance.Reason)")
            $risk = 'High'
            Add-SuspiciousPath $resolved
            Add-HighSignal 'TASK' $resolved "$fullName -> $resolved [$([string]$provenance.Class)]" 'Record the task XML before disabling it.'
        } elseif ($provenance.Severity -eq 'Review' -and $risk -eq 'Info') {
            $reasons.Add("Action binary publisher is unverified: $($provenance.Reason)")
            $risk = 'Review'
        }
    }
    if ($argumentText -match '(?i)(-enc(odedcommand)?\b|frombase64string|invoke-expression|\biex\b|windowstyle\s+hidden|mshta|regsvr32\s+.*(/i:|scrobj)|rundll32\s+.*javascript|\bwscript\b|\bcscript\b|bitsadmin|certutil\s+.*-urlcache|\bcurl(\.exe)?\s|\bwget(\.exe)?\s)') {
        $reasons.Add('Task action arguments match a hidden, encoded, download, or script-host pattern.')
        $risk = 'High'
    }
    $settings = Get-OptionalProperty $Task 'Settings' $null
    if ([bool](Get-OptionalProperty $settings 'Hidden' $false)) {
        $reasons.Add('Task is marked hidden.')
        if ($risk -eq 'Info') { $risk = 'Review' }
    }
    $principal = Get-OptionalProperty $Task 'Principal' $null
    $userId = [string](Get-OptionalProperty $principal 'UserId' '')
    if ($actionText -match '(?i)(\\Users\\|\\Temp\\|\\AppData\\|\\ProgramData\\|\\Downloads\\|\\Public\\)' -and $userId -match '(?i)(SYSTEM|S-1-5-18|Administrators|S-1-5-32-544)') {
        $reasons.Add("Task runs as a privileged principal ($userId) from a user-writable path.")
        $risk = 'High'
    }
    if ($path -and $path -notlike '\Microsoft\*' -and $risk -eq 'Info') {
        $reasons.Add('Task is outside the Microsoft namespace.')
        $risk = 'Review'
    }
    if ($risk -eq 'High' -and [string](Get-OptionalProperty $Task 'State' '') -eq 'Disabled') {
        $reasons.Add('The task is disabled, so the risk is historical rather than active.')
        $risk = 'Review'
    }
    return [pscustomobject]@{
        Risk=$risk; Reasons=@($reasons); Name=$name; Path=$path; FullName=$fullName;
        ActionPaths=@($actionData.Paths); PrivilegedPrincipal=$userId
    }
}
function Test-ScoringComponentText {
    # True when a name, path, or command line points at the CyberPatriot scoring
    # engine or the AFA folder. Those are never offered for removal.
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return [bool]($Text -match '(?i)cyberpatriot|ccsclient|(^|[\\/\s"])AFA([\\/\s"]|$)')
}
function Format-TaskActionText {
    # What a task runs, as one line: program and arguments for each action.
    param($Task)
    $parts=[System.Collections.Generic.List[string]]::new()
    foreach ($action in @(Get-OptionalProperty $Task 'Actions' @())) {
        if ($null -eq $action) { continue }
        $execute=[string](Get-OptionalProperty $action 'Execute' '')
        $arguments=[string](Get-OptionalProperty $action 'Arguments' '')
        if ($execute) { $parts.Add(("$execute $arguments").Trim()); continue }
        $classId=[string](Get-OptionalProperty $action 'ClassId' '')
        if ($classId) { $parts.Add("COM handler $classId"); continue }
        $parts.Add('an email or message action')
    }
    if (-not $parts.Count) { return '(no action)' }
    $text=$parts -join ' ; '
    if ($text.Length -gt 400) { $text=$text.Substring(0,400)+'...' }
    return $text
}
function Format-TaskTriggerText {
    # When a task runs, in plain words.
    param($Task)
    $labels=[System.Collections.Generic.List[string]]::new()
    foreach ($trigger in @(Get-OptionalProperty $Task 'Triggers' @())) {
        if ($null -eq $trigger) { continue }
        $class=''
        try { $class=[string]$trigger.CimClass.CimClassName } catch { $class='' }
        $label='unknown trigger'
        if ($class -match 'Logon') { $label='at logon' }
        elseif ($class -match 'Boot') { $label='at startup' }
        elseif ($class -match 'Daily') { $label='daily' }
        elseif ($class -match 'Weekly') { $label='weekly' }
        elseif ($class -match 'Monthly') { $label='monthly' }
        elseif ($class -match 'Idle') { $label='when the computer is idle' }
        elseif ($class -match 'Event') { $label='when an event is logged' }
        elseif ($class -match 'Registration') { $label='when the task is created' }
        elseif ($class -match 'SessionStateChange') { $label='on session connect, lock, or unlock' }
        elseif ($class -match 'Time') { $label='at a set time' }
        elseif ($class) { $label=$class -replace '^MSFT_Task','' }
        $repeat=''
        try {
            $interval=[string]$trigger.Repetition.Interval
            if ($interval) { $repeat=" (repeats every $interval)" }
        } catch { $repeat='' }
        $labels.Add("$label$repeat")
    }
    if (-not $labels.Count) { return 'no trigger; it runs only when something starts it' }
    return ($labels -join ', ')
}
function Remove-ScheduledTaskWithEvidence {
    # Saves the task's XML in the private run folder, stops it, removes it, and
    # proves it is gone. When the XML cannot be saved the task is disabled instead,
    # so it can still be examined.
    param($Risk)
    $fullName=[string]$Risk.FullName
    try {
        $evidencePath=''
        $exportError='the private run folder is unavailable'
        if (-not [string]::IsNullOrWhiteSpace($script:RunDirectory)) {
            try {
                $xml=Export-ScheduledTask -TaskName $Risk.Name -TaskPath $Risk.Path -ErrorAction Stop
                $safeName=([string]$Risk.Name) -replace '[^A-Za-z0-9_.-]','_'
                if ($safeName.Length -gt 60) { $safeName=$safeName.Substring(0,60) }
                $evidencePath=Join-Path $script:RunDirectory ("Task-$([guid]::NewGuid().ToString('N').Substring(0,8))-$safeName.xml")
                Set-Content -LiteralPath $evidencePath -Value $xml -Encoding UTF8 -ErrorAction Stop
                Add-Ledger 'EVIDENCE' "Task/$fullName" "Task XML exported to $evidencePath"
            } catch {
                $exportError=$_.Exception.Message
                $evidencePath=''
            }
        }
        try { Stop-ScheduledTask -TaskName $Risk.Name -TaskPath $Risk.Path -ErrorAction Stop } catch { Write-Verbose "Stop-ScheduledTask ${fullName}: $($_.Exception.Message)" }
        if (-not $evidencePath) {
            Disable-ScheduledTask -TaskName $Risk.Name -TaskPath $Risk.Path -ErrorAction Stop | Out-Null
            $after=Get-ScheduledTask -TaskName $Risk.Name -TaskPath $Risk.Path -ErrorAction Stop
            if ([string]$after.State -ne 'Disabled') { throw "Readback state is $($after.State), not Disabled." }
            Add-Result Persistence "Task/$fullName" REVIEW "Its XML could not be saved ($exportError), so the task was disabled instead of removed." 'Record the task in Task Scheduler, then delete it there.'
            Add-Ledger 'TASK' "Task/$fullName" 'Disabled (the XML export failed) after the operator answered N.'
            return
        }
        Unregister-ScheduledTask -TaskName $Risk.Name -TaskPath $Risk.Path -Confirm:$false -ErrorAction Stop
        $remaining=@(Get-ScheduledTask -TaskName $Risk.Name -TaskPath $Risk.Path -ErrorAction SilentlyContinue)
        if ($remaining.Count) { throw 'The task still exists after removal.' }
        Add-Result Persistence "Task/$fullName" CHANGED "Removed because the operator answered N (it does not belong). Its XML is saved at $evidencePath." ''
        Add-Ledger 'TASK' "Task/$fullName" "Removed after the operator answered N; XML at $evidencePath."
    } catch {
        Add-Result Persistence "Task/$fullName" FAILED $_.Exception.Message 'Delete the task in Task Scheduler after recording it.'
    }
}
function Invoke-ScheduledTaskAudit {
    # Every task outside the \Microsoft\ folder, and every high-risk task inside
    # it, gets one question: does it belong on this image? Y keeps it. N saves the
    # task's XML to the private run folder, stops the task, and removes it. No
    # answer changes nothing. -AuditOnly and -NonInteractive only list the tasks.
    # Tasks that run the CyberPatriot scoring engine or anything in
    # C:\CyberPatriot or C:\AFA are never offered.
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        Add-Result Persistence 'Scheduled task audit' SKIPPED 'The ScheduledTasks module is unavailable.' 'Inspect Task Scheduler and schtasks /query /xml manually for irregular tasks such as backup_plan.'
        return
    }
    try { $tasks=@(Get-ScheduledTask -ErrorAction Stop) }
    catch {
        Add-Result Persistence 'Scheduled task audit' REVIEW "Unable to enumerate scheduled tasks: $($_.Exception.Message)" 'Run schtasks /query /xml as administrator and inspect tasks such as backup_plan manually.'
        return
    }
    $script:Inventory.ScheduledTasks=@($tasks | Select-Object TaskName,TaskPath,State,Author)
    $candidates=[System.Collections.Generic.List[object]]::new()
    $highCount=0
    foreach ($task in $tasks) {
        $risk=Get-ScheduledTaskRisk $task
        if ($risk.Risk -eq 'High') { $highCount++ }
        $outsideMicrosoft=-not ([string]$risk.Path -like '\Microsoft\*')
        if (-not $outsideMicrosoft -and $risk.Risk -ne 'High') { continue }
        $actionText=Format-TaskActionText $task
        $scoring=(Test-ScoringComponentText ([string]$risk.FullName)) -or (Test-ScoringComponentText $actionText)
        if ($scoring) {
            Add-Result Persistence "Task/$($risk.FullName)" SKIPPED 'This task belongs to the CyberPatriot scoring engine or the AFA folder and is never changed.' ''
            continue
        }
        $candidates.Add([pscustomobject]@{Task=$task;Risk=$risk;Action=$actionText})
    }
    if (-not $candidates.Count) {
        Add-Result Persistence 'Scheduled task review' PASS "No task outside the \Microsoft\ folder and no high-risk task was found among $($tasks.Count) scheduled task(s)." ''
        return
    }
    $ask=$Apply -and -not $NonInteractive -and -not $WhatIfPreference
    if (-not $ask) {
        foreach ($candidate in $candidates) {
            $risk=$candidate.Risk
            $why=if (@($risk.Reasons).Count) { @($risk.Reasons) -join '; ' } else { 'Not a Windows built-in task (outside the \Microsoft\ folder).' }
            Add-Result Persistence "Task/$($risk.FullName)" REVIEW "[$($risk.Risk)] $why Runs: $($candidate.Action)" 'Run with -Apply interactively and answer whether this task belongs: Y keeps it; N removes it after saving its XML.'
        }
        return
    }
    Write-Host ''
    Write-Host "SCHEDULED TASKS: $($candidates.Count) task(s) to confirm ($highCount high-risk). Y = it belongs, keep it. N = it does not belong, remove it (its XML is saved first)." -ForegroundColor Cyan
    $asked=0
    foreach ($candidate in $candidates) {
        if ($asked -ge 80) {
            Add-Result Persistence 'Scheduled task decisions' REVIEW "The questions stopped after 80 tasks; $($candidates.Count - $asked) task(s) were not asked about." 'Re-run the script to continue.'
            break
        }
        $asked++
        $risk=$candidate.Risk
        $task=$candidate.Task
        $principal=Get-OptionalProperty $task 'Principal' $null
        $runAs=[string](Get-OptionalProperty $principal 'UserId' '')
        if (-not $runAs) { $runAs=[string](Get-OptionalProperty $principal 'GroupId' '') }
        if (-not $runAs) { $runAs='unknown' }
        $author=[string](Get-OptionalProperty $task 'Author' '')
        $state=[string](Get-OptionalProperty $task 'State' '')
        $why=if (@($risk.Reasons).Count) { @($risk.Reasons) -join '; ' } else { 'Not a Windows built-in task (outside the \Microsoft\ folder).' }
        Write-Host ''
        Write-Host "TASK ($asked/$($candidates.Count)) $($risk.FullName)" -ForegroundColor Yellow
        Write-Host "  Runs     : $($candidate.Action)"
        Write-Host "  When     : $(Format-TaskTriggerText $task)"
        Write-Host "  Runs as  : $runAs   State: $state   Author: $author"
        $whyColor='Gray'; if ($risk.Risk -eq 'High') { $whyColor='Red' }
        Write-Host "  Why      : [$($risk.Risk)] $why" -ForegroundColor $whyColor
        $answer=Read-YesNo 'Does this task belong on this image? Y keeps it; N removes it (its XML is saved first)'
        if ($answer -eq 'Y') {
            Add-Result Persistence "Task/$($risk.FullName)" SKIPPED "Kept: the operator answered Y (it belongs). [$($risk.Risk)] $why" ''
            continue
        }
        if ($answer -ne 'N') {
            Add-Result Persistence "Task/$($risk.FullName)" REVIEW "No Y/N answer; the task was left unchanged. [$($risk.Risk)] $why Runs: $($candidate.Action)" 'Run again and answer Y if it belongs or N to remove it.'
            continue
        }
        Remove-ScheduledTaskWithEvidence $risk
    }
}
function Invoke-OtherAudits {
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $entries = @(Get-Content -LiteralPath $hostsPath -ErrorAction Stop | Where-Object { $_ -match '^\s*[^#\s]' -and $_ -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost\s*(#.*)?$' })
    if ($entries.Count) { Add-Result Networking 'Hosts file entries' REVIEW ($entries -join '; ') 'Check each mapping against the scenario. No hosts file reset is performed.' }
    foreach ($adapter in Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop) {
        $index=$adapter.Index; $description=$adapter.Description
        Invoke-Setting Networking "NetBIOS/$description" {
            $current=Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "Index=$index" -ErrorAction Stop
            $current.TcpipNetbiosOptions -eq 2
        } {
            Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} -ErrorAction Stop | Out-Null
        } "Current mode=$($adapter.TcpipNetbiosOptions); required mode=2 (disabled)." 'Disable NetBIOS over TCP/IP unless a documented legacy/WINS dependency exists.'
    }
    # Autorun registry values are audited by Invoke-RunKeyAudit from the main sequence.
    foreach ($file in 'sethc.exe','utilman.exe','osk.exe','magnify.exe') {
        $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$file"
        $debugger = Get-RegistryState $key Debugger
        if ($debugger.Exists) { Add-Result Persistence "IFEO/$file" REVIEW 'Debugger redirection exists; command content is omitted.' 'Record evidence and inspect this logon-accessibility redirection. Disabling Sticky Keys shortcuts does not repair a substituted executable.' }
        $binary = Join-Path $env:SystemRoot "System32\$file"
        if (Test-Path -LiteralPath $binary) {
            $signature = Get-AuthenticodeSignature -LiteralPath $binary -ErrorAction Stop
            if ($signature.Status -ne 'Valid') { Add-Result Persistence "$file signature" REVIEW ([string]$signature.Status) 'Verify Windows file integrity and record evidence; do not overwrite the executable automatically.' }
        }
    }
    Invoke-ScheduledTaskAudit
    # Configure Automatic Updates: Computer Configuration > Administrative Templates >
    # Windows Components > Windows Update > Manage end user experience.
    # The GPO writes NoAutoUpdate plus AUOptions for the selected radio button:
    #   2 = notify for download and auto-install, 3 = automatically download and
    #   notify for install, 4 = automatically download and schedule install.
    # Disabled is NoAutoUpdate=1. The values follow the operator's Windows Update
    # answer; nothing is applied by default.
    $updatePolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auPolicy = "$updatePolicy\AU"
    $wsus = Get-RegistryState $updatePolicy WUServer
    $useWsus = Get-RegistryState $auPolicy UseWUServer
    Invoke-AutomaticUpdatesPolicy -Decision $script:AutomaticUpdatesDecision -Mode $(if ($script:AutomaticUpdatesMode) { $script:AutomaticUpdatesMode } else { 0 })
    if ($wsus.Exists) { Add-Result Updates 'WSUS update source' REVIEW "WSUS configured=$($wsus.Exists); UseWUServer=$($useWsus.Value)" 'Verify the legitimate update source/GPO. WSUS is not inherently malicious; it is preserved.' }
    $disableUx = Get-RegistryState $updatePolicy SetDisableUXWUAccess
    if ($disableUx.Exists -and ([string]$disableUx.Value -eq '1')) {
        Add-Result Updates 'Windows Update user experience' REVIEW 'SetDisableUXWUAccess=1 removes access to all Windows Update features.' 'Clear this value only when the scenario does not need the Windows Update experience hidden.'
    }
    $excludeDrivers = Get-RegistryState $updatePolicy ExcludeWUDriversInQualityUpdate
    if ($excludeDrivers.Exists) {
        Add-Result Updates 'Drivers in quality updates' REVIEW "ExcludeWUDriversInQualityUpdate=$($excludeDrivers.Value)" 'Confirm whether the scenario wants drivers excluded from Windows Update quality updates.'
    }
    $noInternetLocations = Get-RegistryState $updatePolicy DoNotConnectToWindowsUpdateInternetLocations
    if ($noInternetLocations.Exists -and ([string]$noInternetLocations.Value -eq '1')) {
        Add-Result Updates 'Windows Update source restriction' REVIEW 'DoNotConnectToWindowsUpdateInternetLocations=1 blocks the Windows Update service from reaching the Windows Update site.' 'Clear it if the scenario requires automatic update checks from Microsoft Update.'
    }
    $disableUpdateAccess = Get-RegistryState $updatePolicy DisableWindowsUpdateAccess
    if ($disableUpdateAccess.Exists -and ([string]$disableUpdateAccess.Value -eq '1')) {
        Add-Result Updates 'Windows Update access' REVIEW 'DisableWindowsUpdateAccess=1 blocks access to the Windows Update site.' 'Clear it if the scenario requires update checks to reach the Windows Update site.'
    }
    if (Get-Service -Name wuauserv -ErrorAction SilentlyContinue) {
        Invoke-Setting Updates 'Windows Update service start mode' {
            (Get-ServiceStartMode (Get-Service -Name wuauserv -ErrorAction Stop)) -ne 'Disabled'
        } {
            Set-Service -Name wuauserv -StartupType Automatic -ErrorAction Stop
        } 'Automatic Updates needs the Windows Update service (wuauserv) to be enabled.' 'Re-enable the Windows Update service if the scenario disables it.'
    }
    $script:Inventory.Hotfixes = @(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID,InstalledOn)
    Add-Result Updates 'OS and required applications' REVIEW 'Installed hotfixes and application versions are collected; availability is not checked online.' 'Check Windows Update and official required-application updates under current round instructions; downloads and restarts are manual.'
    foreach ($certificate in Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop) {
        if ($certificate.NotAfter -lt (Get-Date)) { Add-Result Certificates 'Expired personal certificate' REVIEW "$($certificate.Subject); expires=$($certificate.NotAfter); thumbprint=$($certificate.Thumbprint)" 'Check whether a required service uses it; renew only the relevant certificate. No trust store is modified.' }
    }
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { $script:Inventory.BitLocker = @(Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod) }
    if (Get-Service -Name EventLog -ErrorAction SilentlyContinue) {
        Invoke-Setting 'Event logs' 'Windows Event Log service' {
            $service = Get-Service -Name EventLog -ErrorAction Stop
            [string]$service.Status -eq 'Running' -and (Get-ServiceStartMode $service) -eq 'Automatic'
        } {
            Set-Service -Name EventLog -StartupType Automatic -ErrorAction Stop
            Start-Service -Name EventLog -ErrorAction Stop
        } "Status=$((Get-Service -Name EventLog -ErrorAction Stop).Status); required status=Running and start mode=Automatic." 'Keep the Windows Event Log service running. Disabling it blinds auditing, event collection, and the report verification performed later.'
    } else {
        Add-Result 'Event logs' 'Windows Event Log service' FAILED 'The EventLog service is not installed.' 'Restore the Windows Event Log service before relying on audit evidence.'
    }
    $logSizes = [ordered]@{Security=$SecurityLogSizeKB; Application=$ApplicationLogSizeKB; System=$SystemLogSizeKB}
    foreach ($log in $logSizes.Keys) {
        $requiredBytes = [int64]$logSizes[$log] * 1024
        $configuration = Get-WinEvent -ListLog $log -ErrorAction Stop
        Invoke-Setting 'Event logs' $log {
            $current=Get-WinEvent -ListLog $log -ErrorAction Stop
            $current.IsEnabled -and $current.MaximumSizeInBytes -ge $requiredBytes -and [string]$current.LogMode -eq 'Circular'
        } {
            try {
                Limit-EventLog -LogName $log -MaximumSize ([int64]$logSizes[$log]) -OverflowAction OverwriteAsNeeded -ErrorAction Stop
            } catch {
                $logKey="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$log"
                New-ItemProperty -LiteralPath $logKey -Name MaxSize -Value ([int64]$requiredBytes) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                New-ItemProperty -LiteralPath $logKey -Name Retention -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            }
        } "Enabled=$($configuration.IsEnabled); max=$($configuration.MaximumSizeInBytes) bytes; mode=$($configuration.LogMode); required max>=$requiredBytes and OverwriteAsNeeded." 'Increase log capacity while preserving existing events. All-failure auditing needs the Security log headroom.'
    }
}
# Browser policies are verified in the registry. Runtime policy acceptance still
# needs chrome://policy, edge://policy or about:policies in each installed browser.
# Sources: https://chromeenterprise.google/policies/
# https://www.chromium.org/administrators/policy-templates/
# https://firefox-admin-docs.mozilla.org/reference/policies/
# https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/
function Set-BrowserPolicy {
    param([string]$Path,[string]$Name,$Value,[string]$Type='DWord',[int[]]$AcceptedValues=@())
    Invoke-Setting Browsers "$Path\$Name (registry policy)" {
        $state = Get-RegistryState $Path $Name
        if (-not $state.Exists) { return $false }
        if ([string](Get-Item -LiteralPath $Path -ErrorAction Stop).GetValueKind($Name) -ne $Type) { return $false }
        if ($AcceptedValues.Count) { return [int]$state.Value -in $AcceptedValues }
        return ($state.Value -join "`0") -eq ($Value -join "`0")
    } {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
    } "Registry policy requires $Type value $Value; stronger accepted values are retained." 'Set the documented machine policy, then verify browser policy acceptance and any GPO override.'
}
function Get-FirefoxPreferencesPolicy {
    param([string]$Path)
    $state = Get-RegistryState $Path Preferences
    if (-not $state.Exists) { return [pscustomobject]@{} }
    $document = ($state.Value -join "`n") | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $document -or $document -isnot [pscustomobject]) { throw 'Firefox Preferences policy is not a JSON object; review it without replacing its other preferences.' }
    return $document
}
function Set-FirefoxSafeBrowsing {
    $path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
    $lockedPreferences = @(
        @{Name='browser.safebrowsing.malware.enabled';Value=$true},
        @{Name='browser.safebrowsing.phishing.enabled';Value=$true},
        @{Name='browser.safebrowsing.downloads.enabled';Value=$true},
        @{Name='browser.safebrowsing.downloads.remote.enabled';Value=$true},
        @{Name='browser.safebrowsing.downloads.remote.block_potentially_unwanted';Value=$true},
        @{Name='browser.safebrowsing.downloads.remote.block_uncommon';Value=$true},
        @{Name='browser.safebrowsing.downloads.remote.block_dangerous';Value=$true},
        @{Name='browser.safebrowsing.downloads.remote.block_dangerous_host';Value=$true},
        @{Name='dom.security.https_only_mode';Value=$true},
        @{Name='dom.security.https_only_mode_pbmode';Value=$true},
        @{Name='signon.management.page.breach-alerts.enabled';Value=$true},
        @{Name='privacy.donottrackheader.enabled';Value=$true},
        @{Name='network.cookie.cookieBehavior';Value=1},
        @{Name='network.cookie.cookieBehavior.pbmode';Value=1},
        @{Name='accessibility.blockautorefresh';Value=$true},
        @{Name='app.update.interval';Value=86400},
        @{Name='app.update.background.interval';Value=86400},
        @{Name='xpinstall.whitelist.required';Value=$true},
        @{Name='security.OCSP.enabled';Value=1}
    )
    # Modern Preferences is REG_MULTI_SZ JSON. Preserve every unrelated preference.
    # Existing legacy subkeys override a same-named JSON value. Keep that format
    # when it is already present rather than dropping its other preferences.
    if (Test-Path -LiteralPath "$path\Preferences") {
        foreach ($preference in $lockedPreferences) {
            $value = if ($preference.Value -is [bool]) { if ($preference.Value) { 1 } else { 0 } } else { $preference.Value }
            Set-BrowserPolicy "$path\Preferences\$($preference.Name)" Value $value
            Set-BrowserPolicy "$path\Preferences\$($preference.Name)" Status 'locked' -Type String
        }
        return
    }
    Invoke-Setting Browsers 'Firefox locked security preferences (registry policy)' {
        $state = Get-RegistryState $path Preferences
        if (-not $state.Exists -or [string](Get-Item -LiteralPath $path -ErrorAction Stop).GetValueKind('Preferences') -ne 'MultiString') { return $false }
        $document = Get-FirefoxPreferencesPolicy $path
        foreach ($entry in $lockedPreferences) {
            $preference = Get-OptionalProperty $document $entry.Name
            $value = Get-OptionalProperty $preference Value
            if (($value -join "`0") -ne ($entry.Value -join "`0") -or (Get-OptionalProperty $preference Status) -ne 'locked') { return $false }
        }
        return $true
    } {
        $document = Get-FirefoxPreferencesPolicy $path
        foreach ($entry in $lockedPreferences) { $document | Add-Member -MemberType NoteProperty -Name $entry.Name -Value ([pscustomobject]@{Value=$entry.Value;Status='locked'}) -Force }
        $json = $document | ConvertTo-Json -Depth 100 -Compress
        if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $path -Name Preferences -Value ([string[]]@($json)) -PropertyType MultiString -Force -ErrorAction Stop | Out-Null
    } 'Firefox Safe Browsing (known malware/phishing site warnings), dangerous-download blocking (including dangerous, uncommon, and potentially unwanted files), breach alerts, Do Not Track, third-party cookie blocking (normal and private windows), HTTPS-Only Mode for normal and private windows, autorefresh blocking, daily update intervals, add-on install warning, and OCSP preferences must be enabled and locked.' 'Merge the protection preferences into the documented Preferences registry JSON, then verify about:policies.'
}
function Get-BrowserInstallations {
    param([object[]]$Profiles=@())
    $definitions = @(
        @{Name='Chrome';Pattern='^Google Chrome(\s|$)';Files=@('Google\Chrome\Application\chrome.exe');UserFiles=@('AppData\Local\Google\Chrome\Application\chrome.exe')},
        @{Name='Chromium';Pattern='(^|\s)Chromium(\s|$)';Files=@('Chromium\Application\chrome.exe','Chromium\chrome.exe','Chromium\Application\chromium.exe');UserFiles=@('AppData\Local\Chromium\Application\chrome.exe','AppData\Local\Chromium\Application\chromium.exe')},
        @{Name='Firefox';Pattern='Firefox';Files=@('Mozilla Firefox\firefox.exe');UserFiles=@('AppData\Local\Mozilla Firefox\firefox.exe')},
        @{Name='Edge';Pattern='Microsoft Edge';Files=@('Microsoft\Edge\Application\msedge.exe');UserFiles=@('AppData\Local\Microsoft\Edge\Application\msedge.exe')}
    )
    $paths = @{}; $detected = @{}
    $apps = if ($script:Inventory.Contains('Applications')) { @($script:Inventory['Applications']) } else { @() }
    foreach ($definition in $definitions) {
        $name = $definition.Name; $paths[$name] = [System.Collections.Generic.List[string]]::new()
        $matchedApps = @($apps | Where-Object { (Get-OptionalProperty $_ DisplayName '') -match $definition.Pattern })
        $detected[$name] = $matchedApps.Count -gt 0
        foreach ($root in @($env:ProgramFiles,${env:ProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique) {
            foreach ($relative in $definition.Files) {
                $candidate = Join-Path $root $relative
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { $paths[$name].Add($candidate); $detected[$name]=$true }
            }
        }
        foreach ($application in $matchedApps) {
            $location = Get-OptionalProperty $application InstallLocation ''
            if (-not $location) { continue }
            $fileName = switch ($name) { 'Firefox' {'firefox.exe'}; 'Edge' {'msedge.exe'}; default {'chrome.exe'} }
            $candidate = Join-Path $location $fileName
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $paths[$name].Add($candidate) }
        }
        foreach ($userProfile in $Profiles) {
            foreach ($relative in $definition.UserFiles) {
                $candidate = Join-Path $userProfile.LocalPath $relative
                if (Test-Path -LiteralPath $candidate -PathType Leaf) { $paths[$name].Add($candidate); $detected[$name]=$true }
            }
        }
    }
    foreach ($root in 'HKLM:\SOFTWARE','HKLM:\SOFTWARE\WOW6432Node','HKCU:\SOFTWARE','HKCU:\SOFTWARE\WOW6432Node') {
        foreach ($executable in 'chrome.exe','chromium.exe','firefox.exe','msedge.exe') {
            $key = "$root\Microsoft\Windows\CurrentVersion\App Paths\$executable"
            if (-not (Test-Path -LiteralPath $key)) { continue }
            try {
                $candidate = [Environment]::ExpandEnvironmentVariables([string](Get-Item -LiteralPath $key -ErrorAction Stop).GetValue('')).Trim('"')
                if (-not $candidate -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
                $name = switch ($executable) { 'firefox.exe' {'Firefox'}; 'msedge.exe' {'Edge'}; 'chromium.exe' {'Chromium'}; default { if ($candidate -match '\\Chromium\\') {'Chromium'} else {'Chrome'} } }
                $paths[$name].Add($candidate); $detected[$name]=$true
            } catch { Add-Result Browsers 'App Paths inventory' REVIEW "Unable to inspect $key : $($_.Exception.Message)" 'Inspect that registered browser path manually.' }
        }
    }
    foreach ($definition in $definitions) {
        $name = $definition.Name
        [pscustomobject]@{Name=$name;Detected=[bool]$detected[$name];Executables=@($paths[$name].ToArray() | Select-Object -Unique)}
    }
}
function Invoke-BrowserExtensionInventory {
    param([object[]]$Profiles=@())
    foreach ($userProfile in $Profiles) {
        $root = [string]$userProfile.LocalPath
        $firefox = Join-Path $root 'AppData\Roaming\Mozilla\Firefox\Profiles'
        try {
            if (Test-Path -LiteralPath $firefox) {
                foreach ($directory in Get-ChildItem -LiteralPath $firefox -Directory -ErrorAction Stop) {
                    $jsonPath = Join-Path $directory.FullName 'extensions.json'
                    if (-not (Test-Path -LiteralPath $jsonPath)) { continue }
                    try {
                        $document = Get-Content -LiteralPath $jsonPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                        $addons = @(Get-OptionalProperty $document addons @() | Where-Object { (Get-OptionalProperty $_ type) -eq 'extension' -and -not (Get-OptionalProperty $_ isSystem $false) })
                        if ($addons.Count) { Add-Result Forensics 'Firefox browser extensions' REVIEW "$jsonPath : $(($addons | ForEach-Object { Get-OptionalProperty $_ id }) -join ', ')" 'Confirm extensions against README; inspect about:addons. Extensions are preserved.' }
                    } catch { Add-Result Forensics 'Firefox extension inventory' REVIEW "$jsonPath : $($_.Exception.Message)" 'Inspect the profile manually.' }
                }
            }
        } catch { Add-Result Forensics 'Firefox profile inventory' REVIEW $_.Exception.Message 'Inspect this user profile manually.' }
        foreach ($relative in 'AppData\Local\Google\Chrome\User Data','AppData\Local\Chromium\User Data','AppData\Local\Microsoft\Edge\User Data') {
            $data = Join-Path $root $relative
            try {
                if (-not (Test-Path -LiteralPath $data)) { continue }
                foreach ($directory in Get-ChildItem -LiteralPath $data -Directory -ErrorAction Stop | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }) {
                    $extensions = Join-Path $directory.FullName 'Extensions'
                    if (-not (Test-Path -LiteralPath $extensions)) { continue }
                    $ids = @(Get-ChildItem -LiteralPath $extensions -Directory -ErrorAction Stop | Select-Object -ExpandProperty Name)
                    if ($ids.Count) { Add-Result Forensics 'Chromium-family browser extensions' REVIEW "$extensions : $($ids -join ', ')" 'Confirm installed IDs and publishers against README; extensions and profile files are preserved.' }
                }
            } catch { Add-Result Forensics 'Chromium-family extension inventory' REVIEW "$data : $($_.Exception.Message)" 'Inspect the profile manually.' }
        }
    }
}
function Invoke-BrowserAudit {
    # Configure supported machine policies even when a browser is not detected.
    # This also covers per-user installations and subsequent browser installations.
    # SmartScreen is a Windows policy, not only a browser policy. "Block" means
    # "Warn and prevent bypass", which covers site and download warnings.
    $smartScreen = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    Set-BrowserPolicy $smartScreen EnableSmartScreen 1
    Set-BrowserPolicy $smartScreen ShellSmartScreenLevel 'Block' -Type String
    Set-BrowserPolicy $smartScreen SmartScreenPuaEnabled 1
    Set-BrowserPolicy 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter' PreventOverride 1
    $wtds = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'
    if ($os.ProductType -eq 1 -and [Environment]::OSVersion.Version.Build -ge 22621) {
        Set-BrowserPolicy $wtds ServiceEnabled 1
        Set-BrowserPolicy $wtds NotifyMalicious 1
        Set-BrowserPolicy $wtds NotifyPasswordReuse 1
        Set-BrowserPolicy $wtds NotifyUnsafeApp 1
        Add-Result Browsers 'Enhanced Phishing Protection' PASS 'Windows 11 22H2+ policies ServiceEnabled, NotifyMalicious, NotifyPasswordReuse, and NotifyUnsafeApp are enabled.' ''
    } else {
        Add-Result Browsers 'Enhanced Phishing Protection' SKIPPED 'Windows 11 22H2+ only; this build has no equivalent SmartScreen policy.' 'Configure on Windows 11 clients if the scenario requires it.'
    }
    Set-BrowserPolicy 'HKLM:\SOFTWARE\Policies\Google\Update' UpdateDefault 1
    Set-BrowserPolicy 'HKLM:\SOFTWARE\Policies\Google\Update' AutoUpdateCheckPeriodMinutes 1440
    Set-BrowserPolicy 'HKLM:\SOFTWARE\Policies\Google\Update' 'Update{8A69D345-D564-463C-AFF1-A69D9E530F96}' 1
    foreach ($path in 'HKLM:\SOFTWARE\Policies\Google\Chrome','HKLM:\SOFTWARE\Policies\Chromium') {
        Set-BrowserPolicy $path PasswordManagerEnabled 0
        Set-BrowserPolicy $path SafeBrowsingProtectionLevel 2
        Set-BrowserPolicy $path DownloadRestrictions 4 -AcceptedValues 1,2,3,4
        Set-BrowserPolicy $path PreventSmartScreenPromptOverride 1
        Set-BrowserPolicy $path PreventSmartScreenPromptOverrideForFiles 1
        Set-BrowserPolicy $path DefaultPopupsSetting 2
        Set-BrowserPolicy $path PasswordLeakDetectionEnabled 1
        Set-BrowserPolicy $path BlockThirdPartyCookies 1
        Set-BrowserPolicy $path EnableDoNotTrack 1
        Set-BrowserPolicy $path EnableOnlineRevocationChecks 1
        Set-BrowserPolicy $path HttpsOnlyMode 'force_enabled' -Type String
    }
    $firefox = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
    foreach ($setting in @(
        @($firefox,'PasswordManagerEnabled',0),@($firefox,'OfferToSaveLogins',0),
        @($firefox,'AppAutoUpdate',1),@($firefox,'DisableAppUpdate',0),@($firefox,'BackgroundAppUpdate',1),@($firefox,'HttpsOnlyMode','force_enabled','String'),
        @("$firefox\DisableSecurityBypass",'SafeBrowsing',1),@("$firefox\DisableSecurityBypass",'InvalidCertificate',1),
        @("$firefox\PopupBlocking",'Default',1),@("$firefox\PopupBlocking",'Locked',1),
        @("$firefox\EnableTrackingProtection",'Value',1),@("$firefox\EnableTrackingProtection",'Locked',1),
        @("$firefox\EnableTrackingProtection",'Cryptomining',1),@("$firefox\EnableTrackingProtection",'Fingerprinting',1)
    )) {
        $type = if ($setting.Count -ge 4) { $setting[3] } else { 'DWord' }
        Set-BrowserPolicy $setting[0] $setting[1] $setting[2] -Type $type
    }
    Set-FirefoxSafeBrowsing
    $edge = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
    Set-BrowserPolicy 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' UpdateDefault 1
    Set-BrowserPolicy 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' AutoUpdateCheckPeriodMinutes 1440
    Set-BrowserPolicy 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' 'Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' 1
    Set-BrowserPolicy $edge PasswordManagerEnabled 0
    Set-BrowserPolicy $edge SmartScreenEnabled 1
    Set-BrowserPolicy $edge SmartScreenPuaEnabled 1
    Set-BrowserPolicy $edge PreventSmartScreenPromptOverride 1
    Set-BrowserPolicy $edge PreventSmartScreenPromptOverrideForFiles 1
    Set-BrowserPolicy $edge SmartScreenDnsRequestsEnabled 1
    Set-BrowserPolicy $edge DefaultPopupsSetting 2
    Set-BrowserPolicy $edge PasswordLeakDetectionEnabled 1
    Set-BrowserPolicy $edge BlockThirdPartyCookies 1
    Set-BrowserPolicy $edge EnableDoNotTrack 1
    Set-BrowserPolicy $edge EnableOnlineRevocationChecks 1
    Set-BrowserPolicy $edge HttpsOnlyMode 'force_enabled' -Type String
    $profiles = @()
    try { $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and $_.LocalPath }) }
    catch { Add-Result Forensics 'Browser user profile inventory' REVIEW $_.Exception.Message 'Inspect browser profiles manually; machine policies are checked separately.' }
    $installations = @(Get-BrowserInstallations -Profiles $profiles)
    $script:Inventory.Browsers = $installations
    foreach ($browser in $installations) {
        $evidence = if ($browser.Detected) { "Detected; executable paths: $($browser.Executables -join ', ')" } else { 'No installation detected in application inventory, standard paths, or registered App Paths.' }
        Add-Result Browsers "$($browser.Name) availability and machine policies" PASS $evidence 'Registry readback proves configured machine policy. Browser policy pages can still show cloud/GPO conflicts.'
        if ($browser.Name -eq 'Firefox') {
            foreach ($executable in $browser.Executables) {
                $policyFile = Join-Path (Split-Path -Parent $executable) 'distribution\policies.json'
                if (Test-Path -LiteralPath $policyFile -PathType Leaf) { Add-Result Forensics 'Firefox browser policy file' REVIEW $policyFile 'An additional policy file exists. Inspect it and effective about:policies for conflicts, precedence, and invalid values; this script preserves the file.' }
            }
        }
    }
    foreach ($path in 'HKLM:\SOFTWARE\Policies\Google\Chrome','HKLM:\SOFTWARE\Policies\Chromium','HKLM:\SOFTWARE\Policies\Microsoft\Edge') {
        $javascript = Get-RegistryState $path 'DefaultJavaScriptSetting'
        if ($javascript.Exists -and [int]$javascript.Value -eq 2) {
            Add-Result Browsers "$path JavaScript" REVIEW 'JavaScript is blocked by policy; this script did not change it.' 'Confirm JavaScript should remain enabled for the scenario.'
        } else {
            Add-Result Browsers "$path JavaScript" PASS 'JavaScript is not blocked by this policy path.' ''
        }
    }
    $firefoxRoot = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'
    $firefoxJavaScript = $null
    $firefoxJavaScriptChecked = $true
    $legacyJavaScript = Get-RegistryState "$firefoxRoot\Preferences\javascript.enabled" 'Value'
    if ($legacyJavaScript.Exists) {
        $firefoxJavaScript = $legacyJavaScript.Value
    } elseif ((Get-RegistryState $firefoxRoot 'Preferences').Exists) {
        try {
            $document = Get-FirefoxPreferencesPolicy $firefoxRoot
            $preference = Get-OptionalProperty $document 'javascript.enabled'
            if ($null -ne $preference) { $firefoxJavaScript = Get-OptionalProperty $preference 'Value' }
        } catch {
            Add-Result Browsers 'Firefox JavaScript' REVIEW $_.Exception.Message 'Inspect the Firefox Preferences policy JSON manually.'
            $firefoxJavaScript = $null
            $firefoxJavaScriptChecked = $false
        }
    }
    if ($firefoxJavaScriptChecked) {
        $firefoxJavaScriptText = ([string]$firefoxJavaScript).Trim().ToLowerInvariant()
        if ($null -ne $firefoxJavaScript -and $firefoxJavaScriptText -in @('0','false')) {
            Add-Result Browsers 'Firefox JavaScript' REVIEW 'JavaScript is disabled by Firefox policy; this script did not change it.' 'Confirm JavaScript should remain enabled for the scenario.'
        } else {
            Add-Result Browsers 'Firefox JavaScript' PASS 'JavaScript is not disabled by policy.' ''
        }
    }
    Invoke-BrowserExtensionInventory -Profiles $profiles
    $policyResults = @($script:Results | Where-Object { $_.Category -eq 'Browsers' })
    $policyPassed = @($policyResults | Where-Object { $_.Status -in @('PASS','CHANGED') }).Count
    $policyReview = @($policyResults | Where-Object Status -eq 'REVIEW').Count
    $policyFailed = @($policyResults | Where-Object Status -eq 'FAILED').Count
    $policySkipped = @($policyResults | Where-Object Status -eq 'SKIPPED').Count
    $summaryStatus = if ($policyFailed) { 'FAILED' } elseif ($policyReview) { 'REVIEW' } elseif ($policySkipped) { 'SKIPPED' } else { 'PASS' }
    Add-Result Browsers 'SmartScreen and browser policy readback' $summaryStatus "Registry policy checks: verified=$policyPassed; review=$policyReview; failed=$policyFailed; skipped=$policySkipped. This summary is computed from per-policy readback, including Windows SmartScreen/PUA policies, Chrome/Chromium/Edge pop-up blocking, third-party cookie blocking, daily update checks, SmartScreen prompt override prevention, Firefox add-on install warnings and dangerous-download blocking, and Firefox locked preferences." 'Resolve any REVIEW or FAILED per-policy row; browser policy pages can still report cloud or GPO conflicts.'
}


function Resolve-TextReportPath {
    param([string]$Path)
    $extension = [IO.Path]::GetExtension($Path)
    if ($extension -in @('.json','.csv')) {
        $Path = [IO.Path]::ChangeExtension($Path,'.txt')
        Write-Warning "V6 writes plain text only; report path changed to $Path"
    }
    return $Path
}
function Export-CYPatReportText {
    param([string]$Path,[string]$Mode,[object]$Report)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('============================================================')
    $lines.Add($script:ProductTitle)
    $lines.Add('============================================================')
    $lines.Add("Run time  : $($Report.Time)")
    $lines.Add("Mode      : $Mode")
    if ($Report.Computer) {
        $lines.Add("Computer  : $($Report.Computer.Name)")
        $lines.Add("OS        : $($Report.Computer.OS)")
        $lines.Add("Domain    : $($Report.Computer.Domain) (joined=$($Report.Computer.DomainJoined))")
    }
    if ($script:RunDirectory) { $lines.Add("Run folder: $script:RunDirectory") }
    $lines.Add('')
    $lines.Add('SUMMARY')
    $lines.Add('-------')
    foreach ($status in 'PASS','CHANGED','REVIEW','FAILED','SKIPPED') {
        $count = @($Report.Results | Where-Object Status -eq $status).Count
        $lines.Add(('{0,-8}: {1}' -f $status,$count))
    }
    $lines.Add('')
    $lines.Add('HIGH-SIGNAL INDICATORS')
    $lines.Add('----------------------')
    $highSignalProperty = $Report.PSObject.Properties['HighSignal']
    $highSignal = if ($null -ne $highSignalProperty) { @($highSignalProperty.Value) } else { @() }
    if ($highSignal.Count) {
        $lines.Add("  $($highSignal.Count) lead(s) to review before changing anything:")
        foreach ($entry in $highSignal) {
            $lines.Add("  [$($entry.Kind)] $($entry.Target)")
            if ($entry.Detail) { $lines.Add("    Why   : $($entry.Detail)") }
            if ($entry.Action) { $lines.Add("    Handle: $($entry.Action)") }
        }
    } else {
        $lines.Add('  None. Every object examined during this run resolved to a servicing-owned')
        $lines.Add('  component, a Microsoft signature, or the publisher of an installed product.')
    }
    $lines.Add('')
    $lines.Add('FINDINGS BY CATEGORY')
    $lines.Add('---------------------')
    foreach ($category in @($Report.Results | ForEach-Object { $_.Category } | Select-Object -Unique)) {
        $lines.Add('')
        $lines.Add("[$category]")
        foreach ($entry in @($Report.Results | Where-Object Category -eq $category)) {
            $lines.Add("  $($entry.Status) - $($entry.Item)")
            if ($entry.Evidence) { $lines.Add("    Evidence: $($entry.Evidence)") }
            if ($entry.Recommendation) { $lines.Add("    Action  : $($entry.Recommendation)") }
        }
    }
    $lines.Add('')
    $lines.Add('ACCOUNTS')
    $lines.Add('--------')
    if ($Report.Inventory -and $Report.Inventory.Contains('Accounts')) {
        foreach ($account in @($Report.Inventory['Accounts'])) {
            $lines.Add(('  {0,-24} enabled={1,-5} passwordRequired={2,-5} passwordLastSet={3}' -f $account.Name,[string]$account.Enabled,[string]$account.PasswordRequired,[string]$account.PasswordLastSet))
        }
    } else { $lines.Add('  Account inventory was not collected.') }
    $lines.Add('')
    $lines.Add('GROUPS')
    $lines.Add('------')
    if ($Report.Inventory -and $Report.Inventory.Contains('Groups')) {
        foreach ($groupName in $Report.Inventory['Groups'].Keys) {
            $members = @($Report.Inventory['Groups'][$groupName] | ForEach-Object { $_.Name })
            $memberText = if ($members.Count) { $members -join ', ' } else { '(none)' }
            $lines.Add("  ${groupName}: $memberText")
        }
    } else { $lines.Add('  Group inventory was not collected.') }
    $lines.Add('')
    $lines.Add('PASSWORDLESS ACCOUNTS RESET')
    $lines.Add('---------------------------')
    if ($script:ResetPasswordAccounts.Count) {
        foreach ($name in $script:ResetPasswordAccounts.Keys) { $lines.Add("  $name (new password is in Changed-Passwords.txt)") }
    } else { $lines.Add('  None.') }
    $lines.Add('')
    $lines.Add('QUARANTINE')
    $lines.Add('----------')
    $quarantineFile = if ($script:RunDirectory) { Join-Path $script:RunDirectory 'Quarantine.txt' } else { '' }
    if ($quarantineFile -and (Test-Path -LiteralPath $quarantineFile)) {
        $records = @(Get-Content -LiteralPath $quarantineFile -ErrorAction Stop | Where-Object { $_ -match '^\d{4}-' })
        if ($records.Count) { foreach ($record in $records) { $lines.Add("  $record") } } else { $lines.Add('  No files were quarantined.') }
    } else { $lines.Add('  No quarantine records.') }
    $lines.Add('')
    $lines.Add('INVENTORY SUMMARY')
    $lines.Add('-----------------')
    if ($Report.Inventory -and $Report.Inventory.Contains('Processes')) { $lines.Add("  Processes           : $(@($Report.Inventory['Processes']).Count)") }
    if ($Report.Inventory -and $Report.Inventory.Contains('TcpListeners')) { $lines.Add("  TCP listeners       : $(@($Report.Inventory['TcpListeners']).Count)") }
    if ($Report.Inventory -and $Report.Inventory.Contains('Ports')) {
        $attributedPorts = @($Report.Inventory['Ports'])
        $unexpectedPorts = @($attributedPorts | Where-Object { [string](Get-OptionalProperty $_ 'Verdict' '') -eq 'Unexpected' })
        $undeclaredPorts = @($attributedPorts | Where-Object { [string](Get-OptionalProperty $_ 'Verdict' '') -eq 'Undeclared' })
        $lines.Add("  Port attribution    : $($unexpectedPorts.Count) unexpected service(s), $($undeclaredPorts.Count) undeclared / $($attributedPorts.Count) socket(s)")
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Applications')) { $lines.Add("  Applications        : $(@($Report.Inventory['Applications']).Count)") }
    if ($Report.Inventory -and $Report.Inventory.Contains('ScheduledTasks')) { $lines.Add("  Scheduled tasks     : $(@($Report.Inventory['ScheduledTasks']).Count)") }
    if ($Report.Inventory -and $Report.Inventory.Contains('Hotfixes')) {
        $hotfixes = @($Report.Inventory['Hotfixes'] | ForEach-Object { $_.HotFixID }) -join ', '
        $lines.Add("  Recent hotfixes     : $hotfixes")
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('BackdoorCandidates')) { $lines.Add("  Backdoor candidates : $(@($Report.Inventory['BackdoorCandidates']).Count)") }
    if ($Report.Inventory -and $Report.Inventory.Contains('Defender') -and $null -ne $Report.Inventory['Defender']) {
        $defenderInventory = $Report.Inventory['Defender']
        $defenderText = @($defenderInventory.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; '
        $lines.Add("  Defender            : $defenderText")
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Browsers')) {
        $detectedBrowsers = @($Report.Inventory['Browsers'] | Where-Object { Get-OptionalProperty $_ Detected $false } | ForEach-Object { Get-OptionalProperty $_ Name '' })
        $lines.Add("  Browsers detected   : $(if ($detectedBrowsers.Count) { $detectedBrowsers -join ', ' } else { 'none' })")
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Roles')) { $lines.Add("  Installed roles     : $(@($Report.Inventory['Roles']).Count)") }
    if ($Report.Inventory -and $Report.Inventory.Contains('Shares')) { $lines.Add("  SMB shares          : $(@($Report.Inventory['Shares']).Count)") }
    if ($Report.Inventory -and $Report.Inventory.Contains('SharePermissions')) { $lines.Add("  Share ACL rows      : $(@($Report.Inventory['SharePermissions']).Count)") }
    if ($Report.Inventory -and $Report.Inventory.Contains('Ssh') -and $null -ne $Report.Inventory['Ssh']) {
        $sshSummary = $Report.Inventory['Ssh']
        $lines.Add("  OpenSSH             : found=$([string](Get-OptionalProperty $sshSummary Found $false)) service=$([string](Get-OptionalProperty $sshSummary ServiceStatus 'unknown'))/$([string](Get-OptionalProperty $sshSummary ServiceStartMode 'unknown'))")
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Firewall')) { $lines.Add("  Firewall profiles   : $(@($Report.Inventory['Firewall']).Count)") }
    if ($Report.Inventory -and $Report.Inventory.Contains('DefenderService') -and $null -ne $Report.Inventory['DefenderService']) {
        $lines.Add("  WinDefend service   : $([string](Get-OptionalProperty $Report.Inventory['DefenderService'] Status ''))/$([string](Get-OptionalProperty $Report.Inventory['DefenderService'] StartMode ''))")
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('BitLocker')) { $lines.Add("  BitLocker volumes   : $(@($Report.Inventory['BitLocker']).Count)") }
    $lines.Add('')
    $lines.Add('INVENTORY DETAIL')
    $lines.Add('----------------')
    if ($Report.Inventory -and $Report.Inventory.Contains('Processes')) {
        $processInventory = @($Report.Inventory['Processes'])
        $lines.Add('')
        $lines.Add("PROCESSES ($($processInventory.Count))")
        foreach ($processEntry in $processInventory) {
            $lines.Add(('  PID={0,-7} PPID={1,-7} {2,-28} {3}' -f
                (Get-OptionalProperty $processEntry ProcessId ''),
                (Get-OptionalProperty $processEntry ParentProcessId ''),
                (Get-OptionalProperty $processEntry Name ''),
                (Get-OptionalProperty $processEntry ExecutablePath '')))
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('TcpListeners')) {
        $listenerInventory = @($Report.Inventory['TcpListeners'])
        $lines.Add('')
        $lines.Add("TCP LISTENERS ($($listenerInventory.Count))")
        foreach ($listenerEntry in $listenerInventory) {
            $lines.Add(('  {0,-39} {1,-6} PID={2,-7} {3,-28} {4}' -f
                [string](Get-OptionalProperty $listenerEntry Address ''),
                [string](Get-OptionalProperty $listenerEntry Port ''),
                [string](Get-OptionalProperty $listenerEntry PID ''),
                [string](Get-OptionalProperty $listenerEntry Process ''),
                [string](Get-OptionalProperty $listenerEntry Path '')))
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Ports')) {
        $portInventory = @($Report.Inventory['Ports'])
        $lines.Add('')
        $lines.Add("PORT ATTRIBUTION ($($portInventory.Count))")
        foreach ($portEntry in $portInventory) {
            $lines.Add(('  {0,-4} {1,-6} {2,-28} {3,-18} {4,-26} PID={5,-7} [{6}] {7}; {8}' -f
                [string](Get-OptionalProperty $portEntry Protocol ''),
                [string](Get-OptionalProperty $portEntry Port ''),
                [string](Get-OptionalProperty $portEntry Title ''),
                [string](Get-OptionalProperty $portEntry Address ''),
                [string](Get-OptionalProperty $portEntry Process ''),
                [string](Get-OptionalProperty $portEntry PID ''),
                [string](Get-OptionalProperty $portEntry Verdict ''),
                [string](Get-OptionalProperty $portEntry Class ''),
                [string](Get-OptionalProperty $portEntry Detail '')))
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('UdpListeners')) {
        $udpInventory = @($Report.Inventory['UdpListeners'])
        $lines.Add('')
        $lines.Add("UDP ENDPOINTS ($($udpInventory.Count))")
        foreach ($udpEntry in $udpInventory) {
            $lines.Add(('  {0,-39} {1,-6} PID={2}' -f
                [string](Get-OptionalProperty $udpEntry LocalAddress ''),
                [string](Get-OptionalProperty $udpEntry LocalPort ''),
                [string](Get-OptionalProperty $udpEntry OwningProcess '')))
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Applications')) {
        $applicationInventory = @($Report.Inventory['Applications'])
        $lines.Add('')
        $lines.Add("APPLICATIONS ($($applicationInventory.Count))")
        foreach ($applicationEntry in $applicationInventory) {
            $version = [string](Get-OptionalProperty $applicationEntry DisplayVersion '')
            $publisher = [string](Get-OptionalProperty $applicationEntry Publisher '')
            $location = [string](Get-OptionalProperty $applicationEntry InstallLocation '')
            $lines.Add(("  {0}{1}{2}{3}" -f
                [string](Get-OptionalProperty $applicationEntry DisplayName ''),
                $(if ($version) { " $version" } else { '' }),
                $(if ($publisher) { " [$publisher]" } else { '' }),
                $(if ($location) { " $location" } else { '' })))
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Services')) {
        $serviceInventory = @($Report.Inventory['Services'])
        $lines.Add('')
        $lines.Add("SERVICES ($($serviceInventory.Count))")
        foreach ($serviceEntry in $serviceInventory) {
            $lines.Add(('  {0,-40} {1,-8} {2,-9} {3}' -f
                [string](Get-OptionalProperty $serviceEntry Name ''),
                [string](Get-OptionalProperty $serviceEntry State ''),
                [string](Get-OptionalProperty $serviceEntry StartMode ''),
                [string](Get-OptionalProperty $serviceEntry PathName '')))
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Drivers')) {
        $driverInventory = @($Report.Inventory['Drivers'])
        $lines.Add('')
        $lines.Add("DRIVERS ($($driverInventory.Count))")
        foreach ($driverEntry in $driverInventory) {
            $lines.Add(('  {0,-40} {1,-8} {2,-9} {3}' -f
                [string](Get-OptionalProperty $driverEntry Name ''),
                [string](Get-OptionalProperty $driverEntry State ''),
                [string](Get-OptionalProperty $driverEntry StartMode ''),
                [string](Get-OptionalProperty $driverEntry PathName '')))
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('ScheduledTasks')) {
        $taskInventory = @($Report.Inventory['ScheduledTasks'])
        $lines.Add('')
        $lines.Add("SCHEDULED TASKS ($($taskInventory.Count))")
        foreach ($taskEntry in $taskInventory) {
            $lines.Add("  $([string](Get-OptionalProperty $taskEntry TaskPath ''))$([string](Get-OptionalProperty $taskEntry TaskName '')) [$([string](Get-OptionalProperty $taskEntry State ''))]")
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Shares')) {
        $shareInventory = @($Report.Inventory['Shares'])
        $lines.Add('')
        $lines.Add("SMB SHARES ($($shareInventory.Count))")
        foreach ($shareEntry in $shareInventory) {
            $lines.Add("  $([string](Get-OptionalProperty $shareEntry Name '')) -> $([string](Get-OptionalProperty $shareEntry Path '')) special=$([string](Get-OptionalProperty $shareEntry Special $false))")
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Roles')) {
        $roleInventory = @($Report.Inventory['Roles'])
        $lines.Add('')
        $lines.Add("INSTALLED ROLES AND FEATURES ($($roleInventory.Count))")
        foreach ($roleEntry in $roleInventory) {
            $lines.Add("  $([string](Get-OptionalProperty $roleEntry Name '')) - $([string](Get-OptionalProperty $roleEntry DisplayName ''))")
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Browsers')) {
        $browserInventory = @($Report.Inventory['Browsers'])
        $lines.Add('')
        $lines.Add("BROWSERS ($($browserInventory.Count))")
        foreach ($browserEntry in $browserInventory) {
            $lines.Add("  $([string](Get-OptionalProperty $browserEntry Name '')) detected=$([string](Get-OptionalProperty $browserEntry Detected $false))")
            foreach ($executable in @(Get-OptionalProperty $browserEntry Executables @())) { $lines.Add("    $executable") }
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('SharePermissions')) {
        $sharePermissionInventory = @($Report.Inventory['SharePermissions'])
        $lines.Add('')
        $lines.Add("SHARE AND NTFS PERMISSIONS ($($sharePermissionInventory.Count))")
        foreach ($shareEntry in $sharePermissionInventory) {
            $lines.Add("  $([string](Get-OptionalProperty $shareEntry Name '')) -> $([string](Get-OptionalProperty $shareEntry Path '')) special=$([string](Get-OptionalProperty $shareEntry Special $false)) sensitive=$([string](Get-OptionalProperty $shareEntry Sensitive $false))")
            $shareAceText = @(Get-OptionalProperty $shareEntry ShareAces @() | ForEach-Object { "$([string](Get-OptionalProperty $_ 'AccountName' ''))=$([string](Get-OptionalProperty $_ 'AccessRight' ''))" }) -join ', '
            $explicitText = @(Get-OptionalProperty $shareEntry NtfsExplicitRisky @() | ForEach-Object { "$([string](Get-OptionalProperty (Get-OptionalProperty $_ 'IdentityReference' $null) 'Value' ''))=$([string](Get-OptionalProperty $_ 'FileSystemRights' ''))" }) -join ', '
            $inheritedText = @(Get-OptionalProperty $shareEntry NtfsInheritedRisky @() | ForEach-Object { "$([string](Get-OptionalProperty (Get-OptionalProperty $_ 'IdentityReference' $null) 'Value' ''))=$([string](Get-OptionalProperty $_ 'FileSystemRights' ''))" }) -join ', '
            $lines.Add("    share ACEs        : $(if ($shareAceText) { $shareAceText } else { '(none)' })")
            $lines.Add("    explicit NTFS risk: $(if ($explicitText) { $explicitText } else { '(none)' })")
            $lines.Add("    inherited NTFS risk: $(if ($inheritedText) { $inheritedText } else { '(none)' })")
            foreach ($errorText in @(Get-OptionalProperty $shareEntry Errors @())) { $lines.Add("    error             : $errorText") }
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Ssh') -and $null -ne $Report.Inventory['Ssh']) {
        $sshInventory = $Report.Inventory['Ssh']
        $lines.Add('')
        $lines.Add('OPENSSH')
        foreach ($property in 'Found','ServiceStatus','ServiceStartMode','Capability','BinaryExists','ListenerText','FirewallText','ConfigExists','ConfigPath') {
            $lines.Add("  $property = $([string](Get-OptionalProperty $sshInventory $property ''))")
        }
        $lines.Add("  HostKeys = $(@(Get-OptionalProperty $sshInventory HostKeys @()).Count)")
        $lines.Add("  AuthorizedKeys = $(@(Get-OptionalProperty $sshInventory AuthorizedKeys @()).Count)")
        if ($sshInventory.ConfigExists -and $sshInventory.Config) {
            foreach ($key in @($sshInventory.Config.Keys | Sort-Object)) { $lines.Add("  sshd_config: $key = $($sshInventory.Config[$key])") }
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Firewall')) {
        $firewallInventory = @($Report.Inventory['Firewall'])
        $lines.Add('')
        $lines.Add("FIREWALL PROFILES ($($firewallInventory.Count))")
        foreach ($profileEntry in $firewallInventory) {
            $lines.Add("  $([string](Get-OptionalProperty $profileEntry Name '')): enabled=$([string](Get-OptionalProperty $profileEntry Enabled '')) inbound=$([string](Get-OptionalProperty $profileEntry DefaultInboundAction '')) outbound=$([string](Get-OptionalProperty $profileEntry DefaultOutboundAction '')) localMerge=$([string](Get-OptionalProperty $profileEntry AllowLocalFirewallRules '')) notify=$([string](Get-OptionalProperty $profileEntry NotifyOnListen '')) logBlocked=$([string](Get-OptionalProperty $profileEntry LogBlocked '')) logFile=$([string](Get-OptionalProperty $profileEntry LogFileName '')) logMaxKB=$([string](Get-OptionalProperty $profileEntry LogMaxSizeKilobytes ''))")
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('DefenderService') -and $null -ne $Report.Inventory['DefenderService']) {
        $lines.Add('')
        $lines.Add('DEFENDER SERVICE')
        foreach ($property in $Report.Inventory['DefenderService'].PSObject.Properties) { $lines.Add("  $($property.Name) = $($property.Value)") }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Defender') -and $null -ne $Report.Inventory['Defender']) {
        $lines.Add('')
        $lines.Add('DEFENDER')
        foreach ($property in $Report.Inventory['Defender'].PSObject.Properties) { $lines.Add("  $($property.Name) = $($property.Value)") }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('UpdatePolicy') -and $null -ne $Report.Inventory['UpdatePolicy']) {
        $lines.Add('')
        $lines.Add('WINDOWS UPDATE POLICY')
        foreach ($property in $Report.Inventory['UpdatePolicy'].PSObject.Properties) { $lines.Add("  $($property.Name) = $($property.Value)") }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('Hotfixes')) {
        $hotfixInventory = @($Report.Inventory['Hotfixes'])
        $lines.Add('')
        $lines.Add("RECENT HOTFIXES ($($hotfixInventory.Count))")
        foreach ($hotfixEntry in $hotfixInventory) {
            $lines.Add("  $([string](Get-OptionalProperty $hotfixEntry HotFixID '')) installed=$([string](Get-OptionalProperty $hotfixEntry InstalledOn ''))")
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('BackdoorCandidates')) {
        $backdoorInventory = @($Report.Inventory['BackdoorCandidates'])
        $lines.Add('')
        $lines.Add("BACKDOOR CANDIDATES ($($backdoorInventory.Count))")
        foreach ($backdoorEntry in $backdoorInventory) {
            $lines.Add("  $([string](Get-OptionalProperty $backdoorEntry Name '')) PID=$([string](Get-OptionalProperty $backdoorEntry PID '')) listeners=$([string](Get-OptionalProperty $backdoorEntry Ports '')) signature=$([string](Get-OptionalProperty $backdoorEntry Signature '')) path=$([string](Get-OptionalProperty $backdoorEntry Path ''))")
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('SecurityPolicy')) {
        $securityPolicy = $Report.Inventory['SecurityPolicy']
        $lines.Add('')
        $lines.Add('SYSTEM ACCESS AND USER RIGHTS')
        $lines.Add('----------------------------')
        foreach ($section in 'System Access','Event Audit','Privilege Rights') {
            if (-not $securityPolicy.ContainsKey($section)) { continue }
            $lines.Add("  [$section]")
            foreach ($key in @($securityPolicy[$section].Keys | Sort-Object)) {
                $lines.Add("    $key = $($securityPolicy[$section][$key])")
            }
        }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('DomainPasswordPolicy') -and $null -ne $Report.Inventory['DomainPasswordPolicy']) {
        $lines.Add('')
        $lines.Add('DOMAIN PASSWORD POLICY')
        foreach ($property in $Report.Inventory['DomainPasswordPolicy'].PSObject.Properties) { $lines.Add("  $($property.Name) = $($property.Value)") }
    }
    if ($Report.Inventory -and $Report.Inventory.Contains('BitLocker')) {
        $bitLockerInventory = @($Report.Inventory['BitLocker'])
        $lines.Add('')
        $lines.Add("BITLOCKER ($($bitLockerInventory.Count))")
        foreach ($volumeEntry in $bitLockerInventory) {
            $lines.Add("  $([string](Get-OptionalProperty $volumeEntry MountPoint '')) status=$([string](Get-OptionalProperty $volumeEntry VolumeStatus '')) protection=$([string](Get-OptionalProperty $volumeEntry ProtectionStatus '')) method=$([string](Get-OptionalProperty $volumeEntry EncryptionMethod ''))")
        }
    }
    $lines.Add('')
    $lines.Add('Files in the private run folder: Report.txt, Changed-Passwords.txt, Ledger.txt, Quarantine.txt, Quarantine\')
    $lines.Add('Report, password, ledger, and quarantine records are plain text; Quarantine\ can contain the copied binary files themselves. Keep this folder private.')
    $lines.Add('')
    $lines.Add('Readback verifies registry and security-policy values only. Re-run the audit and check the image scorer after changes.')
    Set-Content -LiteralPath $Path -Value $lines -Encoding UTF8 -ErrorAction Stop
}

# The whole run lives in Invoke-CYPatEnforcer, defined after every other function
# and called on the last line. That lets the file work two ways: run it as a
# file (& '.\Cypat Server 2022 Enforcer v6.ps1' -AuditOnly), or paste its whole text
# into an elevated Windows PowerShell window, for example straight from GitHub.
# A pasted script whose param block sits at the top does not work, because the
# window runs each line on its own and $PSCmdlet is never set.
function Invoke-CYPatEnforcer {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
    param(
        [switch]$Apply,
        [switch]$AuditOnly,
        [switch]$Yes,
        [switch]$NonInteractive,
        [switch]$SkipKnownPasswordCheck,
        [switch]$RemoveEveryoneNetworkLogonRight,
        [switch]$KeepEveryoneNetworkLogonRight,
        [string[]]$RequiredServices=@(),
        [hashtable]$RequiredShares=@{},
        [string[]]$KeepShares=@(),
        [string[]]$RemoveShares=@(),
        [string[]]$ProtectedShareNames=@('AFA','AFA$','CyberPatriot','CyberPatriot$'),
        [string[]]$ProtectedSharePaths=@('C:\AFA','C:\CyberPatriot'),
        [ValidateSet('All')][string]$AuditCoverage='All',
        [switch]$ResetAllUserPasswords,
        [ValidateRange(12,14)][int]$MinimumPasswordLength=14,
        [ValidateRange(1,24)][int]$PasswordHistory=5,
        [ValidateRange(0,998)][int]$MinimumPasswordAge=5,
        [ValidateRange(1,999)][int]$MaximumPasswordAge=30,
        [ValidateRange(5,50)][int]$LockoutThreshold=5,
        [ValidateRange(1,99999)][int]$LockoutMinutes=60,
        [ValidateRange(10,128)][int]$KnownPasswordMinimumLength=10,
        [ValidateRange(12,128)][int]$GeneratedPasswordLength=18,
        [string[]]$AuthorizedUsers=@(),
        [string[]]$AuthorizedAdministrators=@(),
        [string]$ReportPath='',
        [string]$RunRoot='',
        [string[]]$PasswordExemptUsers=@(),
        [ValidateRange(1024,4194304)][int]$SecurityLogSizeKB=196608,
        [ValidateRange(1024,4194304)][int]$ApplicationLogSizeKB=32768,
        [ValidateRange(1024,4194304)][int]$SystemLogSizeKB=32768,
        [switch]$Detailed,
        [switch]$QuickScan,
        [switch]$HuntVendorFolders,
        [switch]$EncryptKeptShares,
        [switch]$SelfTest,
        [string[]]$AllowedPorts=@(),
        [string[]]$RequiredSoftware=@(),
        [string[]]$RemoveUsers=@(),
        [string[]]$ResetPasswords=@(),
        [string[]]$RemovePackages=@(),
        [string[]]$ProhibitedExtensions=@(),
        [switch]$PassThru
    )
    Set-StrictMode -Version 2.0
    $ErrorActionPreference='Stop'
    $ProgressPreference='SilentlyContinue'
    # These checks repeat the #Requires lines for a pasted copy, where #Requires
    # does nothing.
    if ($env:OS -ne 'Windows_NT') {
        Write-Host 'Run this in Windows PowerShell on a Windows 11 or Windows Server computer.' -ForegroundColor Red
        return
    }
    $currentPrincipal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host 'Open PowerShell with Run as administrator, then run or paste the script again.' -ForegroundColor Red
        return
    }
    if ($PSVersionTable.PSVersion.Major -ne 5) {
        Write-Warning "This window runs PowerShell $($PSVersionTable.PSVersion). The script is built for Windows PowerShell 5.1 (the blue Windows PowerShell window); some checks may not work here."
    }
    # Keystrokes left over from a paste are dropped so they are not taken as the
    # answer to the first Y/N question.
    try {
        if (-not [Console]::IsInputRedirected) { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } }
    } catch { Write-Verbose 'Console input could not be cleared.' }
    if ($Apply -and $AuditOnly) { throw 'Choose either -Apply or -AuditOnly, not both.' }
    if (-not $AuditOnly) {
        $Apply = $true
        $Yes = $true
    } else {
        $Apply = $false
    }
    if ($MinimumPasswordAge -ge $MaximumPasswordAge) { throw 'MinimumPasswordAge must be below MaximumPasswordAge.' }
    if ($Apply -and -not $PSBoundParameters.ContainsKey('Confirm')) { $ConfirmPreference='None' }
    $script:CallerCmdlet=$PSCmdlet
    $script:ProductTitle='CYPat Enforcer V6'
    $script:AllowedPortList=@($AllowedPorts | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $script:Results=[System.Collections.Generic.List[object]]::new()
    $script:RunDirectory=$null
    $script:ResetPasswordAccounts=@{}
    $script:ServiceDecisions=[ordered]@{}
    $script:AutomaticUpdatesDecision=$null
    $script:AutomaticUpdatesMode=$null
    $script:RemoteAssistanceDecision=$null
    $script:Inventory=[ordered]@{}
    $script:FileTrustCache=@{}
    $script:BlankPolicyRestoreError=$null
    $script:ProtectedServices=@{}
    $script:RequiredLogical=@{}
    $script:RequiredSoftwareRoots=[System.Collections.Generic.List[object]]::new()
    $script:ProcessImageReaderFailed=$false
    $script:PortCatalog=$null
    $script:HasUserAllowlist=$PSBoundParameters.ContainsKey('AuthorizedUsers')
    $script:HasAdminAllowlist=$PSBoundParameters.ContainsKey('AuthorizedAdministrators')
    $script:NetworkRightRemovalSelected = -not [bool]$KeepEveryoneNetworkLogonRight
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $script:IsDomainController=$computer.DomainRole -in @(4,5)
    $script:IsDomainJoined=[bool]$computer.PartOfDomain
    $script:Inventory.Computer=[pscustomobject]@{Name=$env:COMPUTERNAME;OS=$os.Caption;Version=$os.Version;DomainRole=$computer.DomainRole;DomainJoined=$script:IsDomainJoined;Domain=$computer.Domain}
    if ($Apply) {
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        $principal=New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) { throw 'Apply requires an elevated Windows PowerShell session.' }
    }
    #region v6 provenance engine
    # Origin, not folder name, decides whether a binary belongs here.
    #   OS component    -> hardlinked into WinSxS (CBS servicing owns the file)
    #   Microsoft signed-> valid Authenticode from O=Microsoft Corporation
    #   Installed product -> valid signer whose install folder is registered in Uninstall
    #   anything else   -> a lead, escalated to High when the file also claims a
    #                      vendor it cannot prove, or has no identity at all.
    # A path under Program Files is no longer proof of anything, which is the hole
    # that let a fake vendor binary through in v5 (see Invoke-ProcessAnomalyAudit).
    $script:ProvenanceCache=@{}
    $script:FolderSignerCache=@{}
    $script:CatalogSupport=$null
    $script:InstalledProductMap=$null
    $script:HighSignal=[System.Collections.Generic.List[object]]::new()
    $script:SuspiciousPaths=[System.Collections.Generic.List[string]]::new()
    $mode=if ($Apply) {'APPLY'} else {'AUDIT'}
    Write-Host "CYPat Enforcer V6 | $($os.Caption) | $mode" -ForegroundColor Cyan
    Write-Host 'Read the image README and answer forensics before applying changes. Service answers use that README.' -ForegroundColor Yellow
    if ($os.ProductType -eq 1) { Add-Result Platform 'Windows client detected' REVIEW $os.Caption 'This is a Windows client image. Server-only roles (SMB file shares, DNS, DHCP, IIS) may not exist; those checks report SKIPPED or FAILED for the missing role rather than changing it.' }
    if ($script:IsDomainJoined) { Add-Result 'Group Policy' 'Domain policy' REVIEW "Domain=$($computer.Domain); controller=$script:IsDomainController" 'Use gpresult /r and the governing GPO to verify effective settings. Domain password policy is never changed automatically.' }
    if (-not $WhatIfPreference) {
        Invoke-Check 'Private run folder' {
            $run = Initialize-PrivateRun -Root $RunRoot
            Write-Host "Private plain-text run folder: $run" -ForegroundColor Cyan
        }
    }
    if ($SelfTest) {
        Write-Host 'Provenance self-test: validating the classifier against this host. No hardening is performed.' -ForegroundColor Cyan
        Invoke-Check 'Provenance self-test' { Invoke-ProvenanceSelfTest }
        foreach ($entry in @($script:Results | Where-Object { $_.Category -eq 'Threats' -and $_.Item -eq 'Provenance self-test' })) {
            Write-Host ''
            Write-Host "$($entry.Status) - $($entry.Item)" -ForegroundColor $(if ($entry.Status -eq 'PASS') { 'Green' } else { 'Yellow' })
            Write-Host "  $($entry.Evidence)"
            Write-Host "  $($entry.Recommendation)" -ForegroundColor DarkGray
        }
        Write-Host ''
        Write-Host 'Self-test finished. No image setting was changed.' -ForegroundColor Cyan
        $selfTestCode=if (@($script:Results | Where-Object { $_.Item -eq 'Provenance self-test' -and $_.Status -eq 'PASS' }).Count -eq 1) { 0 } else { 1 }
        # A file run reports the result as its exit code; a pasted run must not
        # close the window, so it only returns.
        if ($PSCommandPath) { exit $selfTestCode }
        return
    }

    Write-Host 'Collecting processes, listening ports, and software before any changes...' -ForegroundColor Cyan
    Invoke-Check 'Initial inventory' { Get-ServerInventory }
    Invoke-Check 'Required software' { Invoke-RequiredSoftwareAudit }
    $serverBeforeShares=Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
    $script:ShareReviewInitialStatus=if ($null -ne $serverBeforeShares) { [string]$serverBeforeShares.Status } else { '' }
    $script:ShareReviewInitialStartMode=if ($null -ne $serverBeforeShares) { Get-ServiceStartMode $serverBeforeShares } else { '' }
    $script:ShareReviewAttemptedServerStart=$false
    $requiredDisplay = if ($RequiredServices.Count) { $RequiredServices -join ', ' } else { 'none selected; use -RequiredServices after reading README' }
    Write-Host "Required services (protected): $requiredDisplay" -ForegroundColor Cyan
    Invoke-Check 'Required service protection' { Initialize-RequiredServices }
    Invoke-Check 'Named account removal' { Invoke-NamedAccountRemoval }
    Invoke-Check 'Named password resets' { Invoke-NamedPasswordReset }
    Invoke-Check Accounts { Invoke-AccountAudit }
    if ($script:NetworkRightRemovalSelected) {
        Invoke-Check 'Network logon right' { Invoke-NetworkLogonRightDecision }
    } else {
        Invoke-Check 'Network logon right' {
            $principals=@(Get-NetworkLogonPrincipals)
            if (@($principals | Where-Object { $_ -match '^(\*?S-1-1-0|Everyone)$' }).Count -eq 0) {
                Add-Result 'User rights' 'SeNetworkLogonRight without Everyone' PASS 'Everyone is not assigned this right.' ''
            } else {
                Add-Result 'User rights' 'SeNetworkLogonRight without Everyone' SKIPPED 'Everyone is assigned this right; removal was explicitly disabled with -KeepEveryoneNetworkLogonRight.' 'Remove that switch only when the README does not require Everyone network access.'
            }
        }
    }
    Invoke-Check 'Security policy and rights' { Invoke-SecurityPolicyAudit }
    Invoke-Check 'Registry security' { Invoke-RegistryAudit }
    Invoke-Check 'Effective auditing' { Invoke-AuditPolicyAudit }
    Invoke-Check Defender { Invoke-DefenderAudit }
    Invoke-Check 'User rights table' { Invoke-DeepUserRights }
    Invoke-Check 'Deep security options' { Invoke-DeepSecurityOptions }
    Invoke-Check 'Anonymous translation and forced logoff' { Invoke-DeepSystemAccess }
    Invoke-Check 'Defender policy overrides and cloud protection' { Invoke-DeepDefenderPolicy }
    Invoke-Check 'Automatic logon' { Invoke-DeepAutoLogon }
    Invoke-Check 'PowerShell 2.0 engine' { Invoke-DeepPowerShellV2 }
    Invoke-Check 'SMB share readiness' { Invoke-ShareServicePreparation }
    $serverService=Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
    try {
        if ($null -ne $serverService -and $serverService.Status -eq 'Running') {
            Invoke-Check SMB { Invoke-SmbAudit }
            Invoke-Check 'Required and selected shares' { Invoke-ShareDecisions }
            Invoke-Check 'Share and NTFS permissions' { Invoke-SharePermissionAudit }
            Invoke-Check 'Kept-share attestation' { Invoke-KeptShareAttestation }
        } else {
            Add-Result Shares 'Share review unavailable' REVIEW 'LanmanServer is stopped; Windows cannot enumerate SMB shares.' 'Start the Server service, then inspect and remove selected shares before optional service decisions.'
        }
    } finally {
        Restore-ShareServiceState
    }

    Write-Host 'Optional service decisions: Y enables; N disables. Required services stay protected; missing services are skipped.' -ForegroundColor Cyan
    Invoke-Check 'RDP decision' { Invoke-RdpDecision }
    Invoke-Check 'RDP security' {
        Set-RegistryBaseline RDP 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1
        Set-RegistryBaseline RDP 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' MinEncryptionLevel 3
        Set-RegistryBaseline RDP 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' SecurityLayer 2
        Set-RegistryBaseline RDP 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' fPromptForPassword 1
        Set-RegistryBaseline RDP 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' fEncryptRPCTraffic 1
        $rdpPolicy='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        foreach ($name in 'UserAuthentication','MinEncryptionLevel','SecurityLayer','fPromptForPassword','fDenyTSConnections') {
            $state=Get-RegistryState $rdpPolicy $name
            if ($state.Exists) { Add-Result RDP "GPO/$name" REVIEW "Policy value=$($state.Value)" 'Verify effective RDP behavior and the governing GPO; local listener settings may be overridden.' }
        }
    }
    Invoke-Check 'Remote Assistance decision' { Invoke-RemoteAssistanceDecision }
    $serviceChoices=@(
        @{Label='SMB/file sharing';Names=@('LanmanServer');Warning='Keep when the README requires file shares. N stops and disables the Server service, so required shares stop being served.'},
        @{Label='WinRM';Names=@('WinRM');Warning='Needed for PowerShell remoting and many management tools. Disabling can disconnect remote management.'},
        @{Label='FTP';Names=@('FTPSVC');Warning='Keep only if the scenario requires FTP; verify authentication and data access separately.'},
        @{Label='SMTP';Names=@('SMTPSVC');Warning='May be needed for mail relay. No SMTP feature is uninstalled.'},
        @{Label='IIS web server';Names=@('W3SVC');Warning='Preserve if hosting a required website. Dependent running services block disable.'},
        @{Label='DNS';Names=@('DNS');Warning='Critical on domain controllers and DNS servers. Domain-controller disable is blocked.'},
        @{Label='DHCP';Names=@('DHCPServer');Warning='Preserve if this server supplies required addresses.'},
        @{Label='Print Spooler';Names=@('Spooler');Warning='Needed for a required print role; verify the README.'},
        @{Label='Simple TCP/IP Services';Names=@('simptcp');Warning='Legacy echo/daytime/discard services; usually unnecessary but decide from README.'},
        @{Label='Remote Registry';Names=@('RemoteRegistry');Warning='May support approved remote administration.'},
        @{Label='Telnet';Names=@('TlntSvr');Warning='Legacy unencrypted remote administration; preserve only if required.'},
        @{Label='SNMP';Names=@('SNMP','SNMPTRAP');Warning='May support required monitoring; check authorized managers and community strings.'},
        @{Label='Routing and Remote Access';Names=@('RemoteAccess');Warning='May support a required VPN or routing role.'},
        @{Label='UPnP, SSDP discovery, and media or connection sharing';Names=@('upnphost','SSDPSRV','WMPNetworkSvc','icssvc','SharedAccess');Warning='Home-network discovery and sharing services that servers rarely need. Keep them only if the README requires them.'},
        @{Label='Gaming and retail demo services';Names=@('XblAuthManager','XblGameSave','XboxGipSvc','XboxNetApiSvc','GamingServices','GamingServicesNet','RetailDemo');Warning='Usually unnecessary on server images; keep only if the README explicitly requires them.'}
    )
    foreach ($choice in $serviceChoices) { Invoke-Check $choice.Label { Invoke-ServiceDecision -Label $choice.Label -Names $choice.Names -Warning $choice.Warning } }
    Invoke-Check SSH { Invoke-SshAudit }
    Invoke-Check 'Windows Update' { Invoke-WindowsUpdateDecision }
    Invoke-Check 'Baseline services' { Invoke-BaselineServiceStartup }
    Invoke-Check 'Server roles' {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $script:Inventory.Roles=@(Get-WindowsFeature -ErrorAction Stop | Where-Object Installed | Select-Object Name,DisplayName)
        }
    }
    Invoke-Check 'Required-service firewall rules' { Invoke-RequiredServiceFirewall }
    Invoke-Check Firewall { Invoke-FirewallAudit }
    Invoke-Check 'WinRM authentication' {
        $winrm=Get-Service WinRM -ErrorAction SilentlyContinue
        if ($winrm -and $winrm.StartType -ne 'Disabled') {
            Add-Result WinRM 'Listeners and authentication' REVIEW "Service=$($winrm.Status)/$($winrm.StartType)" 'Review listener addresses, Basic authentication, AllowUnencrypted, and TrustedHosts locally. Read operations that might start WinRM are deliberately left manual.'
        }
    }
    Invoke-Check 'Persistence, network, updates, certificates' { Invoke-OtherAudits }
    Invoke-Check 'Netcat-family scan' { Invoke-BackdoorDecision }
    Invoke-Check 'Service binary audit' { Invoke-ServiceBinaryAudit }
    Invoke-Check 'Process anomaly audit' { Invoke-ProcessAnomalyAudit }
    Invoke-Check 'Startup folder audit' { Invoke-StartupFolderAudit }
    Invoke-Check 'WMI persistence audit' { Invoke-WmiPersistenceAudit }
    Invoke-Check 'LOLBin argument audit' { Invoke-LolbinAudit }
    Invoke-Check 'Driver baseline audit' { Invoke-DriverBaselineAudit }
    Invoke-Check 'Autorun registry audit' { Invoke-RunKeyAudit }
    Invoke-Check 'Installed software provenance' { Invoke-ApplicationProvenanceAudit }
    Invoke-Check 'Vendor folder sweep' { Invoke-VendorFolderSweep }
    Invoke-Check 'Malware scan and detection history' { Invoke-MalwareScan }
    Invoke-Check IIS { Invoke-IisAudit }
    Invoke-Check 'Defender exclusions' { Invoke-DefenderExclusionAudit }
    Invoke-Check 'DLL search-order hijack' { Invoke-DllHijackAudit }
    Invoke-Check 'Winlogon, LSA, and AppInit persistence' { Invoke-WinlogonLsaAudit }
    Invoke-Check 'Per-user autoruns' { Invoke-PerUserHiveAudit }
    Invoke-Check 'Certificate trust' { Invoke-CertificateTrustAudit }
    Invoke-Check 'Stored credentials and elevation' { Invoke-CredentialExposureAudit }
    Invoke-Check 'Event log forensics' { Invoke-EventLogForensics }
    Invoke-Check 'Execution artifacts' { Invoke-ExecutionArtifactAudit }
    Invoke-Check 'Network pivots' { Invoke-NetworkPivotAudit }
    Invoke-Check 'Listening-port attribution' { Invoke-PortAttribution }
    Invoke-Check 'High-signal quarantine decisions' { Invoke-HighSignalRemediation }
    Invoke-Check 'Package removal' { Invoke-PackageRemoval }
    Invoke-Check 'Prohibited files' { Invoke-ProhibitedFileAudit }
    Invoke-Check Browsers { Invoke-BrowserAudit }
    Invoke-Check 'Update and browser freshness' { Invoke-UpdateFreshnessAudit }
    Invoke-Check 'Final required-service verification' { Invoke-RequiredServicesVerification }

    $report=[pscustomobject]@{
        Version='6';Time=(Get-Date).ToString('o');Mode=$mode
        Computer=$script:Inventory.Computer;RequiredServices=$RequiredServices;RequiredShares=$RequiredShares;KeepShares=$KeepShares;RemoveShares=$RemoveShares
        RemoveEveryoneNetworkLogonRight=$script:NetworkRightRemovalSelected;ProtectedServices=$script:ProtectedServices;ServiceDecisions=$script:ServiceDecisions
        Results=@($script:Results);Inventory=$script:Inventory
        HighSignal=@($script:HighSignal)
    }
    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
        try {
            $resolvedReportPath=Resolve-TextReportPath $ReportPath
            Export-CYPatReportText -Path $resolvedReportPath -Mode $mode -Report $report
            Write-Host "Text report: $resolvedReportPath" -ForegroundColor Cyan
        } catch { Add-Result Reporting 'Text report' FAILED $_.Exception.Message 'Use an existing writable folder and a .txt report filename.' }
    }
    if ($script:RunDirectory) {
        try {
            $report.Results=@($script:Results)
            $runReport=Join-Path $script:RunDirectory 'Report.txt'
            Export-CYPatReportText -Path $runReport -Mode $mode -Report $report
            Write-Host "Private plain-text report: $runReport" -ForegroundColor Cyan
        } catch { Add-Result Reporting 'Private report' FAILED $_.Exception.Message 'Inspect the private run folder permissions.' }
    }
    $passed=@($script:Results | Where-Object Status -eq PASS).Count
    $changed=@($script:Results | Where-Object Status -eq CHANGED).Count
    $failed=@($script:Results | Where-Object Status -eq FAILED).Count
    $review=@($script:Results | Where-Object Status -eq REVIEW).Count
    $skipped=@($script:Results | Where-Object Status -eq SKIPPED).Count
    Write-Host "`nPASSED: $passed | CHANGED: $changed | FAILED: $failed | REVIEW: $review | SKIPPED: $skipped" -ForegroundColor Cyan
    Write-Host 'ORANGE HUMAN REVIEW LIST' -ForegroundColor DarkYellow
    $open=@($script:Results | Where-Object { $_.Status -in @('REVIEW','FAILED') })
    if (-not $open.Count) { Write-Host 'No unresolved findings were recorded.' -ForegroundColor Green }
    foreach ($entry in $open) {
        $evidence=[string]$entry.Evidence
        if (-not $Detailed -and $evidence.Length -gt 220) { $evidence=$evidence.Substring(0,220)+'... (use -Detailed or the private Report.txt for full evidence)' }
        Write-Host "[$($entry.Status)] $($entry.Category) / $($entry.Item): $evidence" -ForegroundColor DarkYellow
        if ($Detailed) { Write-Host "  $($entry.Recommendation)" -ForegroundColor DarkYellow }
    }
    if ($script:ServiceDecisions.Count) {
        Write-Host 'SERVICE DECISIONS' -ForegroundColor Cyan
        foreach ($name in $script:ServiceDecisions.Keys) { Write-Host "  ${name}: $($script:ServiceDecisions[$name])" }
    }
    if ($script:HighSignal.Count) {
        Write-Host 'HIGH-SIGNAL INDICATORS (leads to review before changing anything)' -ForegroundColor Red
        foreach ($entry in $script:HighSignal) {
            Write-Host "  [$($entry.Kind)] $($entry.Target)" -ForegroundColor Red
            if ($Detailed -and $entry.Detail) { Write-Host "    $($entry.Detail)" -ForegroundColor DarkYellow }
        }
        Write-Host '  Each of these is evidence. Record the hash, answer any forensics question, then decide.' -ForegroundColor DarkYellow
    }
    Write-Host 'Configuration readback verifies these checks only; rerun audit and check scoring/required services after changes.' -ForegroundColor Cyan
    if ($PassThru) { $report.Results=@($script:Results); Write-Output $report }
}
Invoke-CYPatEnforcer @args
