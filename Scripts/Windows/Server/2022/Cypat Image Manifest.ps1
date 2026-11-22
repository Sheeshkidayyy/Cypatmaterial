<#
.SYNOPSIS
    CyberPatriot image manifest collector (READ-ONLY).

.DESCRIPTION
    Takes an inventory of an UNMODIFIED CyberPatriot Windows image so it can be
    compared later with the README and the answer key. It changes nothing on the
    machine. The only thing it writes is the output folder.

    Standalone on purpose: this is NOT part of the Server 2022 Enforcer and does
    not share code with it.

    Works on Windows Server 2016/2019/2022/2025 and Windows 10/11 with the
    built-in Windows PowerShell 5.1. Sections that do not apply to a machine
    (for example Active Directory on a workgroup PC, or IIS when it is not
    installed) are skipped and noted in 00_SUMMARY.txt.

    Output (plain text .txt plus .csv for every table):
        C:\findings\manifest_<COMPUTERNAME>_<yyyyMMdd_HHmmss>\
        C:\findings\manifest_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.zip

    Start with 00_SUMMARY.txt. Files are numbered by section.

.HOW TO RUN
    1. Open PowerShell with "Run as administrator".
    2. cd to the folder that holds this file.
    3. Run:
           powershell -ExecutionPolicy Bypass -File ".\Cypat Image Manifest.ps1"
       (The -ExecutionPolicy Bypass only applies to that one run. If Windows
        says the file is blocked because it was downloaded, the same command
        still works.)

    Optional switches:
        -OutputRoot D:\findings   Write somewhere other than C:\findings
        -SkipFileScan             Skip the whole-disk file scan (faster)
        -NoZip                    Do not zip the output folder
        -MaxFileRows 50000        Row cap for the big file lists

    A typical run takes 2 to 6 minutes. The file scan is the slow part.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot = (Join-Path $env:SystemDrive 'findings'),
    [switch]$SkipFileScan,
    [switch]$NoZip,
    [int]$MaxFileRows = 50000
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Admin check
# ---------------------------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'This script must be run from an elevated PowerShell window (Run as administrator).' -ForegroundColor Red
    Write-Host 'Nothing was collected.' -ForegroundColor Red
    return
}

# ---------------------------------------------------------------------------
# Output folder
# ---------------------------------------------------------------------------
$Stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$RunName = 'manifest_{0}_{1}' -f $env:COMPUTERNAME, $Stamp
$RunDir = Join-Path $OutputRoot $RunName
New-Item -ItemType Directory -Path $RunDir -Force | Out-Null

try { Start-Transcript -Path (Join-Path $RunDir '00_console_log.txt') -Force | Out-Null } catch { }

$script:SectionLog = New-Object System.Collections.Generic.List[object]
$script:Highlights = [ordered]@{}
$TotalTimer = [Diagnostics.Stopwatch]::StartNew()

Write-Host ''
Write-Host 'CyberPatriot image manifest collector (read-only)' -ForegroundColor Green
Write-Host "Output: $RunDir" -ForegroundColor Green
Write-Host ''

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Save-Data {
    # Writes <Name>.csv and a readable <Name>.txt for a list of objects.
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        $Data,
        [switch]$List,
        [switch]$NoCsv,
        [string]$Note
    )
    $items = @($Data | Where-Object { $null -ne $_ })
    $txt = Join-Path $RunDir ($Name + '.txt')
    $header = @("# $Name", "# $($items.Count) item(s), collected $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') on $env:COMPUTERNAME")
    if ($Note) { $header += "# $Note" }
    $header += ''
    if ($items.Count -eq 0) {
        ($header + '(none found)') | Out-File -LiteralPath $txt -Encoding UTF8 -Width 4096
        return
    }
    if (-not $NoCsv) {
        $items | Export-Csv -LiteralPath (Join-Path $RunDir ($Name + '.csv')) -NoTypeInformation -Encoding UTF8
    }
    if ($List) {
        $body = $items | Format-List * | Out-String -Width 4096
    } else {
        $body = $items | Format-Table * -AutoSize -Wrap | Out-String -Width 4096
    }
    ($header + $body) | Out-File -LiteralPath $txt -Encoding UTF8 -Width 4096
}

function Save-Text {
    # Runs a command (usually a built-in .exe) and saves its text output.
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )
    $out = & $Command 2>&1 | ForEach-Object { "$_" } | Out-String -Width 4096
    $header = "# $Name`r`n# collected $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') on $env:COMPUTERNAME`r`n"
    ($header + $out) | Out-File -LiteralPath (Join-Path $RunDir ($Name + '.txt')) -Encoding UTF8 -Width 4096
}

function Invoke-Section {
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )
    Write-Host ("[*] {0}" -f $Title) -ForegroundColor Cyan
    $t = [Diagnostics.Stopwatch]::StartNew()
    $status = 'OK'
    $err = ''
    try {
        $r = @(& $Body)
        $skip = $r | Where-Object { $_ -is [string] -and $_ -like 'SKIPPED*' } | Select-Object -First 1
        if ($skip) { $status = $skip }
    } catch {
        $status = 'ERROR'
        $err = $_.Exception.Message
        Write-Host ("    ! {0}" -f $err) -ForegroundColor Yellow
    }
    $t.Stop()
    $script:SectionLog.Add([pscustomobject]@{
        Section = $Title
        Status  = $status
        Seconds = [math]::Round($t.Elapsed.TotalSeconds, 1)
        Error   = $err
    })
}

function Convert-RegValue {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [byte[]]) {
        $hex = ($Value | ForEach-Object { $_.ToString('X2') }) -join ''
        if ($hex.Length -gt 512) { $hex = $hex.Substring(0, 512) + '...(truncated)' }
        return $hex
    }
    if ($Value -is [array]) { return (($Value | ForEach-Object { "$_" }) -join ' | ') }
    return "$Value"
}

function Get-RegValues {
    # Returns one row per registry value under the given key(s).
    param([string[]]$Paths, [switch]$Recurse)
    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $keys = @(Get-Item -LiteralPath $p -ErrorAction SilentlyContinue)
        if ($Recurse) { $keys += @(Get-ChildItem -LiteralPath $p -Recurse -ErrorAction SilentlyContinue) }
        foreach ($k in $keys) {
            if ($null -eq $k) { continue }
            foreach ($n in $k.GetValueNames()) {
                $raw = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
                $valueName = $n
                if ([string]::IsNullOrEmpty($n)) { $valueName = '(Default)' }
                $kind = ''
                try { $kind = "$($k.GetValueKind($n))" } catch { }
                [pscustomobject]@{
                    Key   = $k.Name
                    Name  = $valueName
                    Type  = $kind
                    Value = (Convert-RegValue $raw)
                }
            }
        }
    }
}

function Resolve-Sid {
    param([string]$Sid)
    try {
        return (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value
    } catch {
        return ''
    }
}

function Get-LocalGroupMembersSafe {
    # Get-LocalGroupMember breaks on orphaned SIDs, so fall back to ADSI.
    param([string]$Group)
    try {
        return @(Get-LocalGroupMember -Group $Group -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Group       = $Group
                Member      = $_.Name
                ObjectClass = "$($_.ObjectClass)"
                Source      = "$($_.PrincipalSource)"
                SID         = "$($_.SID)"
            }
        })
    } catch {
        $res = @()
        try {
            $g = [ADSI]("WinNT://$env:COMPUTERNAME/$Group,group")
            foreach ($m in @($g.psbase.Invoke('Members'))) {
                $path = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                $cls  = $m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)
                $res += [pscustomobject]@{
                    Group       = $Group
                    Member      = (($path -replace '^WinNT://', '') -replace '/', '\')
                    ObjectClass = $cls
                    Source      = 'ADSI'
                    SID         = ''
                }
            }
        } catch { }
        return $res
    }
}

function Get-FileInventory {
    # Walks folders without following junctions. Skips folders whose path
    # starts with an ExcludePrefix or contains an ExcludeContains fragment.
    param(
        [string[]]$Roots,
        [string[]]$ExcludePrefixes = @(),
        [string[]]$ExcludeContains = @(),
        [int]$Max = 300000
    )
    $out = New-Object System.Collections.Generic.List[object]
    $stack = New-Object System.Collections.Generic.Stack[System.IO.DirectoryInfo]
    foreach ($r in $Roots) {
        if (Test-Path -LiteralPath $r) { $stack.Push((New-Object System.IO.DirectoryInfo($r))) }
    }
    while ($stack.Count -gt 0) {
        $d = $stack.Pop()
        $full = $d.FullName.TrimEnd('\') + '\'
        $skip = $false
        foreach ($ex in $ExcludePrefixes) {
            if ($full.StartsWith($ex, [StringComparison]::OrdinalIgnoreCase)) { $skip = $true; break }
        }
        if (-not $skip) {
            foreach ($ex in $ExcludeContains) {
                if ($full.IndexOf($ex, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $skip = $true; break }
            }
        }
        if ($skip) { continue }
        try { $entries = $d.GetFileSystemInfos() } catch { continue }
        foreach ($e in $entries) {
            if ($e -is [System.IO.DirectoryInfo]) {
                if (($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) { $stack.Push($e) }
            } else {
                $out.Add($e)
                if ($out.Count -ge $Max) { return ,$out }
            }
        }
    }
    return ,$out
}

function Select-FileRow {
    param($File, [string]$Category = '')
    [pscustomobject]@{
        Category      = $Category
        FullName      = $File.FullName
        SizeKB        = [math]::Round($File.Length / 1KB, 1)
        LastWriteTime = $File.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        CreationTime  = $File.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
        Attributes    = "$($File.Attributes)"
    }
}

# ---------------------------------------------------------------------------
# Machine facts used by several sections
# ---------------------------------------------------------------------------
$OS = Get-CimInstance Win32_OperatingSystem
$CS = Get-CimInstance Win32_ComputerSystem
$DomainRoleNames = @{
    0 = 'Standalone workstation'; 1 = 'Member workstation'; 2 = 'Standalone server'
    3 = 'Member server'; 4 = 'Backup domain controller'; 5 = 'Primary domain controller'
}
$IsDC = ($CS.DomainRole -ge 4)
$ProfilePaths = @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
    Where-Object { -not $_.Special -and $_.LocalPath } | ForEach-Object { $_.LocalPath })

# Process and service lookups by PID (used by network and process sections)
$ProcByPid = @{}
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $ProcByPid[[int]$_.ProcessId] = $_ }
$SvcByPid = @{}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object {
    $id = [int]$_.ProcessId
    if ($SvcByPid.ContainsKey($id)) { $SvcByPid[$id] += ',' + $_.Name } else { $SvcByPid[$id] = $_.Name }
}

# ===========================================================================
# 01 System
# ===========================================================================
Invoke-Section '01 System information' {
    $info = [pscustomobject][ordered]@{
        ComputerName     = $env:COMPUTERNAME
        OS               = $OS.Caption
        Version          = $OS.Version
        Build            = $OS.BuildNumber
        Architecture     = $OS.OSArchitecture
        InstallDate      = $OS.InstallDate
        LastBoot         = $OS.LastBootUpTime
        Domain           = $CS.Domain
        PartOfDomain     = $CS.PartOfDomain
        DomainRole       = $DomainRoleNames[[int]$CS.DomainRole]
        Manufacturer     = $CS.Manufacturer
        Model            = $CS.Model
        MemoryGB         = [math]::Round($CS.TotalPhysicalMemory / 1GB, 1)
        PowerShell       = $PSVersionTable.PSVersion.ToString()
        CollectedAt      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
        CollectedBy      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    Save-Data -Name '01_system_info' -Data $info -List
    $script:Highlights['OS'] = "$($OS.Caption) build $($OS.BuildNumber)"
    $script:Highlights['Domain role'] = $DomainRoleNames[[int]$CS.DomainRole]

    Save-Text -Name '01_systeminfo' -Command { systeminfo.exe }
    Save-Data -Name '01_hotfixes' -Data (Get-HotFix -ErrorAction SilentlyContinue |
        Select-Object HotFixID, Description, InstalledOn, InstalledBy | Sort-Object InstalledOn)
    Save-Data -Name '01_environment_machine' -Data (
        [Environment]::GetEnvironmentVariables('Machine').GetEnumerator() |
        ForEach-Object { [pscustomobject]@{ Name = $_.Key; Value = $_.Value } } | Sort-Object Name)
    Save-Data -Name '01_execution_policy' -Data (Get-ExecutionPolicy -List |
        Select-Object Scope, ExecutionPolicy)
    Save-Data -Name '01_disks' -Data (Get-CimInstance Win32_LogicalDisk |
        Select-Object DeviceID, DriveType, FileSystem, VolumeName,
            @{n = 'SizeGB'; e = { [math]::Round($_.Size / 1GB, 1) } },
            @{n = 'FreeGB'; e = { [math]::Round($_.FreeSpace / 1GB, 1) } })
}

# ===========================================================================
# 02 Local users and groups
# ===========================================================================
Invoke-Section '02 Local users and groups' {
    if ($IsDC) {
        "This machine is a domain controller. Local users and groups are the domain's; see the 03_ad_* files." |
            Out-File -LiteralPath (Join-Path $RunDir '02_local_users_NOTE.txt') -Encoding UTF8
    }

    # Groups and members first, so each user row can list its groups.
    $groups = @()
    try {
        $groups = @(Get-LocalGroup -ErrorAction Stop | Select-Object Name, Description, SID)
    } catch {
        $groups = @(Get-CimInstance Win32_Group -Filter 'LocalAccount=True' |
            Select-Object Name, Description, SID)
    }
    Save-Data -Name '02_local_groups' -Data $groups

    $members = @()
    foreach ($g in $groups) { $members += Get-LocalGroupMembersSafe -Group $g.Name }
    Save-Data -Name '02_local_group_members' -Data $members

    # Readable "Group: member, member" view of non-empty groups
    $lines = @("# Local groups that have members (from 02_local_group_members.csv)", '')
    foreach ($grp in ($members | Group-Object Group | Sort-Object Name)) {
        $lines += ('{0} ({1}):' -f $grp.Name, $grp.Count)
        foreach ($m in $grp.Group) { $lines += ('    {0}  [{1}]' -f $m.Member, $m.ObjectClass) }
        $lines += ''
    }
    $lines | Out-File -LiteralPath (Join-Path $RunDir '02_local_group_members_by_group.txt') -Encoding UTF8 -Width 4096

    $admins = @($members | Where-Object { $_.Group -eq 'Administrators' } | ForEach-Object { $_.Member })
    $script:Highlights['Administrators members'] = ($admins -join ', ')

    # Users
    $users = @()
    try {
        $users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
            $n = $_.Name
            [pscustomobject][ordered]@{
                Name                  = $n
                Enabled               = $_.Enabled
                FullName              = $_.FullName
                Description           = $_.Description
                PasswordRequired      = $_.PasswordRequired
                UserMayChangePassword = $_.UserMayChangePassword
                PasswordExpires       = $_.PasswordExpires
                PasswordLastSet       = $_.PasswordLastSet
                AccountExpires        = $_.AccountExpires
                LastLogon             = $_.LastLogon
                SID                   = "$($_.SID)"
                Groups                = (($members | Where-Object { $_.Member -match ('\\' + [regex]::Escape($n) + '$') } |
                                          ForEach-Object { $_.Group }) -join ', ')
            }
        })
    } catch {
        $users = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | ForEach-Object {
            $n = $_.Name
            [pscustomobject][ordered]@{
                Name               = $n
                Enabled            = -not $_.Disabled
                FullName           = $_.FullName
                Description        = $_.Description
                PasswordRequired   = $_.PasswordRequired
                PasswordChangeable = $_.PasswordChangeable
                PasswordExpires    = $_.PasswordExpires
                Lockout            = $_.Lockout
                SID                = $_.SID
                Groups             = (($members | Where-Object { $_.Member -match ('\\' + [regex]::Escape($n) + '$') } |
                                       ForEach-Object { $_.Group }) -join ', ')
            }
        })
    }
    Save-Data -Name '02_local_users' -Data $users
    $script:Highlights['Local users'] = "$($users.Count) total, $(@($users | Where-Object { $_.Enabled }).Count) enabled"

    # Full "net user" output for every account (shows password and logon details)
    if (-not $IsDC) {
        Save-Text -Name '02_net_user_details' -Command {
            foreach ($u in $users) {
                "==================== $($u.Name) ===================="
                net.exe user "$($u.Name)"
                ''
            }
        }
    }
    Save-Text -Name '02_net_accounts' -Command { net.exe accounts }

    Save-Data -Name '02_user_profiles' -Data (Get-CimInstance Win32_UserProfile | ForEach-Object {
        [pscustomobject]@{
            LocalPath   = $_.LocalPath
            Account     = (Resolve-Sid $_.SID)
            SID         = $_.SID
            Special     = $_.Special
            Loaded      = $_.Loaded
            LastUseTime = $_.LastUseTime
        }
    })
}

# ===========================================================================
# 03 Active Directory (domain-joined machines with the AD module only)
# ===========================================================================
Invoke-Section '03 Active Directory' {
    if (-not $CS.PartOfDomain) { return 'SKIPPED (not domain joined)' }
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { return 'SKIPPED (ActiveDirectory module not installed)' }
    Import-Module ActiveDirectory -ErrorAction Stop

    Save-Data -Name '03_ad_domain' -Data (Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode,
        PDCEmulator, InfrastructureMaster, RIDMaster, DistinguishedName) -List
    Save-Data -Name '03_ad_forest' -Data (Get-ADForest | Select-Object Name, ForestMode, SchemaMaster,
        DomainNamingMaster, @{n = 'Domains'; e = { $_.Domains -join ', ' } },
        @{n = 'GlobalCatalogs'; e = { $_.GlobalCatalogs -join ', ' } }) -List
    Save-Data -Name '03_ad_password_policy' -Data (Get-ADDefaultDomainPasswordPolicy) -List
    Save-Data -Name '03_ad_fine_grained_password_policies' -Data (Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue) -List

    $adUsers = @(Get-ADUser -Filter * -Properties Enabled, Description, MemberOf, PasswordNeverExpires,
        PasswordNotRequired, AllowReversiblePasswordEncryption, DoesNotRequirePreAuth, TrustedForDelegation,
        AdminCount, LastLogonDate, PasswordLastSet, ServicePrincipalName, CannotChangePassword, whenCreated |
        ForEach-Object {
            [pscustomobject][ordered]@{
                SamAccountName              = $_.SamAccountName
                Enabled                     = $_.Enabled
                Description                 = $_.Description
                PasswordNeverExpires        = $_.PasswordNeverExpires
                PasswordNotRequired         = $_.PasswordNotRequired
                ReversibleEncryption        = $_.AllowReversiblePasswordEncryption
                DoesNotRequirePreAuth       = $_.DoesNotRequirePreAuth
                TrustedForDelegation        = $_.TrustedForDelegation
                CannotChangePassword        = $_.CannotChangePassword
                AdminCount                  = $_.AdminCount
                PasswordLastSet             = $_.PasswordLastSet
                LastLogonDate               = $_.LastLogonDate
                WhenCreated                 = $_.whenCreated
                SPNs                        = ($_.ServicePrincipalName -join '; ')
                MemberOf                    = (($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }) -join ', ')
                DistinguishedName           = $_.DistinguishedName
            }
        })
    Save-Data -Name '03_ad_users' -Data $adUsers
    $script:Highlights['AD users'] = "$($adUsers.Count) total, $(@($adUsers | Where-Object { $_.Enabled }).Count) enabled"

    $adGroups = @(Get-ADGroup -Filter * -Properties Members, Description, AdminCount)
    Save-Data -Name '03_ad_groups' -Data ($adGroups | Select-Object Name, GroupScope, GroupCategory, AdminCount, Description,
        @{n = 'MemberCount'; e = { @($_.Members).Count } }, DistinguishedName)
    $gm = foreach ($g in $adGroups) {
        foreach ($m in $g.Members) {
            [pscustomobject]@{ Group = $g.Name; Member = (($m -split ',')[0] -replace '^CN=', ''); MemberDN = $m }
        }
    }
    Save-Data -Name '03_ad_group_members' -Data $gm
    $da = @($gm | Where-Object { $_.Group -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators') } |
        ForEach-Object { "$($_.Group): $($_.Member)" })
    $script:Highlights['AD privileged group members'] = ($da -join '; ')

    Save-Data -Name '03_ad_computers' -Data (Get-ADComputer -Filter * -Properties OperatingSystem, Enabled, LastLogonDate, TrustedForDelegation |
        Select-Object Name, Enabled, OperatingSystem, LastLogonDate, TrustedForDelegation, DistinguishedName)
    Save-Data -Name '03_ad_ous' -Data (Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion |
        Select-Object Name, ProtectedFromAccidentalDeletion, DistinguishedName)
    Save-Data -Name '03_ad_trusts' -Data (Get-ADTrust -Filter * -ErrorAction SilentlyContinue |
        Select-Object Name, Direction, TrustType, ForestTransitive, SelectiveAuthentication, SIDFilteringQuarantined)

    if (Get-Module -ListAvailable -Name GroupPolicy) {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        Save-Data -Name '03_ad_gpos' -Data (Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime,
            ModificationTime, Id, Description)
        try {
            Get-GPOReport -All -ReportType Xml -Path (Join-Path $RunDir '03_ad_gpo_report.xml') -ErrorAction Stop
        } catch { }
    }
}

# ===========================================================================
# 04 Services
# ===========================================================================
Invoke-Section '04 Services' {
    $svcs = @(Get-CimInstance Win32_Service | Sort-Object Name | Select-Object Name, DisplayName, State, StartMode,
        DelayedAutoStart, StartName, PathName, ProcessId, Description)
    Save-Data -Name '04_services' -Data $svcs
    Save-Data -Name '04_services_running' -Data ($svcs | Where-Object { $_.State -eq 'Running' } |
        Select-Object Name, DisplayName, StartMode, StartName, PathName)
    $nonWin = @($svcs | Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\(system32|SysWOW64|servicing|Microsoft\.NET)\\' })
    Save-Data -Name '04_services_outside_windows_folder' -Data $nonWin `
        -Note 'Services whose binary is not under C:\Windows\System32 / SysWOW64. Third-party, or worth a look.'
    $script:Highlights['Services'] = "$($svcs.Count) total, $(@($svcs | Where-Object { $_.State -eq 'Running' }).Count) running, $($nonWin.Count) outside Windows folder"
}

# ===========================================================================
# 05 Scheduled tasks
# ===========================================================================
Invoke-Section '05 Scheduled tasks' {
    $tasks = @(Get-ScheduledTask | ForEach-Object {
        $t = $_
        [pscustomobject][ordered]@{
            TaskPath    = $t.TaskPath
            TaskName    = $t.TaskName
            State       = "$($t.State)"
            Hidden      = $t.Settings.Hidden
            Author      = $t.Author
            RunAs       = $t.Principal.UserId
            RunLevel    = "$($t.Principal.RunLevel)"
            Actions     = (($t.Actions | ForEach-Object {
                              if ($_.Execute) { ('{0} {1}' -f $_.Execute, $_.Arguments).Trim() } else { $_.CimClass.CimClassName }
                          }) -join ' ; ')
            Triggers    = (($t.Triggers | ForEach-Object { ($_.CimClass.CimClassName -replace '^MSFT_Task', '') }) -join ', ')
            Description = $t.Description
        }
    })
    Save-Data -Name '05_scheduled_tasks_all' -Data $tasks
    $custom = @($tasks | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
    Save-Data -Name '05_scheduled_tasks_non_microsoft' -Data $custom -List `
        -Note 'Tasks outside \Microsoft\. On a fresh Windows install this list is short, so anything here is worth reading.'
    $script:Highlights['Scheduled tasks'] = "$($tasks.Count) total, $($custom.Count) outside \Microsoft\"

    # Full XML for the non-Microsoft tasks
    $xmlDir = Join-Path $RunDir '05_task_xml'
    New-Item -ItemType Directory -Path $xmlDir -Force | Out-Null
    foreach ($c in $custom) {
        try {
            $safe = (($c.TaskPath + $c.TaskName) -replace '[\\/:*?"<>|]', '_').Trim('_')
            Export-ScheduledTask -TaskName $c.TaskName -TaskPath $c.TaskPath |
                Out-File -LiteralPath (Join-Path $xmlDir ($safe + '.xml.txt')) -Encoding UTF8
        } catch { }
    }
    Save-Text -Name '05_schtasks_verbose' -Command { schtasks.exe /query /fo LIST /v }
}

# ===========================================================================
# 06 Startup items and persistence locations
# ===========================================================================
Invoke-Section '06 Startup and persistence' {
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    # Every user hive that is currently loaded (logged-on users plus .DEFAULT)
    foreach ($hk in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notlike '*_Classes' })) {
        foreach ($sub in 'Run', 'RunOnce', 'Policies\Explorer\Run') {
            $runKeys += "Registry::HKEY_USERS\$($hk.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\$sub"
        }
    }
    $run = @(Get-RegValues -Paths $runKeys)
    Save-Data -Name '06_registry_run_keys' -Data $run `
        -Note 'Only user hives that are loaded right now are included (normally the current admin and .DEFAULT).'

    Save-Data -Name '06_winlogon' -Data (Get-RegValues -Paths @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon')) `
        -Note 'Check Shell, Userinit, AutoAdminLogon, DefaultUserName and DefaultPassword.'

    $ifeo = foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        Get-RegValues -Paths $base -Recurse | Where-Object { $_.Name -in @('Debugger', 'GlobalFlag', 'VerifierDlls') }
    }
    Save-Data -Name '06_ifeo_debuggers' -Data $ifeo -Note 'Image File Execution Options Debugger/GlobalFlag values (sticky-keys style backdoors).'
    Save-Data -Name '06_silent_process_exit' -Data (Get-RegValues -Recurse -Paths 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit')

    Save-Data -Name '06_appinit_and_misc' -Data (@(
        Get-RegValues -Paths 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                             'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows' |
            Where-Object { $_.Name -in @('AppInit_DLLs', 'LoadAppInit_DLLs', 'RequireSignedAppInit_DLLs') }
        Get-RegValues -Paths 'HKLM:\SOFTWARE\Microsoft\NetSh'
        Get-RegValues -Paths 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' |
            Where-Object { $_.Name -in @('BootExecute', 'SetupExecute', 'Execute') }
    ))

    # Startup folders (all users + every profile)
    $startupDirs = @(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
    foreach ($p in $ProfilePaths) { $startupDirs += Join-Path $p 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
    $sf = foreach ($d in $startupDirs) {
        if (Test-Path -LiteralPath $d) {
            Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{ Folder = $d; Name = $_.Name; LastWriteTime = $_.LastWriteTime; Length = $_.Length }
            }
        }
    }
    Save-Data -Name '06_startup_folders' -Data $sf

    Save-Data -Name '06_wmi_startup_commands' -Data (Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name, Command, Location, User)

    # WMI event subscriptions (fileless persistence)
    $wmi = @()
    foreach ($cls in '__EventFilter', '__EventConsumer', '__FilterToConsumerBinding') {
        $wmi += @(Get-CimInstance -Namespace 'root\subscription' -ClassName $cls -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Class   = $_.CimClass.CimClassName
                Name    = $_.Name
                Query   = $_.Query
                Command = (@($_.CommandLineTemplate, $_.ScriptText, $_.ExecutablePath) | Where-Object { $_ }) -join ' | '
                Filter  = "$($_.Filter)"
                Consumer = "$($_.Consumer)"
            }
        })
    }
    Save-Data -Name '06_wmi_event_subscriptions' -Data $wmi -List

    $script:Highlights['Startup entries'] = "$($run.Count) Run-key values, $(@($sf).Count) startup-folder items, $($wmi.Count) WMI subscription objects"
}

# ===========================================================================
# 07 Shares
# ===========================================================================
Invoke-Section '07 Shares and SMB' {
    $shares = @(Get-SmbShare -ErrorAction Stop | Select-Object Name, Path, Description, ShareType, Special,
        FolderEnumerationMode, EncryptData, CachingMode, CurrentUsers)
    Save-Data -Name '07_shares' -Data $shares
    $access = foreach ($s in $shares) {
        Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue |
            Select-Object Name, AccountName, AccessControlType, AccessRight
    }
    Save-Data -Name '07_share_permissions' -Data $access

    $acl = foreach ($s in ($shares | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path) })) {
        try {
            (Get-Acl -LiteralPath $s.Path).Access | ForEach-Object {
                [pscustomobject]@{
                    Share      = $s.Name
                    Path       = $s.Path
                    Identity   = "$($_.IdentityReference)"
                    Rights     = "$($_.FileSystemRights)"
                    Type       = "$($_.AccessControlType)"
                    Inherited  = $_.IsInherited
                }
            }
        } catch { }
    }
    Save-Data -Name '07_share_folder_ntfs_permissions' -Data $acl
    Save-Text -Name '07_net_share' -Command { net.exe share }
    Save-Data -Name '07_smb_server_configuration' -Data (Get-SmbServerConfiguration) -List
    $custom = @($shares | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$|print\$|NETLOGON|SYSVOL)$' })
    $script:Highlights['Shares'] = "$($shares.Count) total; non-default: $(($custom | ForEach-Object { "$($_.Name) ($($_.Path))" }) -join ', ')"
}

# ===========================================================================
# 08 Installed programs
# ===========================================================================
Invoke-Section '08 Installed programs' {
    $uninstallKeys = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine 64-bit' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine 32-bit' }
    )
    foreach ($hk in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notlike '*_Classes' })) {
        $uninstallKeys += @{ Path = "Registry::HKEY_USERS\$($hk.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"; Scope = "User $(Resolve-Sid $hk.PSChildName)" }
    }
    $progs = foreach ($u in $uninstallKeys) {
        if (-not (Test-Path -LiteralPath $u.Path)) { continue }
        Get-ChildItem -LiteralPath $u.Path -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if ($p.DisplayName) {
                [pscustomobject][ordered]@{
                    DisplayName     = $p.DisplayName
                    Version         = $p.DisplayVersion
                    Publisher       = $p.Publisher
                    InstallDate     = $p.InstallDate
                    InstallLocation = $p.InstallLocation
                    SystemComponent = $p.SystemComponent
                    Scope           = $u.Scope
                    UninstallString = $p.UninstallString
                    RegistryKey     = $_.PSChildName
                }
            }
        }
    }
    $progs = @($progs | Sort-Object DisplayName)
    Save-Data -Name '08_installed_programs' -Data $progs
    $script:Highlights['Installed programs'] = "$($progs.Count) entries"

    $dirs = foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, "$env:SystemDrive\")) {
        if ($root -and (Test-Path -LiteralPath $root)) {
            Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{
                    Parent        = $root
                    Folder        = $_.Name
                    CreationTime  = $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                    LastWriteTime = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    Attributes    = "$($_.Attributes)"
                }
            }
        }
    }
    Save-Data -Name '08_top_level_folders' -Data $dirs -Note 'Top-level folders of Program Files, Program Files (x86), ProgramData and the system drive root.'

    try {
        Save-Data -Name '08_appx_packages' -Data (Get-AppxPackage -AllUsers -ErrorAction Stop |
            Select-Object Name, Version, Publisher, SignatureKind, NonRemovable, InstallLocation | Sort-Object Name)
    } catch { }
}

# ===========================================================================
# 09 Network
# ===========================================================================
Invoke-Section '09 Network and open ports' {
    $tcp = @(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
        $p = $ProcByPid[[int]$_.OwningProcess]
        [pscustomobject][ordered]@{
            State         = "$($_.State)"
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            PID           = $_.OwningProcess
            Process       = $p.Name
            Services      = $SvcByPid[[int]$_.OwningProcess]
            Path          = $p.ExecutablePath
        }
    })
    $listen = @($tcp | Where-Object { $_.State -eq 'Listen' } | Sort-Object LocalPort)
    Save-Data -Name '09_tcp_listening' -Data $listen
    Save-Data -Name '09_tcp_all_connections' -Data ($tcp | Sort-Object State, LocalPort)
    $udp = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object {
        $p = $ProcByPid[[int]$_.OwningProcess]
        [pscustomobject][ordered]@{
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            PID          = $_.OwningProcess
            Process      = $p.Name
            Services     = $SvcByPid[[int]$_.OwningProcess]
            Path         = $p.ExecutablePath
        }
    } | Sort-Object LocalPort)
    Save-Data -Name '09_udp_listening' -Data $udp
    $ports = ($listen | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object) -join ', '
    $script:Highlights['Listening TCP ports'] = $ports

    Save-Text -Name '09_netstat_abno' -Command { netstat.exe -abno }
    Save-Text -Name '09_ipconfig_all' -Command { ipconfig.exe /all }
    Save-Text -Name '09_route_print' -Command { route.exe print }
    Save-Text -Name '09_arp' -Command { arp.exe -a }
    Save-Text -Name '09_winhttp_proxy' -Command { netsh.exe winhttp show proxy }
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    Save-Text -Name '09_hosts_file' -Command { Get-Content -LiteralPath $hosts }
    Save-Data -Name '09_dns_client_servers' -Data (Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses } |
        Select-Object InterfaceAlias, AddressFamily, @{n = 'Servers'; e = { $_.ServerAddresses -join ', ' } })
    Save-Data -Name '09_network_profiles' -Data (Get-NetConnectionProfile -ErrorAction SilentlyContinue |
        Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity, IPv6Connectivity)
    Save-Data -Name '09_adapter_bindings' -Data (Get-NetAdapterBinding -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, ComponentID, Enabled)
}

# ===========================================================================
# 10 Firewall
# ===========================================================================
Invoke-Section '10 Firewall' {
    Save-Text -Name '10_firewall_profiles' -Command { netsh.exe advfirewall show allprofiles }
    Save-Data -Name '10_firewall_profiles_ps' -Data (Get-NetFirewallProfile | Select-Object Name, Enabled,
        DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, NotifyOnListen,
        LogAllowed, LogBlocked, LogFileName, LogMaxSizeKilobytes) -List

    $portF = @{}; Get-NetFirewallPortFilter -All | ForEach-Object { $portF[$_.InstanceID] = $_ }
    $appF  = @{}; Get-NetFirewallApplicationFilter -All | ForEach-Object { $appF[$_.InstanceID] = $_ }
    $addrF = @{}; Get-NetFirewallAddressFilter -All | ForEach-Object { $addrF[$_.InstanceID] = $_ }
    $svcF  = @{}; Get-NetFirewallServiceFilter -All | ForEach-Object { $svcF[$_.InstanceID] = $_ }

    $rules = @(Get-NetFirewallRule | ForEach-Object {
        $id = $_.InstanceID
        $pf = $portF[$id]; $af = $appF[$id]; $ad = $addrF[$id]; $sv = $svcF[$id]
        [pscustomobject][ordered]@{
            DisplayName   = $_.DisplayName
            Enabled       = "$($_.Enabled)"
            Direction     = "$($_.Direction)"
            Action        = "$($_.Action)"
            Profile       = "$($_.Profile)"
            Protocol      = $pf.Protocol
            LocalPort     = ($pf.LocalPort -join ',')
            RemotePort    = ($pf.RemotePort -join ',')
            RemoteAddress = ($ad.RemoteAddress -join ',')
            Program       = $af.Program
            Service       = $sv.Service
            Group         = $_.DisplayGroup
            Source        = "$($_.PolicyStoreSourceType)"
            Name          = $_.Name
        }
    })
    Save-Data -Name '10_firewall_rules_all' -Data $rules
    $enabled = @($rules | Where-Object { $_.Enabled -eq 'True' } | Sort-Object Direction, Action, DisplayName)
    Save-Data -Name '10_firewall_rules_enabled' -Data $enabled
    $inAllow = @($enabled | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' })
    Save-Data -Name '10_firewall_rules_enabled_inbound_allow' -Data $inAllow
    $script:Highlights['Firewall rules'] = "$($rules.Count) total, $($enabled.Count) enabled, $($inAllow.Count) enabled inbound allow"
    Save-Text -Name '10_firewall_rules_netsh_verbose' -Command { netsh.exe advfirewall firewall show rule name=all verbose }
}

# ===========================================================================
# 11 Roles and features
# ===========================================================================
Invoke-Section '11 Roles and features' {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $feat = @(Get-WindowsFeature | Where-Object { $_.Installed } |
            Select-Object Name, DisplayName, FeatureType, Path, Depth)
        Save-Data -Name '11_server_roles_features_installed' -Data $feat
        $script:Highlights['Server roles/features installed'] = (($feat | Where-Object { $_.FeatureType -eq 'Role' } |
            ForEach-Object { $_.Name }) -join ', ')
    }
    Save-Data -Name '11_optional_features_enabled' -Data (Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
        Where-Object { "$($_.State)" -eq 'Enabled' } | Select-Object FeatureName, State | Sort-Object FeatureName)
    Save-Data -Name '11_capabilities_installed' -Data (Get-WindowsCapability -Online -ErrorAction SilentlyContinue |
        Where-Object { "$($_.State)" -eq 'Installed' } | Select-Object Name, State | Sort-Object Name)
}

# ===========================================================================
# 12 Security policy, audit policy, registry security settings
# ===========================================================================
Invoke-Section '12 Security and audit policy' {
    $inf = Join-Path $RunDir '12_secedit_export.inf'
    secedit.exe /export /cfg "$inf" /quiet | Out-Null
    if (Test-Path -LiteralPath $inf) {
        $content = Get-Content -LiteralPath $inf
        $content | Out-File -LiteralPath (Join-Path $RunDir '12_secedit_export.txt') -Encoding UTF8 -Width 4096
        Remove-Item -LiteralPath $inf -Force -ErrorAction SilentlyContinue   # only our own temp export

        # User rights with SIDs turned into names
        $rights = @()
        $inPriv = $false
        foreach ($line in $content) {
            if ($line -match '^\[(.+)\]') { $inPriv = ($Matches[1] -eq 'Privilege Rights'); continue }
            if ($inPriv -and $line -match '^\s*(\S+)\s*=\s*(.*)$') {
                $right = $Matches[1]
                $names = foreach ($e in ($Matches[2] -split ',')) {
                    $e = $e.Trim().TrimStart('*')
                    if ($e -like 'S-1-*') {
                        $n = Resolve-Sid $e
                        if ($n) { "$n ($e)" } else { $e }
                    } elseif ($e) { $e }
                }
                $rights += [pscustomobject]@{ Right = $right; Accounts = ($names -join '; ') }
            }
        }
        Save-Data -Name '12_user_rights_assignment' -Data $rights

        # Password / lockout policy lines, for a quick read
        $sys = @()
        $inSys = $false
        foreach ($line in $content) {
            if ($line -match '^\[(.+)\]') { $inSys = ($Matches[1] -eq 'System Access'); continue }
            if ($inSys -and $line -match '^\s*(\S+)\s*=\s*(.*)$') { $sys += [pscustomobject]@{ Setting = $Matches[1]; Value = $Matches[2] } }
        }
        Save-Data -Name '12_password_and_lockout_policy' -Data $sys
    }

    Save-Text -Name '12_auditpol' -Command { auditpol.exe /get /category:* }
    Save-Text -Name '12_gpresult' -Command { gpresult.exe /z }

    Save-Data -Name '12_registry_policies' -Data (Get-RegValues -Recurse -Paths @(
        'HKLM:\SOFTWARE\Policies',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
        'HKLM:\SOFTWARE\WOW6432Node\Policies')) -Note 'Everything under the machine Policies keys (UAC, Windows Update, Defender, PowerShell logging, etc.).'

    $secKeys = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance',
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
        'HKLM:\SOFTWARE\Microsoft\Windows Defender'
    )
    $sec = @(Get-RegValues -Paths $secKeys)
    $sec += @(Get-RegValues -Recurse -Paths 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols')
    $sec += @(Get-RegValues -Recurse -Paths 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters')
    Save-Data -Name '12_registry_security_settings' -Data $sec `
        -Note 'LSA, NTLM, WDigest, RDP, SMB server/client, Netlogon, SCHANNEL, SNMP community strings and similar.'

    foreach ($log in 'Security', 'System', 'Application') {
        Save-Text -Name "12_eventlog_settings_$log" -Command { wevtutil.exe gl $log }
    }
}

# ===========================================================================
# 13 Windows Defender
# ===========================================================================
Invoke-Section '13 Windows Defender' {
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return 'SKIPPED (Defender cmdlets not present)' }
    Save-Data -Name '13_defender_status' -Data (Get-MpComputerStatus -ErrorAction Stop) -List
    Save-Data -Name '13_defender_preferences' -Data (Get-MpPreference -ErrorAction Stop) -List `
        -Note 'Look at the Exclusion* and Disable* values.'
    Save-Data -Name '13_defender_detections' -Data (Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Select-Object InitialDetectionTime, ThreatID, ProcessName, @{n = 'Resources'; e = { $_.Resources -join '; ' } }, ActionSuccess)
}

# ===========================================================================
# 14 Processes
# ===========================================================================
Invoke-Section '14 Running processes' {
    $owners = @{}
    try { Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object { $owners[$_.Id] = $_.UserName } } catch { }
    $procs = @($ProcByPid.Values | Sort-Object Name | ForEach-Object {
        [pscustomobject][ordered]@{
            PID         = $_.ProcessId
            ParentPID   = $_.ParentProcessId
            Name        = $_.Name
            User        = $owners[[int]$_.ProcessId]
            Services    = $SvcByPid[[int]$_.ProcessId]
            Path        = $_.ExecutablePath
            CommandLine = $_.CommandLine
        }
    })
    Save-Data -Name '14_processes' -Data $procs
}

# ===========================================================================
# 15 Key system binaries (sticky keys / utilman replacement check)
# ===========================================================================
Invoke-Section '15 Accessibility and shell binaries' {
    $sys32 = Join-Path $env:SystemRoot 'System32'
    $names = 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe',
             'cmd.exe', 'powershell.exe', 'explorer.exe', 'taskmgr.exe', 'notepad.exe'
    $cmdHash = ''
    $cmdPath = Join-Path $sys32 'cmd.exe'
    if (Test-Path -LiteralPath $cmdPath) { $cmdHash = (Get-FileHash -LiteralPath $cmdPath -Algorithm SHA256).Hash }
    $rows = foreach ($n in $names) {
        $path = Join-Path $sys32 $n
        if ($n -eq 'powershell.exe') { $path = Join-Path $sys32 'WindowsPowerShell\v1.0\powershell.exe' }
        if ($n -eq 'explorer.exe') { $path = Join-Path $env:SystemRoot 'explorer.exe' }
        if (-not (Test-Path -LiteralPath $path)) {
            [pscustomobject]@{ File = $path; Exists = $false; SHA256 = ''; SameAsCmd = ''; Version = ''; Description = ''; LastWriteTime = '' }
            continue
        }
        $fi = Get-Item -LiteralPath $path
        $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        [pscustomobject][ordered]@{
            File          = $path
            Exists        = $true
            SHA256        = $h
            SameAsCmd     = (($n -ne 'cmd.exe') -and ($h -eq $cmdHash))
            Version       = $fi.VersionInfo.FileVersion
            Description   = $fi.VersionInfo.FileDescription
            LastWriteTime = $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }
    Save-Data -Name '15_key_binaries' -Data $rows -Note 'SameAsCmd = True means the file was replaced with cmd.exe (backdoor).'
}

# ===========================================================================
# 16 Files
# ===========================================================================
Invoke-Section '16 PowerShell history files' {
    $lines = @()
    foreach ($p in $ProfilePaths) {
        $h = Join-Path $p 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path -LiteralPath $h) {
            $lines += "==================== $h ===================="
            $lines += @(Get-Content -LiteralPath $h -ErrorAction SilentlyContinue)
            $lines += ''
        }
    }
    if ($lines.Count -eq 0) { $lines = @('(no PowerShell history files found)') }
    $lines | Out-File -LiteralPath (Join-Path $RunDir '16_powershell_history.txt') -Encoding UTF8 -Width 4096
}

Invoke-Section '16 User profile files' {
    # Everything in each profile except AppData, which is listed separately below
    $userFiles = Get-FileInventory -Roots $ProfilePaths -ExcludeContains @('\AppData\') -Max $MaxFileRows
    Save-Data -Name '16_user_profile_files' -Data ($userFiles | ForEach-Object { Select-FileRow $_ } | Sort-Object FullName) `
        -Note 'All files in user profiles (Desktop, Documents, Downloads, Music, ...) except AppData.'

    # Executables and scripts hidden in AppData (skip the huge Microsoft/Packages caches)
    $appData = Get-FileInventory -Roots ($ProfilePaths | ForEach-Object { Join-Path $_ 'AppData' }) `
        -ExcludeContains @('\AppData\Local\Microsoft\', '\AppData\Local\Packages\', '\AppData\Local\Temp\Diagnostics\') -Max 200000
    $exeExt = '.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.hta', '.scr', '.py', '.jar', '.msi', '.lnk'
    Save-Data -Name '16_appdata_executables_scripts' -Data ($appData | Where-Object { $exeExt -contains $_.Extension.ToLower() } |
        Select-Object -First $MaxFileRows | ForEach-Object { Select-FileRow $_ } | Sort-Object FullName)
    $script:Highlights['User profile files'] = "$($userFiles.Count) files outside AppData"
}

Invoke-Section '16 Web roots and other data folders' {
    $roots = @("$env:SystemDrive\inetpub", "$env:SystemDrive\xampp", "$env:SystemDrive\wamp", "$env:SystemDrive\wamp64") |
        Where-Object { Test-Path -LiteralPath $_ }
    if (-not $roots) { return 'SKIPPED (no inetpub/xampp/wamp folder)' }
    $files = Get-FileInventory -Roots $roots -Max $MaxFileRows
    Save-Data -Name '16_web_root_files' -Data ($files | ForEach-Object { Select-FileRow $_ } | Sort-Object FullName)
}

Invoke-Section '16 Whole-disk file scan' {
    if ($SkipFileScan) { return 'SKIPPED (-SkipFileScan)' }
    $drives = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { $_.DeviceID + '\' })
    $exPrefix = @(
        ($env:SystemRoot.TrimEnd('\') + '\'),
        "$env:SystemDrive\System Volume Information\",
        "$env:ProgramFiles\WindowsApps\",
        "$env:ProgramData\Microsoft\Windows Defender\",
        "$env:ProgramData\Microsoft\Windows\WER\",
        "$env:ProgramData\Package Cache\"
    )
    $exContains = @('\AppData\Local\Microsoft\', '\AppData\Local\Packages\', '\WinSxS\')
    $all = Get-FileInventory -Roots $drives -ExcludePrefixes $exPrefix -ExcludeContains $exContains -Max 400000

    $cats = @{
        Media      = '.mp3', '.mp4', '.m4a', '.m4v', '.wav', '.flac', '.aac', '.ogg', '.wma', '.wmv', '.avi', '.mkv', '.mov', '.mpg', '.mpeg', '.webm', '.3gp'
        Image      = '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tif', '.tiff', '.heic', '.webp'
        Archive    = '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.cab', '.iso'
        Script     = '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.hta', '.py', '.pl', '.rb', '.sh', '.wsf'
        Executable = '.exe', '.msi', '.scr', '.com', '.jar', '.pif'
        Document   = '.txt', '.csv', '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.rtf', '.odt', '.kdbx', '.pst', '.ost'
    }
    $extToCat = @{}
    foreach ($k in $cats.Keys) { foreach ($e in $cats[$k]) { $extToCat[$e] = $k } }
    $pwRegex = '(?i)(pass(word|wd)?|creds?|credential|secret|login|account|shadow|sam\.bak|unattend|sysprep|\.kdbx$)'
    $progFiles = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' }

    $interesting = New-Object System.Collections.Generic.List[object]
    foreach ($f in $all) {
        $ext = $f.Extension.ToLower()
        $cat = $extToCat[$ext]
        $inProg = $false
        foreach ($pf in $progFiles) { if ($f.FullName.StartsWith($pf, [StringComparison]::OrdinalIgnoreCase)) { $inProg = $true; break } }
        # Installed software ships lots of exe/scripts/images/docs; only flag those outside Program Files / ProgramData.
        if ($inProg -and $cat -in @('Executable', 'Script', 'Image', 'Document')) { $cat = $null }
        if ($f.Name -match $pwRegex) { $cat = if ($cat) { "$cat+NameMatch" } else { 'NameMatch' } }
        if (-not $cat -and (($f.Attributes -band [IO.FileAttributes]::Hidden) -ne 0) -and (($f.Attributes -band [IO.FileAttributes]::System) -eq 0) -and -not $inProg) {
            $cat = 'Hidden'
        }
        if ($cat) {
            $interesting.Add((Select-FileRow $f $cat))
            if ($interesting.Count -ge $MaxFileRows) { break }
        }
    }
    Save-Data -Name '16_files_of_interest' -Data ($interesting | Sort-Object Category, FullName) `
        -Note 'Outside C:\Windows. Media, archives, documents, scripts/executables outside Program Files, hidden files, and names like password/creds.'

    # Most recently changed files: on a fresh image these are usually what the image builder planted or edited.
    $recent = $all | Sort-Object LastWriteTime -Descending | Select-Object -First 1000 | ForEach-Object { Select-FileRow $_ 'Recent' }
    Save-Data -Name '16_files_most_recently_modified' -Data $recent `
        -Note 'Newest 1000 files outside C:\Windows by last-write time.'

    $byCat = ($interesting | Group-Object Category | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
    $script:Highlights['Files scanned (outside Windows)'] = "$($all.Count)"
    $script:Highlights['Files of interest'] = $byCat
}

# ===========================================================================
# 17 Server roles detail (only when present)
# ===========================================================================
Invoke-Section '17 IIS and FTP' {
    $appcmd = Join-Path $env:SystemRoot 'System32\inetsrv\appcmd.exe'
    if (-not (Test-Path -LiteralPath $appcmd)) { return 'SKIPPED (IIS not installed)' }
    Save-Text -Name '17_iis_sites' -Command { & $appcmd list site /text:* }
    Save-Text -Name '17_iis_apppools' -Command { & $appcmd list apppool /text:* }
    Save-Text -Name '17_iis_vdirs' -Command { & $appcmd list vdir /text:* }
    Save-Text -Name '17_iis_config_security' -Command {
        foreach ($s in 'system.webServer/security/authentication/anonymousAuthentication',
                       'system.webServer/security/authentication/basicAuthentication',
                       'system.webServer/security/authentication/windowsAuthentication',
                       'system.webServer/directoryBrowse',
                       'system.webServer/security/requestFiltering',
                       'system.webServer/httpLogging',
                       'system.applicationHost/sites') {
            "==================== $s ===================="
            & $appcmd list config /section:$s
            ''
        }
    }
}

Invoke-Section '17 DNS Server' {
    if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) { return 'SKIPPED (DNS Server role not installed)' }
    Save-Data -Name '17_dns_zones' -Data (Get-DnsServerZone -ErrorAction Stop | Select-Object ZoneName, ZoneType,
        IsDsIntegrated, IsReverseLookupZone, DynamicUpdate, SecureSecondaries, @{n = 'SecondaryServers'; e = { $_.SecondaryServers -join ', ' } })
    Save-Data -Name '17_dns_server_settings' -Data (Get-DnsServerRecursion -ErrorAction SilentlyContinue) -List
}

# ===========================================================================
# 00 Summary + zip
# ===========================================================================
$TotalTimer.Stop()
$summary = New-Object System.Collections.Generic.List[string]
$summary.Add('CyberPatriot image manifest')
$summary.Add('===========================')
$summary.Add("Computer : $env:COMPUTERNAME")
$summary.Add("Collected: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')")
$summary.Add("Run time : $([math]::Round($TotalTimer.Elapsed.TotalMinutes, 1)) minutes")
$summary.Add("Folder   : $RunDir")
$summary.Add('This run was read-only. Nothing on the machine was changed.')
$summary.Add('')
$summary.Add('Highlights')
$summary.Add('----------')
foreach ($k in $script:Highlights.Keys) { $summary.Add(('{0,-32}: {1}' -f $k, $script:Highlights[$k])) }
$summary.Add('')
$summary.Add('Sections')
$summary.Add('--------')
foreach ($s in $script:SectionLog) {
    $line = '{0,-40} {1,-45} {2,6}s' -f $s.Section, $s.Status, $s.Seconds
    if ($s.Error) { $line += "   $($s.Error)" }
    $summary.Add($line)
}
$summary.Add('')
$summary.Add('Where to look first')
$summary.Add('-------------------')
$summary.Add('02_local_group_members_by_group.txt  who is in Administrators and other groups')
$summary.Add('02_local_users.txt / 03_ad_users.txt  accounts, enabled state, password flags')
$summary.Add('04_services_outside_windows_folder   third-party services')
$summary.Add('05_scheduled_tasks_non_microsoft     tasks the image builder added')
$summary.Add('06_*                                 Run keys, Winlogon, IFEO, startup folders, WMI subscriptions')
$summary.Add('07_shares.txt                        shares and their permissions')
$summary.Add('08_installed_programs.txt            installed software')
$summary.Add('09_tcp_listening.txt                 open ports with process and service')
$summary.Add('10_firewall_rules_enabled_inbound_allow.txt')
$summary.Add('12_user_rights_assignment.txt / 12_password_and_lockout_policy.txt / 12_auditpol.txt')
$summary.Add('15_key_binaries.txt                  sticky-keys style replacements')
$summary.Add('16_files_of_interest.txt / 16_files_most_recently_modified.txt')
$summary.Add('')
$summary.Add('Files')
$summary.Add('-----')
Get-ChildItem -LiteralPath $RunDir -Recurse -File | Sort-Object FullName | ForEach-Object {
    $summary.Add(('{0,-60} {1,10:N0} bytes' -f $_.FullName.Substring($RunDir.Length + 1), $_.Length))
}
$summary | Out-File -LiteralPath (Join-Path $RunDir '00_SUMMARY.txt') -Encoding UTF8 -Width 4096

try { Stop-Transcript | Out-Null } catch { }

$zip = ''
if (-not $NoZip) {
    try {
        $zip = Join-Path $OutputRoot ($RunName + '.zip')
        Compress-Archive -Path (Join-Path $RunDir '*') -DestinationPath $zip -Force -ErrorAction Stop
    } catch {
        Write-Host "Could not create zip: $($_.Exception.Message)" -ForegroundColor Yellow
        $zip = ''
    }
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host "Folder : $RunDir" -ForegroundColor Green
if ($zip) { Write-Host "Zip    : $zip" -ForegroundColor Green }
Write-Host 'Open 00_SUMMARY.txt first.' -ForegroundColor Green
$errs = @($script:SectionLog | Where-Object { $_.Status -eq 'ERROR' })
if ($errs.Count) { Write-Host "$($errs.Count) section(s) had errors; see 00_SUMMARY.txt." -ForegroundColor Yellow }
