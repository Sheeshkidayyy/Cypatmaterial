﻿# CYPat Enforcer V1 2022- Full Security & Audit Script (Success-only audit for Logon/Logoff + Credential Validation Failures + Remote Assistance disabled + Defender enabled + FTP disabled + classic Windows Update + LimitBlankPasswordUse + more) with y/n checks
# Made by Sheeshkidayyy github.com/sheeshkidayyy Also know as Sheesh
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
    [switch]$Apply,
    [switch]$AuditOnly,
    [switch]$Yes,
    [switch]$NonInteractive,
    [switch]$SkipKnownPasswordCheck,
    [switch]$RemoveEveryoneNetworkLogonRight,
    [string[]]$RequiredServices=@(),
    [hashtable]$RequiredShares=@{},
    [string[]]$KeepShares=@(),
    [string[]]$RemoveShares=@(),
    [ValidateSet('All','Core')][string]$AuditCoverage='All',
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
    [switch]$PassThru
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if ($env:OS -ne 'Windows_NT') { throw 'Run this script in Windows PowerShell on the Windows Server image.' }
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
$script:Results=[System.Collections.Generic.List[object]]::new()
$script:RunDirectory=$null
$script:ResetPasswordAccounts=@{}
$script:ServiceDecisions=[ordered]@{}
$script:Inventory=[ordered]@{}
$script:ProtectedServices=@{}
$script:HasUserAllowlist=$PSBoundParameters.ContainsKey('AuthorizedUsers')
$script:HasAdminAllowlist=$PSBoundParameters.ContainsKey('AuthorizedAdministrators')
$script:NetworkRightRemovalSelected=[bool]$RemoveEveryoneNetworkLogonRight
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


function Add-Result {
    param([string]$Category, [string]$Item,
        [ValidateSet('PASS','CHANGED','REVIEW','FAILED','SKIPPED')][string]$Status,
        [string]$Evidence, [string]$Recommendation)
    $script:Results.Add([pscustomobject]@{Category=$Category;Item=$Item;Status=$Status;Evidence=$Evidence;Recommendation=$Recommendation})
}

function Initialize-PrivateRun {
    param([string]$Root='')
    if ([string]::IsNullOrWhiteSpace($Root)) { $Root = Join-Path $env:ProgramData 'CYPatV2\Runs' }
    $Root = [Environment]::ExpandEnvironmentVariables($Root)
    if (-not (Test-Path -LiteralPath $Root)) { New-Item -Path $Root -ItemType Directory -Force -ErrorAction Stop | Out-Null }
    $stamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
    $suffix = [guid]::NewGuid().ToString('N').Substring(0,8)
    $run = Join-Path $Root "$stamp-$suffix"
    New-Item -Path $run -ItemType Directory -Force -ErrorAction Stop | Out-Null
    New-Item -Path (Join-Path $run 'Quarantine') -ItemType Directory -Force -ErrorAction Stop | Out-Null
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    foreach ($principal in $systemSid,$adminSid) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($principal,'FullControl',$inheritance,$propagation,'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $run -AclObject $acl -ErrorAction Stop
    Set-Acl -LiteralPath (Join-Path $run 'Quarantine') -AclObject $acl -ErrorAction Stop
    $script:RunDirectory = $run
    $header = @(
        'CYPat Server 2022 Enforcer V2 - private run folder',
        "Created : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "Computer: $env:COMPUTERNAME",
        ''
    )
    Set-Content -LiteralPath (Join-Path $run 'Changed-Passwords.txt') -Value ($header + @('Format: timestamp | account | new password')) -Encoding UTF8 -ErrorAction Stop
    Set-Content -LiteralPath (Join-Path $run 'Ledger.txt') -Value ($header + @('Format: timestamp | action | target | detail')) -Encoding UTF8 -ErrorAction Stop
    Set-Content -LiteralPath (Join-Path $run 'Quarantine.txt') -Value ($header + @('Format: timestamp | action | file | original path | SHA256 | notes')) -Encoding UTF8 -ErrorAction Stop
    Set-Content -LiteralPath (Join-Path $run 'README.txt') -Value @(
        'CYPat Server 2022 Enforcer V2 - private plain-text run folder',
        '',
        'Report.txt              Full findings, inventory detail, security policy, and user rights.',
        'Changed-Passwords.txt   Passwords generated by this run. Keep private.',
        'Ledger.txt              Every change made by this run, in order.',
        'Quarantine.txt          Files stopped, copied, or removed, with SHA-256.',
        'Quarantine\             Copies of removed files. This folder can contain binary files.',
        '',
        'This folder is restricted to SYSTEM and BUILTIN\Administrators.',
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
        if (-not $hasAdministrators -or -not $hasUsers) {
            throw 'Administrators and Users or Authenticated Users must remain assigned for required network access; no user right was changed.'
        }
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
        else { Invoke-Check $service.Name { Set-SelectedService $service.Name $selected } }
    }
}

function Invoke-RdpDecision {
    if (Test-ServiceProtected 'TermService') { $choice='Y'; Write-Host 'RDP is required; keeping it enabled.' }
    else {
        Write-Warning 'Enable Remote Desktop only when required. Disabling it may disconnect remote access.'
        $choice=Read-YesNo 'Enable RDP, its Remote Desktop service, and its built-in firewall rules?'
    }
    $script:ServiceDecisions['RDP'] = $choice
    if (-not $choice) { Add-Result 'Remote access' 'RDP' 'REVIEW' 'No explicit Y/N decision; RDP was not changed.' 'Run interactively to select Y or N.'; return }
    if ($choice -eq 'N' -and (Test-RemoteSession)) {
        Add-Result 'Remote access' 'RDP' 'REVIEW' 'Remote session detected; disabling RDP was refused.' 'Use the local console to review RDP.'
        return
    }
    $deny = 1; $enabled = 'False'
    if ($choice -eq 'Y') { $deny=0; $enabled='True' }
    Set-RegistryBaseline 'Remote access' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' $deny
    $service = Get-Service -Name 'TermService' -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $script:ServiceDecisions['TermService'] = $choice
        Invoke-Check 'TermService' { Set-SelectedService 'TermService' $choice }
    } else { Add-Result 'Remote access' 'TermService' 'SKIPPED' 'Service is not installed.' '' }
    $port=Get-RdpConfiguredPort
    if ($null -ne $port) {
        Invoke-ExistingServiceFirewall 'RemoteDesktop-UserMode-In-TCP' 'TCP' $port ($enabled -eq 'True')
        Invoke-ExistingServiceFirewall 'RemoteDesktop-UserMode-In-UDP' 'UDP' $port ($enabled -eq 'True')
    }
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
    if ($script:RequiredLogical.ContainsKey('SMB')) { Invoke-ExistingServiceFirewall 'FPS-SMB-In-TCP' 'TCP' 445 $true -VerifyOnly:$VerifyOnly }
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
function Test-PasswordlessAccount {
    param($User)
    if ($null -eq $User -or -not $User.Enabled) { return $false }
    # Guest, DefaultAccount and WDAGUtilityAccount are built-in and normally disabled.
    if ($User.SID.Value -match '-(501|503|504)$') { return $false }
    return (-not $User.PasswordRequired) -or ($null -eq $User.PasswordLastSet)
}
function Invoke-PasswordlessReset {
    param([object[]]$Users=@())
    $exempt = @($PasswordExemptUsers | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
    $targets = @($Users | Where-Object { Test-PasswordlessAccount $_ })
    if (-not $targets.Count) {
        Add-Result Accounts 'Passwordless accounts' PASS 'No enabled local account is missing a password requirement or a password date.' ''
        return
    }
    if ($Apply -and -not $WhatIfPreference -and [string]::IsNullOrWhiteSpace($script:RunDirectory)) {
        Add-Result Accounts 'Passwordless reset' FAILED 'The private run folder is unavailable; refusing to reset passwords without a durable record.' 'Fix the run-folder path or pass -RunRoot to a writable folder, then re-run.'
        return
    }
    foreach ($user in $targets) {
        $name = [string]$user.Name
        $facts = "PasswordRequired=$($user.PasswordRequired); PasswordLastSet=$($user.PasswordLastSet)"
        if ($name -in $exempt) {
            Add-Result Accounts "Passwordless/$name" SKIPPED $facts 'Excluded by -PasswordExemptUsers. Set a password manually or remove the exemption.'
            Add-Ledger 'EXEMPT' "Account/$name" 'Passwordless account left unchanged by -PasswordExemptUsers.'
            continue
        }
        if (-not $Apply) {
            Add-Result Accounts "Passwordless/$name" REVIEW $facts 'Run with -Apply to generate and set a password.'
            continue
        }
        if ($WhatIfPreference -or -not $script:CallerCmdlet.ShouldProcess($name,'Generate and set a password for this passwordless account')) {
            Add-Result Accounts "Passwordless/$name" SKIPPED $facts 'Change suppressed by -WhatIf or ShouldProcess.'
            continue
        }
        try {
            $password = New-ComplexPassword $GeneratedPasswordLength
            $secure = ConvertTo-SecureString $password -AsPlainText -Force
            Set-LocalUser -Name $name -Password $secure -ErrorAction Stop
            Set-LocalUser -Name $name -PasswordNeverExpires $false -ErrorAction Stop
            $after = Get-LocalUser -Name $name -ErrorAction Stop
            if (-not $after.PasswordRequired -or $null -eq $after.PasswordLastSet) { throw 'Readback still reports the account as passwordless.' }
            $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Write-Host "NEW PASSWORD for $name : $password" -ForegroundColor Yellow
            Write-PrivateLine 'Changed-Passwords.txt' "$stamp | $name | $password"
            Add-Ledger 'PASSWORD' "Account/$name" 'Generated and set a password; the previous password was blank or unknown.'
            Add-Result Accounts "Passwordless/$name" CHANGED "$facts; new password applied and verified. Saved in the private run folder." ''
            $script:ResetPasswordAccounts[$name] = $true
        } catch {
            Add-Result Accounts "Passwordless/$name" FAILED $_.Exception.Message 'Set a password manually in Computer Management > Local Users and Groups.'
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
                Set-LocalUser -Name $user.Name -PasswordNeverExpires $false -ErrorAction Stop
                $after = Get-LocalUser -Name $user.Name -ErrorAction Stop
                if ($null -eq $after.PasswordLastSet) { throw 'Readback still reports no password date for this account.' }
                $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                Write-Host "NEW PASSWORD for $($user.Name): $newPassword" -ForegroundColor Yellow
                Write-PrivateLine 'Changed-Passwords.txt' "$stamp | $($user.Name) | $newPassword"
                Add-Ledger 'PASSWORD' "Account/$($user.Name)" 'Known weak password replaced with a generated password.'
                Add-Result Accounts "Known password/$($user.Name)" CHANGED 'Weak supplied password replaced; generated password was printed once and saved in the private run folder.' ''
            } catch {
                Add-Result Accounts "Known password/$($user.Name)" FAILED $_.Exception.Message 'Set the password manually in Computer Management > Local Users and Groups, then verify the account password date.'
            }
        } catch {
            Add-Result Accounts "Known password/$($user.Name)" FAILED $_.Exception.Message 'Enter the password again or change it manually in Computer Management > Local Users and Groups.'
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
    # Every checked subcategory must have both Success and Failure auditing.
    $requirements = @(
        @{Name='Credential Validation';Suffix='923f'},
        @{Name='Logon';Suffix='9215'},
        @{Name='Account Lockout';Suffix='9217'},
        @{Name='User Account Management';Suffix='9235'},
        @{Name='Security Group Management';Suffix='9237'},
        @{Name='Audit Policy Change';Suffix='922f'},
        @{Name='System Integrity';Suffix='9212'},
        @{Name='Process Creation';Suffix='922b'}
    )
    if ($script:IsDomainController) {
        $requirements += @{Name='Kerberos Authentication Service';Suffix='9242'}
        $requirements += @{Name='Kerberos Service Ticket Operations';Suffix='9240'}
    }
    if ($AuditCoverage -eq 'All') {
        $requirements = @($available | ForEach-Object { @{Name=$_.Name;Guid=$_.Guid} })
    } else {
        foreach ($entry in $requirements) { $entry.Guid="{0cce$($entry.Suffix)-69ae-11d9-bed3-505054503030}" }
        $requirements = @($requirements | Where-Object { $_.Guid -in $available.Guid })
    }
    $script:Inventory.AuditCoverage=$AuditCoverage
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
        @('Audit',$lsa,'AuditBaseObjects',1),
        @('Authentication',$lsa,'EveryoneIncludesAnonymous',0),
        @('Logon',$system,'DisableCAD',0),
        @('Logon',$system,'DontDisplayLastUserName',1),
        @('Logon',$system,'ForceUnlockLogon',1),
        @('Logon',$system,'MaxDevicePasswordFailedAttempts',5),
        @('UAC',$system,'EnableLUA',1),
        @('UAC',$system,'PromptOnSecureDesktop',1),
        @('UAC',$system,'ConsentPromptBehaviorAdmin',2),
        @('Devices',$system,'UndockWithoutLogon',0),
        @('AutoRun','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoDriveTypeAutoRun',255),
        @('AutoRun','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoAutorun',1),
        @('AutoRun','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoAutoplayfornonVolume',1),
        @('Installer','HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated',0),
        @('Installer','HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated',0)
    )) { Set-RegistryBaseline $setting[0] $setting[1] $setting[2] $setting[3] }
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
    Set-RegistryBaseline 'Remote Assistance' 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' fAllowToGetHelp 0
    Set-RegistryBaseline Logon 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' CachedLogonsCount '1' -Type String
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $autoLogon = Get-RegistryState $winlogon AutoAdminLogon
    $savedPassword = Get-RegistryState $winlogon DefaultPassword
    if ($autoLogon.Value -eq '1' -or $savedPassword.Exists) {
        Add-Result Logon 'Automatic logon / stored credential' REVIEW 'AutoAdminLogon is enabled or DefaultPassword exists. Credential value is deliberately omitted.' 'Review requirements; remove stored credentials manually. Never include their contents in reports.'
    }
}
function Invoke-DefenderAudit {
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { Add-Result Defender 'Availability' REVIEW 'Defender cmdlets are unavailable.' 'Verify the approved antivirus and any passive mode.'; return }
    $status = Get-MpComputerStatus -ErrorAction Stop
    $script:Inventory.Defender = $status | Select-Object AntivirusEnabled,AMRunningMode,RealTimeProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureLastUpdated,IsTamperProtected
    $mode = Get-OptionalProperty $status AMRunningMode ''
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
    Invoke-Setting SMB 'SMB1 optional feature' {
        $features = @(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop)
        -not ($features | Where-Object { $_.State -ne 'Disabled' })
    } {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
    } 'SMB1 optional feature should be disabled. Restart may be required for full removal from service.' 'Preserve SMB2/3 and required shares.'
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
function Test-CyberPatriotShare {
    param([string]$Name, [string]$Path='')
    return $Name -in @('AFA','AFA$','CyberPatriot','CyberPatriot$') -or
        $Path -match '^[A-Za-z]:\\(AFA|CyberPatriot)(\\|$)'
}
function Test-ProtectedShare {
    param([string]$Name, [string]$Path='')
    return (Test-CyberPatriotShare -Name $Name -Path $Path) -or
        $Name -in @('ADMIN$','IPC$','SYSVOL','NETLOGON') -or $Name -match '^[A-Za-z]\$$'
}
function Invoke-ShareDecisions {
    $shares=@(Get-SmbShare -IncludeHidden -ErrorAction Stop)
    foreach ($share in @($shares | Where-Object { Test-CyberPatriotShare -Name $_.Name -Path $_.Path })) {
        Add-Result Shares "$($share.Name) protected" PASS "CyberPatriot share retained at $($share.Path)." ''
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
            $_.ScopeName -eq '*' -and -not (Test-ProtectedShare -Name $_.Name -Path $_.Path)
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
            Add-Result Shares $name REVIEW 'A required, CyberPatriot, or administrative share was retained.' 'This script will not remove that share.'
            continue
        }
        $target=@($shares | Where-Object { $_.Name -eq $name })
        if ($target.Count -eq 0) { Add-Result Shares "$name removed" PASS 'The share is absent.' ''; Write-Host "$name is already unshared." -ForegroundColor Green; continue }
        if (Test-ProtectedShare -Name $target[0].Name -Path $target[0].Path) {
            Add-Result Shares $name REVIEW 'A protected CyberPatriot or administrative share was retained.' 'This script will not remove that share.'
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
            if ($currentTarget.Count -eq 1 -and (Test-ProtectedShare -Name $currentTarget[0].Name -Path $currentTarget[0].Path)) {
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
        -not (Test-ProtectedShare -Name $_.Name -Path $_.Path)
    })
    if ($ordinary.Count) {
        Add-Result Shares 'Remaining ordinary shares' REVIEW (($ordinary | ForEach-Object { "$($_.Name)=$($_.Path)" }) -join '; ') 'Compare these shares with the README. A trailing $ does not make a share administrative.'
    }
}
function Invoke-FirewallAudit {
    foreach ($firewallProfile in Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop) {
        $name = [string]$firewallProfile.Name
        Invoke-Setting Firewall "$name profile enabled" { (Get-NetFirewallProfile -Name $name -PolicyStore ActiveStore -ErrorAction Stop).Enabled -eq 'True' } {
            Set-NetFirewallProfile -Profile $name -Enabled True -ErrorAction Stop
        } "Current=$($firewallProfile.Enabled). Existing allow rules are preserved." 'Verify required-service rules at the local console before apply; firewall changes are manual in remote sessions.' -Manual:(Test-RemoteSession)
        Invoke-Setting Firewall "$name inbound default" { (Get-NetFirewallProfile -Name $name -PolicyStore ActiveStore -ErrorAction Stop).DefaultInboundAction -eq 'Block' } {
            Set-NetFirewallProfile -Profile $name -DefaultInboundAction Block -ErrorAction Stop
        } "Current=$($firewallProfile.DefaultInboundAction). Default inbound should be Block." 'Retain necessary allow rules at the local console; governing GPO may override local settings. Remote-session changes remain manual.' -Manual:(Test-RemoteSession)
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
function Get-ServerInventory {
    $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath)
    # Command lines may contain credentials; deliberately collect paths and PIDs only.
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
        Add-Result Backdoor 'Netcat/backdoor scan' PASS 'No running process and no System32/SysWOW64 file matched the netcat family (nc, ncat, netcat, mfc, nc64, cryptcat).' ''
        return
    }
    $script:Inventory.BackdoorCandidates = $candidates
    foreach ($candidate in $candidates) {
        $label = "$($candidate.Name) PID=$($candidate.PID) path=$($candidate.Path) signature=$($candidate.Signature)"
        if ($candidate.Signature -eq 'Valid Microsoft signature') {
            Add-Result Backdoor 'Signed Microsoft candidate' REVIEW $label 'A valid Microsoft-signed binary was not stopped or removed; confirm the scenario before changing it.'
            continue
        }
        if (-not $Apply) {
            Add-Result Backdoor 'Backdoor candidate' REVIEW "$label; listeners=$($candidate.Ports)" 'Run with -Apply interactively and answer Y to stop and quarantine this file.'
            continue
        }
        if ($WhatIfPreference) {
            Add-Result Backdoor 'Backdoor candidate' SKIPPED $label 'Change suppressed by -WhatIf.'
            continue
        }
        if ($NonInteractive) {
            Add-Result Backdoor 'Backdoor candidate' REVIEW $label 'NonInteractive mode will not stop or delete a file. Resolve this manually or run interactively.'
            continue
        }
        $answer = Read-YesNo "Stop and quarantine $($candidate.Name) at $($candidate.Path)?"
        if ($answer -eq 'N') {
            Add-Result Backdoor "Backdoor/$($candidate.Name)" SKIPPED $label 'Left unchanged by operator decision.'
            Add-Ledger 'BACKDOOR' "File/$($candidate.Path)" 'Operator answered N; no change.'
            continue
        }
        if ($answer -ne 'Y') {
            Add-Result Backdoor "Backdoor/$($candidate.Name)" REVIEW $label 'No valid Y/N answer was received; the process and file were left unchanged.'
            Add-Ledger 'BACKDOOR' "File/$($candidate.Path)" 'No valid Y/N answer; no change.'
            continue
        }
        if ($WhatIfPreference -or -not $script:CallerCmdlet.ShouldProcess($candidate.Path,'Stop the process, quarantine the file, and delete the original')) {
            Add-Result Backdoor "Backdoor/$($candidate.Name)" SKIPPED 'Change was not approved by ShouldProcess.' 'Re-run without -WhatIf and answer Y.'
            continue
        }
        try {
            if ([string]::IsNullOrWhiteSpace($script:RunDirectory)) { throw 'The private run folder is unavailable; refusing to delete without a quarantine copy.' }
            $path = [string]$candidate.Path
            if ([string]::IsNullOrWhiteSpace($path)) { throw 'No executable path was returned; stop the process and locate the file manually.' }
            $hash = ''
            if (Test-Path -LiteralPath $path -PathType Leaf) { $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash }
            $stamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
            $quarantineName = "$stamp-$($candidate.Name)"
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
            Add-Result Backdoor "Backdoor/$($candidate.Name)" CHANGED "Process stopped (if running); file copied to $quarantinePath, hash verified, and original deleted." ''
            Write-Host "QUARANTINED $path -> $quarantinePath" -ForegroundColor Yellow
        } catch {
            Add-Result Backdoor "Backdoor/$($candidate.Name)" FAILED $_.Exception.Message 'Stop the process and remove the file manually, or resolve the ACL/ownership problem and re-run.'
        }
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
    foreach ($key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run') {
        if (-not (Test-Path -LiteralPath $key)) { continue }
        $item = Get-Item -LiteralPath $key -ErrorAction Stop
        foreach ($name in $item.GetValueNames()) { Add-Result Persistence "Run entry $name" REVIEW "Registry location: $key" 'Inspect its command and publisher locally; commands are omitted to avoid exposing credentials. Removal is manual.' }
    }
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
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })
    $script:Inventory.ScheduledTasks = @($tasks | Select-Object TaskName,TaskPath,State)
    if ($tasks.Count) { Add-Result Persistence 'Tasks outside Microsoft namespace' REVIEW (($tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }) -join '; ') 'Review actions, triggers, principal, and signatures. Namespace alone does not establish trust; inspect Microsoft tasks too if evidence warrants.' }
    $updatePolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $wsus = Get-RegistryState $updatePolicy WUServer
    Set-RegistryBaseline Updates "$updatePolicy\AU" NoAutoUpdate 0
    if ($wsus.Exists) { Add-Result Updates 'WSUS update source' REVIEW "WSUS configured=$($wsus.Exists)" 'Verify the legitimate update source/GPO. WSUS is not inherently malicious; it is preserved.' }
    $script:Inventory.Hotfixes = @(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID,InstalledOn)
    Add-Result Updates 'OS and required applications' REVIEW 'Installed hotfixes and application versions are collected; availability is not checked online.' 'Check Windows Update and official required-application updates under current round instructions; downloads and restarts are manual.'
    foreach ($certificate in Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop) {
        if ($certificate.NotAfter -lt (Get-Date)) { Add-Result Certificates 'Expired personal certificate' REVIEW "$($certificate.Subject); expires=$($certificate.NotAfter); thumbprint=$($certificate.Thumbprint)" 'Check whether a required service uses it; renew only the relevant certificate. No trust store is modified.' }
    }
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { $script:Inventory.BitLocker = @(Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod) }
    $logSizes = [ordered]@{Security=$SecurityLogSizeKB; Application=$ApplicationLogSizeKB; System=$SystemLogSizeKB}
    foreach ($log in $logSizes.Keys) {
        $requiredBytes = [int64]$logSizes[$log] * 1024
        $configuration = Get-WinEvent -ListLog $log -ErrorAction Stop
        Invoke-Setting 'Event logs' $log {
            $current=Get-WinEvent -ListLog $log -ErrorAction Stop
            $current.IsEnabled -and $current.MaximumSizeInBytes -ge $requiredBytes
        } {
            Invoke-Native wevtutil.exe @('sl',$log,'/e:true',"/ms:$requiredBytes") | Out-Null
        } "Enabled=$($configuration.IsEnabled); max=$($configuration.MaximumSizeInBytes) bytes; required max>=$requiredBytes." 'Increase log capacity while preserving existing events. All-failure auditing needs the Security log headroom.'
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
        @{Name='signon.management.page.breach-alerts.enabled';Value=$true},
        @{Name='privacy.donottrackheader.enabled';Value=$true},
        @{Name='network.cookie.cookieBehavior';Value=1},
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
    } 'Firefox Safe Browsing, breach alerts, Do Not Track, add-on install warning, and OCSP preferences must be enabled and locked.' 'Merge the protection preferences into the documented Preferences registry JSON, then verify about:policies.'
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
        @($firefox,'AppAutoUpdate',1),@($firefox,'DisableAppUpdate',0),@($firefox,'HttpsOnlyMode','force_enabled','String'),
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
    Add-Result Browsers 'Automatic updates and browser security baseline' PASS 'Chrome/Chromium/Edge/Firefox machine policies were checked for automatic updates, third-party cookie blocking, pop-up blocking, password-manager disablement, Safe Browsing/SmartScreen, Do Not Track, OCSP/revocation, tracking protection, and HTTPS-only mode. Windows SmartScreen, PUA blocking, site/download prompt override prevention, IE PhishingFilter override prevention, and Edge SmartScreen DNS reputation checks are also enforced. JavaScript-disabling policy was not written or changed.' ''
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
}


function Resolve-TextReportPath {
    param([string]$Path)
    $extension = [IO.Path]::GetExtension($Path)
    if ($extension -in @('.json','.csv')) {
        $Path = [IO.Path]::ChangeExtension($Path,'.txt')
        Write-Warning "V2 writes plain text only; report path changed to $Path"
    }
    return $Path
}
function Export-CYPatReportText {
    param([string]$Path,[string]$Mode,[object]$Report)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('============================================================')
    $lines.Add('CYPat Server 2022 Enforcer V2')
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
    if ($Report.Inventory -and $Report.Inventory.Contains('Applications')) { $lines.Add("  Applications        : $(@($Report.Inventory['Applications']).Count)") }
    if ($Report.Inventory -and $Report.Inventory.Contains('ScheduledTasks')) { $lines.Add("  Non-Microsoft tasks : $(@($Report.Inventory['ScheduledTasks']).Count)") }
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
    if ($Report.Inventory -and $Report.Inventory.Contains('ScheduledTasks')) {
        $taskInventory = @($Report.Inventory['ScheduledTasks'])
        $lines.Add('')
        $lines.Add("SCHEDULED TASKS OUTSIDE \Microsoft ($($taskInventory.Count))")
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
    if ($Report.Inventory -and $Report.Inventory.Contains('Defender') -and $null -ne $Report.Inventory['Defender']) {
        $lines.Add('')
        $lines.Add('DEFENDER')
        foreach ($property in $Report.Inventory['Defender'].PSObject.Properties) { $lines.Add("  $($property.Name) = $($property.Value)") }
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
$mode=if ($Apply) {'APPLY'} else {'AUDIT'}
Write-Host "CYPat Enforcer V2 | $($os.Caption) | $mode" -ForegroundColor Cyan
Write-Host 'Read the image README and answer forensics before applying changes. Service answers use that README.' -ForegroundColor Yellow
if ($os.ProductType -eq 1) { Add-Result Platform 'Windows client detected' REVIEW $os.Caption 'This tool targets Windows Server. Server-role commands may be unavailable; test on the intended image.' }
if ($script:IsDomainJoined) { Add-Result 'Group Policy' 'Domain policy' REVIEW "Domain=$($computer.Domain); controller=$script:IsDomainController" 'Use gpresult /r and the governing GPO to verify effective settings. Domain password policy is never changed automatically.' }
if (-not $WhatIfPreference) {
    Invoke-Check 'Private run folder' {
        $run = Initialize-PrivateRun -Root $RunRoot
        Write-Host "Private plain-text run folder: $run" -ForegroundColor Cyan
    }
}

Write-Host 'Collecting processes, listening ports, and software before any changes...' -ForegroundColor Cyan
Invoke-Check 'Initial inventory' { Get-ServerInventory }
$smbDeclared=@($RequiredServices | Where-Object { $_ -in @('SMB','LanmanServer') }).Count -gt 0
if ($RequiredShares.Count -and -not $smbDeclared) {
    $RequiredServices=@($RequiredServices) + @('SMB')
    Write-Host 'SMB is protected because a required share was specified.' -ForegroundColor Cyan
}
$serverBeforeShares=Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
$script:ShareReviewInitialStatus=if ($null -ne $serverBeforeShares) { [string]$serverBeforeShares.Status } else { '' }
$script:ShareReviewInitialStartMode=if ($null -ne $serverBeforeShares) { Get-ServiceStartMode $serverBeforeShares } else { '' }
$script:ShareReviewAttemptedServerStart=$false
$requiredDisplay = if ($RequiredServices.Count) { $RequiredServices -join ', ' } else { 'none selected; use -RequiredServices after reading README' }
Write-Host "Required services (protected): $requiredDisplay" -ForegroundColor Cyan
Invoke-Check 'Required service protection' { Initialize-RequiredServices }
Invoke-Check Accounts { Invoke-AccountAudit }
if ($RemoveEveryoneNetworkLogonRight) {
    Invoke-Check 'Network logon right' { Invoke-NetworkLogonRightDecision }
} else {
    Invoke-Check 'Network logon right' {
        $principals=@(Get-NetworkLogonPrincipals)
        if (@($principals | Where-Object { $_ -match '^(\*?S-1-1-0|Everyone)$' }).Count -eq 0) {
            Add-Result 'User rights' 'SeNetworkLogonRight without Everyone' PASS 'Everyone is not assigned this right.' ''
        } else {
            Add-Result 'User rights' 'SeNetworkLogonRight without Everyone' SKIPPED 'Everyone is assigned this right; removal was not selected.' 'Pass -RemoveEveryoneNetworkLogonRight only when the image does not require Everyone to access this computer over the network.'
        }
    }
}
Invoke-Check 'Security policy and rights' { Invoke-SecurityPolicyAudit }
Invoke-Check 'Registry security' { Invoke-RegistryAudit }
Invoke-Check 'Effective auditing' { Invoke-AuditPolicyAudit }
Invoke-Check Defender { Invoke-DefenderAudit }
Invoke-Check 'SMB share readiness' { Invoke-ShareServicePreparation }
$serverService=Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
try {
    if ($null -ne $serverService -and $serverService.Status -eq 'Running') {
        Invoke-Check SMB { Invoke-SmbAudit }
        Invoke-Check 'Required and selected shares' { Invoke-ShareDecisions }
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
    $rdpPolicy='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    foreach ($name in 'UserAuthentication','MinEncryptionLevel','fDenyTSConnections') {
        $state=Get-RegistryState $rdpPolicy $name
        if ($state.Exists) { Add-Result RDP "GPO/$name" REVIEW "Policy value=$($state.Value)" 'Verify effective RDP behavior and the governing GPO; local listener settings may be overridden.' }
    }
}
$serviceChoices=@(
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
    @{Label='OpenSSH server';Names=@('sshd');Warning='May provide required remote administration; keep if needed.'},
    @{Label='SNMP';Names=@('SNMP','SNMPTRAP');Warning='May support required monitoring; check authorized managers and community strings.'},
    @{Label='Routing and Remote Access';Names=@('RemoteAccess');Warning='May support a required VPN or routing role.'},
    @{Label='Gaming and retail demo services';Names=@('XblAuthManager','XblGameSave','XboxGipSvc','XboxNetApiSvc','GamingServices','GamingServicesNet','RetailDemo');Warning='Usually unnecessary on Server images; keep only if the README explicitly requires them.'},
    @{Label='Windows Update';Names=@('wuauserv');Warning='Needed for patching. Choosing Y changes service state only; no update download or installation is started.'}
)
foreach ($choice in $serviceChoices) { Invoke-Check $choice.Label { Invoke-ServiceDecision -Label $choice.Label -Names $choice.Names -Warning $choice.Warning } }
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
Invoke-Check 'Netcat/backdoor decision' { Invoke-BackdoorDecision }
Invoke-Check Browsers { Invoke-BrowserAudit }
Invoke-Check 'Final required-service verification' { Invoke-RequiredServicesVerification }

$report=[pscustomobject]@{
    Version='2';Time=(Get-Date).ToString('o');Mode=$mode
    Computer=$script:Inventory.Computer;RequiredServices=$RequiredServices;RequiredShares=$RequiredShares;KeepShares=$KeepShares;RemoveShares=$RemoveShares
    RemoveEveryoneNetworkLogonRight=$script:NetworkRightRemovalSelected;ProtectedServices=$script:ProtectedServices;ServiceDecisions=$script:ServiceDecisions
    Results=@($script:Results);Inventory=$script:Inventory
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
Write-Host 'Configuration readback verifies these checks only; rerun audit and check scoring/required services after changes.' -ForegroundColor Cyan
if ($PassThru) { $report.Results=@($script:Results); Write-Output $report }
