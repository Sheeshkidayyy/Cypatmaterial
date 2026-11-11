# CYPat Enforcer V1 2022- Full Security & Audit Script (Success-only audit for Logon/Logoff + Credential Validation Failures + Remote Assistance disabled + Defender enabled + FTP disabled + classic Windows Update + LimitBlankPasswordUse + more) with y/n checks
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
    [ValidateRange(12,14)][int]$MinimumPasswordLength=12,
    [ValidateRange(1,24)][int]$PasswordHistory=20,
    [ValidateRange(0,998)][int]$MinimumPasswordAge=5,
    [ValidateRange(1,999)][int]$MaximumPasswordAge=30,
    [ValidateRange(5,50)][int]$LockoutThreshold=5,
    [ValidateRange(1,99999)][int]$LockoutMinutes=60,
    [ValidateRange(10,128)][int]$KnownPasswordMinimumLength=10,
    [ValidateRange(12,128)][int]$GeneratedPasswordLength=18,
    [string[]]$AuthorizedUsers=@(),
    [string[]]$AuthorizedAdministrators=@(),
    [string]$ReportPath='',
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
$script:ServiceDecisions=[ordered]@{}
$script:Inventory=[ordered]@{}
$script:ProtectedServices=@{}
$script:HasUserAllowlist=$PSBoundParameters.ContainsKey('AuthorizedUsers')
$script:HasAdminAllowlist=$PSBoundParameters.ContainsKey('AuthorizedAdministrators')
$script:NetworkRightRemovalSelected=[bool]$Apply
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
    Write-Warning 'No valid Y/N answer was received; this service decision was left unchanged.'
    return $null
}

function Test-RemoteSession {
    $sender = Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue
    return ($env:SESSIONNAME -like 'RDP*') -or ($null -ne $sender -and $null -ne $sender.Value)
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
    $sender = Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue
    if ($Choice -eq 'N' -and $Name -eq 'WinRM' -and $null -ne $sender -and $null -ne $sender.Value) {
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
    $sender=Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue
    if ([Environment]::UserInteractive -and ($null -eq $sender -or $null -eq $sender.Value)) {
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
function Invoke-KnownPasswordWorkflow {
    param([object[]]$Users)
    if ($SkipKnownPasswordCheck) { Add-Result Accounts 'Known password check' SKIPPED 'Skipped by -SkipKnownPasswordCheck.' ''; return }
    if ($NonInteractive) {
        Add-Result Accounts 'Known password check' REVIEW 'NonInteractive mode cannot ask for README-known/current passwords.' 'Run interactively to enter known weak passwords, or change known weak passwords manually.'
        return
    }
    $targets=@($Users | Where-Object { $_.Enabled -and $_.SID.Value -notmatch '-(500|501|503|504)$' })
    if (-not $targets.Count) { return }
    Write-Host 'Known-password check: enter only README-listed or otherwise known passwords. Paste into the credential dialog; cancel it to skip an unknown account. Console fallback accepts a blank answer to skip.' -ForegroundColor Yellow
    foreach ($user in $targets) {
        $secure = Read-KnownPassword -UserName $user.Name
        $plain = ConvertFrom-SecureStringToPlainText $secure
        try {
            if ([string]::IsNullOrEmpty($plain)) { continue }
            if (Test-PasswordComplexity $plain $KnownPasswordMinimumLength) {
                Add-Result Accounts "Known password/$($user.Name)" PASS 'Supplied known password meets the configured complexity floor.' ''
                continue
            }
            if (-not $Apply) {
                Add-Result Accounts "Known password/$($user.Name)" REVIEW 'Supplied known password is weak.' 'In apply mode, this script generates and sets a complex replacement.'
                continue
            }
            $newPassword = New-ComplexPassword $GeneratedPasswordLength
            $secureNew = ConvertTo-SecureString $newPassword -AsPlainText -Force
            Set-LocalUser -Name $user.Name -Password $secureNew -ErrorAction Stop
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $false -ErrorAction Stop
            Write-Host "NEW PASSWORD for $($user.Name): $newPassword" -ForegroundColor Yellow
            Add-Result Accounts "Known password/$($user.Name)" CHANGED 'Weak supplied password replaced; generated password was printed once and is not stored in JSON evidence.' ''
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
    if ($script:HasUserAllowlist) {
        $unknown = @($candidates | Where-Object { $_.Name -notin $AuthorizedUsers -and $_.Name -notin $AuthorizedAdministrators })
        if ($unknown.Count) { Add-Result Accounts 'Not in supplied allowlist' REVIEW ($unknown.Name -join ', ') 'Confirm service/system accounts and the README before removing any account.' }
        else { Add-Result Accounts 'User allowlist' PASS 'All ordinary accounts match the supplied lists.' '' }
    } else {
        Add-Result Accounts 'Authorization' REVIEW (($candidates | ForEach-Object { "$($_.Name) (enabled=$($_.Enabled))" }) -join ', ') 'Compare with README; supply -AuthorizedUsers and -AuthorizedAdministrators to narrow future output. Review known weak passwords manually.'
    }
    foreach ($user in $users | Where-Object Enabled) {
        $machineUser = $cimUsers | Where-Object SID -eq $user.SID.Value | Select-Object -First 1
        $facts = [System.Collections.Generic.List[string]]::new()
        if ($user.SID.Value -match '-501$') { $facts.Add('Built-in Guest is enabled') }
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
function Invoke-SecurityPolicyAudit {
    $policy = Get-SecurityPolicy
    $script:Inventory.SecurityPolicy = $policy
    if (-not $policy.ContainsKey('System Access')) {
        Add-Result 'Account policy' 'Export incomplete' FAILED "Security policy export lacks System Access. Sections returned: $($policy.Keys -join ', ')." 'Run the saved .ps1 from elevated Windows PowerShell. Inspect secpol.msc and net accounts locally; no account-policy changes were attempted. Send this diagnostic if it persists.'
    } else {
        $baseline = @{MinimumPasswordLength=$MinimumPasswordLength;PasswordHistorySize=$PasswordHistory;MinimumPasswordAge=$MinimumPasswordAge;MaximumPasswordAge=$MaximumPasswordAge;PasswordComplexity=1;ClearTextPassword=0;LockoutBadCount=$LockoutThreshold;LockoutDuration=$LockoutMinutes;ResetLockoutCount=$LockoutMinutes}
        $plan = Get-AccountPolicyPlan $policy['System Access'] $baseline
        foreach ($issue in $plan.Issues) { Add-Result 'Account policy' 'Policy exception' REVIEW $issue 'Review in secpol.msc or the governing domain GPO.' }
        if ($plan.Delta.Count) { Invoke-LocalAccountPolicy -Baseline $plan.Delta }
        elseif (-not $plan.Issues.Count) { Add-Result 'Account policy' 'Password and lockout baseline' PASS 'Current exported settings meet or exceed the selected baseline.' '' }
    }
    if ($policy.ContainsKey('Privilege Rights')) {
        $rights = $policy['Privilege Rights']
        foreach ($name in 'SeNetworkLogonRight','SeRemoteInteractiveLogonRight','SeDebugPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege') {
            if (-not $rights.ContainsKey($name)) { continue }
            $assignment = [string]$rights[$name]
            if ($assignment -match '(^|,)\s*\*?S-1-1-0\s*(,|$)|(^|,)\s*Everyone\s*(,|$)') {
                Add-Result 'User rights' $name REVIEW $assignment 'Everyone has this right. Remove only that principal after confirming required groups and domain GPO; never replace the full list blindly.'
            } elseif ($name -eq 'SeNetworkLogonRight') {
                Add-Result 'User rights' $name PASS "Everyone is absent. Assigned principals: $assignment" ''
            } elseif ($name -eq 'SeRemoteInteractiveLogonRight') {
                Add-Result 'User rights' $name REVIEW $assignment 'Verify these SIDs/groups are authorized for network or RDP logon. Account for deny rights and GPO overrides.'
            } else { Add-Result 'User rights' $name PASS 'Everyone is not assigned this privilege; detailed assignments are in optional JSON.' '' }
        }
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
    if (-not $available.Count) { throw 'Windows returned no audit subcategories; no audit policy changes were attempted.' }
    Set-RegistryBaseline 'Audit policy' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' SCENoApplyLegacyAuditPolicy 1
    # Numeric coverage avoids localized auditpol output. 1=Success, 2=Failure.
    $requirements = @(
        @{Name='Credential Validation';Suffix='923f';Mask=3},
        @{Name='Logon';Suffix='9215';Mask=3},
        @{Name='Account Lockout';Suffix='9217';Mask=2},
        @{Name='User Account Management';Suffix='9235';Mask=3},
        @{Name='Security Group Management';Suffix='9237';Mask=3},
        @{Name='Audit Policy Change';Suffix='922f';Mask=3},
        @{Name='System Integrity';Suffix='9212';Mask=3},
        @{Name='Process Creation';Suffix='922b';Mask=1}
    )
    if ($script:IsDomainController) {
        $requirements += @{Name='Kerberos Authentication Service';Suffix='9242';Mask=3}
        $requirements += @{Name='Kerberos Service Ticket Operations';Suffix='9240';Mask=3}
    }
    if ($AuditCoverage -eq 'All') {
        $requirements = @($available | ForEach-Object { @{Name=$_.Name;Guid=$_.Guid;Mask=3} })
    } else {
        foreach ($entry in $requirements) { $entry.Guid="{0cce$($entry.Suffix)-69ae-11d9-bed3-505054503030}" }
        $requirements = @($requirements | Where-Object { $_.Guid -in $available.Guid })
    }
    $script:Inventory.AuditCoverage=$AuditCoverage
    $script:Inventory.AuditSubcategories=@($requirements | ForEach-Object { [pscustomobject]@{Name=$_.Name;Guid=$_.Guid;RequiredMask=$_.Mask} })
    foreach ($requirement in $requirements) {
        $guid = [string]$requirement.Guid; $mask = [int]$requirement.Mask
        $arguments = @('/set',"/subcategory:$guid")
        if ($mask -band 1) { $arguments += '/success:enable' }
        if ($mask -band 2) { $arguments += '/failure:enable' }
        Invoke-Setting 'Audit policy' $requirement.Name { Test-AuditCoverage (Get-AuditMask $guid) $mask } {
            Invoke-Native auditpol.exe $arguments | Out-Null
        } "Required coverage mask=$mask (1=Success,2=Failure)." 'Configure the governing GPO if effective readback does not match.'
    }
}
function Invoke-RegistryAudit {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $system = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    foreach ($setting in @(
        @('Authentication',$lsa,'LimitBlankPasswordUse',1),
        @('Authentication',$lsa,'NoLMHash',1),
        @('Authentication',$lsa,'RestrictAnonymousSAM',1),
        @('Authentication',$lsa,'EveryoneIncludesAnonymous',0),
        @('Logon',$system,'DisableCAD',0),
        @('UAC',$system,'EnableLUA',1),
        @('UAC',$system,'PromptOnSecureDesktop',1),
        @('UAC',$system,'ConsentPromptBehaviorAdmin',2),
        @('AutoRun','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoDriveTypeAutoRun',255),
        @('AutoRun','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoAutorun',1),
        @('AutoRun','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoAutoplayfornonVolume',1),
        @('Installer','HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated',0),
        @('Installer','HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated',0)
    )) { Set-RegistryBaseline $setting[0] $setting[1] $setting[2] $setting[3] }
    Set-RegistryBaseline 'Legacy authentication' $lsa LmCompatibilityLevel 5
    Set-RegistryBaseline 'Legacy authentication' "$lsa\MSV1_0" NtlmMinClientSec 537395200
    Set-RegistryBaseline 'Legacy authentication' "$lsa\MSV1_0" NtlmMinServerSec 537395200
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
    foreach ($profile in Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop) {
        $name = [string]$profile.Name
        Invoke-Setting Firewall "$name profile enabled" { (Get-NetFirewallProfile -Name $name -PolicyStore ActiveStore -ErrorAction Stop).Enabled -eq 'True' } {
            Set-NetFirewallProfile -Profile $name -Enabled True -ErrorAction Stop
        } "Current=$($profile.Enabled). Existing allow rules are preserved." 'Verify required-service rules at the local console before apply; firewall changes are manual in remote sessions.' -Manual:(Test-RemoteSession)
        Invoke-Setting Firewall "$name inbound default" { (Get-NetFirewallProfile -Name $name -PolicyStore ActiveStore -ErrorAction Stop).DefaultInboundAction -eq 'Block' } {
            Set-NetFirewallProfile -Profile $name -DefaultInboundAction Block -ErrorAction Stop
        } "Current=$($profile.DefaultInboundAction). Default inbound should be Block." 'Retain necessary allow rules at the local console; governing GPO may override local settings. Remote-session changes remain manual.' -Manual:(Test-RemoteSession)
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
    $blocked = Get-RegistryState "$updatePolicy\AU" NoAutoUpdate
    Set-RegistryBaseline Updates "$updatePolicy\AU" NoAutoUpdate 0
    if ($wsus.Exists) { Add-Result Updates 'WSUS update source' REVIEW "WSUS configured=$($wsus.Exists)" 'Verify the legitimate update source/GPO. WSUS is not inherently malicious; it is preserved.' }
    $script:Inventory.Hotfixes = @(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID,InstalledOn)
    Add-Result Updates 'OS and required applications' REVIEW 'Installed hotfixes and application versions are collected; availability is not checked online.' 'Check Windows Update and official required-application updates under current round instructions; downloads and restarts are manual.'
    foreach ($certificate in Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop) {
        if ($certificate.NotAfter -lt (Get-Date)) { Add-Result Certificates 'Expired personal certificate' REVIEW "$($certificate.Subject); expires=$($certificate.NotAfter); thumbprint=$($certificate.Thumbprint)" 'Check whether a required service uses it; renew only the relevant certificate. No trust store is modified.' }
    }
    if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { $script:Inventory.BitLocker = @(Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod) }
    foreach ($log in 'Security','System','Application') {
        $configuration = Get-WinEvent -ListLog $log -ErrorAction Stop
        Invoke-Setting 'Event logs' $log {
            $current=Get-WinEvent -ListLog $log -ErrorAction Stop
            $current.IsEnabled -and $current.MaximumSizeInBytes -ge 64MB
        } {
            Invoke-Native wevtutil.exe @('sl',$log,'/e:true','/ms:67108864') | Out-Null
        } "Enabled=$($configuration.IsEnabled); max=$($configuration.MaximumSizeInBytes) bytes; required max>=67108864." 'Increase log capacity while preserving existing events.'
    }
}
function Invoke-BrowserAudit {
    $known = @($script:Inventory.Applications | Where-Object DisplayName -match 'Firefox|Google Chrome|Microsoft Edge')
    foreach ($browser in 'Firefox','Chrome','Edge') {
        if (-not ($known | Where-Object DisplayName -match $browser)) { continue }
        $key = switch ($browser) { 'Firefox' {'HKLM:\SOFTWARE\Policies\Mozilla\Firefox'}; 'Chrome' {'HKLM:\SOFTWARE\Policies\Google\Chrome'}; 'Edge' {'HKLM:\SOFTWARE\Policies\Microsoft\Edge'} }
        Set-RegistryBaseline Browsers $key PasswordManagerEnabled 0 -Manual
    }
    foreach ($profile in Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and $_.LocalPath }) {
        $root = [string]$profile.LocalPath
        $firefox = Join-Path $root 'AppData\Roaming\Mozilla\Firefox\Profiles'
        if (Test-Path -LiteralPath $firefox) {
            foreach ($directory in Get-ChildItem -LiteralPath $firefox -Directory -ErrorAction Stop) {
                $jsonPath = Join-Path $directory.FullName 'extensions.json'
                if (-not (Test-Path -LiteralPath $jsonPath)) { continue }
                try {
                    $document = Get-Content -LiteralPath $jsonPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    $addons = @(Get-OptionalProperty $document addons @() | Where-Object { (Get-OptionalProperty $_ type) -eq 'extension' -and -not (Get-OptionalProperty $_ isSystem $false) })
                    if ($addons.Count) { Add-Result Browsers 'Firefox extensions' REVIEW "$jsonPath : $(($addons | ForEach-Object { Get-OptionalProperty $_ id }) -join ', ')" 'Confirm extensions against README; review about:addons and effective about:policies.' }
                } catch { Add-Result Browsers 'Firefox extension inventory' REVIEW $_.Exception.Message 'Inspect the profile manually.' }
            }
        }
        foreach ($relative in 'AppData\Local\Google\Chrome\User Data','AppData\Local\Microsoft\Edge\User Data') {
            $data = Join-Path $root $relative
            if (-not (Test-Path -LiteralPath $data)) { continue }
            foreach ($directory in Get-ChildItem -LiteralPath $data -Directory -ErrorAction Stop | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }) {
                $extensions = Join-Path $directory.FullName 'Extensions'
                if (Test-Path -LiteralPath $extensions) {
                    $ids = @(Get-ChildItem -LiteralPath $extensions -Directory -ErrorAction Stop | Select-Object -ExpandProperty Name)
                    if ($ids.Count) { Add-Result Browsers 'Chromium extensions' REVIEW "$extensions : $($ids -join ', ')" 'Confirm installed IDs and publishers in the browser; policies and extension removals are manual.' }
                }
            }
        }
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
        foreach ($profile in $Profiles) {
            foreach ($relative in $definition.UserFiles) {
                $candidate = Join-Path $profile.LocalPath $relative
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
    foreach ($profile in $Profiles) {
        $root = [string]$profile.LocalPath
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
    Set-BrowserPolicy 'HKLM:\SOFTWARE\Policies\Google\Update' UpdateDefault 1
    Set-BrowserPolicy 'HKLM:\SOFTWARE\Policies\Google\Update' 'Update{8A69D345-D564-463C-AFF1-A69D9E530F96}' 1
    foreach ($path in 'HKLM:\SOFTWARE\Policies\Google\Chrome','HKLM:\SOFTWARE\Policies\Chromium') {
        Set-BrowserPolicy $path PasswordManagerEnabled 0
        Set-BrowserPolicy $path SafeBrowsingProtectionLevel 2
        Set-BrowserPolicy $path DownloadRestrictions 4 -AcceptedValues 1,2,3,4
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
    Add-Result Browsers 'Automatic updates and browser security baseline' PASS 'Chrome/Chromium/Edge/Firefox machine policies were checked for automatic updates, password-manager disablement, Safe Browsing, popups, Do Not Track, OCSP/revocation, tracking protection, and HTTPS-only mode.' ''
    Invoke-BrowserExtensionInventory -Profiles $profiles
}


$mode=if ($Apply) {'APPLY'} else {'AUDIT'}
Write-Host "CYPat Enforcer V5.3 | $($os.Caption) | $mode" -ForegroundColor Cyan
Write-Host 'Read the image README and answer forensics before applying changes. Service answers use that README.' -ForegroundColor Yellow
if ($os.ProductType -eq 1) { Add-Result Platform 'Windows client detected' REVIEW $os.Caption 'This tool targets Windows Server. Server-role commands may be unavailable; test on the intended image.' }
if ($script:IsDomainJoined) { Add-Result 'Group Policy' 'Domain policy' REVIEW "Domain=$($computer.Domain); controller=$script:IsDomainController" 'Use gpresult /r and the governing GPO to verify effective settings. Domain password policy is never changed automatically.' }

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
Invoke-Check 'Network logon right' { Invoke-NetworkLogonRightDecision }
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
Invoke-Check Browsers { Invoke-BrowserAudit }
Invoke-Check 'Final required-service verification' { Invoke-RequiredServicesVerification }

$report=[pscustomobject]@{
    Version='5.3';Time=(Get-Date).ToString('o');Mode=$mode
    Computer=$script:Inventory.Computer;RequiredServices=$RequiredServices;RequiredShares=$RequiredShares;KeepShares=$KeepShares;RemoveShares=$RemoveShares
    RemoveEveryoneNetworkLogonRight=$script:NetworkRightRemovalSelected;ProtectedServices=$script:ProtectedServices;ServiceDecisions=$script:ServiceDecisions
    Results=@($script:Results);Inventory=$script:Inventory
}
if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
    try { $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ReportPath -Encoding UTF8 -ErrorAction Stop; Write-Host "JSON report: $ReportPath" -ForegroundColor Cyan }
    catch { Add-Result Reporting 'JSON report' FAILED $_.Exception.Message 'Use an existing writable folder and a new report filename.' }
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
    if (-not $Detailed -and $evidence.Length -gt 220) { $evidence=$evidence.Substring(0,220)+'... (use -Detailed or JSON for full evidence)' }
    Write-Host "[$($entry.Status)] $($entry.Category) / $($entry.Item): $evidence" -ForegroundColor DarkYellow
    if ($Detailed) { Write-Host "  $($entry.Recommendation)" -ForegroundColor DarkYellow }
}
if ($script:ServiceDecisions.Count) {
    Write-Host 'SERVICE DECISIONS' -ForegroundColor Cyan
    foreach ($name in $script:ServiceDecisions.Keys) { Write-Host "  ${name}: $($script:ServiceDecisions[$name])" }
}
Write-Host 'Configuration readback verifies these checks only; rerun audit and check scoring/required services after changes.' -ForegroundColor Cyan
if ($PassThru) { $report.Results=@($script:Results); Write-Output $report }
