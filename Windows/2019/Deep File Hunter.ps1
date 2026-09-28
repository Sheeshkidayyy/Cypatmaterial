<#
.SYNOPSIS
  Read-only deep scan for media, document, archive, script and executable files on Windows Server 2019.

.DESCRIPTION
  Non-destructive scanner that enumerates common locations on all filesystem drives and logs files by category:
  - PROHIBITED: Files that should never exist (suspicious)
  - ALLOWED: Files that are legitimate but tracked
  - SYSTEM: Pre-installed Windows Server 2019 files (filtered by default)

.PARAMETER ScanRoots
  Optional list of drive roots to scan (e.g., C:\, D:\). If omitted the script auto-discovers filesystem drives.

.PARAMETER ExtraPaths
  Additional paths to include in the scan.

.PARAMETER ExcludePaths
  Paths to exclude (prefix-match, case-insensitive).

.PARAMETER ReportPath
  Path to the output report file. Defaults to $env:TEMP\cypat_prohibited_scan_report.txt

.PARAMETER IncludeHidden
  Include hidden and system files/folders in enumeration.

.PARAMETER IncludeSystemFiles
  Include Windows Server 2019 system files in output (default is to filter them out).

.PARAMETER Parallel
  If supplied, will attempt parallel processing per-root using Start-Job for isolation.

.EXAMPLE
  .\Deep_File_Hunter.ps1
  Run default scan (excludes system files).

.EXAMPLE
  .\Deep_File_Hunter.ps1 -IncludeSystemFiles
  Include system files in the output.
#>

param(
    [string[]]$ScanRoots,
    [string[]]$ExtraPaths = @(),
    [string[]]$ExcludePaths = @(),
    [string]$ReportPath = (Join-Path $env:TEMP "cypat_prohibited_scan_report.txt"),
    [switch]$IncludeHidden,
    [switch]$IncludeSystemFiles,
    [switch]$Parallel
)

function Get-SystemExclusionPaths {
    <#
    .SYNOPSIS
      Returns Windows Server 2019 system directories to exclude.
    #>
    $exclusions = @(
        $env:SystemRoot,
        $env:ProgramFiles,
        "${env:ProgramFiles(x86)}",
        (Join-Path $env:SystemRoot "System32"),
        (Join-Path $env:SystemRoot "SysWOW64"),
        (Join-Path $env:SystemRoot "WinSxS"),
        (Join-Path $env:SystemRoot "Temp"),
        (Join-Path $env:SystemRoot "Prefetch"),
        (Join-Path $env:SystemRoot "Tasks"),
        (Join-Path $env:SystemRoot "inf"),
        (Join-Path $env:SystemRoot "Fonts"),
        (Join-Path $env:ProgramFiles "Windows Defender"),
        (Join-Path $env:ProgramFiles "Internet Explorer"),
        (Join-Path $env:ProgramFiles "Windows Mail"),
        (Join-Path $env:ProgramFiles "Windows Media Player"),
        (Join-Path $env:ProgramFiles "WindowsApps"),
        "${env:ProgramFiles(x86)}\Internet Explorer",
        "${env:ProgramFiles(x86)}\Windows Defender",
        "C:\ProgramData\Microsoft",
        "C:\ProgramData\Package Cache",
        "C:\ProgramData\NVIDIA",
        "C:\ProgramData\Intel",
        "C:\ProgramData\AMD",
        (Join-Path $env:SystemRoot "System Recovery"),
        (Join-Path $env:SystemRoot "servicing"),
        (Join-Path $env:SystemRoot "Panther"),
        (Join-Path $env:SystemRoot "Downloaded Program Files")
    )
    
    return $exclusions | Where-Object { $_ } | Select-Object -Unique | ForEach-Object { $_.TrimEnd('\') }
}

function Test-IsSystemPath {
    <#
    .SYNOPSIS
      Tests if a file path is part of Windows Server 2019 default installation.
    #>
    param([string]$FilePath)
    
    $systemPaths = Get-SystemExclusionPaths
    foreach ($sysPath in $systemPaths) {
        if ($FilePath.StartsWith($sysPath, [System.StringComparison]::InvariantCultureIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Get-AllowedExtensions {
    <#
    .SYNOPSIS
      Extensions that are allowed/normal in a business environment but still tracked.
    #>
    return @("doc","docx","xls","xlsx","ppt","pptx","pdf","odt","ods","odp","rtf","txt","csv","md")
}

function Get-ProhibitedExtensions {
    <#
    .SYNOPSIS
      Extensions that are suspicious and should never exist on a server.
    #>
    return @("mp4","avi","mov","mkv","wmv","flv","mpg","mpeg","m4v","webm","3gp","3g2","ts","m2ts","ogv","vob",
             "mp3","wav","m4a","flac","aac","ogg","wma","aiff","alac","opus",
             "ps1","psm1","bat","cmd","vbs","vbe","js","jse","wsf","wsh","py","pl","rb","php","sh","psd1",
             "jpg","jpeg","png","gif","bmp","tiff","svg","webp","heic",
             "zip","rar","7z","tar","gz","bz2","xz","iso","msi",
             "exe","dll","bin","com","scr")
}

function Find-ProhibitedFiles {
    param(
        [string[]]$ScanRootsParam,
        [string[]]$ExtraPathsParam,
        [string[]]$ExcludePathsParam,
        [string]$OutFile,
        [switch]$IncludeHiddenParam,
        [switch]$IncludeSystemFilesParam
    )

    Write-Host "`n--- DEEP SCAN FOR SUSPICIOUS FILES ON WINDOWS SERVER 2019 ---" -ForegroundColor Magenta

    $prohibitedExt = Get-ProhibitedExtensions
    $allowedExt = Get-AllowedExtensions
    $allTrackedExt = ($prohibitedExt + $allowedExt) | Sort-Object -Unique

    # Build scan paths
    $scanPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($root in $ScanRootsParam) {
        if (-not $root) { continue }
        $candidates = @(
            (Join-Path $root "Users"),
            (Join-Path $root "ProgramData"),
            (Join-Path $root "Program Files"),
            (Join-Path $root "Program Files (x86)"),
            $root.TrimEnd('\')
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

        foreach ($p in $candidates) { $scanPaths.Add($p) }
    }

    foreach ($p in $ExtraPathsParam) { if ($p -and (Test-Path $p)) { $scanPaths.Add($p) } }

    # Apply exclusions
    $scanPaths = $scanPaths | Where-Object {
        $exclude = $false
        foreach ($ex in $ExcludePathsParam) {
            if (-not $ex) { continue }
            if ($_.StartsWith($ex, [System.StringComparison]::InvariantCultureIgnoreCase)) { $exclude = $true; break }
        }
        -not $exclude
    } | Select-Object -Unique

    if (-not $scanPaths -or $scanPaths.Count -eq 0) {
        Write-Host "No valid scan paths found. Exiting." -ForegroundColor Yellow
        return
    }

    # Initialize report
    $reportHeader = "Prohibited File Scan Report - {0}`nScan started: {1}`n" -f (Get-Date -Format o), (Get-Date)
    if (-not $IncludeSystemFilesParam) {
        $reportHeader += "Filtering: Windows Server 2019 system files excluded`n"
    }
    $reportHeader += "`nCategories:`n  PROHIBITED = Suspicious files (media, scripts, archives)`n  ALLOWED = Business files tracked for compliance`n  SYSTEM = Windows Server 2019 default files`n`nResults:`n"
    
    Set-Content -Path $OutFile -Value $reportHeader

    # Counters
    $counts = [ordered]@{ 
        Prohibited=0
        Allowed=0
        System=0
        Errors=0
    }

    foreach ($rootPath in $scanPaths) {
        Write-Host "`nScanning: $rootPath" -ForegroundColor Cyan
        try {
            $getChildParams = @{ Path = $rootPath; Recurse = $true; File = $true; ErrorAction = 'SilentlyContinue' }
            if ($IncludeHiddenParam) { $getChildParams['Force'] = $true }

            $items = Get-ChildItem @getChildParams
            if (-not $items) { continue }

            foreach ($file in $items) {
                try {
                    $extNoDot = $file.Extension.TrimStart('.').ToLower()
                    if ([string]::IsNullOrEmpty($extNoDot)) { continue }

                    $isSystemFile = Test-IsSystemPath -FilePath $file.FullName

                    if ($isSystemFile -and -not $IncludeSystemFilesParam) {
                        # Skip system files unless requested
                        continue
                    }

                    if ($prohibitedExt -contains $extNoDot) {
                        if ($isSystemFile) {
                            Write-Host "[SYSTEM-PROHIBITED] $($file.FullName)" -ForegroundColor DarkYellow
                            Add-Content -Path $OutFile -Value ("[SYSTEM-PROHIBITED] {0}" -f $file.FullName)
                            $counts.System++
                        } else {
                            Write-Host "[PROHIBITED] $($file.FullName)" -ForegroundColor Red
                            Add-Content -Path $OutFile -Value ("[PROHIBITED] {0}" -f $file.FullName)
                            $counts.Prohibited++
                        }
                    }
                    elseif ($allowedExt -contains $extNoDot) {
                        if ($isSystemFile) {
                            Write-Host "[SYSTEM-ALLOWED] $($file.FullName)" -ForegroundColor DarkGreen
                            Add-Content -Path $OutFile -Value ("[SYSTEM-ALLOWED] {0}" -f $file.FullName)
                            $counts.System++
                        } else {
                            Write-Host "[ALLOWED] $($file.FullName)" -ForegroundColor Green
                            Add-Content -Path $OutFile -Value ("[ALLOWED] {0}" -f $file.FullName)
                            $counts.Allowed++
                        }
                    }
                } catch {
                    $counts.Errors++
                    $msg = "Error processing file {0}: {1}" -f $file.FullName, $_.Exception.Message
                    Add-Content -Path $OutFile -Value $msg
                }
            }
        } catch {
            Write-Warning "Failed to enumerate $rootPath : $_"
            Add-Content -Path $OutFile -Value ("Failed to enumerate path {0}: {1}" -f $rootPath, $_.Exception.Message)
        }
    }

    # Summary
    Add-Content -Path $OutFile -Value "`n`nSUMMARY:`n"
    foreach ($k in $counts.Keys) {
        $line = "{0,-15} : {1}" -f $k, $counts[$k]
        Add-Content -Path $OutFile -Value $line
    }

    Write-Host "`n`nScan Complete. Summary:" -ForegroundColor Magenta
    $counts.GetEnumerator() | ForEach-Object { 
        Write-Host ("{0,-15} : {1}" -f $_.Name, $_.Value) 
    }
    Write-Host "`nFull report saved to: $OutFile" -ForegroundColor Green
    Write-Host "CRITICAL: Only delete files classified as [PROHIBITED]." -ForegroundColor White
}

# --- Main execution ---
if ($ScanRoots -and $ScanRoots.Count -gt 0) {
    $finalScanRoots = $ScanRoots
} else {
    $finalScanRoots = (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | ForEach-Object { $_.Root })
}

$allExcludePaths = @()
if (-not $IncludeSystemFiles) {
    $allExcludePaths += Get-SystemExclusionPaths
}
if ($ExcludePaths -and $ExcludePaths.Count -gt 0) {
    $allExcludePaths += $ExcludePaths
}
$allExcludePaths = $allExcludePaths | Select-Object -Unique

if ($Parallel) {
    $jobs = @()
    foreach ($r in $finalScanRoots) {
        $j = Start-Job -ScriptBlock {
            param($root,$extra,$excl,$out,$includeHidden,$includeSysFiles)
            Find-ProhibitedFiles -ScanRootsParam @($root) -ExtraPathsParam $extra -ExcludePathsParam $excl -OutFile $out -IncludeHiddenParam:$includeHidden -IncludeSystemFilesParam:$includeSysFiles
        } -ArgumentList ($r,$ExtraPaths,$allExcludePaths,$ReportPath,$IncludeHidden.IsPresent,$IncludeSystemFiles.IsPresent)
        $jobs += $j
    }
    Write-Host "Started $($jobs.Count) jobs; waiting for completion..." -ForegroundColor Cyan
    Receive-Job -Job $jobs -Wait -AutoRemoveJob | Out-Null
} else {
    Find-ProhibitedFiles -ScanRootsParam $finalScanRoots -ExtraPathsParam $ExtraPaths -ExcludePathsParam $allExcludePaths -OutFile $ReportPath -IncludeHiddenParam:$IncludeHidden -IncludeSystemFilesParam:$IncludeSystemFiles
}

Write-Host "`nDone." -ForegroundColor Green
