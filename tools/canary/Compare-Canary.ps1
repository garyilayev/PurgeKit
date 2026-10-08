#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Gives the canary verdict from the pre/post manifests (guest side).

.DESCRIPTION
    FAIL (exit 1) on any of:
      - a file or folder removed or changed outside every rule root,
        unless it matches a reviewed line in noise.txt;
      - a protected file (passwords, bookmarks, credentials) changed or gone;
      - a planted KEEP fixture file changed or gone;
      - a trap (junction, symlink, hard link, read-only, locked) gone, or any
        file in the victim folder changed;
      - a rule root folder removed;
      - measured recovery more than 10% away from the estimate.
    WARN on planted DELETE fixture files that are still present.

    -Control compares control-pre/control-post (a run with no clean, same
    wait) and writes noise-suggested.txt: what Windows itself changes. Review
    it by hand before you copy lines into noise.txt.
#>
param(
    [string]$OutDir = 'C:\Canary',
    [string]$NoiseFile = (Join-Path $PSScriptRoot 'noise.txt'),
    [switch]$Control,
    [double]$RecoveryTolerance = 0.10
)

$ErrorActionPreference = 'Stop'

function Read-Manifest([string]$path) {
    $m = @{}
    foreach ($line in [IO.File]::ReadLines($path)) {
        $f = $line.Split("`t")
        $m[$f[5].ToLowerInvariant()] = [pscustomobject]@{
            Kind = $f[0]; Size = [long]$f[1]; Ticks = [long]$f[2]; Attrs = [int]$f[3]; Sha = $f[4]; Path = $f[5]
        }
    }
    return $m
}

$preLabel, $postLabel = if ($Control) { 'control-pre', 'control-post' } else { 'pre', 'post' }
$pre = Read-Manifest (Join-Path $OutDir "manifest-$preLabel.tsv")
$post = Read-Manifest (Join-Path $OutDir "manifest-$postLabel.tsv")
$seed = Get-Content -Raw (Join-Path $OutDir 'seed.json') | ConvertFrom-Json

$roots = @($seed.roots.PSObject.Properties | ForEach-Object { $_.Value.ToLowerInvariant().TrimEnd('\') })
$roots += "$($env:SystemDrive.ToLowerInvariant())\`$recycle.bin"

$noise = @()
if (Test-Path $NoiseFile) {
    $noise = @(Get-Content $NoiseFile | Where-Object { $_ -and $_ -notmatch '^\s*#' })
}

$up = $seed.user_profile
$tokenValues = @{
    '%LOCALAPPDATA%' = Join-Path $up 'AppData\Local'
    '%APPDATA%'      = Join-Path $up 'AppData\Roaming'
    '%TEMP%'         = Join-Path $up 'AppData\Local\Temp'
    '%WINDIR%'       = $env:windir
    '%SYSTEMDRIVE%'  = $env:SystemDrive
}
$allowed = @(Get-Content (Join-Path $PSScriptRoot 'allowed.txt') | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
    $re = $_
    foreach ($t in $tokenValues.Keys) { $re = $re.Replace($t, [regex]::Escape($tokenValues[$t])) }
    $re
})

function Test-UnderRoot([string]$lower) {
    foreach ($r in $roots) { if ($lower.StartsWith("$r\")) { return $true } }
    return $false
}
# Second opinion, independent of the PurgeKit matcher (see allowed.txt).
function Test-Allowed([string]$path) {
    foreach ($a in $allowed) { if ($path -match $a) { return $true } }
    return $false
}
function Test-Noise([string]$path) {
    foreach ($n in $noise) { if ($path -match $n) { return $true } }
    return $false
}

$fail = New-Object System.Collections.Generic.List[string]
$warn = New-Object System.Collections.Generic.List[string]
$info = New-Object System.Collections.Generic.List[string]
$outside = New-Object System.Collections.Generic.List[string]
$freedLogical = 0L
$removedInRoots = 0

foreach ($k in $pre.Keys) {
    $a = $pre[$k]
    $b = $post[$k]
    if ($a.Kind -eq 'X') { continue }
    if ($null -eq $b) {
        if ($a.Sha) { $fail.Add("PROTECTED REMOVED  $($a.Path)"); continue }
        if ($roots -contains $k) { $fail.Add("RULE ROOT REMOVED  $($a.Path)"); continue }
        if (Test-UnderRoot $k) {
            if (-not (Test-Allowed $a.Path)) {
                $outside.Add("removed  $($a.Path)")
                if (-not $Control) { $fail.Add("REMOVED IN RULE ROOT, OUTSIDE CACHE AREA  $($a.Path)") }
                continue
            }
            $removedInRoots++
            if ($a.Kind -eq 'F') { $freedLogical += $a.Size }
            continue
        }
        $outside.Add("removed  $($a.Path)")
        if (-not (Test-Noise $a.Path)) { $fail.Add("REMOVED OUTSIDE RULES  $($a.Path)") }
        continue
    }
    if ($a.Sha -and $a.Sha -ne $b.Sha) { $fail.Add("PROTECTED CHANGED  $($a.Path)"); continue }
    if ($a.Kind -ne $b.Kind) {
        $outside.Add("kind $($a.Kind)->$($b.Kind)  $($a.Path)")
        if (-not (Test-Noise $a.Path)) { $fail.Add("KIND CHANGED  $($a.Path)") }
        continue
    }
    # Folder mtimes move whenever a child changes; only files count as changes.
    if ($a.Kind -eq 'F' -and ($a.Size -ne $b.Size -or $a.Ticks -ne $b.Ticks)) {
        if (Test-Allowed $a.Path) { continue }
        $outside.Add("changed  $($a.Path)")
        if (-not (Test-Noise $a.Path)) { $fail.Add("CHANGED OUTSIDE RULES  $($a.Path)") }
    }
}
$added = @($post.Keys | Where-Object { -not $pre.ContainsKey($_) -and -not (Test-UnderRoot $_) }).Count
$info.Add("$added new entries outside rule roots (new files are not a failure)")

if ($Control) {
    $dirs = $outside | ForEach-Object { Split-Path ($_ -replace '^\S+(\s\S+)?\s{2}', '') } | Sort-Object -Unique
    $suggest = $dirs | ForEach-Object { '^' + [regex]::Escape($_) + '\\' }
    $suggest | Set-Content -Encoding UTF8 (Join-Path $OutDir 'noise-suggested.txt')
    $outside | Set-Content -Encoding UTF8 (Join-Path $OutDir 'control-changes.txt')
    Write-Host "Control run: $($outside.Count) changes outside rule roots in $($dirs.Count) folders."
    Write-Host "Review $OutDir\control-changes.txt; copy only harmless lines from noise-suggested.txt into noise.txt."
    return
}

# Planted fixtures.
foreach ($p in $seed.planted) {
    $b = $post[$p.path.ToLowerInvariant()]
    if ($p.verdict -eq 'KEEP') {
        if ($null -eq $b) { $fail.Add("KEEP FIXTURE REMOVED  [$($p.rule)] $($p.path)") }
        elseif ($p.sha256 -and (Test-Path -LiteralPath $p.path)) {
            $fs = [IO.File]::Open($p.path, 'Open', 'Read', 'ReadWrite, Delete')
            try { $h = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($fs)).Replace('-', '') }
            finally { $fs.Dispose() }
            if ($h -ne $p.sha256) { $fail.Add("KEEP FIXTURE CHANGED  [$($p.rule)] $($p.path)") }
        }
    } elseif (-not $p.preexisting -and $null -ne $b) {
        $warn.Add("DELETE fixture still present  [$($p.rule)] $($p.path)")
    }
}

# Traps and victim.
foreach ($t in $seed.traps) {
    if (-not (Test-Path -LiteralPath $t.path)) { $fail.Add("TRAP REMOVED ($($t.kind))  $($t.path)") }
}
foreach ($v in $seed.victim_hashes.PSObject.Properties) {
    if (-not (Test-Path -LiteralPath $v.Name)) { $fail.Add("VICTIM REMOVED  $($v.Name)"); continue }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $v.Name).Hash -ne $v.Value) { $fail.Add("VICTIM CHANGED  $($v.Name)") }
}

# Recovery: last history entry written by the clean.
$history = Join-Path $seed.user_profile 'AppData\Local\PurgeKit\history.json'
if (Test-Path $history) {
    $last = (Get-Content -Raw $history | ConvertFrom-Json).entries | Select-Object -Last 1
    $est = [double]$last.estimated_bytes
    if ($null -eq $last.measured_bytes) {
        $fail.Add('RECOVERY: last history entry has no measured value')
    } else {
        $meas = [double]$last.measured_bytes
        $dev = if ($est -gt 0) { [math]::Abs($meas - $est) / $est } else { 0 }
        $line = 'RECOVERY estimated {0:N0} B, measured {1:N0} B, deviation {2:P1} (limit {3:P0})' -f $est, $meas, $dev, $RecoveryTolerance
        if ($dev -gt $RecoveryTolerance) { $fail.Add($line) } else { $info.Add($line) }
        $info.Add("history: $($last.files_deleted) deleted, $($last.files_skipped) skipped, categories: $($last.categories -join ', ')")
    }
} else {
    $fail.Add("RECOVERY: no history file at $history (was the clean run as this user?)")
}
$info.Add("$removedInRoots entries removed inside rule roots, {0:N0} logical bytes" -f $freedLogical)

if ($seed.lock_pid) { Stop-Process -Id $seed.lock_pid -ErrorAction SilentlyContinue }

$report = @()
$report += "PurgeKit canary report  $(Get-Date -Format o)"
$report += "VERDICT: $(if ($fail.Count) { 'FAIL' } else { 'PASS' })"
$report += ''; $report += "FAIL ($($fail.Count))"; $report += $fail
$report += ''; $report += "WARN ($($warn.Count))"; $report += $warn
$report += ''; $report += 'INFO'; $report += $info
$report | Set-Content -Encoding UTF8 (Join-Path $OutDir 'canary-report.txt')
$report | Select-Object -First 60 | Write-Host
Write-Host "Full report: $OutDir\canary-report.txt"
if ($fail.Count) { exit 1 }
