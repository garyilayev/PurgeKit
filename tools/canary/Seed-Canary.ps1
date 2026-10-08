#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Plants the rule fixtures and safety traps in the canary VM (guest side).

.DESCRIPTION
    For every rule fixture in tests/fixtures/rules/<rule id>.txt, creates each
    DELETE and KEEP path under the rule's real root, with its timestamps set to
    the fixture age. A file that already exists is never overwritten (it may be
    a real browser profile file); it is recorded as preexisting instead.

    Also plants the traps the cleaner must survive: junctions and a symlink
    into a victim folder, a hard-linked file, a read-only file and a locked
    file (held open by a background process until Compare-Canary.ps1 runs).

    Writes the result to <OutDir>\seed.json. Run it right before the clean:
    fixture ages are relative to the seed time, and a "23h" KEEP file turns
    into a DELETE file an hour later.

    Run elevated (Windows\Temp needs it) from the account under test.
#>
param(
    [Parameter(Mandatory)][string]$RepoDir,
    [string]$OutDir = 'C:\Canary',
    [string]$UserProfile = $env:USERPROFILE
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $OutDir | Out-Null

$local = Join-Path $UserProfile 'AppData\Local'
$tokens = @{
    '{LocalAppData}'   = $local
    '{RoamingAppData}' = Join-Path $UserProfile 'AppData\Roaming'
    '{Temp}'           = Join-Path $local 'Temp'
    '{Windows}'        = $env:windir
}

function Resolve-Root([string]$root) {
    foreach ($k in $tokens.Keys) { $root = $root.Replace($k, $tokens[$k]) }
    if ($root -match '\{') { throw "Unknown root token in '$root'" }
    return $root.Replace('/', '\')
}

function ConvertTo-Age([string]$s) {
    if ($s -notmatch '^(\d+)([smhd])$') { throw "Bad age '$s'" }
    $n = [int]$Matches[1]
    switch ($Matches[2]) {
        's' { [TimeSpan]::FromSeconds($n) }
        'm' { [TimeSpan]::FromMinutes($n) }
        'h' { [TimeSpan]::FromHours($n) }
        'd' { [TimeSpan]::FromDays($n) }
    }
}

function Get-Sha256([string]$path) {
    $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite, Delete')
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        return [BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '')
    } finally { $fs.Dispose() }
}

function New-OldFile([string]$path, [TimeSpan]$age, [string]$content) {
    New-Item -ItemType Directory -Force (Split-Path $path) | Out-Null
    [IO.File]::WriteAllText($path, $content)
    $t = [DateTime]::Now - $age
    $item = Get-Item -LiteralPath $path
    $item.CreationTime = $t; $item.LastWriteTime = $t; $item.LastAccessTime = $t
}

# Rule roots come from rules/*.toml so the seed follows the shipped rules.
$roots = @{}
foreach ($f in Get-ChildItem (Join-Path $RepoDir 'rules') -Filter *.toml) {
    $text = Get-Content -Raw $f.FullName
    if ($text -match '(?m)^id\s*=\s*"([^"]+)"' ) { $id = $Matches[1] } else { continue }
    if ($text -match '(?m)^root\s*=\s*"([^"]+)"') { $roots[$id] = Resolve-Root $Matches[1] }
}

$now = [DateTime]::Now
$planted = New-Object System.Collections.Generic.List[object]
foreach ($fx in Get-ChildItem (Join-Path $RepoDir 'tests\fixtures\rules') -Filter *.txt) {
    $id = $fx.BaseName
    if (-not $roots.ContainsKey($id)) { Write-Host "skip $id (no path root)"; continue }
    $root = $roots[$id]
    foreach ($line in Get-Content $fx.FullName) {
        if ($line -match '^\s*(#|$)') { continue }
        if ($line -notmatch '^(DELETE|KEEP)\s+(?:age=(\S+)\s+)?(.+)$') { throw "Bad fixture line in ${id}: $line" }
        $verdict = $Matches[1]
        $age = if ($Matches[2]) { ConvertTo-Age $Matches[2] } else { [TimeSpan]::FromDays(365) }
        $rel = $Matches[3].Trim()
        $path = Join-Path $root $rel.Replace('/', '\')
        $entry = [ordered]@{ rule = $id; verdict = $verdict; path = $path; preexisting = $false; sha256 = $null }
        if (Test-Path -LiteralPath $path) {
            $entry.preexisting = $true
        } else {
            New-OldFile $path $age "purgekit-canary $id $rel"
        }
        if (Test-Path -LiteralPath $path -PathType Leaf) { $entry.sha256 = Get-Sha256 $path }
        $planted.Add($entry)
    }
}

# --- Traps -------------------------------------------------------------------
$temp = $tokens['{Temp}']
$victim = Join-Path $UserProfile 'Documents\canary-victim'
$old = [TimeSpan]::FromDays(400)
New-OldFile (Join-Path $victim 'precious.txt') $old 'victim file: must survive'
New-OldFile (Join-Path $victim 'sub\deep.bin') $old 'victim file: must survive'
New-OldFile (Join-Path $victim 'hardlinked.txt') $old 'victim file with a second link in Temp'

$traps = New-Object System.Collections.Generic.List[object]
function Add-Trap($kind, $path, $expect) { $traps.Add([ordered]@{ kind = $kind; path = $path; expect = $expect }) }

$jTemp = Join-Path $temp 'canary-trap-junction'
cmd /c mklink /J "$jTemp" "$victim" | Out-Null
Add-Trap 'junction' $jTemp 'present'

if ($roots.ContainsKey('chrome.cache')) {
    $jChrome = Join-Path $roots['chrome.cache'] 'Default\Cache\Cache_Data\canary-trap-junction'
    New-Item -ItemType Directory -Force (Split-Path $jChrome) | Out-Null
    cmd /c mklink /J "$jChrome" "$victim" | Out-Null
    Add-Trap 'junction' $jChrome 'present'
}

$sym = Join-Path $temp 'canary-trap-symlink.tmp'
cmd /c mklink "$sym" (Join-Path $victim 'precious.txt') | Out-Null
Add-Trap 'symlink' $sym 'present'

$hard = Join-Path $temp 'canary-hardlink.tmp'
cmd /c mklink /H "$hard" (Join-Path $victim 'hardlinked.txt') | Out-Null
Add-Trap 'hardlink' $hard 'present'

$ro = Join-Path $temp 'canary-readonly.tmp'
New-OldFile $ro $old 'read-only: must be skipped'
Set-ItemProperty -LiteralPath $ro -Name IsReadOnly -Value $true
Add-Trap 'readonly' $ro 'present'

$locked = Join-Path $temp 'canary-locked.tmp'
New-OldFile $locked $old 'locked: must be skipped'
$holder = Start-Process powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @(
    '-NoProfile', '-Command',
    "`$f = [IO.File]::Open('$locked', 'Open', 'ReadWrite', 'None'); Start-Sleep -Seconds 86400"
)
Add-Trap 'locked' $locked 'present'

$victimHashes = [ordered]@{}
foreach ($v in Get-ChildItem -LiteralPath $victim -Recurse -File) { $victimHashes[$v.FullName] = Get-Sha256 $v.FullName }

$state = [ordered]@{
    seeded_at     = $now.ToString('o')
    user_profile  = $UserProfile
    roots         = $roots
    planted       = $planted
    traps         = $traps
    victim        = $victim
    victim_hashes = $victimHashes
    lock_pid      = $holder.Id
}
$state | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $OutDir 'seed.json')

$n = ($planted | Where-Object { -not $_.preexisting }).Count
Write-Host "Planted $n fixture files ($($planted.Count - $n) preexisting, left as is), $($traps.Count) traps."
Write-Host "Lock holder PID $($holder.Id). Next: Get-CanaryManifest.ps1 -Label pre"
