#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Records every file and folder on a volume (guest side).

.DESCRIPTION
    Writes <OutDir>\manifest-<Label>.tsv with one line per entry:
        kind  size  mtime-ticks  attributes  sha256  path
    kind is F (file), D (directory) or R (reparse point, never entered).
    sha256 is filled only for protected files (the same name rules as
    purgekit-core::protected), so hashing stays fast; every other change is
    detected by size, mtime and presence.

    Run it with every browser and app closed: open apps lock and rewrite
    their profile files.
#>
param(
    [Parameter(Mandatory)][ValidateSet('pre', 'post', 'control-pre', 'control-post')][string]$Label,
    [string]$Volume = 'C:\',
    [string]$OutDir = 'C:\Canary'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force $OutDir | Out-Null

# Mirrors crates/purgekit-core/src/protected.rs. Keep the two in step.
$namePrefixes = 'login data', 'bookmarks', 'web data', 'local state', 'logins.json',
    'logins-backup.json', 'key4.db', 'key3.db', 'signons.sqlite', 'places.sqlite'
$nameContains = '.kdbx', '.kdb'
$dirNames = 'bookmarkbackups', 'bitwarden', '1password', 'keepassxc', 'keepass'
$dirPairs = 'microsoft\protect', 'microsoft\credentials', 'microsoft\vault'

function Test-Protected([string]$path) {
    $parts = $path.ToLowerInvariant().Split('\')
    for ($i = 0; $i -lt $parts.Length; $i++) {
        $c = $parts[$i]
        foreach ($p in $namePrefixes) { if ($c.StartsWith($p)) { return $true } }
        foreach ($s in $nameContains) { if ($c.Contains($s)) { return $true } }
        if ($dirNames -contains $c) { return $true }
        if ($i -gt 0 -and $dirPairs -contains "$($parts[$i - 1])\$c") { return $true }
    }
    return $false
}

function Get-Sha256([string]$path) {
    try {
        $fs = [IO.File]::Open("\\?\$path", 'Open', 'Read', 'ReadWrite, Delete')
        try {
            $sha = [Security.Cryptography.SHA256]::Create()
            return [BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '')
        } finally { $fs.Dispose() }
    } catch { return 'UNREADABLE' }
}

$out = Join-Path $OutDir "manifest-$Label.tsv"
$skipPrefix = $OutDir.TrimEnd('\') + '\'
$writer = New-Object IO.StreamWriter($out, $false, (New-Object Text.UTF8Encoding($false)))
$reparse = [IO.FileAttributes]::ReparsePoint
$stack = New-Object System.Collections.Generic.Stack[string]
$stack.Push($Volume.TrimEnd('\'))
$count = 0; $denied = 0
$sw = [Diagnostics.Stopwatch]::StartNew()

try {
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            $entries = ([IO.DirectoryInfo]"\\?\$dir\").EnumerateFileSystemInfos()
            foreach ($e in $entries) {
                $path = $e.FullName.Substring(4)   # drop \\?\
                if ($path.StartsWith($skipPrefix, 'OrdinalIgnoreCase') -or $path -eq $OutDir) { continue }
                $attrs = [int]$e.Attributes
                $ticks = $e.LastWriteTimeUtc.Ticks
                if ($e.Attributes -band $reparse) {
                    $writer.WriteLine("R`t0`t$ticks`t$attrs`t`t$path")
                } elseif ($e -is [IO.DirectoryInfo]) {
                    $writer.WriteLine("D`t0`t$ticks`t$attrs`t`t$path")
                    $stack.Push($path)
                } else {
                    $hash = if (Test-Protected $path) { Get-Sha256 $path } else { '' }
                    $writer.WriteLine("F`t$($e.Length)`t$ticks`t$attrs`t$hash`t$path")
                }
                $count++
            }
        } catch [UnauthorizedAccessException], [IO.IOException] {
            $denied++
            $writer.WriteLine("X`t0`t0`t0`t`t$dir")
        }
    }
} finally { $writer.Dispose() }

Write-Host "$count entries, $denied unreadable folders, $([int]$sw.Elapsed.TotalSeconds) s -> $out"
