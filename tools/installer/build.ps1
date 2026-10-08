# Builds the PurgeKit installer with Inno Setup 6.
#
#   pwsh tools/installer/build.ps1 [-BinDir target\release] [-OutputDir target\installer] [-Version x.y.z]
#
# -Version defaults to the workspace version from Cargo. In GitHub Actions,
# Inno Setup is installed with Chocolatey if it is missing; locally, install
# Inno Setup 6 first. Signing happens outside this script (release.yml).
param(
    [string]$BinDir = "target\release",
    [string]$OutputDir = "target\installer",
    [string]$Version
)
$ErrorActionPreference = 'Stop'

if (-not $Version) {
    $meta = cargo metadata --no-deps --format-version 1 | ConvertFrom-Json
    $Version = ($meta.packages | Where-Object name -eq 'purgekit').version
}

$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) {
    if (-not $env:GITHUB_ACTIONS) { throw "Inno Setup 6 not found at $iscc" }
    choco install innosetup -y --no-progress
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup install failed" }
}

$bin = (Resolve-Path $BinDir).Path
$out = [IO.Path]::GetFullPath($OutputDir)
& $iscc "/DAppVersion=$Version" "/DBinDir=$bin" "/DOutputDir=$out" "$PSScriptRoot\purgekit.iss"
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }
Write-Output (Join-Path $out "PurgeKit-Setup-$Version.exe")
