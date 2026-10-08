<#
.SYNOPSIS
    Builds and signs a sideload MSIX of PurgeKit for the packaging spike.

.DESCRIPTION
    Stages purgekit.exe and purgekit-helper.exe, generates placeholder logos,
    fills AppxManifest.template.xml, packs with makeappx and signs with a
    self-signed test certificate (created once, kept in tools\msix\out).

    The test certificate is for the spike VM only. Never publish a package
    signed with it.

    Install in the VM (elevated):
        Import-Certificate -FilePath PurgeKitSpike.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople
        Add-AppxPackage .\PurgeKit-<variant>.msix

.EXAMPLE
    .\Build-Msix.ps1 -Variant virtualized
    .\Build-Msix.ps1 -Variant unvirtualized
#>
param(
    [Parameter(Mandatory)][ValidateSet('virtualized', 'unvirtualized')][string]$Variant,
    [string]$BinDir = (Join-Path $PSScriptRoot '..\..\target\release'),
    [string]$Version = '0.1.0.0',
    [string]$Publisher = 'CN=PurgeKit Spike'
)

$ErrorActionPreference = 'Stop'
$out = Join-Path $PSScriptRoot 'out'
$stage = Join-Path $out "stage-$Variant"
New-Item -ItemType Directory -Force $out | Out-Null
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force (Join-Path $stage 'Assets') | Out-Null

function Find-SdkTool([string]$name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", 'E:\Windows Kits\10\bin')
    $hit = $roots | Where-Object { Test-Path $_ } |
        ForEach-Object { Get-ChildItem $_ -Recurse -Filter $name -ErrorAction SilentlyContinue } |
        Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $hit) { throw "$name not found. Install the Windows SDK signing tools (see tools\msix\README.md)." }
    return $hit.FullName
}
$makeappx = Find-SdkTool 'makeappx.exe'
$signtool = Find-SdkTool 'signtool.exe'

foreach ($exe in 'purgekit.exe', 'purgekit-helper.exe') {
    $src = Join-Path $BinDir $exe
    if (-not (Test-Path $src)) { throw "$src missing. Run: cargo build --release -p purgekit -p purgekit-helper" }
    Copy-Item $src $stage
}

# Placeholder logos: solid squares. Real art arrives with the release package.
Add-Type -AssemblyName System.Drawing
foreach ($logo in @(@('StoreLogo.png', 50), @('Square44x44Logo.png', 44), @('Square150x150Logo.png', 150))) {
    $bmp = New-Object Drawing.Bitmap($logo[1], $logo[1])
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.Clear([Drawing.Color]::FromArgb(0, 120, 212))
    $g.Dispose()
    $bmp.Save((Join-Path $stage "Assets\$($logo[0])"), [Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}

$virt = ''; $extra = ''
if ($Variant -eq 'unvirtualized') {
    $virt = '    <desktop6:FileSystemWriteVirtualization>disabled</desktop6:FileSystemWriteVirtualization>'
    $extra = '    <rescap:Capability Name="unvirtualizedResources" />'
}
$manifest = (Get-Content -Raw (Join-Path $PSScriptRoot 'AppxManifest.template.xml')).
    Replace('{{PUBLISHER}}', $Publisher).Replace('{{VERSION}}', $Version).
    Replace('{{VIRTUALIZATION}}', $virt).Replace('{{EXTRA_CAPABILITIES}}', $extra)
Set-Content -Encoding UTF8 (Join-Path $stage 'AppxManifest.xml') $manifest

$msix = Join-Path $out "PurgeKit-$Variant.msix"
& $makeappx pack /o /d $stage /p $msix
if ($LASTEXITCODE) { throw "makeappx failed ($LASTEXITCODE)" }

# Self-signed test certificate, created once.
$pfx = Join-Path $out 'PurgeKitSpike.pfx'
$cer = Join-Path $out 'PurgeKitSpike.cer'
$pwd = ConvertTo-SecureString 'purgekit-spike' -AsPlainText -Force
if (-not (Test-Path $pfx)) {
    $cert = New-SelfSignedCertificate -Type Custom -Subject $Publisher -KeyUsage DigitalSignature `
        -FriendlyName 'PurgeKit packaging spike (test only)' -CertStoreLocation 'Cert:\CurrentUser\My' `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pwd | Out-Null
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
}

& $signtool sign /fd SHA256 /f $pfx /p 'purgekit-spike' $msix
if ($LASTEXITCODE) { throw "signtool failed ($LASTEXITCODE)" }

Write-Host "Built $msix"
Write-Host "Copy $msix and $cer into the VM, then follow tools\msix\README.md."
