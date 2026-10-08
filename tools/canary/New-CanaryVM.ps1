#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Creates the PurgeKit canary VM on Hyper-V (host side).

.DESCRIPTION
    Gen 2 VM with Secure Boot and a virtual TPM (Windows 11 needs both),
    a dynamic VHDX, the Windows ISO attached, and the Guest Service
    Interface on so files can be copied in with Copy-VMFile / PowerShell
    Direct. The VM starts on the Default Switch so apps can be installed;
    disconnect it with -Offline before a canary run.

.EXAMPLE
    .\New-CanaryVM.ps1 -IsoPath E:\ISO\Win11_Enterprise_Eval.iso
    .\New-CanaryVM.ps1 -Offline        # disconnect the network adapter
#>
[CmdletBinding(DefaultParameterSetName = 'Create')]
param(
    [Parameter(ParameterSetName = 'Create', Mandatory)]
    [string]$IsoPath,
    [string]$Name = 'PurgeKit-Canary',
    [Parameter(ParameterSetName = 'Create')]
    [string]$Root = 'E:\HyperV',
    [Parameter(ParameterSetName = 'Create')]
    [int]$CpuCount = 4,
    [Parameter(ParameterSetName = 'Create')]
    [long]$MemoryBytes = 6GB,
    [Parameter(ParameterSetName = 'Create')]
    [long]$DiskBytes = 80GB,
    [Parameter(ParameterSetName = 'Offline', Mandatory)]
    [switch]$Offline,
    [Parameter(ParameterSetName = 'Online', Mandatory)]
    [switch]$Online
)

$ErrorActionPreference = 'Stop'

if ($Offline) {
    Disconnect-VMNetworkAdapter -VMName $Name
    Write-Host "$Name network adapter disconnected."
    return
}
if ($Online) {
    Connect-VMNetworkAdapter -VMName $Name -SwitchName 'Default Switch'
    Write-Host "$Name connected to Default Switch."
    return
}

if (-not (Test-Path $IsoPath)) { throw "ISO not found: $IsoPath" }
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "VM '$Name' already exists." }

$vmDir = Join-Path $Root $Name
$vhd = Join-Path $vmDir "$Name.vhdx"
New-Item -ItemType Directory -Force $vmDir | Out-Null

New-VM -Name $Name -Generation 2 -Path $Root -MemoryStartupBytes $MemoryBytes `
    -NewVHDPath $vhd -NewVHDSizeBytes $DiskBytes -SwitchName 'Default Switch' | Out-Null

# Static memory keeps peak-RAM measurements in the guest comparable between runs.
Set-VMMemory -VMName $Name -DynamicMemoryEnabled $false -StartupBytes $MemoryBytes
Set-VMProcessor -VMName $Name -Count $CpuCount
Set-VM -Name $Name -CheckpointType Production -AutomaticCheckpointsEnabled $false

Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
Set-VMKeyProtector -VMName $Name -NewLocalKeyProtector
Enable-VMTPM -VMName $Name

Enable-VMIntegrationService -VMName $Name -Name 'Guest Service Interface'

$dvd = Add-VMDvdDrive -VMName $Name -Path $IsoPath -Passthru
Set-VMFirmware -VMName $Name -FirstBootDevice $dvd

Write-Host "Created $Name in $vmDir."
Write-Host "Next: vmconnect localhost $Name, start it, press a key to boot the ISO, install Windows."
