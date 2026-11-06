# ==============================================================================
# scripts/apply_host_hardening_windows.ps1
# ==============================================================================
# ST2027 Military Host Hardening & Posture Configuration Script (Windows 11 / Server)
#
# Aligned with:
# - DoD Zero Trust Strategy (Endpoint Pillar - Workstation Integrity & Posture)
# - NIST SP 800-207 (Zero Trust Architecture: Endpoint Posture Enforcement)
# - NIST SP 800-193 (Platform Firmware Resiliency)
# - DISA Windows 11 STIG v2r3 (Device Guard, VBS, HVCI, Credential Guard)
#
# Configures:
# 1. Virtualization-Based Security (VBS) in Hypervisor Enclave (VTL 1)
# 2. Hypervisor-Protected Code Integrity (HVCI / Memory Integrity)
# 3. Kernel DMA Protection against rogue external PCIe/USB4/Thunderbolt bus taps
# 4. Windows Defender System Guard Secure Launch (DRTM / Dynamic Root of Trust)
# 5. Windows Defender Credential Guard (Isolated LSA in VTL 1)
# 6. Optional Radio Silence / RF Emission Discipline (TEMPEST SDIP-29 compliance)
# ==============================================================================

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$DryRun,
    [switch]$EnforceRadioSilence,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-MilitaryHeader {
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "  ST2027 MILITARY HOST HARDENING & POSTURE ENFORCEMENT ENGINE" -ForegroundColor Cyan
    Write-Host "  Standards: DISA STIG | NIST SP 800-207 | DoD Zero Trust Architecture" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
}

function Test-AdminPrivileges {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-RegistryDword {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value,
        [string]$Description
    )

    if (-not (Test-Path $Path)) {
        if ($DryRun) {
            Write-Host "[DRY-RUN] Create registry key: $Path" -ForegroundColor Yellow
        } else {
            New-Item -Path $Path -Force | Out-Null
        }
    }

    if ($DryRun) {
        Write-Host "[DRY-RUN] Set $Path\$Name = $Value ($Description)" -ForegroundColor Yellow
    } else {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
        Write-Host "[ENFORCED] $Name = $Value ($Description)" -ForegroundColor Green
    }
}

# --- 1. Privilege Validation ---
Write-MilitaryHeader

if (-not (Test-AdminPrivileges)) {
    Write-Host "`n[FATAL] Administrator privileges required to configure hypervisor security policies." -ForegroundColor Red
    Write-Host "Please re-run this script in an elevated PowerShell terminal (Run as Administrator).`n" -ForegroundColor Red
    exit 1
}

Write-Host "`n[PHASE 1] Enforcing Group Policy & Hypervisor Enclave Isolation (VBS / HVCI)..." -ForegroundColor Yellow

# --- 2. Virtualization-Based Security (VBS) Policies ---
# DISA STIG: WN11-CC-000050, WN11-CC-000055
$dgPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
Set-RegistryDword -Path $dgPolicyPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Description "Enable VBS"
Set-RegistryDword -Path $dgPolicyPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Description "Require Secure Boot and DMA Protection"
Set-RegistryDword -Path $dgPolicyPath -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -Description "Enable HVCI (Memory Integrity)"
Set-RegistryDword -Path $dgPolicyPath -Name "HVCIMATRequired" -Value 1 -Description "Enforce Memory Access Table validation"
Set-RegistryDword -Path $dgPolicyPath -Name "ConfigureSystemGuardLaunch" -Value 1 -Description "Enable System Guard Secure Launch (DRTM)"

# Direct Control Plane state
$dgControlPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
Set-RegistryDword -Path $dgControlPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Description "DeviceGuard VBS Control"
Set-RegistryDword -Path $dgControlPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Description "DeviceGuard SecureBoot+DMA Control"

$hvciScenarioPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
Set-RegistryDword -Path $hvciScenarioPath -Name "Enabled" -Value 1 -Description "HVCI Scenario Enforced"
Set-RegistryDword -Path $hvciScenarioPath -Name "WasEnabledBy" -Value 2 -Description "Policy Enforced Mode"

# --- 3. Credential Guard (LSA Protection) ---
# DISA STIG: WN11-CC-000060
Write-Host "`n[PHASE 2] Hardening Local Security Authority (LSA) & Credential Guard..." -ForegroundColor Yellow
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-RegistryDword -Path $lsaPath -Name "LsaCfgFlags" -Value 1 -Description "Credential Guard enabled with UEFI lock"
Set-RegistryDword -Path $lsaPath -Name "RunAsPPL" -Value 1 -Description "Run LSA as Protected Process Light (PPL)"

# --- 4. Kernel DMA Protection ---
Write-Host "`n[PHASE 3] Hardening Direct Memory Access (DMA) Bus Interposition..." -ForegroundColor Yellow
$kernelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
Set-RegistryDword -Path $kernelPath -Name "KernelDMAProtection" -Value 1 -Description "Kernel DMA Protection registry flag"

# DmaGuard Peripheral Enumeration Policy
$dmaGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
Set-RegistryDword -Path $dmaGuardPath -Name "DeviceEnumerationPolicy" -Value 0 -Description "Block external DMA devices while locked"

# --- 5. Radio Silence / RF Discipline (TEMPEST SDIP-29) ---
if ($EnforceRadioSilence) {
    Write-Host "`n[PHASE 4] Enforcing Radio Silence / RF Emission Discipline (TEMPEST)..." -ForegroundColor Yellow
    try {
        $wirelessAdapters = Get-NetAdapter | Where-Object {
            $_.PhysicalMediaType -match "Native 802.11" -or 
            $_.InterfaceDescription -match "Wi-Fi|Wireless|802\.11|Bluetooth|Cellular|WWAN"
        }
        foreach ($adapter in $wirelessAdapters) {
            if ($DryRun) {
                Write-Host "[DRY-RUN] Disable wireless network adapter: $($adapter.Name)" -ForegroundColor Yellow
            } else {
                Disable-NetAdapter -Name $adapter.Name -Confirm:$false
                Write-Host "[DISABLED] Wireless adapter: $($adapter.Name)" -ForegroundColor Green
            }
        }

        # Disable Bluetooth Support Service
        if ($DryRun) {
            Write-Host "[DRY-RUN] Stop and disable Bluetooth service (bthserv)" -ForegroundColor Yellow
        } else {
            Stop-Service -Name "bthserv" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "bthserv" -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "[DISABLED] Bluetooth Support Service (bthserv)" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Radio silence configuration encountered warning: $_"
    }
}

# --- 6. Status Report & UEFI Firmware Guidance ---
Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "  HARDENING CONFIGURATION COMMITTED" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

Write-Host @"
  CRITICAL: Physical Motherboard Firmware (UEFI / BIOS) Prerequisites:
  ------------------------------------------------------------------
  To complete full hardware-enforced isolation, ensure the following
  options are set in the host motherboard firmware setup (F2/Del at boot):

  [1] UEFI Secure Boot:
      - Set to: 'Enabled' (Standard Mode)
      - Enroll Microsoft UEFI CA or sovereign PK/KEK platform certificates.

  [2] CPU Hardware Virtualization:
      - Intel: Enable 'Intel Virtualization Technology (Intel VT-x)'
      - AMD:   Enable 'SVM Mode (Secure Virtual Machine)'

  [3] IOMMU / Kernel DMA Protection:
      - Intel: Enable 'Intel VT-d (Virtualization Technology for Directed I/O)'
      - AMD:   Enable 'AMD-Vi (IOMMU)'

  [4] Reboot Workstation:
      - System reboot is REQUIRED to instantiate the hypervisor VTL 1 enclave.
"@ -ForegroundColor White

Write-Host "================================================================================`n" -ForegroundColor Cyan
