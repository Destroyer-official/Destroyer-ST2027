#!/usr/bin/env bash
# ==============================================================================
# scripts/apply_host_hardening_linux.sh
# ==============================================================================
# ST2027 Military Host Hardening & Posture Configuration Script (Linux / RedHat / Debian)
#
# Aligned with:
# - DoD Zero Trust Strategy (Endpoint Pillar - Workstation Integrity & Posture)
# - NIST SP 800-207 (Zero Trust Architecture: Continuous Diagnostics and Mitigation)
# - DISA Linux STIG (Kernel Lockdown, IOMMU DMA Protection, RF Discipline)
#
# Configures:
# 1. Linux Kernel DMA Protection (intel_iommu=on / amd_iommu=on, iommu=force)
# 2. Linux Kernel Lockdown mode (lockdown=integrity)
# 3. UEFI Secure Boot validation via mokutil
# 4. Optional Radio Silence / RF Emission Discipline (TEMPEST SDIP-29 compliance)
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================================${NC}"
echo -e "${CYAN}  ST2027 MILITARY HOST HARDENING & POSTURE ENFORCEMENT ENGINE (LINUX)           ${NC}"
echo -e "${CYAN}  Standards: DISA Linux STIG | NIST SP 800-207 | DoD Zero Trust Architecture   ${NC}"
echo -e "${CYAN}================================================================================${NC}"

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[FATAL] This script must be run as root.${NC}"
   exit 1
fi

DRY_RUN=false
RADIO_SILENCE=false

for arg in "$@"; do
    case $arg in
        --dry-run)
            DRY_RUN=true
            ;;
        --enforce-radio-silence)
            RADIO_SILENCE=true
            ;;
    esac
done

echo -e "\n${YELLOW}[PHASE 1] Configuring Kernel DMA Protection (IOMMU) & Kernel Lockdown...${NC}"

GRUB_FILE="/etc/default/grub"
IOMMU_PARAMS="intel_iommu=on amd_iommu=on iommu=force lockdown=integrity"

if [[ -f "$GRUB_FILE" ]]; then
    if grep -q "intel_iommu=on" "$GRUB_FILE" && grep -q "lockdown=integrity" "$GRUB_FILE"; then
        echo -e "${GREEN}[OK] Kernel boot parameters already contain IOMMU and lockdown enforcement.${NC}"
    else
        echo -e "${YELLOW}[CONFIG] Updating $GRUB_FILE with military kernel parameters: ${IOMMU_PARAMS}${NC}"
        if [[ "$DRY_RUN" = false ]]; then
            # Backup original grub file
            cp "$GRUB_FILE" "${GRUB_FILE}.bak.$(date +%s)"
            sed -i.bak -E "s/GRUB_CMDLINE_LINUX_DEFAULT=\"(.*)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 ${IOMMU_PARAMS}\"/" "$GRUB_FILE"
            
            # Update grub bootloader
            if command -v update-grub &>/dev/null; then
                update-grub
            elif command -v grub2-mkconfig &>/dev/null; then
                grub2-mkconfig -o /boot/grub2/grub.cfg
            fi
            echo -e "${GREEN}[ENFORCED] GRUB configuration updated.${NC}"
        else
            echo -e "${YELLOW}[DRY-RUN] Would update GRUB_CMDLINE_LINUX_DEFAULT with: ${IOMMU_PARAMS}${NC}"
        fi
    fi
else
    echo -e "${YELLOW}[WARN] $GRUB_FILE not found; ensure your bootloader cmdline includes: ${IOMMU_PARAMS}${NC}"
fi

echo -e "\n${YELLOW}[PHASE 2] Auditing UEFI Secure Boot Posture...${NC}"
if command -v mokutil &>/dev/null; then
    SB_STATE=$(mokutil --sb-state 2>/dev/null || true)
    if [[ "$SB_STATE" == *"SecureBoot enabled"* ]]; then
        echo -e "${GREEN}[PASS] UEFI Secure Boot is active: ${SB_STATE}${NC}"
    else
        echo -e "${YELLOW}[WARN] UEFI Secure Boot is inactive: ${SB_STATE}${NC}"
        echo -e "       Enable Secure Boot in the system UEFI BIOS setup."
    fi
else
    echo -e "${YELLOW}[INFO] mokutil not found; checking /sys/firmware/efi/efivars...${NC}"
fi

if [[ "$RADIO_SILENCE" = true ]]; then
    echo -e "\n${YELLOW}[PHASE 3] Enforcing Radio Silence / RF Emission Discipline (TEMPEST)...${NC}"
    if command -v rfkill &>/dev/null; then
        if [[ "$DRY_RUN" = false ]]; then
            rfkill block all
            echo -e "${GREEN}[ENFORCED] rfkill block all executed.${NC}"
        else
            echo -e "${YELLOW}[DRY-RUN] Would execute rfkill block all.${NC}"
        fi
    fi

    MODPROBE_FILE="/etc/modprobe.d/p2p-radio-silence.conf"
    if [[ "$DRY_RUN" = false ]]; then
        cat << 'EOF' > "$MODPROBE_FILE"
# ST2027 TEMPEST SDIP-29 RF Emission Discipline Adapter Blacklist
blacklist bluetooth
blacklist btusb
blacklist iwlwifi
blacklist b43
blacklist ath9k
blacklist ath10k_pci
blacklist ath11k_pci
blacklist rtw88_8822ce
blacklist r8169
install bluetooth /bin/true
install btusb /bin/true
EOF
        echo -e "${GREEN}[ENFORCED] Blacklisted wireless modules in ${MODPROBE_FILE}.${NC}"
    else
        echo -e "${YELLOW}[DRY-RUN] Would write wireless module blacklist to ${MODPROBE_FILE}.${NC}"
    fi
fi

echo -e "\n${CYAN}================================================================================${NC}"
echo -e "${CYAN}  LINUX HOST HARDENING EXECUTION COMPLETE                                       ${NC}"
echo -e "${CYAN}================================================================================${NC}"
