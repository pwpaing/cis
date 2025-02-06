#!/usr/bin/env bash

#
# CIS Red Hat Enterprise Linux 8 Benchmark v3.0.0 Build Kit script
# 
# Name              Date		Description
# ------------------------------------------------------------------------------------------------
# jbrown	2023-11-29	    Build Kit: "CIS Red Hat Enterprise Linux 8 Benchmark v3.0.0"
#

# Ensure script is executed in bash
if [ ! "$BASH_VERSION" ] ; then
	exec /bin/bash "$0" "$@"
fi

echo -e "
\n\t########################################################\n\n
\t\t\tCIS Benchmark\n\n
\t\tCIS Red Hat Enterprise Linux 8 Benchmark v3.0.0\n\n
\t\t\tLinux Build Kit\n\n
\t\tCIS Red Hat Enterprise Linux 8 Benchmark v3.0.0.3\n\n
\t########################################################\n"

# Set global variables
PDFURL="https://workbench.cisecurity.org/benchmarks/8754"
BDIR="$(dirname "$(readlink -f "$0")")"
FDIR=$BDIR/functions
RECDIR="$FDIR"/recommendations
GDIR="$FDIR"/general
LDIR=$BDIR/logs
# RDIR=$BDIR/backup
DTG=$(date +%m_%d_%Y_%H%M)
mkdir $LDIR/$DTG
# mkdir $RDIR/$DTG
LOGDIR=$LDIR/$DTG
# BKDIR=$RDIR/$DTG
LOG=$LOGDIR/CIS-LBK_verbose.log
SLOG=$LOGDIR/CIS-LBK.log
ELOG=$LOGDIR/CIS-LBK_error.log
FRLOG=$LOGDIR/CIS-LBK_failed.log
MANLOG=$LOGDIR/CIS-LBK_manual.log
passed_recommendations="0"
failed_recommendations="0"
remediated_recommendations="0"
not_applicable_recommendations="0"
excluded_recommendations="0"
manual_recommendations="0"
skipped_recommendations="0"
total_recommendations="0"

# Populate header of log files
# Standard Log
echo "*****************************************************************" | tee -a "$SLOG" 2>> "$ELOG"
echo -e "*****************************************************************\n" | tee -a "$SLOG" 2>> "$ELOG"
echo -e " - The entries below countain the result of each benchmark item.\n" | tee -a "$SLOG" 2>> "$ELOG"
echo -e " - To investigate any issues further, open the corresponding CIS Benchmark PDF and navigate to the same recommendation number and name in the document.\n" | tee -a "$SLOG" 2>> "$ELOG"
echo -e " - A copy of the benchmark PDF document can be obtained at the following URL:\n\n   $PDFURL\n" | tee -a "$SLOG" 2>> "$ELOG"
echo "*****************************************************************" | tee -a "$SLOG" 2>> "$ELOG"

# Error Log
echo "*****************************************************************" | tee -a "$ELOG" 2>> "$ELOG"
echo -e "*****************************************************************\n" | tee -a "$ELOG" 2>> "$ELOG"
echo -e " - Each entry below countains any errors encountered in the remediation process.\n" | tee -a "$ELOG" 2>> "$ELOG"
echo -e " - To investigate any issues further, open the corresponding CIS Benchmark PDF and navigate to the same recommendation number and name in the document.\n" | tee -a "$ELOG" 2>> "$ELOG"
echo -e " - Sections describing the recommendation, the impact, and how to audit and remediate can be found for each item. Follow those instructions given in order to investigate the error and/or bring the system into compliance with the benchmark.\n" | tee -a "$ELOG" 2>> "$ELOG"
echo -e " - A copy of the benchmark PDF document can be obtained at the following URL:\n\n   $PDFURL\n" | tee -a "$ELOG" 2>> "$ELOG"
echo "*****************************************************************" | tee -a "$ELOG" 2>> "$ELOG"

# Fail Log
echo "*****************************************************************" | tee -a "$FRLOG" 2>> "$ELOG"
echo -e "*****************************************************************\n" | tee -a "$FRLOG" 2>> "$ELOG"
echo -e " - Each entry below countains a specific recommendation title that failed remediation and should be addressed.\n" | tee -a "$FRLOG" 2>> "$ELOG"
echo -e " - To investigate any failing recommendations further, open the corresponding CIS Benchmark PDF and navigate to the same recommendation number and name in the document.\n" | tee -a "$FRLOG" 2>> "$ELOG"
echo -e " - Sections describing the recommendation, the impact, and how to audit and remediate can be found for each item. Follow those instructions given in order to investigate the error and/or bring the system into compliance with the benchmark.\n" | tee -a "$FRLOG" 2>> "$ELOG"
echo -e " - A copy of the benchmark PDF document can be obtained at the following URL:\n\n   $PDFURL\n" | tee -a "$FRLOG" 2>> "$ELOG"
echo "*****************************************************************" | tee -a "$FRLOG" 2>> "$ELOG"

# Manual Log
echo "*****************************************************************" | tee -a "$MANLOG" 2>> "$ELOG"
echo -e "*****************************************************************\n" | tee -a "$MANLOG" 2>> "$ELOG"
echo -e " - Each entry below countains a specific recommendation title that requires manual remediation and should be addressed.\n" | tee -a "$MANLOG" 2>> "$ELOG"
echo -e " - To properly remediate each manual recommendation, open the corresponding CIS Benchmark PDF and navigate to the same recommendation number and name in the document.\n - Steps to audit and remediate that recommendation can be found for each item. Follow those instructions given in order to bring the system into compliance with the benchmark.\n" | tee -a "$MANLOG" 2>> "$ELOG"
echo -e " - It is sometimes helpful after following the steps in the Remediation section to follow up by performing the steps in the Audit section to verify that the remediation was performed successfully.\n" | tee -a "$MANLOG" 2>> "$ELOG"
echo -e " - A copy of the benchmark PDF document can be obtained at the following URL:\n\n   $PDFURL\n" | tee -a "$MANLOG" 2>> "$ELOG"
echo "*****************************************************************" | tee -a "$MANLOG" 2>> "$ELOG"

# Load functions (Order matters)
for func in "$GDIR"/*.sh; do
	[ -e "$func" ] || break
	. "$func"
done
for func in "$RECDIR"/**/*.sh; do
	[ -e "$func" ] || break
	. "$func"
done

#Clear the screen for output
clear
# Display the build kit banner
BANR
# Ensure script is being run as root
ROOTUSRCK
# Display the terms of use
# terms_of_use
# Display CIS Linux Build Kit warning banner
WARBNR
#run_profile=L2S # Uncomment this line to provide profile to be run manually
# Profile Options:
# L1S - For Level 1 Server
# L1W - For Level 1 Workstation
# L2S - For Level 2 Server
# L2W - For Level 2 Workstation
# Have user select profile to run
select_profile
# Recommediations This is where a BM specific script begins.

# 1 - Initial Setup

# 1.1 - Filesystem

# 1.1.1 - Configure Filesystem Kernel Modules

RN="1.1.1.1"
RNA="Ensure cramfs kernel module is not available"
profile="L1S L1W"
REC="ensure_cramfs_filesystem_disabled"
FSN="nix_ensure_cramfs_filesystem_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.1.2"
RNA="Ensure freevxfs kernel module is not available"
profile="L1S L1W"
REC="ensure_mounting_freevxfs_filesystem_disabled"
FSN="nix_ensure_mounting_freevxfs_filesystem_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.1.3"
RNA="Ensure hfs kernel module is not available"
profile="L1S L1W"
REC="ensure_mounting_hfs_filesystem_disabled"
FSN="nix_ensure_mounting_hfs_filesystem_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.1.4"
RNA="Ensure hfsplus kernel module is not available"
profile="L1S L1W"
REC="ensure_mounting_hfsplus_filesystem_disabled"
FSN="nix_ensure_mounting_hfsplus_filesystem_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.1.5"
RNA="Ensure jffs2 kernel module is not available"
profile="L1S L1W"
REC="ensure_mounting_jffs2_filesystem_disabled"
FSN="nix_ensure_mounting_jffs2_filesystem_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.1.6"
RNA="Ensure squashfs kernel module is not available"
profile="L2S L2W"
REC="ensure_squashfs_filesystem_disabled"
FSN="nix_ensure_squashfs_filesystem_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.1.7"
RNA="Ensure udf kernel module is not available"
profile="L2S L2W"
REC="ensure_udf_filesystem_disabled"
FSN="nix_ensure_udf_filesystem_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.1.8"
RNA="Ensure usb-storage kernel module is not available"
profile="L1S L2W"
REC="disable_usb_storage"
FSN="nix_disable_usb_storage.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.1.2 - Configure Filesystem Partitions

# 1.1.2.1 - Configure /tmp

RN="1.1.2.1.1"
RNA="Ensure /tmp is a separate partition"
profile="L1S L1W"
REC="ensure_tmp_separate_partition"
FSN="nix_ensure_tmp_separate_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.1.2"
RNA="Ensure nodev option set on /tmp partition"
profile="L1S L1W"
REC="ensure_nodev_set_tmp_partition"
FSN="nix_ensure_nodev_set_tmp_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.1.3"
RNA="Ensure nosuid option set on /tmp partition"
profile="L1S L1W"
REC="ensure_nosuid_set_tmp_partition"
FSN="nix_ensure_nosuid_set_tmp_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.1.4"
RNA="Ensure noexec option set on /tmp partition"
profile="L1S L1W"
REC="ensure_noexec_set_tmp_partition"
FSN="nix_ensure_noexec_set_tmp_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.1.2.2 - Configure /dev/shm

RN="1.1.2.2.1"
RNA="Ensure /dev/shm is a separate partition"
profile="L1S L1W"
REC="ensure_dev_shm_separate_partition"
FSN="nix_ensure_dev_shm_separate_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.2.2"
RNA="Ensure nodev option set on /dev/shm partition"
profile="L1S L1W"
REC="ensure_nodev_set_dev_shm_partition"
FSN="nix_ensure_nodev_set_dev_shm_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.2.3"
RNA="Ensure nosuid option set on /dev/shm partition"
profile="L1S L1W"
REC="ensure_nosuid_set_dev_shm_partition"
FSN="nix_ensure_nosuid_set_dev_shm_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.2.4"
RNA="Ensure noexec option set on /dev/shm partition"
profile="L1S L1W"
REC="ensure_noexec_set_dev_shm_partition"
FSN="nix_ensure_noexec_set_dev_shm_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.1.2.3 - Configure /home

RN="1.1.2.3.1"
RNA="Ensure separate partition exists for /home"
profile="L2S L2W"
REC="ensure_home_separate_partition"
FSN="nix_ensure_home_separate_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.3.2"
RNA="Ensure nodev option set on /home partition"
profile="L1S L1W"
REC="ensure_nodev_set_home_partition"
FSN="nix_ensure_nodev_set_home_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.3.3"
RNA="Ensure nosuid option set on /home partition"
profile="L1S L1W"
REC="ensure_nosuid_set_home_partition"
FSN="nix_ensure_nosuid_set_home_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.1.2.4 - Configure /var

RN="1.1.2.4.1"
RNA="Ensure separate partition exists for /var"
profile="L2S L2W"
REC="ensure_var_separate_partition"
FSN="nix_ensure_var_separate_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.4.2"
RNA="Ensure nodev option set on /var partition"
profile="L1S L1W"
REC="ensure_nodev_set_var_partition"
FSN="nix_ensure_nodev_set_var_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.4.3"
RNA="Ensure nosuid option set on /var partition"
profile="L1S L1W"
REC="ensure_nosuid_set_var_partition"
FSN="nix_ensure_nosuid_set_var_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.1.2.5 - Configure /var/tmp

RN="1.1.2.5.1"
RNA="Ensure separate partition exists for /var/tmp"
profile="L2S L2W"
REC="ensure_var_tmp_separate_partition"
FSN="nix_ensure_var_tmp_separate_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.5.2"
RNA="Ensure nodev option set on /var/tmp partition"
profile="L1S L1W"
REC="ensure_nodev_set_var_tmp_partition"
FSN="nix_ensure_nodev_set_var_tmp_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.5.3"
RNA="Ensure nosuid option set on /var/tmp partition"
profile="L1S L1W"
REC="ensure_nosuid_set_var_tmp_partition"
FSN="nix_ensure_nosuid_set_var_tmp_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.5.4"
RNA="Ensure noexec option set on /var/tmp partition"
profile="L1S L1W"
REC="ensure_noexec_set_var_tmp_partition"
FSN="nix_ensure_noexec_set_var_tmp_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.1.2.6 - Configure /var/log

RN="1.1.2.6.1"
RNA="Ensure separate partition exists for /var/log"
profile="L2S L2W"
REC="ensure_var_log_separate_partition"
FSN="nix_ensure_var_log_separate_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.6.2"
RNA="Ensure nodev option set on /var/log partition"
profile="L1S L1W"
REC="ensure_nodev_set_var_log_partition"
FSN="nix_ensure_nodev_set_var_log_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.6.3"
RNA="Ensure nosuid option set on /var/log partition"
profile="L1S L1W"
REC="ensure_nosuid_set_var_log_partition"
FSN="nix_ensure_nosuid_set_var_log_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.6.4"
RNA="Ensure noexec option set on /var/log partition"
profile="L1S L1W"
REC="ensure_noexec_set_var_log_partition"
FSN="nix_ensure_noexec_set_var_log_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.1.2.7 - Configure /var/log/audit

RN="1.1.2.7.1"
RNA="Ensure separate partition exists for /var/log/audit"
profile="L2S L2W"
REC="ensure_var_log_audit_separate_partition"
FSN="nix_ensure_var_log_audit_separate_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.7.2"
RNA="Ensure nodev option set on /var/log/audit partition"
profile="L1S L1W"
REC="ensure_nodev_set_var_log_audit_partition"
FSN="nix_ensure_nodev_set_var_log_audit_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.7.3"
RNA="Ensure nosuid option set on /var/log/audit partition"
profile="L1S L1W"
REC="ensure_nosuid_set_var_log_audit_partition"
FSN="nix_ensure_nosuid_set_var_log_audit_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.2.7.4"
RNA="Ensure noexec option set on /var/log/audit partition"
profile="L1S L1W"
REC="ensure_var_log_audit_separate_partition"
FSN="nix_ensure_var_log_audit_separate_partition.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.2 - Configure Software and Patch Management

RN="1.2.1"
RNA="Ensure GPG keys are configured"
profile="L1S L1W"
REC="ensure_gpg_keys_configured"
FSN="nix_ensure_gpg_keys_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.2.2"
RNA="Ensure gpgcheck is globally activated"
profile="L1S L1W"
REC="fed_ensure_gpgcheck_globally_activated"
FSN="nix_fed_ensure_gpgcheck_globally_activated.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.2.3"
RNA="Ensure repo_gpgcheck is globally activated"
profile="L2S L2W"
REC="fed_ensure_repo_gpgcheck_globally_activated"
FSN="nix_fed_ensure_repo_gpgcheck_globally_activated.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.2.4"
RNA="Ensure package manager repositories are configured"
profile="L1S L1W"
REC="ensure_package_manager_repositories_configured"
FSN="nix_ensure_package_manager_repositories_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.2.5"
RNA="Ensure updates, patches, and additional security software are installed"
profile="L1S L1W"
REC="ensure_updates_patches_security_software_installed"
FSN="nix_ensure_updates_patches_security_software_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.3 - Configure Secure Boot Settings

RN="1.3.1"
RNA="Ensure bootloader password is set"
profile="L1S L1W"
REC="fed_ensure_bootloader_password_set"
FSN="nix_fed_ensure_bootloader_password_set.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.3.2"
RNA="Ensure permissions on bootloader config are configured"
profile="L1S L1W"
REC="ensure_permissions_bootloader_config_configured"
FSN="nix_ensure_permissions_bootloader_config_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.4 - Configure Additional Process Hardening

RN="1.4.1"
RNA="Ensure address space layout randomization (ASLR) is enabled"
profile="L1S L1W"
REC="ensure_address_space_layout_randomization_enabled"
FSN="nix_ensure_address_space_layout_randomization_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.4.2"
RNA="Ensure ptrace_scope is restricted"
profile="L1S L1W"
REC="ensure_ptrace_scope_restricted"
FSN="nix_ensure_ptrace_scope_restricted.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.4.3"
RNA="Ensure core dump backtraces are disabled"
profile="L1S L1W"
REC="ensure_core_dump_backtraces_disabled"
FSN="nix_ensure_core_dump_backtraces_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.4.4"
RNA="Ensure core dump storage is disabled"
profile="L1S L1W"
REC="ensure_core_dump_storage_disabled"
FSN="nix_ensure_core_dump_storage_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.5 - Mandatory Access Control

# 1.5.1 - Configure SELinux

RN="1.5.1.1"
RNA="Ensure SELinux is installed"
profile="L1S L1W"
REC="fed_ensure_selinux_installed"
FSN="nix_fed_ensure_selinux_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.5.1.2"
RNA="Ensure SELinux is not disabled in bootloader configuration"
profile="L1S L1W"
REC="fed28_ensure_selinux_not_disabled_bootloader_configuration"
FSN="nix_fed28_ensure_selinux_not_disabled_bootloader_configuration.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.5.1.3"
RNA="Ensure SELinux policy is configured"
profile="L1S L1W"
REC="fed_ensure_selinux_policy_configured"
FSN="nix_fed_ensure_selinux_policy_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.5.1.4"
RNA="Ensure the SELinux mode is not disabled"
profile="L1S L1W"
REC="fed_ensure_selinux_state_enforcing_or_permissive"
FSN="nix_fed_ensure_selinux_state_enforcing_or_permissive.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.5.1.5"
RNA="Ensure the SELinux mode is enforcing"
profile="L2S L2W"
REC="fed_ensure_selinux_state_enforcing"
FSN="nix_fed_ensure_selinux_state_enforcing.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.5.1.6"
RNA="Ensure no unconfined services exist"
profile="L1S L1W"
REC="fed_ensure_no_unconfined_services_exist"
FSN="nix_fed_ensure_no_unconfined_services_exist.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.5.1.7"
RNA="Ensure the MCS Translation Service (mcstrans) is not installed"
profile="L1S L1W"
REC="fed_ensure_mcstrans_not_installed"
FSN="nix_fed_ensure_mcstrans_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.5.1.8"
RNA="Ensure SETroubleshoot is not installed"
profile="L1S"
REC="fed_ensure_setroubleshoot_not_installed"
FSN="nix_fed_ensure_setroubleshoot_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.6 - Configure system wide crypto policy

RN="1.6.1"
RNA="Ensure system wide crypto policy is not set to legacy"
profile="L1S L1W"
REC="fed_ensure_system-wide_crypto_policy_not_legacy"
FSN="nix_fed_ensure_system-wide_crypto_policy_not_legacy.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.6.2"
RNA="Ensure system wide crypto policy disables sha1 hash and signature support"
profile="L1S L1W"
REC="fed_ensure_system_wide_crypto_policy_disables_sha1_hash_and_signature"
FSN="nix_fed_ensure_system_wide_crypto_policy_disables_sha1_hash_and_signature.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.6.3"
RNA="Ensure system wide crypto policy disables cbc for ssh"
profile="L1S L1W"
REC="fed_ensure_system_wide_crypto_policy_disables_cbc_for_ssh"
FSN="nix_fed_ensure_system_wide_crypto_policy_disables_cbc_for_ssh.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.6.4"
RNA="Ensure system wide crypto policy disables macs less than 128 bits"
profile="L1S L1W"
REC="fed_ensure_system_wide_crypto_policy_disables_macs_less_than_128bits"
FSN="nix_fed_ensure_system_wide_crypto_policy_disables_macs_less_than_128bits.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.7 - Configure Command Line Warning Banners

RN="1.7.1"
RNA="Ensure message of the day is configured properly"
profile="L1S L1W"
REC="ensure_motd_configured"
FSN="nix_ensure_motd_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.7.2"
RNA="Ensure local login warning banner is configured properly"
profile="L1S L1W"
REC="ensure_local_login_warning_banner_configured"
FSN="nix_ensure_local_login_warning_banner_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.7.3"
RNA="Ensure remote login warning banner is configured properly"
profile="L1S L1W"
REC="ensure_remote_login_warning_banner_configured"
FSN="nix_ensure_remote_login_warning_banner_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.7.4"
RNA="Ensure access to /etc/motd is configured"
profile="L1S L1W"
REC="ensure_permissions_motd_configured"
FSN="nix_ensure_permissions_motd_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.7.5"
RNA="Ensure access to /etc/issue is configured"
profile="L1S L1W"
REC="ensure_permissions_issue_configured"
FSN="nix_ensure_permissions_issue_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.7.6"
RNA="Ensure access to /etc/issue.net is configured"
profile="L1S L1W"
REC="ensure_permissions_issue_net_configured"
FSN="nix_ensure_permissions_issue_net_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 1.8 - Configure GNOME Display Manager

RN="1.8.1"
RNA="Ensure GNOME Display Manager is removed"
profile="L2S"
REC="ensure_gdm_removed"
FSN="nix_ensure_gdm_removed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.8.2"
RNA="Ensure GDM login banner is configured"
profile="L1S L1W"
REC="ensure_gdm_login_banner_configured"
FSN="nix_ensure_gdm_login_banner_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.8.3"
RNA="Ensure GDM disable-user-list option is enabled"
profile="L1S L1W"
REC="ensure_gdm_disable-user-list_option_enabled"
FSN="nix_ensure_gdm_disable-user-list_option_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.8.4"
RNA="Ensure GDM screen locks when the user is idle"
profile="L1S L1W"
REC="ensure_gdm_screen_locks_when_user_idle"
FSN="nix_ensure_gdm_screen_locks_when_user_idle.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.8.5"
RNA="Ensure GDM screen locks cannot be overridden"
profile="L1S L1W"
REC="ensure_gdm_screen_locks_cannot_be_overridden"
FSN="nix_ensure_gdm_screen_locks_cannot_be_overridden.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.8.6"
RNA="Ensure GDM automatic mounting of removable media is disabled"
profile="L1S L2W"
REC="ensure_gdm_auto_mount_removable_media_disabled"
FSN="nix_ensure_gdm_auto_mount_removable_media_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.8.7"
RNA="Ensure GDM disabling automatic mounting of removable media is not overridden"
profile="L1S L2W"
REC="ensure_gdm_disable_auto_mount_cannot_be_overridden"
FSN="nix_ensure_gdm_disable_auto_mount_cannot_be_overridden.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.8.8"
RNA="Ensure GDM autorun-never is enabled"
profile="L1S L1W"
REC="ensure_gdm_autorun-never_enabled"
FSN="nix_ensure_gdm_autorun-never_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.8.9"
RNA="Ensure GDM autorun-never is not overridden"
profile="L1S L1W"
REC="ensure_gdm_autorun-never_cannot_be_overridden"
FSN="nix_ensure_gdm_autorun-never_cannot_be_overridden.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.8.10"
RNA="Ensure XDMCP is not enabled"
profile="L1S L1W"
REC="fed_ensure_xdmcp_not_enabled"
FSN="nix_fed_ensure_xdmcp_not_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 2 - Services

# 2.1 - Configure Time Synchronization

RN="2.1.1"
RNA="Ensure time synchronization is in use"
profile="L1S L1W"
REC="fed_ensure_time_synchronization_in_use"
FSN="nix_fed_ensure_time_synchronization_in_use.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.1.2"
RNA="Ensure chrony is configured"
profile="L1S L1W"
REC="fed_chrony_configured"
FSN="nix_fed_chrony_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.1.3"
RNA="Ensure chrony is not run as the root user"
profile="L1S L1W"
REC="ensure_chrony_not_run_as_root"
FSN="nix_ensure_chrony_not_run_as_root.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 2.2 - Configure Special Purpose Services

RN="2.2.1"
RNA="Ensure autofs services are not in use"
profile="L1S L2W"
REC="disable_automounting"
FSN="nix_disable_automounting.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.2"
RNA="Ensure avahi daemon services are not in use"
profile="L1S L2W"
REC="ensure_avahi_server_not_installed"
FSN="nix_ensure_avahi_server_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.3"
RNA="Ensure dhcp server services are not in use"
profile="L1S L1W"
REC="ensure_dhcp_server_not_installed"
FSN="nix_ensure_dhcp_server_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.4"
RNA="Ensure dns server services are not in use"
profile="L1S L1W"
REC="ensure_dns_server_not_installed"
FSN="nix_ensure_dns_server_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.5"
RNA="Ensure dnsmasq services are not in use"
profile="L1S L1W"
REC="ensure_dnsmasq_not_installed"
FSN="nix_ensure_dnsmasq_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.6"
RNA="Ensure samba file server services are not in use"
profile="L1S L1W"
REC="ensure_samba_not_installed"
FSN="nix_ensure_samba_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.7"
RNA="Ensure ftp server services are not in use"
profile="L1S L1W"
REC="ensure_ftp_server_not_installed"
FSN="nix_ensure_ftp_server_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.8"
RNA="Ensure message access server services are not in use"
profile="L1S L1W"
REC="ensure_imap_and_pop3_server_not_installed"
FSN="nix_ensure_imap_and_pop3_server_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.9"
RNA="Ensure network file system services are not in use"
profile="L1S L1W"
REC="fed_ensure_nfs_server_not_installed_or_masked"
FSN="nix_fed_ensure_nfs_server_not_installed_or_masked.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.10"
RNA="Ensure nis server services are not in use"
profile="L1S L1W"
REC="ensure_nis_server_not_installed"
FSN="nix_ensure_nis_server_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.11"
RNA="Ensure print server services are not in use"
profile="L1S"
REC="ensure_cups_not_installed"
FSN="nix_ensure_cups_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.12"
RNA="Ensure rpcbind services are not in use"
profile="L1S L1W"
REC="fed_ensure_rpcbind_not_installed_or_masked"
FSN="nix_fed_ensure_rpcbind_not_installed_or_masked.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.13"
RNA="Ensure rsync services are not in use"
profile="L1S L1W"
REC="ensure_rsync_service_not_enabled"
FSN="nix_ensure_rsync_service_not_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.14"
RNA="Ensure snmp services are not in use"
profile="L1S L1W"
REC="ensure_snmp_server_not_installed"
FSN="nix_ensure_snmp_server_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.15"
RNA="Ensure telnet server services are not in use"
profile="L1S L1W"
REC="fed_ensure_telnet_server_not_installed"
FSN="nix_fed_ensure_telnet_server_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.16"
RNA="Ensure tftp server services are not in use"
profile="L1S L1W"
REC="ensure_tftp_client_not_installed"
FSN="nix_ensure_tftp_client_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.17"
RNA="Ensure web proxy server services are not in use"
profile="L1S L1W"
REC="ensure_http_proxy_server_not_installed"
FSN="nix_ensure_http_proxy_server_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.18"
RNA="Ensure web server services are not in use"
profile="L1S L1W"
REC="ensure_web_server_not_installed"
FSN="nix_ensure_web_server_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.19"
RNA="Ensure xinetd services are not in use"
profile="L1S L1W"
REC="ensure_xinetd_not_installed"
FSN="nix_ensure_xinetd_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.20"
RNA="Ensure X window server services are not in use"
profile="L2S"
REC="ensure_x11_server_components_not_installed"
FSN="nix_ensure_x11_server_components_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.21"
RNA="Ensure mail transfer agents are configured for local-only mode"
profile="L1S L1W"
REC="ensure_mail_transfer_agent_configured_local_only"
FSN="nix_ensure_mail_transfer_agent_configured_local_only.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.22"
RNA="Ensure only approved services are listening on a network interface"
profile="L1S L1W"
REC="ensure_only_approved_services_listening_network_interface"
FSN="nix_ensure_only_approved_services_listening_network_interface.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 2.3 - Configure Service Clients

RN="2.3.1"
RNA="Ensure ftp client is not installed"
profile="L1S L1W"
REC="ensure_ftp_client_not_installed"
FSN="nix_ensure_ftp_client_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.3.2"
RNA="Ensure ldap client is not installed"
profile="L2S L2W"
REC="ensure_ldap_client_not_installed"
FSN="nix_ensure_ldap_client_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.3.3"
RNA="Ensure nis client is not installed"
profile="L1S L1W"
REC="ensure_nis_client_not_installed"
FSN="nix_ensure_nis_client_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.3.4"
RNA="Ensure telnet client is not installed"
profile="L1S L1W"
REC="ensure_telnet_client_not_installed"
FSN="nix_ensure_telnet_client_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.3.5"
RNA="Ensure tftp client is not installed"
profile="L1S L1W"
REC="ensure_tftp_client_not_installed"
FSN="nix_ensure_tftp_client_not_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 3 - Network

# 3.1 - Configure Network Devices

RN="3.1.1"
RNA="Ensure IPv6 status is identified"
profile="L1S L1W"
REC="fed_ensure_ipv6_status_identified"
FSN="nix_fed_ensure_ipv6_status_identified.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.1.2"
RNA="Ensure wireless interfaces are disabled"
profile="L1S"
REC="ensure_wireless_interfaces_disabled"
FSN="nix_ensure_wireless_interfaces_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.1.3"
RNA="Ensure bluetooth services are not in use"
profile="L1S L2W"
REC="fed28_ensure_bluetooth_services_not_in_use"
FSN="nix_fed28_ensure_bluetooth_services_not_in_use.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 3.2 - Configure Network Kernel Modules

RN="3.2.1"
RNA="Ensure dccp kernel module is not available"
profile="L2S L2W"
REC="ensure_dccp_disabled"
FSN="nix_ensure_dccp_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.2.2"
RNA="Ensure tipc kernel module is not available"
profile="L2S L2W"
REC="ensure_tipc_disabled"
FSN="nix_ensure_tipc_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.2.3"
RNA="Ensure rds kernel module is not available"
profile="L2S L2W"
REC="ensure_rds_disabled"
FSN="nix_ensure_rds_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.2.4"
RNA="Ensure sctp kernel module is not available"
profile="L2S L2W"
REC="ensure_sctp_disabled"
FSN="nix_ensure_sctp_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 3.3 - Configure Network Kernel Parameters

RN="3.3.1"
RNA="Ensure ip forwarding is disabled"
profile="L1S L1W"
REC="ensure_ip_forwarding_disabled"
FSN="nix_ensure_ip_forwarding_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.2"
RNA="Ensure packet redirect sending is disabled"
profile="L1S L1W"
REC="ensure_packet_redirect_sending_disabled"
FSN="nix_ensure_packet_redirect_sending_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.3"
RNA="Ensure bogus icmp responses are ignored"
profile="L1S L1W"
REC="ensure_bogus_icmp_responses_ignored"
FSN="nix_ensure_bogus_icmp_responses_ignored.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.4"
RNA="Ensure broadcast icmp requests are ignored"
profile="L1S L1W"
REC="ensure_broadcast_icmp_requests_ignored"
FSN="nix_ensure_broadcast_icmp_requests_ignored.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.5"
RNA="Ensure icmp redirects are not accepted"
profile="L1S L1W"
REC="ensure_icmp_redirects_not_accepted"
FSN="nix_ensure_icmp_redirects_not_accepted.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.6"
RNA="Ensure secure icmp redirects are not accepted"
profile="L1S L1W"
REC="ensure_secure_icmp_redirects_not_accepted"
FSN="nix_ensure_secure_icmp_redirects_not_accepted.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.7"
RNA="Ensure reverse path filtering is enabled"
profile="L1S L1W"
REC="ensure_reverse_path_filtering_enabled"
FSN="nix_ensure_reverse_path_filtering_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.8"
RNA="Ensure source routed packets are not accepted"
profile="L1S L1W"
REC="ensure_source_routed_packets_not_accepted"
FSN="nix_ensure_source_routed_packets_not_accepted.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.9"
RNA="Ensure suspicious packets are logged"
profile="L1S L1W"
REC="ensure_suspicious_packets_logged"
FSN="nix_ensure_suspicious_packets_logged.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.10"
RNA="Ensure tcp syn cookies is enabled"
profile="L1S L1W"
REC="ensure_tcp_syn_cookies_enabled"
FSN="nix_ensure_tcp_syn_cookies_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.11"
RNA="Ensure ipv6 router advertisements are not accepted"
profile="L1S L1W"
REC="ensure_ipv6_router_advertisements_not_accepted"
FSN="nix_ensure_ipv6_router_advertisements_not_accepted.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 3.4 - Configure Host Based Firewall

# 3.4.1 - Configure a firewall utility

RN="3.4.1.1"
RNA="Ensure nftables is installed"
profile="L1S L1W"
REC="fed28_ensure_nftables_installed"
FSN="nix_fed28_ensure_nftables_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.4.1.2"
RNA="Ensure a single firewall configuration utility is in use"
profile="L1S L1W"
REC="fed_ensure_single_firewall_configuration_utility"
FSN="nix_fed_ensure_single_firewall_configuration_utility.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 3.4.2 - Configure firewall rules

RN="3.4.2.1"
RNA="Ensure nftables base chains exist"
profile="L1S L1W"
REC="fed_ensure_nftables_base_chains_exist"
FSN="nix_fed_ensure_nftables_base_chains_exist.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.4.2.2"
RNA="Ensure host based firewall loopback traffic is configured"
profile="L1S L1W"
REC="fed28_ensure_nftables_loopback_traffic_is_configured"
FSN="nix_fed28_ensure_nftables_loopback_traffic_is_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.4.2.3"
RNA="Ensure firewalld drops unnecessary services and ports"
profile="L1S L1W"
REC="fed_ensure_firewalld_drops_unnecessary_services_and_ports"
FSN="nix_fed_ensure_firewalld_drops_unnecessary_services_and_ports.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.4.2.4"
RNA="Ensure nftables established connections are configured"
profile="L1S L1W"
REC="fed_ensure_nftables_outbound_established_connections_configured"
FSN="nix_fed_ensure_nftables_outbound_established_connections_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.4.2.5"
RNA="Ensure nftables default deny firewall policy"
profile="L1S L1W"
REC="fed_ensure_nftables_default_deny_firewall_policy"
FSN="nix_fed_ensure_nftables_default_deny_firewall_policy.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4 - Access, Authentication and Authorization

# 4.1 - Configure job schedulers

# 4.1.1 - Configure cron

RN="4.1.1.1"
RNA="Ensure cron daemon is enabled and active"
profile="L1S L1W"
REC="fed_ensure_cron_daemon_enabled"
FSN="nix_fed_ensure_cron_daemon_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.1.2"
RNA="Ensure permissions on /etc/crontab are configured"
profile="L1S L1W"
REC="ensure_permissions_crontab_configured"
FSN="nix_ensure_permissions_crontab_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.1.3"
RNA="Ensure permissions on /etc/cron.hourly are configured"
profile="L1S L1W"
REC="ensure_permissions_cron_hourly_configured"
FSN="nix_ensure_permissions_cron_hourly_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.1.4"
RNA="Ensure permissions on /etc/cron.daily are configured"
profile="L1S L1W"
REC="ensure_permissions_cron_daily_configured"
FSN="nix_ensure_permissions_cron_daily_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.1.5"
RNA="Ensure permissions on /etc/cron.weekly are configured"
profile="L1S L1W"
REC="ensure_permissions_cron_weekly_configured"
FSN="nix_ensure_permissions_cron_weekly_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.1.6"
RNA="Ensure permissions on /etc/cron.monthly are configured"
profile="L1S L1W"
REC="ensure_permissions_cron_monthly_configured"
FSN="nix_ensure_permissions_cron_monthly_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.1.7"
RNA="Ensure permissions on /etc/cron.d are configured"
profile="L1S L1W"
REC="ensure_permissions_cron_d_configured"
FSN="nix_ensure_permissions_cron_d_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.1.8"
RNA="Ensure crontab is restricted to authorized users"
profile="L1S L1W"
REC="fed_ensure_cron_restricted_authorized_users"
FSN="nix_fed_ensure_cron_restricted_authorized_users.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.1.2 - Configure at

RN="4.1.2.1"
RNA="Ensure at is restricted to authorized users"
profile="L1S L1W"
REC="fed_ensure_at_restricted_authorized_users"
FSN="nix_fed_ensure_at_restricted_authorized_users.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.2 - Configure SSH Server

RN="4.2.1"
RNA="Ensure permissions on /etc/ssh/sshd_config are configured"
profile="L1S L1W"
REC="ensure_permissions_sshd_config_configured"
FSN="nix_ensure_permissions_sshd_config_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.2"
RNA="Ensure permissions on SSH private host key files are configured"
profile="L1S L1W"
REC="ensure_permissions_ssh_private_hostkey_files_configured"
FSN="nix_ensure_permissions_ssh_private_hostkey_files_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.3"
RNA="Ensure permissions on SSH public host key files are configured"
profile="L1S L1W"
REC="ensure_permissions_ssh_public_hostkey_files_configured"
FSN="nix_ensure_permissions_ssh_public_hostkey_files_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.4"
RNA="Ensure sshd access is configured"
profile="L1S L1W"
REC="ensure_sshd_access_configured"
FSN="nix_ensure_sshd_access_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.5"
RNA="Ensure sshd Banner is configured"
profile="L1S L1W"
REC="ensure_ssh_warning_banner_configured"
FSN="nix_ensure_ssh_warning_banner_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.6"
RNA="Ensure sshd Ciphers are configured"
profile="L1S L1W"
REC="ssh7_ensure_strong_ciphers_used"
FSN="nix_ssh7_ensure_strong_ciphers_used.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.7"
RNA="Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured"
profile="L1S L1W"
REC="ensure_sshd_clientaliveinterval_and_clientalivecountmax_configured"
FSN="nix_ensure_sshd_clientaliveinterval_and_clientalivecountmax_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.8"
RNA="Ensure sshd DisableForwarding is enabled"
profile="L1W L2S"
REC="ensure_sshd_disableforwarding_enabled"
FSN="nix_ensure_sshd_disableforwarding_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.9"
RNA="Ensure sshd HostbasedAuthentication is disabled"
profile="L1S L1W"
REC="ensure_sshd_hostbasedauthentication_disabled"
FSN="nix_ensure_sshd_hostbasedauthentication_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.10"
RNA="Ensure sshd IgnoreRhosts is enabled"
profile="L1S L1W"
REC="ensure_sshd_ignorerhosts_enabled"
FSN="nix_ensure_sshd_ignorerhosts_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.11"
RNA="Ensure sshd KexAlgorithms is configured"
profile="L1S L1W"
REC="ssh7_ensure_strong_key_exchange_algorithms_used"
FSN="nix_ssh7_ensure_strong_key_exchange_algorithms_used.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.12"
RNA="Ensure sshd LoginGraceTime is configured"
profile="L1S L1W"
REC="ensure_sshd_logingracetime_configured"
FSN="nix_ensure_sshd_logingracetime_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.13"
RNA="Ensure sshd LogLevel is configured"
profile="L1S L1W"
REC="ensure_sshd_loglevel_configured"
FSN="nix_ensure_sshd_loglevel_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.14"
RNA="Ensure sshd MACs are configured"
profile="L1S L1W"
REC="ssh7_ensure_strong_mac_algorithms_used"
FSN="nix_ssh7_ensure_strong_mac_algorithms_used.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.15"
RNA="Ensure sshd MaxAuthTries is configured"
profile="L1S L1W"
REC="ensure_sshd_maxauthtries_configured"
FSN="nix_ensure_sshd_maxauthtries_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.16"
RNA="Ensure sshd MaxSessions is configured"
profile="L1S L1W"
REC="ensure_sshd_maxsessions_configured"
FSN="nix_ensure_sshd_maxsessions_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.17"
RNA="Ensure sshd MaxStartups is configured"
profile="L1S L1W"
REC="ensure_sshd_maxstartups_configured"
FSN="nix_ensure_sshd_maxstartups_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.18"
RNA="Ensure sshd PermitEmptyPasswords is disabled"
profile="L1S L1W"
REC="ensure_sshd_permitemptypasswords_disabled"
FSN="nix_ensure_sshd_permitemptypasswords_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.19"
RNA="Ensure sshd PermitRootLogin is disabled"
profile="L1S L1W"
REC="ensure_sshd_permitrootlogin_disabled"
FSN="nix_ensure_sshd_permitrootlogin_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.20"
RNA="Ensure sshd PermitUserEnvironment is disabled"
profile="L1S L1W"
REC="ensure_sshd_permituserenvironment_disabled"
FSN="nix_ensure_sshd_permituserenvironment_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.21"
RNA="Ensure sshd UsePAM is enabled"
profile="L1S L1W"
REC="ensure_sshd_usepam_enabled"
FSN="nix_ensure_sshd_usepam_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.2.22"
RNA="Ensure sshd crypto_policy is not set"
profile="L1S L1W"
REC="fed_ensure_system-wide_crypto_policy_not_over-ridden"
FSN="nix_fed_ensure_system-wide_crypto_policy_not_over-ridden.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.3 - Configure privilege escalation

RN="4.3.1"
RNA="Ensure sudo is installed"
profile="L1S L1W"
REC="ensure_sudo_installed"
FSN="nix_ensure_sudo_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.3.2"
RNA="Ensure sudo commands use pty"
profile="L1S L1W"
REC="ensure_sudo_commands_pty"
FSN="nix_ensure_sudo_commands_pty.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.3.3"
RNA="Ensure sudo log file exists"
profile="L1S L1W"
REC="ensure_sudo_logfile_exists"
FSN="nix_ensure_sudo_logfile_exists.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.3.4"
RNA="Ensure users must provide password for escalation"
profile="L2S L2W"
REC="ensure_user_must_provide_password_for_escalation"
FSN="nix_ensure_user_must_provide_password_for_escalation.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.3.5"
RNA="Ensure re-authentication for privilege escalation is not disabled globally"
profile="L1S L1W"
REC="ensure_reauth_for_escalation_not_disabled"
FSN="nix_ensure_reauth_for_escalation_not_disabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.3.6"
RNA="Ensure sudo authentication timeout is configured correctly"
profile="L1S L1W"
REC="ensure_sudo_authentication_timeout_configured"
FSN="nix_ensure_sudo_authentication_timeout_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.3.7"
RNA="Ensure access to the su command is restricted"
profile="L1S L1W"
REC="ensure_access_su_command_restricted"
FSN="nix_ensure_access_su_command_restricted.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.4 - Configure Pluggable Authentication Modules

# 4.4.1 - Configure PAM software packages

RN="4.4.1.1"
RNA="Ensure latest version of pam is installed"
profile="L1S L1W"
REC="fed28_ensure_latest_version_pam_installed"
FSN="nix_fed28_ensure_latest_version_pam_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.1.2"
RNA="Ensure latest version of authselect is installed"
profile="L1S L1W"
REC="ensure_authselect_installed"
FSN="nix_ensure_authselect_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.4.2 - Configure authselect

RN="4.4.2.1"
RNA="Ensure active authselect profile includes pam modules"
profile="L1S L1W"
REC="fed_ensure_custom_authselect_profile_used"
FSN="nix_fed_ensure_custom_authselect_profile_used.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.2.2"
RNA="Ensure pam_faillock module is enabled"
profile="L1S L1W"
REC="fed_ensure_pam_faillock_module_enabled"
FSN="nix_fed_ensure_pam_faillock_module_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.2.3"
RNA="Ensure pam_pwquality module is enabled"
profile="L1S L1W"
REC="fed_ensure_pam_pwquality_module_enabled"
FSN="nix_fed_ensure_pam_pwquality_module_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.2.4"
RNA="Ensure pam_pwhistory module is enabled"
profile="L1S L1W"
REC="fed_ensure_pam_pwhistory_module_enabled"
FSN="nix_fed_ensure_pam_pwhistory_module_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.2.5"
RNA="Ensure pam_unix module is enabled"
profile="L1S L1W"
REC="fed_ensure_pam_unix_module_enabled"
FSN="nix_fed_ensure_pam_unix_module_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.4.3 - Configure pluggable module arguments

# 4.4.3.1 - Configure pam_faillock module

RN="4.4.3.1.1"
RNA="Ensure password failed attempts lockout is configured"
profile="L1S L1W"
REC="fed_ensure_password_failed_attempts_lockout_configured"
FSN="nix_fed_ensure_password_failed_attempts_lockout_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.1.2"
RNA="Ensure password unlock time is configured"
profile="L1S L1W"
REC="fed_ensure_password_unlock_time_configured"
FSN="nix_fed_ensure_password_unlock_time_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.1.3"
RNA="Ensure password failed attempts lockout includes root account"
profile="L2S L2W"
REC="fed_ensure_password_failed_attempts_lockout_includes_root"
FSN="nix_fed_ensure_password_failed_attempts_lockout_includes_root.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.4.3.2 - Configure pam_pwquality module

RN="4.4.3.2.1"
RNA="Ensure password number of changed characters is configured"
profile="L1S L1W"
REC="ensure_number_changed_chars_password_configured"
FSN="nix_ensure_number_changed_chars_password_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.2.2"
RNA="Ensure password length is configured"
profile="L1S L1W"
REC="fed_ensure_password_creation_requirements_configured"
FSN="nix_fed_ensure_password_creation_requirements_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.2.3"
RNA="Ensure password complexity is configured"
profile="L1S L1W"
REC="fed_ensure_password_complexity_configured"
FSN="nix_fed_ensure_password_complexity_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.2.4"
RNA="Ensure password same consecutive characters is configured"
profile="L1S L1W"
REC="ensure_max_number_consecutive_chars_password_configured"
FSN="nix_ensure_max_number_consecutive_chars_password_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.2.5"
RNA="Ensure password maximum sequential characters is configured"
profile="L1S L1W"
REC="fed_ensure_password_maximum_sequential_characters_configured"
FSN="nix_fed_ensure_password_maximum_sequential_characters_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.2.6"
RNA="Ensure password dictionary check is enabled"
profile="L1S L1W"
REC="ensure_prevent_dictionary_words_in_password_configured"
FSN="nix_ensure_prevent_dictionary_words_in_password_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.2.7"
RNA="Ensure password quality is enforced for the root user"
profile="L1S L1W"
REC="fed_ensure_password_quality_enforced_for_root_user"
FSN="nix_fed_ensure_password_quality_enforced_for_root_user.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.4.3.3 - Configure pam_pwhistory module

RN="4.4.3.3.1"
RNA="Ensure password history remember is configured"
profile="L1S L1W"
REC="fed_ensure_password_history_remember_configured"
FSN="nix_fed_ensure_password_history_remember_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.3.2"
RNA="Ensure password history is enforced for the root user"
profile="L1S L1W"
REC="fed_ensure_password_history_enforced_for_root_user"
FSN="nix_fed_ensure_password_history_enforced_for_root_user.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.3.3"
RNA="Ensure pam_pwhistory includes use_authtok"
profile="L1S L1W"
REC="fed_ensure_pam_pwhistory_includes_use_authtok"
FSN="nix_fed_ensure_pam_pwhistory_includes_use_authtok.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.4.3.4 - Configure pam_unix module

RN="4.4.3.4.1"
RNA="Ensure pam_unix does not include nullok"
profile="L1S L1W"
REC="fed_ensure_pam_unix_does_not_include_nullok"
FSN="nix_fed_ensure_pam_unix_does_not_include_nullok.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.4.2"
RNA="Ensure pam_unix does not include remember"
profile="L1S L1W"
REC="fed_ensure_pam_unix_does_not_include_remember"
FSN="nix_fed_ensure_pam_unix_does_not_include_remember.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.4.3"
RNA="Ensure pam_unix includes a strong password hashing algorithm"
profile="L1S L1W"
REC="fed_ensure_pam_unix_incldues_strong_password_hashing_algorithm"
FSN="nix_fed_ensure_pam_unix_incldues_strong_password_hashing_algorithm.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.4.3.4.4"
RNA="Ensure pam_unix includes use_authtok"
profile="L1S L1W"
REC="fed_ensure_pam_unix_includes_use_authtok"
FSN="nix_fed_ensure_pam_unix_includes_use_authtok.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.5 - User Accounts and Environment

# 4.5.1 - Configure shadow password suite parameters

RN="4.5.1.1"
RNA="Ensure strong password hashing algorithm is configured"
profile="L1S L1W"
REC="fed28_ensure_password_hashing_algorithm_sha512"
FSN="nix_fed28_ensure_password_hashing_algorithm_sha512.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.5.1.2"
RNA="Ensure password expiration is 365 days or less"
profile="L1S L1W"
REC="ensure_password_expiration_365_days_less"
FSN="nix_ensure_password_expiration_365_days_less.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.5.1.3"
RNA="Ensure password expiration warning days is 7 or more"
profile="L1S L1W"
REC="ensure_expiration_warning_days_7_more"
FSN="nix_ensure_expiration_warning_days_7_more.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.5.1.4"
RNA="Ensure inactive password lock is 30 days or less"
profile="L1S L1W"
REC="ensure_inactive_password_lock_30_days_less"
FSN="nix_ensure_inactive_password_lock_30_days_less.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.5.1.5"
RNA="Ensure all users last password change date is in the past"
profile="L1S L1W"
REC="ensure_all_users_last_password_change_in_past"
FSN="nix_ensure_all_users_last_password_change_in_past.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.5.2 - Configure root and system accounts and environment

RN="4.5.2.1"
RNA="Ensure default group for the root account is GID 0"
profile="L1S L1W"
REC="ensure_default_group_for_root_gid_0"
FSN="nix_ensure_default_group_for_root_gid_0.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.5.2.2"
RNA="Ensure root user umask is configured"
profile="L1S L1W"
REC="fed_ensure_user_root_umask_configured"
FSN="nix_fed_ensure_user_root_umask_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.5.2.3"
RNA="Ensure system accounts are secured"
profile="L1S L1W"
REC="ensure_system_accounts_secured"
FSN="nix_ensure_system_accounts_secured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.5.2.4"
RNA="Ensure root password is set"
profile="L1S L1W"
REC="fed_ensure_root_password_is_set"
FSN="nix_fed_ensure_root_password_is_set.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 4.5.3 - Configure user default environment

RN="4.5.3.1"
RNA="Ensure nologin is not listed in /etc/shells"
profile="L2S L2W"
REC="ensure_nologin_not_listed_etc_shells"
FSN="nix_ensure_nologin_not_listed_etc_shells.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.5.3.2"
RNA="Ensure default user shell timeout is configured"
profile="L1S L1W"
REC="ensure_default_user_shell_timeout_configured"
FSN="nix_ensure_default_user_shell_timeout_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.5.3.3"
RNA="Ensure default user umask is configured"
profile="L1S L1W"
REC="ensure_default_user_umask_027_more_restrictive_v2"
FSN="nix_ensure_default_user_umask_027_more_restrictive_v2.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 5 - Logging and Auditing

# 5.1 - Configure Logging

RN="5.1.3"
RNA="Ensure logrotate is configured"
profile="L1S L1W"
REC="ensure_logrotate_configured"
FSN="nix_ensure_logrotate_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.4"
RNA="Ensure all logfiles have appropriate access configured"
profile="L1S L1W"
REC="ensure_logfiles_appropriate_permissions_and_ownership"
FSN="nix_ensure_logfiles_appropriate_permissions_and_ownership.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 5.1.1 - Configure rsyslog

RN="5.1.1.1"
RNA="Ensure rsyslog is installed"
profile="L1S L1W"
REC="ensure_rsyslog_installed"
FSN="nix_ensure_rsyslog_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.1.2"
RNA="Ensure rsyslog service is enabled"
profile="L1S L1W"
REC="ensure_rsyslog_service_enabled_running"
FSN="nix_ensure_rsyslog_service_enabled_running.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.1.3"
RNA="Ensure journald is configured to send logs to rsyslog"
profile="L1S L1W"
REC="ensure_journald_configured_send_logs_rsyslog"
FSN="nix_ensure_journald_configured_send_logs_rsyslog.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.1.4"
RNA="Ensure rsyslog default file permissions are configured"
profile="L1S L1W"
REC="ensure_rsyslog_default_file_permissions_configured"
FSN="nix_ensure_rsyslog_default_file_permissions_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.1.5"
RNA="Ensure logging is configured"
profile="L1S L1W"
REC="ensure_logging_configured"
FSN="nix_ensure_logging_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.1.6"
RNA="Ensure rsyslog is configured to send logs to a remote log host"
profile="L1S L1W"
REC="ensure_rsyslog_configured_send_logs_remote_host"
FSN="nix_ensure_rsyslog_configured_send_logs_remote_host.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.1.7"
RNA="Ensure rsyslog is not configured to receive logs from a remote client"
profile="L1S L1W"
REC="ensure_remote_rsyslog_messages_only_accepted_designated_host"
FSN="nix_ensure_remote_rsyslog_messages_only_accepted_designated_host.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 5.1.2 - Configure journald

RN="5.1.2.2"
RNA="Ensure journald service is enabled"
profile="L1S L1W"
REC="ensure_journald_service_enabled"
FSN="nix_ensure_journald_service_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.2.3"
RNA="Ensure journald is configured to compress large log files"
profile="L1S L1W"
REC="ensure_journald_configured_compress_large_files"
FSN="nix_ensure_journald_configured_compress_large_files.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.2.4"
RNA="Ensure journald is configured to write logfiles to persistent disk"
profile="L1S L1W"
REC="ensure_journald_configured_write_logfiles_disk"
FSN="nix_ensure_journald_configured_write_logfiles_disk.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.2.5"
RNA="Ensure journald is not configured to send logs to rsyslog"
profile="L1S L1W"
REC="ensure_journald_configured_not_send_logs_rsyslog"
FSN="nix_ensure_journald_configured_not_send_logs_rsyslog.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.2.6"
RNA="Ensure journald log rotation is configured per site policy"
profile="L1S L1W"
REC="ensure_journald_log_rotation_configured"
FSN="nix_ensure_journald_log_rotation_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 5.1.2.1 - Ensure journald is configured to send logs to a remote log host

RN="5.1.2.1.1"
RNA="Ensure systemd-journal-remote is installed"
profile="L1S L1W"
REC="ensure_systemd-journal-remote_installed"
FSN="nix_ensure_systemd-journal-remote_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.2.1.2"
RNA="Ensure systemd-journal-remote is configured"
profile="L1S L1W"
REC="ensure_systemd-journal-remote_configured"
FSN="nix_ensure_systemd-journal-remote_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.2.1.3"
RNA="Ensure systemd-journal-remote is enabled"
profile="L1S L1W"
REC="ensure_systemd-journal-remote_service_enabled"
FSN="nix_ensure_systemd-journal-remote_service_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.2.1.4"
RNA="Ensure journald is not configured to receive logs from a remote client"
profile="L1S L1W"
REC="ensure_journald_not_configured_receive_logs_from_remote_client"
FSN="nix_ensure_journald_not_configured_receive_logs_from_remote_client.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 5.2 - Configure System Accounting (auditd)

# 5.2.1 - Ensure auditing is enabled

RN="5.2.1.1"
RNA="Ensure audit is installed"
profile="L2S L2W"
REC="ensure_auditd_installed"
FSN="nix_ensure_auditd_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.1.2"
RNA="Ensure auditing for processes that start prior to auditd is enabled"
profile="L2S L2W"
REC="fed_ensure_auditing_processes_start_prior_auditd_enabled"
FSN="nix_fed_ensure_auditing_processes_start_prior_auditd_enabled.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.1.3"
RNA="Ensure audit_backlog_limit is sufficient"
profile="L2S L2W"
REC="fed_ensure_audit_backlog_limit_sufficient"
FSN="nix_fed_ensure_audit_backlog_limit_sufficient.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.1.4"
RNA="Ensure auditd service is enabled"
profile="L2S L2W"
REC="ensure_auditd_service_enabled_running"
FSN="nix_ensure_auditd_service_enabled_running.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 5.2.2 - Configure Data Retention

RN="5.2.2.1"
RNA="Ensure audit log storage size is configured"
profile="L2S L2W"
REC="ensure_audit_log_storage_size_configured"
FSN="nix_ensure_audit_log_storage_size_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.2.2"
RNA="Ensure audit logs are not automatically deleted"
profile="L2S L2W"
REC="ensure_audit_logs_not_automatically_deleted"
FSN="nix_ensure_audit_logs_not_automatically_deleted.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.2.3"
RNA="Ensure system is disabled when audit logs are full"
profile="L2S L2W"
REC="fed_ensure_system_is_disabled_when_audit_logs_are_full"
FSN="nix_fed_ensure_system_is_disabled_when_audit_logs_are_full.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.2.4"
RNA="Ensure system warns when audit logs are low on space"
profile="L2S L2W"
REC="ensure_system_disabled_audit_logs_full"
FSN="nix_ensure_system_disabled_audit_logs_full.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 5.2.3 - Configure auditd rules

RN="5.2.3.1"
RNA="Ensure changes to system administration scope (sudoers) is collected"
profile="L2S L2W"
REC="ensure_changes_sudoers_collected"
FSN="nix_ensure_changes_sudoers_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.2"
RNA="Ensure actions as another user are always logged"
profile="L2S L2W"
REC="ensure_actions_another_user_always_logged"
FSN="nix_ensure_actions_another_user_always_logged.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.3"
RNA="Ensure events that modify the sudo log file are collected"
profile="L2S L2W"
REC="ensure_events_modify_sudo_log_file_collected"
FSN="nix_ensure_events_modify_sudo_log_file_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.4"
RNA="Ensure events that modify date and time information are collected"
profile="L2S L2W"
REC="ensure_events_modify_date_time_information_collected"
FSN="nix_ensure_events_modify_date_time_information_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.5"
RNA="Ensure events that modify the system's network environment are collected"
profile="L2S L2W"
REC="fed_ensure_events_modify_systems_network_environment_collected"
FSN="nix_fed_ensure_events_modify_systems_network_environment_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.6"
RNA="Ensure use of privileged commands are collected"
profile="L2S L2W"
REC="fed_ensure_use_privileged_commands_collected"
FSN="nix_fed_ensure_use_privileged_commands_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.7"
RNA="Ensure unsuccessful file access attempts are collected"
profile="L2S L2W"
REC="ensure_unsuccessful_file_access_attempts_collected"
FSN="nix_ensure_unsuccessful_file_access_attempts_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.8"
RNA="Ensure events that modify user/group information are collected"
profile="L2S L2W"
REC="ensure_events_modify_user_group_information_collected"
FSN="nix_ensure_events_modify_user_group_information_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.9"
RNA="Ensure discretionary access control permission modification events are collected"
profile="L2S L2W"
REC="ensure_dac_permission_modification_events_collected"
FSN="nix_ensure_dac_permission_modification_events_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.10"
RNA="Ensure successful file system mounts are collected"
profile="L2S L2W"
REC="ensure_successful_file_system_mounts_collected"
FSN="nix_ensure_successful_file_system_mounts_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.11"
RNA="Ensure session initiation information is collected"
profile="L2S L2W"
REC="ensure_session_initiation_information_collected"
FSN="nix_ensure_session_initiation_information_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.12"
RNA="Ensure login and logout events are collected"
profile="L2S L2W"
REC="fed_ensure_login_logout_events_collected"
FSN="nix_fed_ensure_login_logout_events_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.13"
RNA="Ensure file deletion events by users are collected"
profile="L2S L2W"
REC="fed_ensure_file_deletion_events_by_users_collected"
FSN="nix_fed_ensure_file_deletion_events_by_users_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.14"
RNA="Ensure events that modify the system's Mandatory Access Controls are collected"
profile="L2S L2W"
REC="fed_ensure_events_modify_systems_mac_collected"
FSN="nix_fed_ensure_events_modify_systems_mac_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.15"
RNA="Ensure successful and unsuccessful attempts to use the chcon command are recorded"
profile="L2S L2W"
REC="ensure_successful_and_unsuccessful_use_of_chcon_command_recorded"
FSN="nix_ensure_successful_and_unsuccessful_use_of_chcon_command_recorded.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.16"
RNA="Ensure successful and unsuccessful attempts to use the setfacl command are recorded"
profile="L2S L2W"
REC="ensure_successful_and_unsuccessful_use_of_setfacl_command_recorded"
FSN="nix_ensure_successful_and_unsuccessful_use_of_setfacl_command_recorded.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.17"
RNA="Ensure successful and unsuccessful attempts to use the chacl command are recorded"
profile="L2S L2W"
REC="ensure_successful_and_unsuccessful_use_of_chacl_command_recorded"
FSN="nix_ensure_successful_and_unsuccessful_use_of_chacl_command_recorded.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.18"
RNA="Ensure successful and unsuccessful attempts to use the usermod command are recorded"
profile="L2S L2W"
REC="ensure_successful_and_unsuccessful_use_of_usermod_commands_recorded"
FSN="nix_ensure_successful_and_unsuccessful_use_of_usermod_commands_recorded.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.19"
RNA="Ensure kernel module loading unloading and modification is collected"
profile="L2S L2W"
REC="ensure_kernel_module_loading_unloading_collected"
FSN="nix_ensure_kernel_module_loading_unloading_collected.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.20"
RNA="Ensure the audit configuration is immutable"
profile="L2S L2W"
REC="ensure_audit_configuration_immutable"
FSN="nix_ensure_audit_configuration_immutable.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.3.21"
RNA="Ensure the running and on disk configuration is the same"
profile="L2S L2W"
REC="ensure_running_and_disk_configuration"
FSN="nix_ensure_running_and_disk_configuration.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 5.2.4 - Configure auditd file access

RN="5.2.4.1"
RNA="Ensure the audit log directory is 0750 or more restrictive"
profile="L2S L2W"
REC="ensure_audit_log_dir_750_or_more_restricted"
FSN="nix_ensure_audit_log_dir_750_or_more_restricted.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.4.2"
RNA="Ensure audit log files are mode 0640 or less permissive"
profile="L2S L2W"
REC="ensure_audit_config_files_mode_640"
FSN="nix_ensure_audit_config_files_mode_640.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.4.3"
RNA="Ensure only authorized users own audit log files"
profile="L2S L2W"
REC="ensure_only_authorized_users_own_audit_log_files"
FSN="nix_ensure_only_authorized_users_own_audit_log_files.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.4.4"
RNA="Ensure only authorized groups are assigned ownership of audit log files"
profile="L2S L2W"
REC="ensure_only_authorized_groups_assigned_ownership_audit_log_files"
FSN="nix_ensure_only_authorized_groups_assigned_ownership_audit_log_files.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.4.5"
RNA="Ensure audit configuration files are 640 or more restrictive"
profile="L2S L2W"
REC="ensure_audit_config_files_mode_640"
FSN="nix_ensure_audit_config_files_mode_640.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.4.6"
RNA="Ensure audit configuration files are owned by root"
profile="L2S L2W"
REC="ensure_audit_config_files_owned_root"
FSN="nix_ensure_audit_config_files_owned_root.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.4.7"
RNA="Ensure audit configuration files belong to group root"
profile="L2S L2W"
REC="ensure_audit_config_files_group_root"
FSN="nix_ensure_audit_config_files_group_root.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.4.8"
RNA="Ensure audit tools are 755 or more restrictive"
profile="L2S L2W"
REC="ensure_audit_tools_files_mode_755"
FSN="nix_ensure_audit_tools_files_mode_755.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.4.9"
RNA="Ensure audit tools are owned by root"
profile="L2S L2W"
REC="ensure_audit_tools_files_owned_root"
FSN="nix_ensure_audit_tools_files_owned_root.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.4.10"
RNA="Ensure audit tools belong to group root"
profile="L2S L2W"
REC="ensure_audit_tools_files_group_root"
FSN="nix_ensure_audit_tools_files_group_root.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 5.3 - Configure Integrity Checking

RN="5.3.1"
RNA="Ensure AIDE is installed"
profile="L1S L1W"
REC="ensure_aide_installed"
FSN="nix_ensure_aide_installed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.3.2"
RNA="Ensure filesystem integrity is regularly checked"
profile="L1S L1W"
REC="ensure_filesystem_integrity_regularly_checked"
FSN="nix_ensure_filesystem_integrity_regularly_checked.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.3.3"
RNA="Ensure cryptographic mechanisms are used to protect the integrity of audit tools"
profile="L1S L1W"
REC="fed_ensure_cryptographic_mechanisms_used_protect_integrity_audit_tools"
FSN="nix_fed_ensure_cryptographic_mechanisms_used_protect_integrity_audit_tools.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 6 - System Maintenance

# 6.1 - System File Permissions

RN="6.1.1"
RNA="Ensure permissions on /etc/passwd are configured"
profile="L1S L1W"
REC="ensure_perms_etc_passwd"
FSN="nix_ensure_perms_etc_passwd.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.2"
RNA="Ensure permissions on /etc/passwd- are configured"
profile="L1S L1W"
REC="ensure_perms_etc_passwd_dash"
FSN="nix_ensure_perms_etc_passwd_dash.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.3"
RNA="Ensure permissions on /etc/opasswd are configured"
profile="L1S L1W"
REC="ensure_perms_etc_opasswd_configured"
FSN="nix_ensure_perms_etc_opasswd_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.4"
RNA="Ensure permissions on /etc/group are configured"
profile="L1S L1W"
REC="ensure_perms_etc_group"
FSN="nix_ensure_perms_etc_group.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.5"
RNA="Ensure permissions on /etc/group- are configured"
profile="L1S L1W"
REC="ensure_perms_etc_group_dash"
FSN="nix_ensure_perms_etc_group_dash.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.6"
RNA="Ensure permissions on /etc/shadow are configured"
profile="L1S L1W"
REC="fed_ensure_perms_etc_shadow"
FSN="nix_fed_ensure_perms_etc_shadow.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.7"
RNA="Ensure permissions on /etc/shadow- are configured"
profile="L1S L1W"
REC="fed_ensure_perms_etc_shadow_dash"
FSN="nix_fed_ensure_perms_etc_shadow_dash.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.8"
RNA="Ensure permissions on /etc/gshadow are configured"
profile="L1S L1W"
REC="fed_ensure_perms_etc_gshadow_dash"
FSN="nix_fed_ensure_perms_etc_gshadow_dash.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.9"
RNA="Ensure permissions on /etc/gshadow- are configured"
profile="L1S L1W"
REC="fed_ensure_perms_etc_gshadow_dash"
FSN="nix_fed_ensure_perms_etc_gshadow_dash.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.10"
RNA="Ensure permissions on /etc/shells are configured"
profile="L1S L1W"
REC="ensure_perms_etc_shells_configured"
FSN="nix_ensure_perms_etc_shells_configured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.11"
RNA="Ensure world writable files and directories are secured"
profile="L1S L1W"
REC="ensure_world_writable_files_dirs_secured"
FSN="nix_ensure_world_writable_files_dirs_secured.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.12"
RNA="Ensure no unowned or ungrouped files or directories exist"
profile="L1S L1W"
REC="ensure_no_unowned_ungrouped_files_dirs_exist"
FSN="nix_ensure_no_unowned_ungrouped_files_dirs_exist.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.13"
RNA="Ensure SUID and SGID files are reviewed"
profile="L1S L1W"
REC="ensure_suid_sgid_files_reviewed"
FSN="nix_ensure_suid_sgid_files_reviewed.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.1.14"
RNA="Audit system file permissions"
profile="L2S L2W"
REC="audit_system_file_permissions"
FSN="nix_audit_system_file_permissions.sh"
total_recommendations=$((total_recommendations+1))
runrec

# 6.2 - Local User and Group Settings

RN="6.2.1"
RNA="Ensure accounts in /etc/passwd use shadowed passwords"
profile="L1S L1W"
REC="ensure_accounts_in_etc_passwd_use_shadowed_passwords"
FSN="nix_ensure_accounts_in_etc_passwd_use_shadowed_passwords.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.2"
RNA="Ensure /etc/shadow password fields are not empty"
profile="L1S L1W"
REC="ensure_etc_shadow_password_fields_not_empty"
FSN="nix_ensure_etc_shadow_password_fields_not_empty.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.3"
RNA="Ensure all groups in /etc/passwd exist in /etc/group"
profile="L1S L1W"
REC="ensure_all_groups_etc_passwd_exist_etc_group"
FSN="nix_ensure_all_groups_etc_passwd_exist_etc_group.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.4"
RNA="Ensure no duplicate UIDs exist"
profile="L1S L1W"
REC="ensure_no_duplicate_uid_exist"
FSN="nix_ensure_no_duplicate_uid_exist.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.5"
RNA="Ensure no duplicate GIDs exist"
profile="L1S L1W"
REC="ensure_no_duplicate_gid_exist"
FSN="nix_ensure_no_duplicate_gid_exist.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.6"
RNA="Ensure no duplicate user names exist"
profile="L1S L1W"
REC="ensure_no_duplicate_user_names_exist"
FSN="nix_ensure_no_duplicate_user_names_exist.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.7"
RNA="Ensure no duplicate group names exist"
profile="L1S L1W"
REC="ensure_no_duplicate_group_names_exist"
FSN="nix_ensure_no_duplicate_group_names_exist.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.8"
RNA="Ensure root path integrity"
profile="L1S L1W"
REC="ensure_root_path_integrity"
FSN="nix_ensure_root_path_integrity.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.9"
RNA="Ensure root is the only UID 0 account"
profile="L1S L1W"
REC="ensure_root_only_uid_0_account"
FSN="nix_ensure_root_only_uid_0_account.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.10"
RNA="Ensure local interactive user home directories are configured"
profile="L1S L1W"
REC="ensure_local_interactive_users_home_dir_mode_750"
FSN="nix_ensure_local_interactive_users_home_dir_mode_750.sh"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.11"
RNA="Ensure local interactive user dot files access is configured"
profile="L1S L1W"
REC="ensure_local_interactive_users_dot_files_not_group_world_writable"
FSN="nix_ensure_local_interactive_users_dot_files_not_group_world_writable.sh"
total_recommendations=$((total_recommendations+1))
runrec

# # End of recommendations

# Update grub.cfg permissions (again)
[ -f /boot/grub/grub.cfg ] && chmod og-rwx /boot/grub/grub.cfg
[ -f /boot/grub2/grub.cfg ] && chmod og-rwx /boot/grub2/grub.cfg

# Provide summary report
summary_report

# End of build kit
