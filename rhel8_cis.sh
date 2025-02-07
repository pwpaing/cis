#!/bin/bash

# Load configuration file
source config.sh

# Load OS release information
. /etc/os-release
MAIN_VERSION_ID="$(echo ${VERSION_ID} |cut -f1 -d'.')"

# Initialize counters
TOTAL=0; PASS=0; FAILED=0

# Function to print bold text
function echo_bold {
  echo -e "\e[1m${@} \e[0m"
}

# Function to print red text
function echo_red {
  echo -e "\e[91m${@} \e[0m"
}

# Function to print green text
function echo_green {
  echo -e "\e[92m${@} \e[0m"
}

# Function to check file owner and group
function check_owner_group {
  local file=$1
  local owner_group="root:root"
  stat -c '%U:%G' $1 | grep -q ${owner_group} || return
}

# Function to check if a kernel module is loaded
function check_kernel_module {
  local module=$1
  if lsmod | grep -q "^${module}"; then
    return 1
  else
    return 0
  fi
}

# Function to check partition options
function check_partition_option {
  local partition=$1
  local option=$2
  if mount | grep -E "\s${partition}\s" | grep -q "${option}"; then
    return 0
  else
    return 1
  fi
}

# Function to check if GPG keys are configured
function check_gpg_keys_configured {
  if rpm -q gpg-pubkey; then
    return 0
  else
    return 1
  fi
}

# Function to check if gpgcheck is globally activated
function check_gpgcheck_globally_activated {
  if grep -q "^gpgcheck=1" $YUM_CONF; then
    return 0
  else
    return 1
  fi
}

# Function to check if package manager repositories are configured
function check_package_manager_repositories_configured {
  if ls /etc/yum.repos.d/*.repo; then
    return 0
  else
    return 1
  fi
}

# Function to check if updates are installed
function check_updates_installed {
  if yum check-update; then
    return 0
  else
    return 1
  fi
}

# Function to check if bootloader password is set
function check_bootloader_password_set {
  if grep -q "^GRUB2_PASSWORD" $GRUB_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check bootloader permissions
function check_bootloader_permissions_configured {
  if [ $(stat -c "%a" $GRUB_CFG) -eq 600 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if ASLR is enabled
function check_aslr_enabled {
  if [ $(sysctl kernel.randomize_va_space | awk '{print $3}') -eq 2 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if ptrace_scope is restricted
function check_ptrace_scope_restricted {
  if [ $(sysctl kernel.yama.ptrace_scope | awk '{print $3}') -eq 1 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if core dump backtraces are disabled
function check_core_dump_backtraces_disabled {
  if [ $(sysctl fs.suid_dumpable | awk '{print $3}') -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if core dump storage is disabled
function check_core_dump_storage_disabled {
  if [ $(sysctl fs.suid_dumpable | awk '{print $3}') -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if SELinux is installed
function check_selinux_installed {
  if rpm -q libselinux; then
    return 0
  else
    return 1
  fi
}

# Function to check if SELinux is not disabled in bootloader
function check_selinux_not_disabled_in_bootloader {
  if ! grep -q "selinux=0" $GRUB_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if SELinux policy is configured
function check_selinux_policy_configured {
  if sestatus | grep -q "Loaded policy name"; then
    return 0
  else
    return 1
  fi
}

# Function to check if SELinux mode is not disabled
function check_selinux_mode_not_disabled {
  if [ $(getenforce) != "Disabled" ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if no unconfined services exist
function check_no_unconfined_services_exist {
  if ! ps -eZ | grep unconfined_service_t; then
    return 0
  else
    return 1
  fi
}

# Function to check if mcstrans is not installed
function check_mcstrans_not_installed {
  if ! rpm -q mcstrans; then
    return 0
  else
    return 1
  fi
}

# Function to check if crypto policy is not legacy
function check_crypto_policy_not_legacy {
  if ! update-crypto-policies --show | grep -q "LEGACY"; then
    return 0
  else
    return 1
  fi
}

# Function to check if crypto policy disables SHA1
function check_crypto_policy_disables_sha1 {
  if ! update-crypto-policies --show | grep -q "SHA1"; then
    return 0
  else
    return 1
  fi
}

# Function to check if crypto policy disables CBC
function check_crypto_policy_disables_cbc {
  if ! update-crypto-policies --show | grep -q "CBC"; then
    return 0
  else
    return 1
  fi
}

# Function to check if crypto policy disables weak MACs
function check_crypto_policy_disables_weak_macs {
  if ! update-crypto-policies --show | grep -q "MACS"; then
    return 0
  else
    return 1
  fi
}

# Function to check if MOTD is configured properly
function check_motd_configured_properly {
  if [ -f $MOTD ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if local login warning banner is configured
function check_local_login_warning_banner_configured {
  if [ -f $ISSUE ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if remote login warning banner is configured
function check_remote_login_warning_banner_configured {
  if [ -f $ISSUE_NET ]; then
    return 0
  else
    return 1
  fi
}

# Function to check access to MOTD
function check_access_motd {
  if [ -f $MOTD ] && [ $(stat -c "%a" $MOTD) -eq 644 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check access to ISSUE
function check_access_issue {
  if [ -f $ISSUE ] && [ $(stat -c "%a" $ISSUE) -eq 644 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check access to ISSUE_NET
function check_access_issue_net {
  if [ -f $ISSUE_NET ] && [ $(stat -c "%a" $ISSUE_NET) -eq 644 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if GDM login banner is configured
function check_gdm_login_banner {
  if grep -q "banner-message-enable=true" /etc/gdm/custom.conf; then
    return 0
  else
    return 1
  fi
}

# Function to check if GDM disable-user-list is enabled
function check_gdm_disable_user_list {
  if grep -q "disable-user-list=true" /etc/gdm/custom.conf; then
    return 0
  else
    return 1
  fi
}

# Function to check if GDM screen locks when the user is idle
function check_gdm_screen_lock_idle {
  if grep -q "idle-delay" /etc/gdm/custom.conf; then
    return 0
  else
    return 1
  fi
}

# Function to check if GDM screen locks cannot be overridden
function check_gdm_screen_lock_override {
  if grep -q "lock-delay" /etc/gdm/custom.conf; then
    return 0
  else
    return 1
  fi
}

# Function to check if GDM autorun-never is enabled
function check_gdm_autorun_never {
  if grep -q "autorun-never=true" /etc/gdm/custom.conf; then
    return 0
  else
    return 1
  fi
}

# Function to check if GDM autorun-never is not overridden
function check_gdm_autorun_never_override {
  if ! grep -q "autorun-never=false" /etc/gdm/custom.conf; then
    return 0
  else
    return 1
  fi
}

# Function to check if XDMCP is not enabled
function check_xdmcp_not_enabled {
  if ! grep -q "Enable=true" /etc/gdm/custom.conf; then
    return 0
  else
    return 1
  fi
}

# Function to check if time synchronization is in use
function check_time_sync_in_use {
  if systemctl is-active chronyd || systemctl is-active ntpd; then
    return 0
  else
    return 1
  fi
}

# Function to check if chrony is configured
function check_chrony_configured {
  if [ -f $CHRONY_CONF ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if chrony is not run as the root user
function check_chrony_not_root {
  if ! ps -u root | grep chronyd; then
    return 0
  else
    return 1
  fi
}

# Function to check if DHCP is not in use
function check_dhcp_not_in_use {
  if ! systemctl is-active dhcpd; then
    return 0
  else
    return 1
  fi
}

# Function to check if DNS is not in use
function check_dns_not_in_use {
  if ! systemctl is-active named; then
    return 0
  else
    return 1
  fi
}

# Function to check if dnsmasq is not in use
function check_dnsmasq_not_in_use {
  if ! systemctl is-active dnsmasq; then
    return 0
  else
    return 1
  fi
}

# Function to check if Samba is not in use
function check_samba_not_in_use {
  if ! systemctl is-active smb; then
    return 0
  else
    return 1
  fi
}

# Function to check if FTP is not in use
function check_ftp_not_in_use {
  if ! systemctl is-active vsftpd; then
    return 0
  else
    return 1
  fi
}

# Function to check if message access server is not in use
function check_message_access_not_in_use {
  if ! systemctl is-active dovecot; then
    return 0
  else
    return 1
  fi
}

# Function to check if NFS is not in use
function check_nfs_not_in_use {
  if ! systemctl is-active nfs; then
    return 0
  else
    return 1
  fi
}

# Function to check if NIS is not in use
function check_nis_not_in_use {
  if ! systemctl is-active ypserv; then
    return 0
  else
    return 1
  fi
}

# Function to check if rpcbind is not in use
function check_rpcbind_not_in_use {
  if ! systemctl is-active rpcbind; then
    return 0
  else
    return 1
  fi
}

# Function to check if rsync is not in use
function check_rsync_not_in_use {
  if ! systemctl is-active rsync; then
    return 0
  else
    return 1
  fi
}

# Function to check if SNMP is not in use
function check_snmp_not_in_use {
  if ! systemctl is-active snmpd; then
    return 0
  else
    return 1
  fi
}

# Function to check if telnet server is not in use
function check_telnet_server_not_in_use {
  if ! systemctl is-active telnet.socket; then
    return 0
  else
    return 1
  fi
}

# Function to check if TFTP server is not in use
function check_tftp_server_not_in_use {
  if ! systemctl is-active tftp.socket; then
    return 0
  else
    return 1
  fi
}

# Function to check if web proxy is not in use
function check_web_proxy_not_in_use {
  if ! systemctl is-active squid; then
    return 0
  else
    return 1
  fi
}

# Function to check if web server is not in use
function check_web_server_not_in_use {
  if ! systemctl is-active httpd; then
    return 0
  else
    return 1
  fi
}

# Function to check if xinetd is not in use
function check_xinetd_not_in_use {
  if ! systemctl is-active xinetd; then
    return 0
  else
    return 1
  fi
}

# Function to check if mail transfer agents are configured for local-only mode
function check_mail_transfer_agents_local_only {
  if grep -q "^inet_interfaces = loopback-only" /etc/postfix/main.cf; then
    return 0
  else
    return 1
  fi
}

# Function to check if only approved services are listening on a network interface
function check_approved_services_listening {
  if netstat -tuln | grep -q LISTEN; then
    return 0
  else
    return 1
  fi
}

# Function to check if FTP client is not installed
function check_ftp_client_not_installed {
  if ! rpm -q ftp; then
    return 0
  else
    return 1
  fi
}

# Function to check if NIS client is not installed
function check_nis_client_not_installed {
  if ! rpm -q ypbind; then
    return 0
  else
    return 1
  fi
}

# Function to check if telnet client is not installed
function check_telnet_client_not_installed {
  if ! rpm -q telnet; then
    return 0
  else
    return 1
  fi
}

# Function to check if TFTP client is not installed
function check_tftp_client_not_installed {
  if ! rpm -q tftp; then
    return 0
  else
    return 1
  fi
}

# Function to check if IPv6 status is identified
function check_ipv6_status_identified {
  if [ -f /proc/net/if_inet6 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if IP forwarding is disabled
function check_ip_forwarding_disabled {
  if [ $(sysctl net.ipv4.ip_forward | awk '{print $3}') -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if packet redirect sending is disabled
function check_packet_redirect_sending_disabled {
  if [ $(sysctl net.ipv4.conf.all.send_redirects | awk '{print $3}') -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if bogus ICMP responses are ignored
function check_bogus_icmp_responses_ignored {
  if [ $(sysctl net.ipv4.icmp_ignore_bogus_error_responses | awk '{print $3}') -eq 1 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if broadcast ICMP requests are ignored
function check_broadcast_icmp_requests_ignored {
  if [ $(sysctl net.ipv4.icmp_echo_ignore_broadcasts | awk '{print $3}') -eq 1 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if ICMP redirects are not accepted
function check_icmp_redirects_not_accepted {
  if [ $(sysctl net.ipv4.conf.all.accept_redirects | awk '{print $3}') -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if secure ICMP redirects are not accepted
function check_secure_icmp_redirects_not_accepted {
  if [ $(sysctl net.ipv4.conf.all.secure_redirects | awk '{print $3}') -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if reverse path filtering is enabled
function check_reverse_path_filtering_enabled {
  if [ $(sysctl net.ipv4.conf.all.rp_filter | awk '{print $3}') -eq 1 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if source routed packets are not accepted
function check_source_routed_packets_not_accepted {
  if [ $(sysctl net.ipv4.conf.all.accept_source_route | awk '{print $3}') -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if suspicious packets are logged
function check_suspicious_packets_logged {
  if [ $(sysctl net.ipv4.conf.all.log_martians | awk '{print $3}') -eq 1 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if TCP SYN cookies are enabled
function check_tcp_syn_cookies_enabled {
  if [ $(sysctl net.ipv4.tcp_syncookies | awk '{print $3}') -eq 1 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if IPv6 router advertisements are not accepted
function check_ipv6_router_advertisements_not_accepted {
  if [ $(sysctl net.ipv6.conf.all.accept_ra | awk '{print $3}') -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if nftables is installed
function check_nftables_installed {
  if rpm -q nftables; then
    return 0
  else
    return 1
  fi
}

# Function to check if a single firewall configuration utility is in use
function check_single_firewall_utility_in_use {
  if systemctl is-active firewalld && ! systemctl is-active iptables; then
    return 0
  else
    return 1
  fi
}

# Function to check if nftables base chains exist
function check_nftables_base_chains_exist {
  if nft list ruleset | grep -q "chain input"; then
    return 0
  else
    return 1
  fi
}

# Function to check if firewall loopback traffic is configured
function check_firewall_loopback_traffic_configured {
  if nft list ruleset | grep -q "iif lo accept"; then
    return 0
  else
    return 1
  fi
}

# Function to check if firewalld drops unnecessary services
function check_firewalld_drops_unnecessary_services {
  if firewall-cmd --list-all | grep -q "services: "; then
    return 0
  else
    return 1
  fi
}

# Function to check if nftables established connections are configured
function check_nftables_established_connections_configured {
  if nft list ruleset | grep -q "ct state established,related accept"; then
    return 0
  else
    return 1
  fi
}

# Function to check if nftables default deny policy is configured
function check_nftables_default_deny_policy {
  if nft list ruleset | grep -q "policy drop"; then
    return 0
  else
    return 1
  fi
}

# Function to check if cron daemon is enabled
function check_cron_daemon_enabled {
  if systemctl is-active crond; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on crontab
function check_permissions_crontab {
  if [ $(stat -c "%a" $CRONTAB) -eq 600 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on cron.hourly
function check_permissions_cron_hourly {
  if [ $(stat -c "%a" $CRON_HOURLY) -eq 700 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on cron.daily
function check_permissions_cron_daily {
  if [ $(stat -c "%a" $CRON_DAILY) -eq 700 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on cron.weekly
function check_permissions_cron_weekly {
  if [ $(stat -c "%a" $CRON_WEEKLY) -eq 700 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on cron.monthly
function check_permissions_cron_monthly {
  if [ $(stat -c "%a" $CRON_MONTHLY) -eq 700 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on cron.d
function check_permissions_cron_d {
  if [ $(stat -c "%a" $CRON_DIR) -eq 700 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if crontab is restricted to authorized users
function check_crontab_restricted {
  if [ -f $CRON_ALLOW ] && [ ! -f $CRON_DENY ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if at is restricted to authorized users
function check_at_restricted {
  if [ -f $AT_ALLOW ] && [ ! -f $AT_DENY ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on sshd_config
function check_permissions_sshd_config {
  if [ $(stat -c "%a" $SSHD_CFG) -eq 600 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on SSH private host key files
function check_permissions_ssh_private_keys {
  for key in /etc/ssh/*_key; do
    if [ $(stat -c "%a" $key) -ne 600 ]; then
      return 1
    fi
  done
  return 0
}

# Function to check permissions on SSH public host key files
function check_permissions_ssh_public_keys {
  for key in /etc/ssh/*.pub; do
    if [ $(stat -c "%a" $key) -ne 644 ]; then
      return 1
    fi
  done
  return 0
}

# Function to check if sshd access is configured
function check_sshd_access_configured {
  if grep -q "AllowUsers" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd banner is configured
function check_sshd_banner_configured {
  if grep -q "Banner" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd ciphers are configured
function check_sshd_ciphers_configured {
  if grep -q "Ciphers" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd client alive settings are configured
function check_sshd_client_alive_configured {
  if grep -q "ClientAliveInterval" $SSHD_CFG && grep -q "ClientAliveCountMax" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd disable forwarding is enabled
function check_sshd_disable_forwarding_enabled {
  if grep -q "DisableForwarding yes" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd hostbased authentication is disabled
function check_sshd_hostbased_authentication_disabled {
  if grep -q "HostbasedAuthentication no" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd ignore rhosts is enabled
function check_sshd_ignore_rhosts_enabled {
  if grep -q "IgnoreRhosts yes" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd kex algorithms are configured
function check_sshd_kex_algorithms_configured {
  if grep -q "KexAlgorithms" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd login grace time is configured
function check_sshd_login_grace_time_configured {
  if grep -q "LoginGraceTime" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd log level is configured
function check_sshd_log_level_configured {
  if grep -q "LogLevel" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd MACs are configured
function check_sshd_macs_configured {
  if grep -q "MACs" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd max auth tries is configured
function check_sshd_max_auth_tries_configured {
  if grep -q "MaxAuthTries" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd max sessions is configured
function check_sshd_max_sessions_configured {
  if grep -q "MaxSessions" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd max startups is configured
function check_sshd_max_startups_configured {
  if grep -q "MaxStartups" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd permit empty passwords is disabled
function check_sshd_permit_empty_passwords_disabled {
  if grep -q "PermitEmptyPasswords no" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd permit root login is disabled
function check_sshd_permit_root_login_disabled {
  if grep -q "PermitRootLogin no" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd permit user environment is disabled
function check_sshd_permit_user_environment_disabled {
  if grep -q "PermitUserEnvironment no" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd use PAM is enabled
function check_sshd_use_pam_enabled {
  if grep -q "UsePAM yes" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sshd crypto policy is not set
function check_sshd_crypto_policy_not_set {
  if ! grep -q "CRYPTO_POLICY" $SSHD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if sudo is installed
function check_sudo_installed {
  if rpm -q sudo; then
    return 0
  else
    return 1
  fi
}

# Function to check if sudo commands use pty
function check_sudo_commands_use_pty {
  if grep -q "Defaults use_pty" /etc/sudoers; then
    return 0
  else
    return 1
  fi
}

# Function to check if sudo log file exists
function check_sudo_log_file_exists {
  if grep -q "Defaults logfile=" /etc/sudoers; then
    return 0
  else
    return 1
  fi
}

# Function to check if sudo re-authentication is not disabled
function check_sudo_reauth_not_disabled {
  if ! grep -q "Defaults !authenticate" /etc/sudoers; then
    return 0
  else
    return 1
  fi
}

# Function to check if sudo authentication timeout is configured
function check_sudo_auth_timeout_configured {
  if grep -q "Defaults timestamp_timeout=" /etc/sudoers; then
    return 0
  else
    return 1
  fi
}

# Function to check if access to the su command is restricted
function check_su_command_restricted {
  if grep -q "auth required pam_wheel.so use_uid" $PAM_SU; then
    return 0
  else
    return 1
  fi
}

# Function to check if latest version of pam is installed
function check_latest_pam_installed {
  if rpm -q pam; then
    return 0
  else
    return 1
  fi
}

# Function to check if latest version of authselect is installed
function check_latest_authselect_installed {
  if rpm -q authselect; then
    return 0
  else
    return 1
  fi
}

# Function to check if active authselect profile includes pam modules
function check_authselect_profile_includes_pam {
  if authselect current | grep -q "Profile ID: sssd"; then
    return 0
  else
    return 1
  fi
}

# Function to check if pam_faillock module is enabled
function check_pam_faillock_enabled {
  if grep -q "pam_faillock.so" $SYSTEM_AUTH; then
    return 0
  else
    return 1
  fi
}

# Function to check if pam_pwquality module is enabled
function check_pam_pwquality_enabled {
  if grep -q "pam_pwquality.so" $SYSTEM_AUTH; then
    return 0
  else
    return 1
  fi
}

# Function to check if pam_pwhistory module is enabled
function check_pam_pwhistory_enabled {
  if grep -q "pam_pwhistory.so" $SYSTEM_AUTH; then
    return 0
  else
    return 1
  fi
}

# Function to check if pam_unix module is enabled
function check_pam_unix_enabled {
  if grep -q "pam_unix.so" $SYSTEM_AUTH; then
    return 0
  else
    return 1
  fi
}

# Function to check if password failed attempts lockout is configured
function check_password_failed_attempts_lockout {
  if grep -q "deny=" /etc/security/faillock.conf; then
    return 0
  else
    return 1
  fi
}

# Function to check if password unlock time is configured
function check_password_unlock_time {
  if grep -q "unlock_time=" /etc/security/faillock.conf; then
    return 0
  else
    return 1
  fi
}

# Function to check if password number of changed characters is configured
function check_password_changed_characters {
  if grep -q "difok=" $PWQUAL_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if password length is configured
function check_password_length {
  if grep -q "minlen=" $PWQUAL_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if password complexity is configured
function check_password_complexity {
  if grep -q "minclass=" $PWQUAL_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if password same consecutive characters is configured
function check_password_same_consecutive_characters {
  if grep -q "maxrepeat=" $PWQUAL_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if password maximum sequential characters is configured
function check_password_maximum_sequential_characters {
  if grep -q "maxsequence=" $PWQUAL_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if password dictionary check is enabled
function check_password_dictionary_check {
  if grep -q "dictcheck=" $PWQUAL_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if password quality is enforced for the root user
function check_password_quality_enforced_root {
  if grep -q "enforce_for_root" $PWQUAL_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if password history remember is configured
function check_password_history_remember_configured {
  if grep -q "remember=" $PWQUAL_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if password history is enforced for the root user
function check_password_history_enforced_root {
  if grep -q "enforce_for_root" $PWQUAL_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if pam_pwhistory includes use_authtok
function check_pam_pwhistory_use_authtok {
  if grep -q "use_authtok" $SYSTEM_AUTH; then
    return 0
  else
    return 1
  fi
}

# Function to check if pam_unix does not include nullok
function check_pam_unix_not_nullok {
  if ! grep -q "nullok" $SYSTEM_AUTH; then
    return 0
  else
    return 1
  fi
}

# Function to check if pam_unix does not include remember
function check_pam_unix_not_remember {
  if ! grep -q "remember" $SYSTEM_AUTH; then
    return 0
  else
    return 1
  fi
}

# Function to check if pam_unix includes a strong password hashing algorithm
function check_pam_unix_strong_hashing {
  if grep -q "sha512" $SYSTEM_AUTH; then
    return 0
  else
    return 1
  fi
}

# Function to check if pam_unix includes use_authtok
function check_pam_unix_use_authtok {
  if grep -q "use_authtok" $SYSTEM_AUTH; then
    return 0
  else
    return 1
  fi
}

# Function to check if strong password hashing algorithm is configured
function check_strong_password_hashing_algorithm {
  if grep -q "sha512" $LOGIN_DEFS; then
    return 0
  else
    return 1
  fi
}

# Function to check if password expiration is 365 days or less
function check_password_expiration {
  if grep -q "PASS_MAX_DAYS" $LOGIN_DEFS && [ $(grep "PASS_MAX_DAYS" $LOGIN_DEFS | awk '{print $2}') -le 365 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if password expiration warning days is 7 or more
function check_password_expiration_warning {
  if grep -q "PASS_WARN_AGE" $LOGIN_DEFS && [ $(grep "PASS_WARN_AGE" $LOGIN_DEFS | awk '{print $2}') -ge 7 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if inactive password lock is 30 days or less
function check_inactive_password_lock {
  if grep -q "INACTIVE" /etc/default/useradd && [ $(grep "INACTIVE" /etc/default/useradd | awk '{print $2}') -le 30 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if all users last password change date is in the past
function check_users_last_password_change {
  if chage -l $(getent passwd | awk -F: '$3 >= 1000 {print $1}') | grep -q "Last password change"; then
    return 0
  else
    return 1
  fi
}

# Function to check if default group for the root account is GID 0
function check_default_group_root_gid {
  if [ $(id -g root) -eq 0 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if root user umask is configured
function check_root_user_umask {
  if grep -q "umask 077" /root/.bashrc; then
    return 0
  else
    return 1
  fi
}

# Function to check if system accounts are secured
function check_system_accounts_secured {
  if ! awk -F: '($3 < 1000) {print $1}' $PASSWD | grep -vE "root|sync|shutdown|halt"; then
    return 0
  else
    return 1
  fi
}

# Function to check if root password is set
function check_root_password_set {
  if passwd -S root | grep -q "P"; then
    return 0
  else
    return 1
  fi
}

# Function to check if default user shell timeout is configured
function check_default_user_shell_timeout {
  if grep -q "TMOUT" $PROFILE; then
    return 0
  else
    return 1
  fi
}

# Function to check if default user umask is configured
function check_default_user_umask {
  if grep -q "umask 027" $PROFILE; then
    return 0
  else
    return 1
  fi
}

# Function to check if logrotate is configured
function check_logrotate_configured {
  if [ -f /etc/logrotate.conf ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if all logfiles have appropriate access configured
function check_logfiles_access_configured {
  if find /var/log -type f -perm /o+w; then
    return 1
  else
    return 0
  fi
}

# Function to check if rsyslog is installed
function check_rsyslog_installed {
  if rpm -q rsyslog; then
    return 0
  else
    return 1
  fi
}

# Function to check if rsyslog service is enabled
function check_rsyslog_service_enabled {
  if systemctl is-enabled rsyslog; then
    return 0
  else
    return 1
  fi
}

# Function to check if journald is configured to send logs to rsyslog
function check_journald_send_logs_to_rsyslog {
  if grep -q "ForwardToSyslog=yes" $JOURNALD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if rsyslog default file permissions are configured
function check_rsyslog_default_file_permissions {
  if grep -q "FileCreateMode" $RSYSLOG_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if logging is configured
function check_logging_configured {
  if [ -f $RSYSLOG_CNF ] || [ -f /etc/rsyslog.d/*.conf ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if rsyslog is configured to send logs to a remote log host
function check_rsyslog_send_logs_remote {
  if grep -q "action(type=\"omfwd\"" $RSYSLOG_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if rsyslog is not configured to receive logs from a remote client
function check_rsyslog_not_receive_remote_logs {
  if ! grep -q "module(load=\"imtcp\")" $RSYSLOG_CNF; then
    return 0
  else
    return 1
  fi
}

# Function to check if journald service is enabled
function check_journald_service_enabled {
  if systemctl is-enabled systemd-journald; then
    return 0
  else
    return 1
  fi
}

# Function to check if journald is configured to compress large log files
function check_journald_compress_logs {
  if grep -q "Compress=yes" $JOURNALD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if journald is configured to write logfiles to persistent disk
function check_journald_persistent_storage {
  if grep -q "Storage=persistent" $JOURNALD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if journald is not configured to send logs to rsyslog
function check_journald_not_send_logs_to_rsyslog {
  if ! grep -q "ForwardToSyslog=yes" $JOURNALD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if journald log rotation is configured per site policy
function check_journald_log_rotation {
  if grep -q "SystemMaxUse=" $JOURNALD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if systemd-journal-remote is installed
function check_systemd_journal_remote_installed {
  if rpm -q systemd-journal-remote; then
    return 0
  else
    return 1
  fi
}

# Function to check if systemd-journal-remote is configured
function check_systemd_journal_remote_configured {
  if [ -f /etc/systemd/journal-remote.conf ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if systemd-journal-remote is enabled
function check_systemd_journal_remote_enabled {
  if systemctl is-enabled systemd-journal-remote; then
    return 0
  else
    return 1
  fi
}

# Function to check if journald is not configured to receive logs from a remote client
function check_journald_not_receive_remote_logs {
  if ! grep -q "ForwardToSyslog=yes" $JOURNALD_CFG; then
    return 0
  else
    return 1
  fi
}

# Function to check if AIDE is installed
function check_aide_installed {
  if rpm -q aide; then
    return 0
  else
    return 1
  fi
}

# Function to check if filesystem integrity is regularly checked
function check_filesystem_integrity_checked {
  if crontab -l | grep -q "aide --check"; then
    return 0
  else
    return 1
  fi
}

# Function to check if cryptographic mechanisms are used to protect the integrity of audit tools
function check_crypto_mechanisms_audit_tools {
  if rpm -V aide | grep -q "5"; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on passwd
function check_permissions_passwd {
  if [ $(stat -c "%a" $PASSWD) -eq 644 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on passwd-
function check_permissions_passwd_dash {
  if [ $(stat -c "%a" /etc/passwd-) -eq 600 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on opasswd
function check_permissions_opasswd {
  if [ $(stat -c "%a" /etc/opasswd) -eq 600 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on group
function check_permissions_group {
  if [ $(stat -c "%a" $GROUP) -eq 644 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on group-
function check_permissions_group_dash {
  if [ $(stat -c "%a" /etc/group-) -eq 600 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on shadow
function check_permissions_shadow {
  if [ $(stat -c "%a" $SHADOW) -eq 000 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on shadow-
function check_permissions_shadow_dash {
  if [ $(stat -c "%a" /etc/shadow-) -eq 600 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on gshadow
function check_permissions_gshadow {
  if [ $(stat -c "%a" $GSHADOW) -eq 000 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on gshadow-
function check_permissions_gshadow_dash {
  if [ $(stat -c "%a" /etc/gshadow-) -eq 600 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check permissions on shells
function check_permissions_shells {
  if [ $(stat -c "%a" /etc/shells) -eq 644 ]; then
    return 0
  else
    return 1
  fi
}

# Function to check if world writable files and directories are secured
function check_world_writable_files {
  if find / -xdev -type f -perm -0002; then
    return 1
  else
    return 0
  fi
}

# Function to check if no unowned or ungrouped files or directories exist
function check_no_unowned_files {
  if find / -xdev \( -nouser -o -nogroup \); then
    return 1
  else
    return 0
  fi
}

# Function to check if SUID and SGID files are reviewed
function check_suid_sgid_files {
  if find / -xdev \( -perm -4000 -o -perm -2000 \); then
    return 0
  else
    return 1
  fi
}

# Function to check if accounts in passwd use shadowed passwords
function check_shadowed_passwords {
  if awk -F: '($2 == "x")' $PASSWD; then
    return 0
  else
    return 1
  fi
}

# Function to check if shadow password fields are not empty
function check_shadow_password_fields_not_empty {
  if awk -F: '($2 == "")' $SHADOW; then
    return 1
  else
    return 0
  fi
}

# Function to check if all groups in passwd exist in group
function check_groups_in_passwd_exist_in_group {
  if awk -F: '{print $4}' $PASSWD | while read group; do grep -q "^$group:" $GROUP; done; then
    return 0
  else
    return 1
  fi
}

# Function to check if no duplicate UIDs exist
function check_no_duplicate_uids {
  if awk -F: '{print $3}' $PASSWD | sort | uniq -d; then
    return 1
  else
    return 0
  fi
}

# Function to check if no duplicate GIDs exist
function check_no_duplicate_gids {
  if awk -F: '{print $3}' $GROUP | sort | uniq -d; then
    return 1
  else
    return 0
  fi
}

# Function to check if no duplicate user names exist
function check_no_duplicate_usernames {
  if awk -F: '{print $1}' $PASSWD | sort | uniq -d; then
    return 1
  else
    return 0
  fi
}

# Function to check if no duplicate group names exist
function check_no_duplicate_groupnames {
  if awk -F: '{print $1}' $GROUP | sort | uniq -d; then
    return 1
  else
    return 0
  fi
}

# Function to check if root path integrity is maintained
function check_root_path_integrity {
  if echo $PATH | grep -q "::" || echo $PATH | grep -q ":$"; then
    return 1
  else
    return 0
  fi
}

# Function to check if root is the only UID 0 account
function check_root_only_uid_0 {
  if awk -F: '($3 == 0) {print $1}' $PASSWD | grep -q "^root$"; then
    return 0
  else
    return 1
  fi
}

# Function to check if local interactive user home directories are configured
function check_local_user_home_directories {
  if awk -F: '($3 >= 1000 && $7 != "/sbin/nologin") {print $6}' $PASSWD | while read dir; do [ -d "$dir" ]; done; then
    return 0
  else
    return 1
  fi
}

# Function to check if local interactive user dot files access is configured
function check_local_user_dot_files_access {
  if awk -F: '($3 >= 1000 && $7 != "/sbin/nologin") {print $6}' $PASSWD | while read dir; do find "$dir" -name ".*" -perm /o+w; done; then
    return 1
  else
    return 0
  fi
}

# Main function to run all checks
function main {
  # Kernel Module Checks
  cis_num="1.1.1.1"
  name="Ensure cramfs kernel module is not available"
  func_wrapper check_kernel_module "cramfs" "${name}" "${cis_num}"

  cis_num="1.1.1.2"
  name="Ensure freevxfs kernel module is not available"
  func_wrapper check_kernel_module "freevxfs" "${name}" "${cis_num}"

  cis_num="1.1.1.3"
  name="Ensure hfs kernel module is not available"
  func_wrapper check_kernel_module "hfs" "${name}" "${cis_num}"

  cis_num="1.1.1.4"
  name="Ensure hfsplus kernel module is not available"
  func_wrapper check_kernel_module "hfsplus" "${name}" "${cis_num}"

  cis_num="1.1.1.5"
  name="Ensure jffs2 kernel module is not available"
  func_wrapper check_kernel_module "jffs2" "${name}" "${cis_num}"

  # Partition Option Checks
  cis_num="1.1.2.1.2"
  name="Ensure nodev option set on /tmp partition"
  func_wrapper check_partition_option "/tmp" "${name}" "${cis_num}"

  cis_num="1.1.2.1.3"
  name="Ensure nosuid option set on /tmp partition"
  func_wrapper check_partition_option "/tmp" "${name}" "${cis_num}"

  cis_num="1.1.2.1.4"
  name="Ensure noexec option set on /tmp partition"
  func_wrapper check_partition_option "/tmp" "${name}" "${cis_num}"

  cis_num="1.1.2.2.2"
  name="Ensure nodev option set on /dev/shm partition"
  func_wrapper check_partition_option "/dev/shm" "${name}" "${cis_num}"

  cis_num="1.1.2.2.3"
  name="Ensure nosuid option set on /dev/shm partition"
  func_wrapper check_partition_option "/dev/shm" "${name}" "${cis_num}"

  cis_num="1.1.2.2.4"
  name="Ensure noexec option set on /dev/shm partition"
  func_wrapper check_partition_option "/dev/shm" "${name}" "${cis_num}"

  cis_num="1.1.2.3.2"
  name="Ensure nodev option set on /home partition"
  func_wrapper check_partition_option "/home" "${name}" "${cis_num}"

  cis_num="1.1.2.3.3"
  name="Ensure nosuid option set on /home partition"
  func_wrapper check_partition_option "/home" "${name}" "${cis_num}"

  cis_num="1.1.2.4.2"
  name="Ensure nodev option set on /var partition"
  func_wrapper check_partition_option "/var" "${name}" "${cis_num}"

  cis_num="1.1.2.4.3"
  name="Ensure nosuid option set on /var partition"
  func_wrapper check_partition_option "/var" "${name}" "${cis_num}"

  cis_num="1.1.2.5.2"
  name="Ensure nodev option set on /var/tmp partition"
  func_wrapper check_partition_option "/var/tmp" "${name}" "${cis_num}"

  cis_num="1.1.2.5.3"
  name="Ensure nosuid option set on /var/tmp partition"
  func_wrapper check_partition_option "/var/tmp" "${name}" "${cis_num}"

  cis_num="1.1.2.5.4"
  name="Ensure noexec option set on /var/tmp partition"
  func_wrapper check_partition_option "/var/tmp" "${name}" "${cis_num}"

  cis_num="1.1.2.6.2"
  name="Ensure nodev option set on /var/log partition"
  func_wrapper check_partition_option "/var/log" "${name}" "${cis_num}"

  cis_num="1.1.2.6.3"
  name="Ensure nosuid option set on /var/log partition"
  func_wrapper check_partition_option "/var/log" "${name}" "${cis_num}"

  cis_num="1.1.2.6.4"
  name="Ensure noexec option set on /var/log partition"
  func_wrapper check_partition_option "/var/log" "${name}" "${cis_num}"

  cis_num="1.1.2.7.2"
  name="Ensure nodev option set on /var/log/audit partition"
  func_wrapper check_partition_option "/var/log/audit" "${name}" "${cis_num}"

  cis_num="1.1.2.7.3"
  name="Ensure nosuid option set on /var/log/audit partition"
  func_wrapper check_partition_option "/var/log/audit" "${name}" "${cis_num}"

  cis_num="1.1.2.7.4"
  name="Ensure noexec option set on /var/log/audit partition"
  func_wrapper check_partition_option "/var/log/audit" "${name}" "${cis_num}"

  cis_num="1.2.1"
  name="Ensure GPG keys are configured"
  func_wrapper check_gpg_keys_configured "gpg_key_installed" "${name}" "${cis_num}"

  cis_num="1.2.2"
  name="Ensure gpgcheck is globally activated"
  func_wrapper check_gpgcheck_globally_activated "${name}" "${cis_num}"

  cis_num="1.2.4"
  name="Ensure package manager repositories are configured"
  func_wrapper check_package_manager_repositories_configured "${name}" "${cis_num}"

  cis_num="1.2.5"
  name="Ensure updates, patches, and additional security software are installed"
  func_wrapper check_updates_installed "${name}" "${cis_num}"

  cis_num="1.3.1"
  name="Ensure bootloader password is set"
  func_wrapper check_bootloader_password_set "${name}" "${cis_num}"

  cis_num="1.3.2"
  name="Ensure permissions on bootloader config are configured"
  func_wrapper check_bootloader_permissions_configured "${name}" "${cis_num}"

  cis_num="1.4.1"
  name="Ensure address space layout randomization (ASLR) is enabled"
  func_wrapper check_aslr_enabled "${name}" "${cis_num}"

  cis_num="1.4.2"
  name="Ensure ptrace_scope is restricted"
  func_wrapper check_ptrace_scope_restricted "${name}" "${cis_num}"

  cis_num="1.4.3"
  name="Ensure core dump backtraces are disabled"
  func_wrapper check_core_dump_backtraces_disabled "${name}" "${cis_num}"

  cis_num="1.4.4"
  name="Ensure core dump storage is disabled"
  func_wrapper check_core_dump_storage_disabled "${name}" "${cis_num}"

  cis_num="1.5.1.1"
  name="Ensure SELinux is installed"
  func_wrapper check_selinux_installed "${name}" "${cis_num}"

  cis_num="1.5.1.2"
  name="Ensure SELinux is not disabled in bootloader configuration"
  func_wrapper check_selinux_not_disabled_in_bootloader "${name}" "${cis_num}"

  cis_num="1.5.1.3"
  name="Ensure SELinux policy is configured"
  func_wrapper check_selinux_policy_configured "${name}" "${cis_num}"

  cis_num="1.5.1.4"
  name="Ensure the SELinux mode is not disabled"
  func_wrapper check_selinux_mode_not_disabled "${name}" "${cis_num}"

  cis_num="1.5.1.6"
  name="Ensure no unconfined services exist"
  func_wrapper check_no_unconfined_services_exist "${name}" "${cis_num}"

  cis_num="1.5.1.7"
  name="Ensure the MCS Translation Service (mcstrans) is not installed"
  func_wrapper check_mcstrans_not_installed "${name}" "${cis_num}"

  cis_num="1.6.1"
  name="Ensure system wide crypto policy is not set to legacy"
  func_wrapper check_crypto_policy_not_legacy "${name}" "${cis_num}"

  cis_num="1.6.2"
  name="Ensure system wide crypto policy disables sha1 hash and signature support"
  func_wrapper check_crypto_policy_disables_sha1 "${name}" "${cis_num}"

  cis_num="1.6.3"
  name="Ensure system wide crypto policy disables cbc for ssh"
  func_wrapper check_crypto_policy_disables_cbc "${name}" "${cis_num}"

  cis_num="1.6.4"
  name="Ensure system wide crypto policy disables macs less than 128 bits"
  func_wrapper check_crypto_policy_disables_weak_macs "${name}" "${cis_num}"

  cis_num="1.7.1"
  name="Ensure message of the day is configured properly"
  func_wrapper check_motd_configured_properly "${name}" "${cis_num}"

  cis_num="1.7.2"
  name="Ensure local login warning banner is configured properly"
  func_wrapper check_local_login_warning_banner_configured "${name}" "${cis_num}"

  cis_num="1.7.3"
  name="Ensure remote login warning banner is configured properly"
  func_wrapper check_remote_login_warning_banner_configured "${name}" "${cis_num}"
  # Access Configuration Checks
  cis_num="1.7.4"
  name="Ensure access to /etc/motd is configured"
  func_wrapper check_access_motd "${name}" "${cis_num}"

  cis_num="1.7.5"
  name="Ensure access to /etc/issue is configured"
  func_wrapper check_access_issue "${name}" "${cis_num}"

  cis_num="1.7.6"
  name="Ensure access to /etc/issue.net is configured"
  func_wrapper check_access_issue_net "${name}" "${cis_num}"

  # GDM Configuration Checks
  cis_num="1.8.2"
  name="Ensure GDM login banner is configured"
  func_wrapper check_gdm_login_banner "${name}" "${cis_num}"

  cis_num="1.8.3"
  name="Ensure GDM disable-user-list option is enabled"
  func_wrapper check_gdm_disable_user_list "${name}" "${cis_num}"

  cis_num="1.8.4"
  name="Ensure GDM screen locks when the user is idle"
  func_wrapper check_gdm_screen_lock_idle "${name}" "${cis_num}"

  cis_num="1.8.5"
  name="Ensure GDM screen locks cannot be overridden"
  func_wrapper check_gdm_screen_lock_override "${name}" "${cis_num}"

  cis_num="1.8.8"
  name="Ensure GDM autorun-never is enabled"
  func_wrapper check_gdm_autorun_never "${name}" "${cis_num}"

  cis_num="1.8.9"
  name="Ensure GDM autorun-never is not overridden"
  func_wrapper check_gdm_autorun_never_override "${name}" "${cis_num}"

  cis_num="1.8.10"
  name="Ensure XDMCP is not enabled"
  func_wrapper check_xdmcp_not_enabled "${name}" "${cis_num}"

  # Time Synchronization Checks
  cis_num="2.1.1"
  name="Ensure time synchronization is in use"
  func_wrapper check_time_sync_in_use "${name}" "${cis_num}"

  cis_num="2.1.2"
  name="Ensure chrony is configured"
  func_wrapper check_chrony_configured "${name}" "${cis_num}"

  cis_num="2.1.3"
  name="Ensure chrony is not run as the root user"
  func_wrapper check_chrony_not_root "${name}" "${cis_num}"

  # Service Checks
  cis_num="2.2.3"
  name="Ensure dhcp server services are not in use"
  func_wrapper check_dhcp_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.4"
  name="Ensure dns server services are not in use"
  func_wrapper check_dns_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.5"
  name="Ensure dnsmasq services are not in use"
  func_wrapper check_dnsmasq_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.6"
  name="Ensure samba file server services are not in use"
  func_wrapper check_samba_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.7"
  name="Ensure ftp server services are not in use"
  func_wrapper check_ftp_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.8"
  name="Ensure message access server services are not in use"
  func_wrapper check_message_access_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.9"
  name="Ensure network file system services are not in use"
  func_wrapper check_nfs_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.10"
  name="Ensure nis server services are not in use"
  func_wrapper check_nis_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.12"
  name="Ensure rpcbind services are not in use"
  func_wrapper check_rpcbind_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.13"
  name="Ensure rsync services are not in use"
  func_wrapper check_rsync_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.14"
  name="Ensure snmp services are not in use"
  func_wrapper check_snmp_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.15"
  name="Ensure telnet server services are not in use"
  func_wrapper check_telnet_server_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.16"
  name="Ensure tftp server services are not in use"
  func_wrapper check_tftp_server_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.17"
  name="Ensure web proxy server services are not in use"
  func_wrapper check_web_proxy_not_in_use "${name}" "${cis_num}"

  # Service Checks
  cis_num="2.2.18"
  name="Ensure web server services are not in use"
  func_wrapper check_web_server_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.19"
  name="Ensure xinetd services are not in use"
  func_wrapper check_xinetd_not_in_use "${name}" "${cis_num}"

  cis_num="2.2.21"
  name="Ensure mail transfer agents are configured for local-only mode"
  func_wrapper check_mail_transfer_agents_local_only "${name}" "${cis_num}"

  cis_num="2.2.22"
  name="Ensure only approved services are listening on a network interface"
  func_wrapper check_approved_services_listening "${name}" "${cis_num}"

  cis_num="2.3.1"
  name="Ensure ftp client is not installed"
  func_wrapper check_ftp_client_not_installed "${name}" "${cis_num}"

  cis_num="2.3.3"
  name="Ensure nis client is not installed"
  func_wrapper check_nis_client_not_installed "${name}" "${cis_num}"

  cis_num="2.3.4"
  name="Ensure telnet client is not installed"
  func_wrapper check_telnet_client_not_installed "${name}" "${cis_num}"

  cis_num="2.3.5"
  name="Ensure tftp client is not installed"
  func_wrapper check_tftp_client_not_installed "${name}" "${cis_num}"

  # IPv6 Status Check
  cis_num="3.1.1"
  name="Ensure IPv6 status is identified"
  func_wrapper check_ipv6_status_identified "${name}" "${cis_num}"

  # Network Configuration Checks
  cis_num="3.3.1"
  name="Ensure ip forwarding is disabled"
  func_wrapper check_ip_forwarding_disabled "${name}" "${cis_num}"

  cis_num="3.3.2"
  name="Ensure packet redirect sending is disabled"
  func_wrapper check_packet_redirect_sending_disabled "${name}" "${cis_num}"

  cis_num="3.3.3"
  name="Ensure bogus icmp responses are ignored"
  func_wrapper check_bogus_icmp_responses_ignored "${name}" "${cis_num}"

  cis_num="3.3.4"
  name="Ensure broadcast icmp requests are ignored"
  func_wrapper check_broadcast_icmp_requests_ignored "${name}" "${cis_num}"

  cis_num="3.3.5"
  name="Ensure icmp redirects are not accepted"
  func_wrapper check_icmp_redirects_not_accepted "${name}" "${cis_num}"

  cis_num="3.3.6"
  name="Ensure secure icmp redirects are not accepted"
  func_wrapper check_secure_icmp_redirects_not_accepted "${name}" "${cis_num}"

  cis_num="3.3.7"
  name="Ensure reverse path filtering is enabled"
  func_wrapper check_reverse_path_filtering_enabled "${name}" "${cis_num}"

  cis_num="3.3.8"
  name="Ensure source routed packets are not accepted"
  func_wrapper check_source_routed_packets_not_accepted "${name}" "${cis_num}"

  cis_num="3.3.9"
  name="Ensure suspicious packets are logged"
  func_wrapper check_suspicious_packets_logged "${name}" "${cis_num}"

  cis_num="3.3.10"
  name="Ensure tcp syn cookies is enabled"
  func_wrapper check_tcp_syn_cookies_enabled "${name}" "${cis_num}"

  # IPv6 Router Advertisements Check
  cis_num="3.3.11"
  name="Ensure ipv6 router advertisements are not accepted"
  func_wrapper check_ipv6_router_advertisements_not_accepted "${name}" "${cis_num}"

  # nftables Checks
  cis_num="3.4.1.1"
  name="Ensure nftables is installed"
  func_wrapper check_nftables_installed "${name}" "${cis_num}"

  cis_num="3.4.1.2"
  name="Ensure a single firewall configuration utility is in use"
  func_wrapper check_single_firewall_utility_in_use "${name}" "${cis_num}"

  cis_num="3.4.2.1"
  name="Ensure nftables base chains exist"
  func_wrapper check_nftables_base_chains_exist "${name}" "${cis_num}"

  cis_num="3.4.2.2"
  name="Ensure host based firewall loopback traffic is configured"
  func_wrapper check_firewall_loopback_traffic_configured "${name}" "${cis_num}"

  cis_num="3.4.2.3"
  name="Ensure firewalld drops unnecessary services and ports"
  func_wrapper check_firewalld_drops_unnecessary_services "${name}" "${cis_num}"

  cis_num="3.4.2.4"
  name="Ensure nftables established connections are configured"
  func_wrapper check_nftables_established_connections_configured "${name}" "${cis_num}"

  cis_num="3.4.2.5"
  name="Ensure nftables default deny firewall policy"
  func_wrapper check_nftables_default_deny_policy "${name}" "${cis_num}"

  # Cron Checks
  cis_num="4.1.1.1"
  name="Ensure cron daemon is enabled and active"
  func_wrapper check_cron_daemon_enabled "${name}" "${cis_num}"

  cis_num="4.1.1.2"
  name="Ensure permissions on /etc/crontab are configured"
  func_wrapper check_permissions_crontab "${name}" "${cis_num}"

  cis_num="4.1.1.3"
  name="Ensure permissions on /etc/cron.hourly are configured"
  func_wrapper check_permissions_cron_hourly "${name}" "${cis_num}"

  cis_num="4.1.1.4"
  name="Ensure permissions on /etc/cron.daily are configured"
  func_wrapper check_permissions_cron_daily "${name}" "${cis_num}"

  cis_num="4.1.1.5"
  name="Ensure permissions on /etc/cron.weekly are configured"
  func_wrapper check_permissions_cron_weekly "${name}" "${cis_num}"

  cis_num="4.1.1.6"
  name="Ensure permissions on /etc/cron.monthly are configured"
  func_wrapper check_permissions_cron_monthly "${name}" "${cis_num}"

  cis_num="4.1.1.7"
  name="Ensure permissions on /etc/cron.d are configured"
  func_wrapper check_permissions_cron_d "${name}" "${cis_num}"

  cis_num="4.1.1.8"
  name="Ensure crontab is restricted to authorized users"
  func_wrapper check_crontab_restricted "${name}" "${cis_num}"

  cis_num="4.1.2.1"
  name="Ensure at is restricted to authorized users"
  func_wrapper check_at_restricted "${name}" "${cis_num}"

  # SSH Configuration Checks
  cis_num="4.2.1"
  name="Ensure permissions on /etc/ssh/sshd_config are configured"
  func_wrapper check_permissions_sshd_config "${name}" "${cis_num}"

  cis_num="4.2.2"
  name="Ensure permissions on SSH private host key files are configured"
  func_wrapper check_permissions_ssh_private_keys "${name}" "${cis_num}"

  cis_num="4.2.3"
  name="Ensure permissions on SSH public host key files are configured"
  func_wrapper check_permissions_ssh_public_keys "${name}" "${cis_num}"

  # SSH Configuration Checks
  cis_num="4.2.4"
  name="Ensure sshd access is configured"
  func_wrapper check_sshd_access_configured "${name}" "${cis_num}"

  cis_num="4.2.5"
  name="Ensure sshd Banner is configured"
  func_wrapper check_sshd_banner_configured "${name}" "${cis_num}"

  cis_num="4.2.6"
  name="Ensure sshd Ciphers are configured"
  func_wrapper check_sshd_ciphers_configured "${name}" "${cis_num}"

  cis_num="4.2.7"
  name="Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured"
  func_wrapper check_sshd_client_alive_configured "${name}" "${cis_num}"

  cis_num="4.2.8"
  name="Ensure sshd DisableForwarding is enabled"
  func_wrapper check_sshd_disable_forwarding_enabled "${name}" "${cis_num}"

  cis_num="4.2.9"
  name="Ensure sshd HostbasedAuthentication is disabled"
  func_wrapper check_sshd_hostbased_authentication_disabled "${name}" "${cis_num}"

  cis_num="4.2.10"
  name="Ensure sshd IgnoreRhosts is enabled"
  func_wrapper check_sshd_ignore_rhosts_enabled "${name}" "${cis_num}"

  cis_num="4.2.11"
  name="Ensure sshd KexAlgorithms is configured"
  func_wrapper check_sshd_kex_algorithms_configured "${name}" "${cis_num}"

  cis_num="4.2.12"
  name="Ensure sshd LoginGraceTime is configured"
  func_wrapper check_sshd_login_grace_time_configured "${name}" "${cis_num}"

  cis_num="4.2.13"
  name="Ensure sshd LogLevel is configured"
  func_wrapper check_sshd_log_level_configured "${name}" "${cis_num}"

  cis_num="4.2.14"
  name="Ensure sshd MACs are configured"
  func_wrapper check_sshd_macs_configured "${name}" "${cis_num}"

  cis_num="4.2.15"
  name="Ensure sshd MaxAuthTries is configured"
  func_wrapper check_sshd_max_auth_tries_configured "${name}" "${cis_num}"

  cis_num="4.2.16"
  name="Ensure sshd MaxSessions is configured"
  func_wrapper check_sshd_max_sessions_configured "${name}" "${cis_num}"

  cis_num="4.2.17"
  name="Ensure sshd MaxStartups is configured"
  func_wrapper check_sshd_max_startups_configured "${name}" "${cis_num}"

  cis_num="4.2.18"
  name="Ensure sshd PermitEmptyPasswords is disabled"
  func_wrapper check_sshd_permit_empty_passwords_disabled "${name}" "${cis_num}"

  cis_num="4.2.19"
  name="Ensure sshd PermitRootLogin is disabled"
  func_wrapper check_sshd_permit_root_login_disabled "${name}" "${cis_num}"

  cis_num="4.2.20"
  name="Ensure sshd PermitUserEnvironment is disabled"
  func_wrapper check_sshd_permit_user_environment_disabled "${name}" "${cis_num}"

  cis_num="4.2.21"
  name="Ensure sshd UsePAM is enabled"
  func_wrapper check_sshd_use_pam_enabled "${name}" "${cis_num}"

  cis_num="4.2.22"
  name="Ensure sshd crypto_policy is not set"
  func_wrapper check_sshd_crypto_policy_not_set "${name}" "${cis_num}"

  # Sudo Check
  cis_num="4.3.1"
  name="Ensure sudo is installed"
  func_wrapper check_sudo_installed "${name}" "${cis_num}"
  # Sudo Configuration Checks
  cis_num="4.3.2"
  name="Ensure sudo commands use pty"
  func_wrapper check_sudo_commands_use_pty "${name}" "${cis_num}"

  cis_num="4.3.3"
  name="Ensure sudo log file exists"
  func_wrapper check_sudo_log_file_exists "${name}" "${cis_num}"

  cis_num="4.3.5"
  name="Ensure re-authentication for privilege escalation is not disabled globally"
  func_wrapper check_sudo_reauth_not_disabled "${name}" "${cis_num}"

  cis_num="4.3.6"
  name="Ensure sudo authentication timeout is configured correctly"
  func_wrapper check_sudo_auth_timeout_configured "${name}" "${cis_num}"

  cis_num="4.3.7"
  name="Ensure access to the su command is restricted"
  func_wrapper check_su_command_restricted "${name}" "${cis_num}"

  # PAM and Authselect Checks
  cis_num="4.4.1.1"
  name="Ensure latest version of pam is installed"
  func_wrapper check_latest_pam_installed "${name}" "${cis_num}"

  cis_num="4.4.1.2"
  name="Ensure latest version of authselect is installed"
  func_wrapper check_latest_authselect_installed "${name}" "${cis_num}"

  cis_num="4.4.2.1"
  name="Ensure active authselect profile includes pam modules"
  func_wrapper check_authselect_profile_includes_pam "${name}" "${cis_num}"

  cis_num="4.4.2.2"
  name="Ensure pam_faillock module is enabled"
  func_wrapper check_pam_faillock_enabled "${name}" "${cis_num}"

  cis_num="4.4.2.3"
  name="Ensure pam_pwquality module is enabled"
  func_wrapper check_pam_pwquality_enabled "${name}" "${cis_num}"

  cis_num="4.4.2.4"
  name="Ensure pam_pwhistory module is enabled"
  func_wrapper check_pam_pwhistory_enabled "${name}" "${cis_num}"

  cis_num="4.4.2.5"
  name="Ensure pam_unix module is enabled"
  func_wrapper check_pam_unix_enabled "${name}" "${cis_num}"

  # Password Policy Checks
  cis_num="4.4.3.1.1"
  name="Ensure password failed attempts lockout is configured"
  func_wrapper check_password_failed_attempts_lockout "${name}" "${cis_num}"

  cis_num="4.4.3.1.2"
  name="Ensure password unlock time is configured"
  func_wrapper check_password_unlock_time "${name}" "${cis_num}"

  cis_num="4.4.3.2.1"
  name="Ensure password number of changed characters is configured"
  func_wrapper check_password_changed_characters "${name}" "${cis_num}"

  cis_num="4.4.3.2.2"
  name="Ensure password length is configured"
  func_wrapper check_password_length "${name}" "${cis_num}"

  cis_num="4.4.3.2.3"
  name="Ensure password complexity is configured"
  func_wrapper check_password_complexity "${name}" "${cis_num}"

  cis_num="4.4.3.2.4"
  name="Ensure password same consecutive characters is configured"
  func_wrapper check_password_same_consecutive_characters "${name}" "${cis_num}"

  cis_num="4.4.3.2.5"
  name="Ensure password maximum sequential characters is configured"
  func_wrapper check_password_maximum_sequential_characters "${name}" "${cis_num}"

  cis_num="4.4.3.2.6"
  name="Ensure password dictionary check is enabled"
  func_wrapper check_password_dictionary_check "${name}" "${cis_num}"

  cis_num="4.4.3.2.7"
  name="Ensure password quality is enforced for the root user"
  func_wrapper check_password_quality_enforced_root "${name}" "${cis_num}"

  # Password History Checks
  cis_num="4.4.3.3.1"
  name="Ensure password history remember is configured"
  func_wrapper check_password_history_remember_configured "${name}" "${cis_num}"

  cis_num="4.4.3.3.2"
  name="Ensure password history is enforced for the root user"
  func_wrapper check_password_history_enforced_root "${name}" "${cis_num}"

  cis_num="4.4.3.3.3"
  name="Ensure pam_pwhistory includes use_authtok"
  func_wrapper check_pam_pwhistory_use_authtok "${name}" "${cis_num}"

  # PAM Unix Checks
  cis_num="4.4.3.4.1"
  name="Ensure pam_unix does not include nullok"
  func_wrapper check_pam_unix_not_nullok "${name}" "${cis_num}"

  cis_num="4.4.3.4.2"
  name="Ensure pam_unix does not include remember"
  func_wrapper check_pam_unix_not_remember "${name}" "${cis_num}"

  cis_num="4.4.3.4.3"
  name="Ensure pam_unix includes a strong password hashing algorithm"
  func_wrapper check_pam_unix_strong_hashing "${name}" "${cis_num}"

  cis_num="4.4.3.4.4"
  name="Ensure pam_unix includes use_authtok"
  func_wrapper check_pam_unix_use_authtok "${name}" "${cis_num}"

  # Password Policy Checks
  cis_num="4.5.1.1"
  name="Ensure strong password hashing algorithm is configured"
  func_wrapper check_strong_password_hashing_algorithm "${name}" "${cis_num}"

  cis_num="4.5.1.2"
  name="Ensure password expiration is 365 days or less"
  func_wrapper check_password_expiration "${name}" "${cis_num}"

  cis_num="4.5.1.3"
  name="Ensure password expiration warning days is 7 or more"
  func_wrapper check_password_expiration_warning "${name}" "${cis_num}"

  cis_num="4.5.1.4"
  name="Ensure inactive password lock is 30 days or less"
  func_wrapper check_inactive_password_lock "${name}" "${cis_num}"

  cis_num="4.5.1.5"
  name="Ensure all users last password change date is in the past"
  func_wrapper check_users_last_password_change "${name}" "${cis_num}"

  # Root Account Checks
  cis_num="4.5.2.1"
  name="Ensure default group for the root account is GID 0"
  func_wrapper check_default_group_root_gid "${name}" "${cis_num}"

  cis_num="4.5.2.2"
  name="Ensure root user umask is configured"
  func_wrapper check_root_user_umask "${name}" "${cis_num}"

  cis_num="4.5.2.3"
  name="Ensure system accounts are secured"
  func_wrapper check_system_accounts_secured "${name}" "${cis_num}"

  cis_num="4.5.2.4"
  name="Ensure root password is set"
  func_wrapper check_root_password_set "${name}" "${cis_num}"

  # User Shell and Umask Checks
  cis_num="4.5.3.2"
  name="Ensure default user shell timeout is configured"
  func_wrapper check_default_user_shell_timeout "${name}" "${cis_num}"

  cis_num="4.5.3.3"
  name="Ensure default user umask is configured"
  func_wrapper check_default_user_umask "${name}" "${cis_num}"

  # Logrotate and Logfile Access Checks
  cis_num="5.1.3"
  name="Ensure logrotate is configured"
  func_wrapper check_logrotate_configured "${name}" "${cis_num}"

  cis_num="5.1.4"
  name="Ensure all logfiles have appropriate access configured"
  func_wrapper check_logfiles_access_configured "${name}" "${cis_num}"

  # Rsyslog Check
  cis_num="5.1.1.1"
  name="Ensure rsyslog is installed"
  func_wrapper check_rsyslog_installed "${name}" "${cis_num}"

  # Rsyslog and Journald Configuration Checks
  cis_num="5.1.1.2"
  name="Ensure rsyslog service is enabled"
  func_wrapper check_rsyslog_service_enabled "${name}" "${cis_num}"

  cis_num="5.1.1.3"
  name="Ensure journald is configured to send logs to rsyslog"
  func_wrapper check_journald_send_logs_to_rsyslog "${name}" "${cis_num}"

  cis_num="5.1.1.4"
  name="Ensure rsyslog default file permissions are configured"
  func_wrapper check_rsyslog_default_file_permissions "${name}" "${cis_num}"

  cis_num="5.1.1.5"
  name="Ensure logging is configured"
  func_wrapper check_logging_configured "${name}" "${cis_num}"

  cis_num="5.1.1.6"
  name="Ensure rsyslog is configured to send logs to a remote log host"
  func_wrapper check_rsyslog_send_logs_remote "${name}" "${cis_num}"

  cis_num="5.1.1.7"
  name="Ensure rsyslog is not configured to receive logs from a remote client"
  func_wrapper check_rsyslog_not_receive_remote_logs "${name}" "${cis_num}"

  cis_num="5.1.2.2"
  name="Ensure journald service is enabled"
  func_wrapper check_journald_service_enabled "${name}" "${cis_num}"

  cis_num="5.1.2.3"
  name="Ensure journald is configured to compress large log files"
  func_wrapper check_journald_compress_logs "${name}" "${cis_num}"

  cis_num="5.1.2.4"
  name="Ensure journald is configured to write logfiles to persistent disk"
  func_wrapper check_journald_persistent_storage "${name}" "${cis_num}"

  cis_num="5.1.2.5"
  name="Ensure journald is not configured to send logs to rsyslog"
  func_wrapper check_journald_not_send_logs_to_rsyslog "${name}" "${cis_num}"

  cis_num="5.1.2.6"
  name="Ensure journald log rotation is configured per site policy"
  func_wrapper check_journald_log_rotation "${name}" "${cis_num}"

  cis_num="5.1.2.1.1"
  name="Ensure systemd-journal-remote is installed"
  func_wrapper check_systemd_journal_remote_installed "${name}" "${cis_num}"

  cis_num="5.1.2.1.2"
  name="Ensure systemd-journal-remote is configured"
  func_wrapper check_systemd_journal_remote_configured "${name}" "${cis_num}"

  cis_num="5.1.2.1.3"
  name="Ensure systemd-journal-remote is enabled"
  func_wrapper check_systemd_journal_remote_enabled "${name}" "${cis_num}"

  cis_num="5.1.2.1.4"
  name="Ensure journald is not configured to receive logs from a remote client"
  func_wrapper check_journald_not_receive_remote_logs "${name}" "${cis_num}"

  # AIDE and Filesystem Integrity Checks
  cis_num="5.3.1"
  name="Ensure AIDE is installed"
  func_wrapper check_aide_installed "${name}" "${cis_num}"

  cis_num="5.3.2"
  name="Ensure filesystem integrity is regularly checked"
  func_wrapper check_filesystem_integrity_checked "${name}" "${cis_num}"

  cis_num="5.3.3"
  name="Ensure cryptographic mechanisms are used to protect the integrity of audit tools"
  func_wrapper check_crypto_mechanisms_audit_tools "${name}" "${cis_num}"

  # Permissions Checks
  cis_num="6.1.1"
  name="Ensure permissions on /etc/passwd are configured"
  func_wrapper check_permissions_passwd "${name}" "${cis_num}"

  cis_num="6.1.2"
  name="Ensure permissions on /etc/passwd- are configured"
  func_wrapper check_permissions_passwd_dash "${name}" "${cis_num}"

  cis_num="6.1.3"
  name="Ensure permissions on /etc/opasswd are configured"
  func_wrapper check_permissions_opasswd "${name}" "${cis_num}"

  # Permissions Checks
  cis_num="6.1.4"
  name="Ensure permissions on /etc/group are configured"
  func_wrapper check_permissions_group "${name}" "${cis_num}"

  cis_num="6.1.5"
  name="Ensure permissions on /etc/group- are configured"
  func_wrapper check_permissions_group_dash "${name}" "${cis_num}"

  cis_num="6.1.6"
  name="Ensure permissions on /etc/shadow are configured"
  func_wrapper check_permissions_shadow "${name}" "${cis_num}"

  cis_num="6.1.7"
  name="Ensure permissions on /etc/shadow- are configured"
  func_wrapper check_permissions_shadow_dash "${name}" "${cis_num}"

  cis_num="6.1.8"
  name="Ensure permissions on /etc/gshadow are configured"
  func_wrapper check_permissions_gshadow "${name}" "${cis_num}"

  cis_num="6.1.9"
  name="Ensure permissions on /etc/gshadow- are configured"
  func_wrapper check_permissions_gshadow_dash "${name}" "${cis_num}"

  cis_num="6.1.10"
  name="Ensure permissions on /etc/shells are configured"
  func_wrapper check_permissions_shells "${name}" "${cis_num}"

  cis_num="6.1.11"
  name="Ensure world writable files and directories are secured"
  func_wrapper check_world_writable_files "${name}" "${cis_num}"

  cis_num="6.1.12"
  name="Ensure no unowned or ungrouped files or directories exist"
  func_wrapper check_no_unowned_files "${name}" "${cis_num}"

  cis_num="6.1.13"
  name="Ensure SUID and SGID files are reviewed"
  func_wrapper check_suid_sgid_files "${name}" "${cis_num}"

  # Account Checks
  cis_num="6.2.1"
  name="Ensure accounts in /etc/passwd use shadowed passwords"
  func_wrapper check_shadowed_passwords "${name}" "${cis_num}"

  cis_num="6.2.2"
  name="Ensure /etc/shadow password fields are not empty"
  func_wrapper check_shadow_password_fields_not_empty "${name}" "${cis_num}"

  cis_num="6.2.3"
  name="Ensure all groups in /etc/passwd exist in /etc/group"
  func_wrapper check_groups_in_passwd_exist_in_group "${name}" "${cis_num}"

  cis_num="6.2.4"
  name="Ensure no duplicate UIDs exist"
  func_wrapper check_no_duplicate_uids "${name}" "${cis_num}"

  cis_num="6.2.5"
  name="Ensure no duplicate GIDs exist"
  func_wrapper check_no_duplicate_gids "${name}" "${cis_num}"

  cis_num="6.2.6"
  name="Ensure no duplicate user names exist"
  func_wrapper check_no_duplicate_usernames "${name}" "${cis_num}"

  cis_num="6.2.7"
  name="Ensure no duplicate group names exist"
  func_wrapper check_no_duplicate_groupnames "${name}" "${cis_num}"

  cis_num="6.2.8"
  name="Ensure root path integrity"
  func_wrapper check_root_path_integrity "${name}" "${cis_num}"

  cis_num="6.2.9"
  name="Ensure root is the only UID 0 account"
  func_wrapper check_root_only_uid_0 "${name}" "${cis_num}"

  cis_num="6.2.10"
  name="Ensure local interactive user home directories are configured"
  func_wrapper check_local_user_home_directories "${name}" "${cis_num}"

  cis_num="6.2.11"
  name="Ensure local interactive user dot files access is configured"
  func_wrapper check_local_user_dot_files_access "${name}" "${cis_num}"

}

# Function to print summary of results
function summary {
  echo "","Scanning Completed","Total results","Total $TOTAL checks: $PASS passed ($(expr $PASS \* 100 / $TOTAL)%)/ $FAILED failed ($(expr $FAILED \* 100 / $TOTAL)%)"
}

main
summary
