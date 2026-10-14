# What each control is rated on

Generated from `evidence/controls.yml` by `tools/render_controls.py`. Each endpoint collector measures the metrics from configuration and logs (window: 30 days); the manager scores them. Score = points earned / points available × 100, including the SCA checks mapped to the control (weight 15).

Ratings: Compliant ≥ 90, Largely compliant ≥ 70, Partially compliant ≥ 40, Non-compliant ≥ 0. Evidence older than 26 h is flagged stale.

## A.5.9 Inventory of information and other associated assets

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Wazuh agent is running and reporting the asset | `wazuh_running` | yes | 20 |
| both | Hardware/software inventory collection is enabled | `syscollector_enabled` | yes | 30 |
| both | OS, software list and hardware serial were all collected | `inventory_complete` | yes | 30 |
| both | Hardware serial number is recorded | `hardware_serial_recorded` | yes | 20 |
| both | Installed software packages | `software_packages` | shown only | 0 |

## A.5.16 Identity management

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Guest account is disabled | `guest_disabled` | yes | 20 |
| both | No enabled account unused for 90+ days | `stale_accounts` | ≤ 0 (half ≤ 1) | 25 |
| both | Every enabled account requires a password | `password_not_required_accounts` | ≤ 0 | 20 |
| both | Account create/change/delete events are audited | `account_management_audited` | yes | 20 |
| both | No enabled account that has never been used | `never_logged_in_accounts` | ≤ 0 (half ≤ 2) | 15 |
| both | Account lifecycle events in the window | `account_changes_window` | shown only | 0 |

## A.5.17 Authentication information

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | No account has an empty password | `empty_password_accounts` | ≤ 0 | 25 |
| linux | No password stored with MD5/DES hashes | `weak_hash_accounts` | ≤ 0 | 20 |
| linux | /etc/shadow is not world-accessible | `shadow_protected` | yes | 20 |
| linux | SSH refuses empty passwords | `ssh_permit_empty_passwords` | no | 15 |
| linux | Passwords expire within 365 days | `pass_max_days` | ≤ 365 | 10 |
| windows | Blank-password accounts cannot log on over the network | `blank_password_network_logon_blocked` | yes | 15 |
| windows | Weak LM password hashes are not stored | `lm_hash_disabled` | yes | 15 |
| windows | WDigest does not keep plaintext passwords in memory | `wdigest_plaintext_disabled` | yes | 15 |
| windows | LSA protection (RunAsPPL) guards stored credentials | `lsa_protection` | yes | 10 |
| windows | Passwords are not stored with reversible encryption | `reversible_encryption_disabled` | yes | 10 |
| windows | Password history remembers 24 passwords | `password_history` | ≥ 24 (half ≥ 5) | 10 |
| windows | Passwords expire within 365 days | `password_max_age_days` | 1-365 | 5 |
| windows | Windows does not store network passwords | `network_credentials_not_stored` | yes | 5 |
| both | No login account with a never-expiring password | `passwords_never_expire` | ≤ 0 (half ≤ 1) | 10 |
| both | Password changes/resets in the window | `password_changes_window` | shown only | 0 |

## A.5.18 Access rights

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | New accounts lock 1-45 days after password expiry | `inactive_days_default` | 1-45 | 25 |
| both | No enabled login account unused for 90+ days | `stale_accounts` | ≤ 0 (half ≤ 1) | 35 |
| both | No enabled login account that has never been used | `never_logged_in_accounts` | ≤ 0 (half ≤ 2) | 15 |
| both | Account and group changes in the window | `account_changes_window` | shown only | 0 |

## A.7.10 Storage media

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | USB/removable storage is blocked, write-protected or must be encrypted | `removable_control` | yes | 45 |
| windows | AutoRun is disabled for all drives | `autorun_disabled` | yes | 25 |
| windows | Removable-storage access is audited | `removable_storage_audited` | yes | 15 |
| both | USB storage connections in the window | `usb_storage_insertions_window` | shown only | 0 |
| windows | USB storage devices ever connected | `usb_storage_devices_ever` | shown only | 0 |

## A.8.2 Privileged access rights

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | root is the only UID 0 account | `uid0_accounts` | ≤ 1 | 20 |
| linux | Root cannot log in over SSH with a password | `ssh_root_login_restricted` | yes | 15 |
| linux | sudo always asks for a password (no NOPASSWD) | `sudo_nopasswd_entries` | ≤ 0 (half ≤ 1) | 20 |
| linux | At most 3 users hold sudo/admin rights | `privileged_users` | ≤ 3 (half ≤ 5) | 15 |
| linux | No unauthorised sudo attempts in the window | `not_in_sudoers_window` | ≤ 0 (half ≤ 2) | 10 |
| linux | Few failed privilege elevations in the window | `privilege_failures_window` | ≤ 5 (half ≤ 20) | 5 |
| windows | At most 2 members of local Administrators | `administrators` | ≤ 2 (half ≤ 3) | 25 |
| windows | Built-in Administrator is disabled | `builtin_admin_disabled` | yes | 15 |
| windows | User Account Control is on | `uac_enabled` | yes | 20 |
| windows | Admins are prompted before elevation | `uac_prompts_admins` | yes | 10 |
| windows | Administrators-group changes are audited | `group_management_audited` | yes | 15 |
| linux | sudo commands run in the window | `sudo_commands_window` | shown only | 0 |
| windows | Administrators-group membership changes in the window | `admin_group_changes_window` | shown only | 0 |
| windows | Logons with administrative privileges in the window | `privileged_logons_window` | shown only | 0 |

## A.8.3 Information access restriction

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Anonymous users cannot list accounts | `anonymous_sam_restricted` | yes | 25 |
| both | Anonymous users cannot list shares | `anonymous_shares_restricted` | yes | 20 |
| both | Everyone permissions do not apply to anonymous users | `everyone_excludes_anonymous` | yes | 15 |
| both | No shares are reachable by null sessions | `null_session_shares` | ≤ 0 | 10 |
| both | No share grants Everyone/Users write access | `shares_open_to_broad_groups` | ≤ 0 | 30 |

## A.8.5 Secure authentication

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | SSH uses keys, not passwords | `ssh_password_auth` | no | 15 |
| linux | Accounts lock after repeated failures (faillock) | `lockout_configured` | yes | 15 |
| linux | SSH allows at most 4 attempts per connection | `ssh_max_auth_tries` | ≤ 4 (half ≤ 6) | 5 |
| windows | Accounts lock after 1-10 failed attempts | `lockout_threshold` | 1-10 | 15 |
| windows | Failed logons are audited | `logon_failures_audited` | yes | 15 |
| windows | Remote Desktop requires Network Level Authentication | `rdp_nla_required` | yes | 5 |
| windows | Ctrl+Alt+Del is required to sign in | `ctrl_alt_del_required` | yes | 5 |
| both | Minimum password length is 14 | `password_min_length` | ≥ 14 (half ≥ 8) | 15 |
| both | No brute-force bursts (10+ failures per hour from one source) | `brute_force_bursts` | ≤ 0 (half ≤ 3) | 15 |
| both | No successful logon from a source with 5+ failures | `success_after_failures` | ≤ 0 | 20 |
| both | Failed logons in the window | `failed_logons_window` | shown only | 0 |
| windows | Account lockouts in the window | `account_lockouts_window` | shown only | 0 |

## A.8.6 Capacity management

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | Every filesystem is below 80% used | `max_filesystem_used_pct` | ≤ 80 (half ≤ 90) | 35 |
| linux | Every filesystem is below 80% inode use | `max_inode_used_pct` | ≤ 80 (half ≤ 90) | 10 |
| linux | No out-of-memory kills in the window | `oom_events_window` | ≤ 0 (half ≤ 3) | 20 |
| windows | Every volume has 20% free space | `min_volume_free_pct` | ≥ 20 (half ≥ 10) | 45 |
| windows | No low-memory warnings in the window | `low_memory_events_window` | ≤ 0 (half ≤ 3) | 15 |
| both | No disk-full events in the window | `disk_full_events_window` | ≤ 0 (half ≤ 3) | 25 |
| both | Memory available at collection time (%) | `memory_available_pct` | shown only | 0 |

## A.8.7 Protection against malware

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Anti-malware is installed and running | `av_running` | yes | 25 |
| windows | Real-time protection is on | `realtime_protection` | yes | 10 |
| linux | Files are scanned on access | `on_access_scanning` | yes | 10 |
| both | Signatures are at most 2 days old | `signature_age_days` | ≤ 2 (half ≤ 7) | 20 |
| both | A scan ran in the last 7 days | `last_scan_age_days` | ≤ 7 (half ≤ 30) | 15 |
| windows | Tamper protection is on | `tamper_protection` | yes | 5 |
| windows | Every detected threat was remediated | `remediation_failures_window` | ≤ 0 | 10 |
| windows | No unresolved threats | `unresolved_threats` | ≤ 0 | 5 |
| windows | Protection was not switched off in the window | `protection_disabled_events_window` | ≤ 0 (half ≤ 2) | 5 |
| linux | Wazuh rootkit detection is on | `rootcheck_enabled` | yes | 15 |
| both | Few signature update failures | `signature_update_failures_window` | ≤ 2 (half ≤ 10) | 5 |
| both | Malware detections in the window | `detections_window` | shown only | 0 |

## A.8.8 Management of technical vulnerabilities

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Automatic updates are enabled | `auto_updates_enabled` | yes | 15 |
| both | Updates were installed in the last 35 days | `days_since_last_upgrade` | ≤ 35 (half ≤ 60) | 20 |
| both | Update sources were checked in the last 7 days | `days_since_metadata_refresh` | ≤ 7 (half ≤ 14) | 10 |
| both | No security updates waiting | `pending_security_updates` | ≤ 0 (half ≤ 5) | 25 |
| both | No failed updates in the window | `update_failures_window` | ≤ 0 (half ≤ 3) | 10 |
| both | No restart pending to finish updates | `reboot_required` | no | 10 |
| linux | The newest installed kernel is running | `running_latest_kernel` | yes | 10 |
| both | All pending updates | `pending_updates` | shown only | 0 |

## A.8.12 Data leakage prevention

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Privileged programs cannot write core dumps | `suid_dumpable` | 0 | 40 |
| both | Core dumps are disabled system-wide | `core_dumps_restricted` | yes | 40 |
| both | No core dumps captured in the window | `core_dumps_window` | ≤ 0 (half ≤ 3) | 20 |

## A.8.13 Information backup

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | A backup job is configured | `backup_configured` | yes | 15 |
| both | Backups are scheduled at least daily | `backup_interval_hours` | ≤ 24 (half ≤ 168) | 10 |
| both | Backup runs are recorded in logs | `backup_log_verified` | yes | 10 |
| both | Backups ran as often as scheduled (successful runs / expected runs) | `backup_adherence_pct` | ≥ 95 (half ≥ 80) | 20 |
| both | Backup runs succeeded (successful / all runs) | `backup_success_rate_pct` | ≥ 95 (half ≥ 80) | 20 |
| both | Latest successful backup is within 1.5 schedule intervals | `backup_last_success_age_ratio` | ≤ 1.5 (half ≤ 3) | 15 |
| both | No scheduled backup was missed | `backup_missed_runs` | ≤ 0 (half ≤ 2) | 10 |
| both | Latest successful backup | `backup_last_success` | shown only | 0 |
| both | Failed backup runs in the window | `backup_runs_failed` | shown only | 0 |

## A.8.15 Logging

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | The audit daemon is running | `auditd_active` | yes | 15 |
| linux | Audit rules are locked until reboot | `audit_rules_immutable` | yes | 5 |
| linux | The system journal survives reboots | `journal_persistent` | yes | 10 |
| windows | Security log holds at least 1 GB | `security_log_max_mb` | ≥ 1024 (half ≥ 196) | 10 |
| windows | Logs were not cleared in the window | `log_cleared_window` | ≤ 0 | 20 |
| both | Audit policy covers 80% of required event types | `audit_coverage_pct` | ≥ 80 (half ≥ 50) | 20 |
| both | At least 90 days of logs are retained | `log_retention_days` | ≥ 90 (half ≥ 30) | 20 |
| both | Events were logged in the last 24 hours | `logging_alive` | yes | 10 |
| both | No log-loss events (log full, backlog/rate limit) | `log_loss_events_window` | ≤ 0 (half ≤ 5) | 5 |
| windows | Security events per day | `security_events_per_day` | shown only | 0 |

## A.8.16 Monitoring activities

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Wazuh agent is connected to the manager | `wazuh_connected` | yes | 25 |
| windows | Last keepalive within 10 minutes | `keepalive_age_minutes` | ≤ 10 (half ≤ 60) | 10 |
| linux | Authentication logs are collected by Wazuh | `auth_logs_monitored` | yes | 20 |
| linux | The audit log is collected by Wazuh | `audit_log_monitored` | yes | 15 |
| linux | Logs leave the host (Wazuh or syslog forwarding) | `central_collection` | yes | 15 |
| linux | No log-forwarding errors in the window | `forwarding_errors_window` | ≤ 0 (half ≤ 5) | 10 |
| windows | The Security event log is collected by Wazuh | `security_log_monitored` | yes | 20 |
| windows | Wazuh collects 80% of key event channels | `monitored_channels_pct` | ≥ 80 (half ≥ 50) | 15 |
| windows | PowerShell script-block logging is on | `scriptblock_logging` | yes | 15 |
| windows | Sysmon is running for detailed process/network telemetry | `sysmon_running` | yes | 15 |
| linux | fail2ban is active | `fail2ban_active` | shown only | 0 |

## A.8.17 Clock synchronization

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Time synchronization is configured | `ntp_enabled` | yes | 15 |
| linux | The clock reports NTP-synchronized | `ntp_synchronized` | yes | 10 |
| windows | Windows Time service is running | `time_service_running` | yes | 10 |
| both | Clock is within 1 second of the time source | `clock_offset_seconds` | ≤ 1 (half ≤ 5) | 30 |
| both | Last successful sync within 24 hours | `last_sync_age_hours` | ≤ 24 (half ≤ 168) | 20 |
| both | Few sync failures in the window | `sync_failures_window` | ≤ 5 (half ≤ 30) | 15 |
| both | No clock jumps (steps of 1 s or more) in the window | `clock_steps_window` | ≤ 0 (half ≤ 3) | 10 |

## A.8.18 Use of privileged utility programs

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | sudo runs commands in a pseudo-terminal | `sudo_use_pty` | yes | 20 |
| linux | sudo use is logged | `sudo_logging` | yes | 20 |
| linux | No setuid programs outside the standard list | `unexpected_suid_binaries` | ≤ 0 (half ≤ 3) | 45 |
| windows | Remote Registry is disabled | `remote_registry_disabled` | yes | 25 |
| windows | PowerShell 2.0 (no logging) is removed | `powershell_v2_enabled` | no | 20 |
| windows | No PsExec service left behind | `psexec_service_present` | no | 15 |
| windows | Only Administrators can debug programs | `debug_privilege_restricted` | yes | 15 |
| windows | WinRM remote management is not running | `winrm_running` | no | 10 |
| windows | Services installed in the window | `services_installed_window` | shown only | 0 |

## A.8.19 Installation of software on operational systems

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Installers cannot run elevated for standard users | `always_install_elevated` | no | 40 |
| both | Application control (Smart App Control/AppLocker) is enforced | `application_control` | yes | 30 |
| both | Few failed installs | `software_install_failures_window` | ≤ 2 (half ≤ 10) | 15 |
| both | Programs installed in the window | `software_installs_window` | shown only | 0 |
| both | Smart App Control state | `smart_app_control` | shown only | 0 |

## A.8.20 Networks security

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | A host firewall is active | `firewall_active` | yes | 25 |
| linux | Inbound traffic is denied by default | `default_inbound_deny` | yes | 25 |
| linux | Kernel network hardening settings applied | `kernel_network_hardening_pct` | ≥ 100 (half ≥ 70) | 20 |
| windows | Firewall is on for every profile | `firewall_all_profiles_enabled` | yes | 25 |
| windows | Inbound traffic is blocked by default | `default_inbound_block` | yes | 20 |
| windows | At most 10 inbound allow rules on public networks | `inbound_allow_rules_public` | ≤ 10 (half ≤ 25) | 10 |
| windows | Firewall was not stopped in the window | `firewall_stopped_events_window` | ≤ 0 | 10 |
| both | Dropped connections are logged | `firewall_logs_drops` | yes | 15 |
| both | At most 5 services listen on the network | `exposed_listening_services` | ≤ 5 (half ≤ 10) | 15 |
| windows | Firewall rule/setting changes in the window | `firewall_rule_changes_window` | shown only | 0 |

## A.8.21 Security of network services

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | No telnet/rsh/tftp/NIS services installed | `legacy_services_installed` | ≤ 0 | 25 |
| linux | No plaintext protocols listening | `plaintext_listeners` | ≤ 0 | 25 |
| linux | SSH offers no weak ciphers/MACs/key exchange | `ssh_weak_algorithms` | ≤ 0 (half ≤ 2) | 20 |
| linux | SSH X11 forwarding is off | `ssh_x11_forwarding` | no | 10 |
| linux | Samba refuses SMBv1 | `smb_min_protocol_ok` | yes | 10 |
| linux | No NFS exports with no_root_squash/insecure | `nfs_insecure_exports` | ≤ 0 | 10 |
| windows | SMBv1 server is off | `smb1_server_enabled` | no | 25 |
| windows | SMBv1 client is off | `smb1_client_enabled` | no | 15 |
| windows | LLMNR name resolution is off | `llmnr_disabled` | yes | 15 |
| windows | NetBIOS over TCP/IP is off on all adapters | `netbios_disabled_pct` | ≥ 100 (half ≥ 50) | 10 |
| windows | SSL 3.0/TLS 1.0/1.1 are not enabled for servers | `legacy_tls_enabled` | no | 15 |
| windows | No SMBv1 connection attempts in the window | `smb1_access_attempts_window` | ≤ 0 | 10 |
| windows | Remote Desktop enabled | `rdp_enabled` | shown only | 0 |

## A.8.22 Segregation of networks

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Host does not route IPv4 between networks | `ipv4_forwarding` | no | 40 |
| both | Host does not route IPv6 between networks | `ipv6_forwarding` | no | 30 |
| both | Not bridging two physical networks | `multi_homed_with_forwarding` | no | 30 |

## A.8.23 Web filtering

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | A web filter is in place (agent, proxy, filtering DNS or network protection) | `filtering_layer` | yes | 45 |
| windows | Windows SmartScreen is on | `windows_smartscreen` | yes | 20 |
| windows | Edge SmartScreen is not disabled | `edge_smartscreen_on` | yes | 10 |
| windows | Edge SmartScreen is enforced by policy | `edge_smartscreen_enforced` | yes | 5 |
| windows | Defender network protection blocks malicious sites | `network_protection` | block (half: audit) | 20 |
| linux | Uses a filtering DNS resolver | `filtering_dns` | yes | 20 |
| windows | Web requests blocked in the window | `web_blocks_window` | shown only | 0 |

## A.8.24 Use of cryptography

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | Root filesystem is on an encrypted volume | `root_encrypted` | yes | 35 |
| linux | Swap is encrypted or absent | `swap_encrypted_or_absent` | yes | 10 |
| linux | LUKS volumes use strong ciphers and keys | `weak_luks_volumes` | ≤ 0 | 10 |
| linux | No world-readable private keys | `world_readable_private_keys` | ≤ 0 | 20 |
| linux | No DSA or short RSA SSH host keys | `weak_ssh_host_keys` | ≤ 0 | 10 |
| windows | System drive is protected by BitLocker/device encryption | `os_volume_protected` | yes | 30 |
| windows | Every fixed drive is encrypted | `fixed_volumes_protected_pct` | ≥ 100 (half ≥ 50) | 15 |
| windows | Encryption uses XTS-AES | `strong_encryption_method` | yes | 10 |
| windows | Encrypted drives have a recovery password | `recovery_password_protector` | yes | 10 |
| windows | No drive has protection suspended | `protection_suspended_volumes` | ≤ 0 | 10 |
| windows | SMB server signing is required | `smb_server_signing_required` | yes | 5 |
| windows | SMB client signing is required | `smb_client_signing_required` | yes | 5 |
| both | Legacy TLS/SSL is not enabled | `legacy_tls_allowed` | no | 15 |

## A.8.26 Application security requirements

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| both | Application workers do not run as root | `app_workers_as_root` | ≤ 0 | 50 |
| both | Web server does not offer TLS 1.0/1.1 | `web_legacy_tls` | no | 25 |
| both | Web server hides its version | `web_version_disclosure` | no | 25 |

## A.8.31 Separation of development, test and production environments

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | No compilers/debuggers (gcc, make, gdb) on the host | `core_dev_tools_present` | ≤ 0 (half ≤ 1) | 60 |
| linux | Few development tools installed | `dev_tools_present` | ≤ 0 (half ≤ 3) | 25 |
| windows | Developer Mode is off | `developer_mode` | no | 60 |
| windows | Development tools installed | `dev_tools_present` | shown only | 0 |
| windows | WSL distributions installed | `wsl_distributions` | shown only | 0 |

## A.8.32 Change management

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | Package changes are recorded | `package_history_available` | yes | 20 |
| linux | /etc is under version control (etckeeper/git) | `etc_version_controlled` | yes | 15 |
| windows | Service, task and policy changes are audited | `change_audit_pct` | ≥ 100 (half ≥ 34) | 25 |
| both | Wazuh file integrity monitoring is configured | `fim_configured` | yes | 25 |
| both | FIM covers the critical system paths | `fim_critical_coverage_pct` | ≥ 80 (half ≥ 40) | 25 |
| both | FIM watches in real time / who-data | `fim_realtime` | yes | 15 |
| linux | Package transactions in the window | `package_changes_window` | shown only | 0 |
| windows | Recorded changes in the window | `changes_window` | shown only | 0 |

## A.8.34 Protection of information systems during audit testing

| OS | Criterion | Metric | Required | Weight |
|---|---|---|---|---|
| linux | Audit tools are writable by root only | `audit_tools_restricted` | yes | 30 |
| linux | Audit logs are readable by root/admin group only | `audit_logs_protected` | yes | 30 |
| linux | Changes to the audit configuration are audited | `audit_config_watched` | yes | 25 |
| linux | auditd was not stopped in the window | `audit_service_stops_window` | ≤ 0 (half ≤ 2) | 15 |
| windows | Audit-policy changes are audited | `audit_policy_change_audited` | yes | 30 |
| windows | Only Administrators manage auditing and the security log | `security_privilege_restricted` | yes | 30 |
| windows | Security log was not cleared in the window | `log_cleared_window` | ≤ 0 | 25 |
| windows | Few audit-policy changes in the window | `audit_policy_changes_window` | ≤ 0 (half ≤ 3) | 15 |
