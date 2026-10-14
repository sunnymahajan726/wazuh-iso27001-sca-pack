# How each check is tested

What every SCA check in this pack looks at, and when it passes. The exact rule Wazuh runs is in the policy YAML (`rules:`).

## Linux

| Control | Check | Basis |
|---|---|---|
| A.5.9 | Wazuh agent is installed | Looks for the /var/ossec directory. Passes when the Wazuh agent is installed. |
| A.8.2 | No UID 0 accounts other than root | Reads /etc/passwd for accounts with UID 0. Passes when root is the only one. |
| A.8.2 | Root SSH login is disabled | Reads the effective SSH server settings (sshd -T). Passes when PermitRootLogin is 'no' or 'prohibit-password' (keys only). |
| A.8.5 | SSH password authentication is disabled | Reads the effective SSH server settings (sshd -T). Passes when PasswordAuthentication is 'no'. |
| A.5.17 | SSH empty passwords are disabled | Reads the effective SSH server settings (sshd -T). Passes when PermitEmptyPasswords is 'no'. |
| A.8.5 | PAM password quality is configured | Searches /etc/pam.d for pam_pwquality or pam_cracklib. Passes when either is configured. |
| A.5.18 | Dormant accounts have an inactivity period | Reads the new-account defaults (useradd -D). Passes when INACTIVE is 1 day or more, so accounts lock after their password expires. |
| A.8.2 | Sudo commands require authentication | Searches /etc/sudoers and /etc/sudoers.d for active NOPASSWD entries. Passes when there are none. |
| A.8.18 | Sudo uses a pseudo-terminal | Searches sudoers for 'Defaults use_pty'. Passes when it is set. |
| A.8.15 | Audit daemon is active | Checks the auditd service. Passes when it is running. |
| A.8.15 | Audit rules are immutable | Searches the audit rules for '-e 2'. Passes when the rules are locked (immutable) until reboot. |
| A.8.15 | Authentication log exists | Looks for /var/log/auth.log or /var/log/secure. Passes when either exists. |
| A.8.15 | Persistent journal storage is configured | Reads the journald configuration. Passes when Storage=persistent. |
| A.8.16 | Remote log forwarding is configured | Searches the rsyslog configuration for remote forwarding (@, @@, omfwd, target=). Passes when logs are forwarded. |
| A.8.17 | Clock synchronization is active | Asks timedatectl whether the clock is NTP-synchronized. Passes when it is. |
| A.8.20 | Host firewall is active | Checks firewalld, nftables and ufw. Passes when any of them is active. |
| A.8.22 | IP forwarding is disabled | Reads the kernel setting net.ipv4.ip_forward. Passes when it is 0 (not routing traffic). |
| A.8.20 | Source routing is disabled | Reads the kernel setting net.ipv4.conf.all.accept_source_route. Passes when it is 0. |
| A.8.24 | Private keys are not world-readable | Finds *.key files under /etc that everyone can read. Passes when there are none. |
| A.8.24 | Disk encryption is present | Lists block devices (lsblk). Passes when an encrypted (crypt/LUKS) volume exists. |
| A.8.8 | Automatic security updates are enabled | Checks unattended-upgrades, dnf-automatic and yum-cron. Passes when any is enabled. |
| A.8.7 | Endpoint protection is active | Checks ClamAV (clamav-daemon, clamd@scan) and Microsoft Defender for Linux (wdavdaemon). Passes when any is running. |
| A.8.12 | Core dumps are restricted | Reads the kernel setting fs.suid_dumpable. Passes when it is 0 (no core dumps from privileged programs). |
| A.7.10 | USB storage is disabled where required | Reads the modprobe configuration for usb-storage. Passes when the module is blacklisted or replaced with /bin/true or /bin/false. |
| A.8.13 | Backup service or success marker exists | Checks borgmatic, restic-backup.timer and the marker file /var/lib/iso27001/last-backup-ok. Passes when any is active or present. |
| A.8.6 | Root filesystem use is below 90 percent | Measures disk use on / (df). Passes when it is below 90%. |
| A.8.21 | Legacy network services are absent | Lists installed telnet, rsh, rlogin, rexec and tftp services. Passes when there are none. |
| A.8.23 | Web filtering agent is active | Looks for squid or a Zscaler, Netskope, Umbrella or Websense process. Passes when one is running. |
| A.8.26 | Application workers do not run as root | Looks for nginx, httpd, apache2, tomcat, node or java running as root. Passes when there are none. |
| A.8.31 | Development tools are absent from production | Looks for gcc, make and gdb. Passes when none is installed. |
| A.8.32 | Package-manager history is available | Looks for the apt, dnf or yum history log. Passes when one exists. |
| A.8.32 | Wazuh FIM is configured | Searches the Wazuh ossec.conf for a <syscheck> section. Passes when file integrity monitoring is configured. |
| A.8.34 | Audit utility access is restricted | Reads the permissions of /usr/sbin/auditctl. Passes when they are 755 or stricter. |

## Windows

| Control | Check | Basis |
|---|---|---|
| A.5.9 | Wazuh agent service is installed | Looks for the WazuhSvc service in the registry. Passes when the Wazuh agent service is installed. |
| A.5.16 | Guest account is disabled | Finds the built-in Guest account (SID ending -501). Passes when it is disabled. |
| A.8.2 | Built-in Administrator is disabled or renamed | Finds the built-in Administrator account (SID ending -500). Passes when it is disabled or renamed. |
| A.5.17 | Blank-password network logons are restricted | Reads registry Lsa\LimitBlankPasswordUse. Passes when it is 1 (accounts with blank passwords can't log on over the network). |
| A.8.5 | Last signed-in user is hidden | Reads registry Policies\System\DontDisplayLastUserName. Passes when it is 1. |
| A.8.5 | Secure attention sequence is required | Reads registry Policies\System\DisableCAD. Passes when it is 0 (Ctrl+Alt+Del required). Fails if the setting is missing. |
| A.8.5 | Minimum password length is at least 14 | Runs 'net accounts'. Passes when the minimum password length is 14 or more. |
| A.5.17 | Credential storage is disabled | Reads registry Lsa\DisableDomainCreds. Passes when it is 1 (Windows doesn't store network passwords). |
| A.5.17 | LM hashes are not stored | Reads registry Lsa\NoLMHash. Passes when it is 1 (weak LM password hashes aren't stored). |
| A.8.7 | Defender real-time protection is enabled | Asks Microsoft Defender for its status. Passes when real-time protection is on. |
| A.8.8 | Windows Update is enabled | Reads the Windows Update service (wuauserv) startup type. Passes when it is Automatic or Manual, not Disabled. |
| A.8.20 | Firewall is enabled for all profiles | Reads the firewall profiles actually in effect. Passes when Domain, Private and Public are all enabled. |
| A.8.20 | Inbound firewall defaults to block | Reads the firewall profiles actually in effect. Passes when every profile blocks inbound traffic by default. |
| A.8.21 | SMBv1 is disabled | Asks the SMB server whether SMBv1 is enabled. Passes when it is off. |
| A.8.24 | SMB server signing is required | Reads registry LanmanServer\Parameters\RequireSecuritySignature. Passes when it is 1. Fails if the setting is missing. |
| A.8.24 | BitLocker protects the OS volume | Queries disk encryption on the system drive. Passes when BitLocker or device encryption protection is on. |
| A.8.15 | Security log is at least 1 GB | Reads the Security event log's maximum size. Passes when it is 1024 MB or more. |
| A.8.15 | Logon auditing records success and failure | Runs auditpol for the Logon subcategory. Passes when both Success and Failure are audited. |
| A.8.16 | PowerShell script-block logging is enabled | Reads registry PowerShell\ScriptBlockLogging\EnableScriptBlockLogging. Passes when it is 1. Fails if the setting is missing. |
| A.8.17 | Windows Time is running | Checks the Windows Time service (W32Time). Passes when it is running. |
| A.8.5 | RDP requires NLA | Reads registry RDP-Tcp\UserAuthentication. Passes when it is 1 (Network Level Authentication required). |
| A.8.3 | Anonymous SAM enumeration is restricted | Reads registry Lsa\RestrictAnonymousSAM. Passes when it is 1 (anonymous users can't list accounts). |
| A.7.10 | AutoRun is disabled | Reads registry Policies\Explorer\NoDriveTypeAutoRun. Passes when it is 255 (AutoRun off for all drives). Fails if the setting is missing. |
| A.8.13 | Backup service is active | Checks Windows Server Backup (wbengine) and Veeam Agent. Passes when either is running. |
| A.8.6 | System drive has at least 10 percent free | Measures free space on the system drive. Passes when it is 10% or more. |
| A.8.18 | Remote Registry is disabled | Reads the Remote Registry service startup type. Passes when it is Disabled. |
| A.8.31 | Developer Mode is disabled | Reads registry AppModelUnlock\AllowDevelopmentWithoutDevLicense. Passes unless it is 1 (Developer Mode on). |
| A.8.19 | AlwaysInstallElevated is disabled | Reads registry Policies\Microsoft\Windows\Installer\AlwaysInstallElevated. Passes unless it is 1. |
| A.8.32 | Wazuh FIM is configured | Searches the Wazuh agent's ossec.conf for a <syscheck> section. Passes when file integrity monitoring is configured. |
| A.8.23 | Edge SmartScreen is enabled | Reads registry Policies\Microsoft\Edge\SmartScreenEnabled. Passes when it is 1. Fails if the setting is missing. |
| A.8.34 | Audit-policy changes are recorded | Runs auditpol for the Audit Policy Change subcategory. Passes when Success is audited. |
