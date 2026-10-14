<#
ISO/IEC 27001:2022 evidence collector for Windows (wazuh-iso27001-sca-pack).

Run as SYSTEM by the Wazuh command wodle (64-bit PowerShell). For every Annex A
control mapped in the Windows policy it reads the relevant configuration *and*
the event logs over the last $WindowDays days, and writes one JSON line:

  {"iso27001":{"type":"evidence","collector":"windows","control":"A.8.13",
               "metrics":{...},"evidence":[...],"errors":[...]}}

Metrics are raw measurements; scoring against thresholds happens on the manager
(evidence/controls.yml). Read-only: it changes nothing on the host.

Run by hand (elevated PowerShell) to see what it reports:
  powershell -ExecutionPolicy Bypass -File iso27001_collect.ps1 A.8.13
#>
param([string[]]$Only)

$Version = '1.0'
$WindowDays = 30
$StaleAccountDays = 90
$BruteForcePerHour = 10
$BackupPattern = 'backup|robocopy|restic|veeam|acronis|macrium|reflect|duplicati|kopia|borg|rclone|urbackup|cobian|arcserve|carbonite|backblaze|idrive|wbadmin|filehistory'
# Any backup tool can report here: one line per run, "<ISO-8601 time> SUCCESS|FAILURE [job=name]".
$BackupStatusLog = Join-Path $env:ProgramData 'iso27001\backup-status.log'
$FilteringDns = @('1.1.1.2','1.0.0.2','1.1.1.3','1.0.0.3','9.9.9.9','149.112.112.112','208.67.222.222',
                  '208.67.220.220','94.140.14.14','94.140.15.15','185.228.168.9','185.228.169.9','76.76.2.1')
$WebFilterProcesses = 'zsatunnel|zscaler|stagentsvc|nsclient|netskope|acumbrellaagent|csc_umbrellaagent|wepsvc|forcepoint|websense|dnsfilter|dnsagent'

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$Now = Get-Date
$Since = $Now.AddDays(-$WindowDays)
$WindowMs = [int64]$WindowDays * 86400000
$Collected = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

# ------------------------------------------------------------------ helpers
$script:M = $null; $script:EV = $null
function M($k, $v) { $script:M[$k] = $v }
function E($s) { if ($null -ne $s -and "$s" -ne '') { [void]$script:EV.Add([string]$s) } }
function Iso($d) { if ($d) { ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }
function AgeH($d) { if ($d) { [math]::Round(($Now - [datetime]$d).TotalHours, 1) } else { $null } }
function AgeD($d) { if ($d) { [math]::Round(($Now - [datetime]$d).TotalDays, 1) } else { $null } }
function Pct($a, $b) { if ($b) { [math]::Round(100.0 * $a / $b, 1) } else { $null } }

function RegV($Path, $Name) {
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

# Events from a log within the window. $Ids <= 20 per call.
function Get-Ev($Log, $Ids, $Provider, $Days = $WindowDays, $Max = 5000) {
    $f = @{ LogName = $Log; StartTime = (Get-Date).AddDays(-$Days) }
    if ($Ids) { $f.Id = $Ids }
    if ($Provider) { $f.ProviderName = $Provider }
    try { @(Get-WinEvent -FilterHashtable $f -MaxEvents $Max -ErrorAction Stop) } catch { @() }
}

function Get-EvX($Log, $XPath, $Max = 5000) {
    try { @(Get-WinEvent -LogName $Log -FilterXPath $XPath -MaxEvents $Max -ErrorAction Stop) } catch { @() }
}

function EvData($e) {
    $h = @{}
    try { foreach ($d in ([xml]$e.ToXml()).Event.EventData.Data) { if ($d.Name) { $h[$d.Name] = $d.'#text' } } } catch {}
    $h
}

$script:AuditCache = $null
function Get-AuditSetting($Guid) {
    # 0 none, 1 success, 2 failure, 3 both. auditpol /backup is locale-independent.
    if ($null -eq $script:AuditCache) {
        $script:AuditCache = @{}
        $f = Join-Path $env:TEMP "iso27001_ap_$PID.csv"
        try {
            auditpol.exe /backup /file:"$f" | Out-Null
            foreach ($r in (Import-Csv $f)) {
                if ($r.'Subcategory GUID' -and "$($r.'Setting Value')" -match '^\d+$') {
                    $script:AuditCache[$r.'Subcategory GUID'.Trim('{}').ToUpper()] = [int]$r.'Setting Value'
                }
            }
        } catch {} finally { Remove-Item $f -ErrorAction SilentlyContinue }
    }
    $v = $script:AuditCache[$Guid.ToUpper()]
    if ($null -eq $v) { 0 } else { $v }
}

$script:SecPolCache = $null
function Get-SecPol($Key) {
    if ($null -eq $script:SecPolCache) {
        $script:SecPolCache = @{}
        $f = Join-Path $env:TEMP "iso27001_sp_$PID.inf"
        try {
            secedit.exe /export /cfg "$f" /quiet | Out-Null
            foreach ($l in (Get-Content $f)) {
                if ($l -match '^\s*([^=\[;]+?)\s*=\s*(.*)$') { $script:SecPolCache[$Matches[1]] = $Matches[2].Trim() }
            }
        } catch {} finally { Remove-Item $f -ErrorAction SilentlyContinue }
    }
    $script:SecPolCache[$Key]
}

function IntOr($v, $d) { $o = 0; if ([int]::TryParse("$v", [ref]$o)) { $o } else { $d } }

function Get-UserHives {
    # Loaded user hives (signed-in users) with their profile path.
    $res = @()
    foreach ($p in @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Special })) {
        if (Test-Path ("Registry::HKEY_USERS\" + $p.SID)) {
            $res += [pscustomobject]@{ SID = $p.SID; Path = $p.LocalPath; Hive = "Registry::HKEY_USERS\" + $p.SID }
        }
    }
    $res
}

function Get-Software {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    foreach ($h in Get-UserHives) { $keys += ($h.Hive + '\Software\Microsoft\Windows\CurrentVersion\Uninstall\*') }
    @(Get-ItemProperty $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent })
}

$script:AgentDir = $null
function Get-AgentDir {
    if (-not $script:AgentDir) {
        $svc = Get-CimInstance Win32_Service -Filter "Name='WazuhSvc'" -ErrorAction SilentlyContinue
        if ($svc -and $svc.PathName -match '^"?(.+\\)[^\\]+\.exe') { $script:AgentDir = $Matches[1] }
        else { $script:AgentDir = (Get-Location).Path + '\' }
    }
    $script:AgentDir
}
function Get-WazuhConf {
    $d = Get-AgentDir
    (Get-Content (Join-Path $d 'ossec.conf') -Raw -ErrorAction SilentlyContinue) + (Get-Content (Join-Path $d 'shared\agent.conf') -Raw -ErrorAction SilentlyContinue)
}

function Svc($Name) { Get-Service -Name $Name -ErrorAction SilentlyContinue }

# Interval (hours) of a scheduled task from its triggers; $null if event-based only.
function Get-TaskIntervalHours($Task) {
    $best = $null
    foreach ($t in @($Task.Triggers)) {
        $h = $null
        $cls = $t.CimClass.CimClassName
        if ($t.Repetition -and $t.Repetition.Interval) {
            try { $h = ([Xml.XmlConvert]::ToTimeSpan($t.Repetition.Interval)).TotalHours } catch {}
        }
        if (-not $h) {
            switch ($cls) {
                'MSFT_TaskDailyTrigger' { $h = 24 * [math]::Max(1, [int]$t.DaysInterval) }
                'MSFT_TaskWeeklyTrigger' {
                    $days = 0; $mask = [int]$t.DaysOfWeek
                    for ($i = 0; $i -lt 7; $i++) { if ($mask -band (1 -shl $i)) { $days++ } }
                    $h = 168 * [math]::Max(1, [int]$t.WeeksInterval) / [math]::Max(1, $days)
                }
                'MSFT_TaskTimeTrigger' { $h = $null }
                default { if ($cls -match 'Monthly') { $h = 730 } }
            }
        }
        if ($h -and (-not $best -or $h -lt $best)) { $best = $h }
    }
    if ($best) { [math]::Round($best, 2) } else { $null }
}

function Backup-Stats($Mechanisms, $Runs) {
    $runs = @($Runs | Where-Object { $_.Time -ge $Since } | Sort-Object Time)
    $ok = @($runs | Where-Object { $_.Ok } | ForEach-Object { $_.Time })
    $bad = @($runs | Where-Object { -not $_.Ok })
    $intervals = @($Mechanisms | Where-Object { $_.IntervalH } | ForEach-Object { [double]$_.IntervalH })
    $interval = $null; $source = $null
    if ($intervals.Count) { $interval = ($intervals | Measure-Object -Minimum).Minimum; $source = 'configured' }
    elseif ($ok.Count -ge 2) {
        $gaps = @(@(for ($i = 1; $i -lt $ok.Count; $i++) { ($ok[$i] - $ok[$i - 1]).TotalHours }) | Sort-Object)
        $interval = [math]::Round($gaps[[int][math]::Floor($gaps.Count / 2)], 2); $source = 'inferred from logs'
    }
    M 'backup_mechanisms' @($Mechanisms).Count
    M 'backup_configured' ([bool]@($Mechanisms).Count)
    M 'backup_interval_hours' $interval
    M 'backup_interval_source' $source
    M 'backup_runs_success' $ok.Count
    M 'backup_runs_failed' $bad.Count
    M 'backup_log_verified' ([bool]$runs.Count)
    M 'backup_success_rate_pct' (Pct $ok.Count $runs.Count)
    if ($interval) {
        $expected = [math]::Max(1, [math]::Floor($WindowDays * 24 / $interval))
        M 'backup_runs_expected' $expected
        M 'backup_adherence_pct' ([math]::Round([math]::Min(100, 100.0 * $ok.Count / $expected), 1))
        if ($ok.Count) {
            $gaps = @(for ($i = 1; $i -lt $ok.Count; $i++) { ($ok[$i] - $ok[$i - 1]).TotalHours }) + @(($Now - $ok[-1]).TotalHours)
            $missed = 0; foreach ($g in $gaps) { $missed += [math]::Max(0, [math]::Round($g / $interval) - 1) }
            M 'backup_missed_runs' $missed
            M 'backup_max_gap_hours' ([math]::Round(($gaps | Measure-Object -Maximum).Maximum, 1))
            M 'backup_last_success_age_ratio' ([math]::Round(($Now - $ok[-1]).TotalHours / $interval, 2))
        } else { M 'backup_missed_runs' $expected }
    }
    if ($ok.Count) { M 'backup_last_success' (Iso $ok[-1]); M 'backup_last_success_age_hours' (AgeH $ok[-1]) }
    else { M 'backup_last_success' $null; M 'backup_last_success_age_hours' $null }
    if ($bad.Count) { M 'backup_last_failure' (Iso $bad[-1].Time) } else { M 'backup_last_failure' $null }
}

# ------------------------------------------------------------------ controls
$Controls = [ordered]@{}

$Controls['A.5.9'] = {
    $svc = Svc 'WazuhSvc'
    M 'wazuh_running' ([bool]($svc -and $svc.Status -eq 'Running'))
    $ver = Get-Content (Join-Path (Get-AgentDir) 'VERSION') -ErrorAction SilentlyContinue | Select-Object -First 1
    M 'wazuh_version' ("$ver".Trim())
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    M 'os' $os.Caption
    M 'os_build' ("{0}.{1}" -f (RegV $cv 'CurrentBuild'), (RegV $cv 'UBR'))
    M 'os_release' (RegV $cv 'DisplayVersion')
    M 'hostname' $env:COMPUTERNAME
    $bios = Get-CimInstance Win32_BIOS; $cs = Get-CimInstance Win32_ComputerSystem
    $serial = "$($bios.SerialNumber)".Trim()
    M 'hardware_serial_recorded' ([bool]($serial -and $serial -notmatch '^(0|None|Default string|To be filled by O\.E\.M\.|System Serial Number)$'))
    M 'hardware_model' ("$($cs.Manufacturer) $($cs.Model)".Trim())
    $sw = Get-Software
    M 'software_packages' $sw.Count
    M 'syscollector_enabled' ([bool]((Get-WazuhConf) -match '<wodle name="syscollector">\s*<disabled>no'))
    M 'inventory_complete' ([bool]($os.Caption -and $sw.Count -and $script:M['hardware_serial_recorded']))
    E "OS $($os.Caption) $($script:M['os_release']) build $($script:M['os_build']), host $env:COMPUTERNAME, domain/workgroup $($cs.Domain)"
    E "Hardware $($script:M['hardware_model']), serial $(if ($script:M['hardware_serial_recorded']) { $serial } else { 'not available' })"
    E "$($sw.Count) installed programs; Wazuh agent $ver $(if ($script:M['wazuh_running']) { 'running' } else { 'NOT running' }); syscollector $(if ($script:M['syscollector_enabled']) { 'on' } else { 'off' })"
}

$Controls['A.5.16'] = {
    $users = @(Get-LocalUser -ErrorAction SilentlyContinue)
    $guest = $users | Where-Object { $_.SID.Value -match '-501$' }
    M 'guest_disabled' ([bool](-not $guest -or -not $guest.Enabled))
    $enabled = @($users | Where-Object { $_.Enabled })
    M 'enabled_accounts' $enabled.Count
    $stale = @($enabled | Where-Object { $_.LastLogon -and $_.LastLogon -lt $Now.AddDays(-$StaleAccountDays) })
    $never = @($enabled | Where-Object { -not $_.LastLogon -and $_.SID.Value -notmatch '-(500|501|503|504)$' })
    $nopw = @($enabled | Where-Object { -not $_.PasswordRequired })
    M 'stale_accounts' $stale.Count
    M 'never_logged_in_accounts' $never.Count
    M 'password_not_required_accounts' $nopw.Count
    $ev = Get-Ev 'Security' 4720, 4722, 4725, 4726, 4738, 4781
    M 'account_changes_window' $ev.Count
    M 'account_management_audited' ([bool]((Get-AuditSetting '0CCE9235-69AE-11D9-BED3-505054503030') -band 1))
    E "Enabled local accounts: $(($enabled | ForEach-Object { $_.Name + $(if ($_.LastLogon) { ' (last logon ' + $_.LastLogon.ToString('yyyy-MM-dd') + ')' } else { ' (never)' }) }) -join ', ')"
    E "Guest account $(if ($script:M['guest_disabled']) { 'disabled' } else { 'ENABLED' })"
    if ($stale.Count) { E "Not used for $StaleAccountDays+ days: $(($stale.Name) -join ', ')" }
    if ($nopw.Count) { E "Enabled accounts that do not require a password: $(($nopw.Name) -join ', ')" }
    E "$($ev.Count) account lifecycle events (create/enable/disable/delete/change) in $WindowDays days; user-account auditing $(if ($script:M['account_management_audited']) { 'on' } else { 'OFF - changes are not recorded' })"
    foreach ($e in ($ev | Select-Object -First 6)) { $d = EvData $e; E "$(Iso $e.TimeCreated) event $($e.Id) account $($d.TargetUserName) by $($d.SubjectUserName)" }
}

$Controls['A.5.17'] = {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    M 'blank_password_network_logon_blocked' ((RegV $lsa 'LimitBlankPasswordUse') -eq 1)
    M 'lm_hash_disabled' ((RegV $lsa 'NoLMHash') -eq 1)
    M 'network_credentials_not_stored' ((RegV $lsa 'DisableDomainCreds') -eq 1)
    M 'lsa_protection' ((RegV $lsa 'RunAsPPL') -in 1, 2)
    M 'wdigest_plaintext_disabled' ((RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -ne 1)
    M 'password_history' (IntOr (Get-SecPol 'PasswordHistorySize') 0)
    M 'password_max_age_days' (IntOr (Get-SecPol 'MaximumPasswordAge') -1)
    M 'password_complexity' ((Get-SecPol 'PasswordComplexity') -eq '1')
    M 'reversible_encryption_disabled' ((Get-SecPol 'ClearTextPassword') -ne '1')
    $never = @(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -and -not $_.PasswordExpires -and $_.SID.Value -notmatch '-(500|501|503|504)$' })
    M 'passwords_never_expire' $never.Count
    $ev = Get-Ev 'Security' 4723, 4724
    M 'password_changes_window' $ev.Count
    E "Blank-password network logons blocked: $($script:M['blank_password_network_logon_blocked']); LM hashes off: $($script:M['lm_hash_disabled']); LSA protection: $($script:M['lsa_protection']); WDigest plaintext off: $($script:M['wdigest_plaintext_disabled'])"
    E "Password policy: history $($script:M['password_history']), max age $($script:M['password_max_age_days']) days (-1 = never), complexity $($script:M['password_complexity']), reversible encryption off $($script:M['reversible_encryption_disabled'])"
    if ($never.Count) { E "Accounts whose password never expires: $(($never.Name) -join ', ')" }
    E "$($ev.Count) password change/reset events in $WindowDays days"
}

$Controls['A.8.2'] = {
    $members = @()
    try { $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name }) }
    catch {
        try {
            $name = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[1]
            $grp = [ADSI]"WinNT://./$name,group"
            $members = @($grp.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })
        } catch {}
    }
    M 'administrators' $members.Count
    $admin = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -match '-500$' }
    M 'builtin_admin_disabled' ([bool](-not $admin -or -not $admin.Enabled))
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    M 'uac_enabled' ((RegV $pol 'EnableLUA') -ne 0)
    $cpa = RegV $pol 'ConsentPromptBehaviorAdmin'; if ($null -eq $cpa) { $cpa = 5 }
    M 'uac_admin_prompt' $cpa
    M 'uac_prompts_admins' ($cpa -ne 0)
    M 'uac_secure_desktop' ((RegV $pol 'PromptOnSecureDesktop') -ne 0)
    $grpEv = @(Get-Ev 'Security' 4732, 4733 | Where-Object { (EvData $_).TargetSid -eq 'S-1-5-32-544' })
    M 'admin_group_changes_window' $grpEv.Count
    $priv = Get-EvX 'Security' "*[System[(EventID=4672) and TimeCreated[timediff(@SystemTime) <= $WindowMs]]] and *[EventData[Data[@Name='SubjectUserSid']!='S-1-5-18' and Data[@Name='SubjectUserSid']!='S-1-5-19' and Data[@Name='SubjectUserSid']!='S-1-5-20']]" 10000
    M 'privileged_logons_window' $priv.Count
    M 'group_management_audited' ([bool]((Get-AuditSetting '0CCE9237-69AE-11D9-BED3-505054503030') -band 1))
    E "Local Administrators ($($members.Count)): $($members -join ', ')"
    E "Built-in Administrator $(if ($script:M['builtin_admin_disabled']) { 'disabled' } else { 'ENABLED (' + $admin.Name + ')' }); UAC $(if ($script:M['uac_enabled']) { 'on' } else { 'OFF' }), admin prompt level $cpa, secure desktop $($script:M['uac_secure_desktop'])"
    E "$($priv.Count) logons with administrative privileges and $($grpEv.Count) Administrators-group membership changes in $WindowDays days; group-change auditing $(if ($script:M['group_management_audited']) { 'on' } else { 'OFF' })"
    foreach ($e in ($grpEv | Select-Object -First 5)) { $d = EvData $e; E "$(Iso $e.TimeCreated) $(if ($e.Id -eq 4732) { 'added' } else { 'removed' }) $($d.MemberSid) by $($d.SubjectUserName)" }
}

$Controls['A.8.3'] = {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    M 'anonymous_sam_restricted' ((RegV $lsa 'RestrictAnonymousSAM') -eq 1)
    M 'anonymous_shares_restricted' ((RegV $lsa 'RestrictAnonymous') -ge 1)
    M 'everyone_excludes_anonymous' ((RegV $lsa 'EveryoneIncludesAnonymous') -ne 1)
    $null_sh = RegV 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'NullSessionShares'
    M 'null_session_shares' @($null_sh | Where-Object { $_ }).Count
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.Name -notmatch '\$$' })
    $open = @()
    foreach ($s in $shares) {
        foreach ($a in @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)) {
            if ($a.AccessControlType -eq 'Allow' -and $a.AccessRight -in 'Full', 'Change' -and $a.AccountName -match 'Everyone|Guests|ANONYMOUS|Authenticated Users|\\Users$') {
                $open += "$($s.Name): $($a.AccountName) $($a.AccessRight)"
            }
        }
    }
    M 'shares' $shares.Count
    M 'shares_open_to_broad_groups' $open.Count
    M 'share_access_events_window' (Get-Ev 'Security' 5140 -Max 10000).Count
    E "Anonymous SAM enumeration restricted: $($script:M['anonymous_sam_restricted']); anonymous share enumeration restricted: $($script:M['anonymous_shares_restricted']); null-session shares: $($script:M['null_session_shares'])"
    E "Shared folders: $(if ($shares.Count) { ($shares.Name) -join ', ' } else { 'none' })"
    foreach ($o in $open) { E "Broad write access: $o" }
}

$Controls['A.8.5'] = {
    M 'password_min_length' (IntOr (Get-SecPol 'MinimumPasswordLength') 0)
    M 'lockout_threshold' (IntOr (Get-SecPol 'LockoutBadCount') 0)
    M 'lockout_duration_minutes' (IntOr (Get-SecPol 'LockoutDuration') 0)
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    M 'last_user_hidden' ((RegV $pol 'DontDisplayLastUserName') -eq 1)
    M 'ctrl_alt_del_required' ((RegV $pol 'DisableCAD') -eq 0)
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    M 'rdp_enabled' ((RegV $ts 'fDenyTSConnections') -eq 0)
    M 'rdp_nla_required' ((RegV "$ts\WinStations\RDP-Tcp" 'UserAuthentication') -eq 1)
    $logonAudit = Get-AuditSetting '0CCE9215-69AE-11D9-BED3-505054503030'
    M 'logon_failures_audited' ([bool]($logonAudit -band 2))
    $fails = Get-Ev 'Security' 4625 -Max 20000
    $lock = Get-Ev 'Security' 4740
    M 'failed_logons_window' $fails.Count
    M 'account_lockouts_window' $lock.Count
    $perHour = @{}; $perSrc = @{}
    foreach ($e in $fails) {
        $d = EvData $e
        $src = if ($d.IpAddress -and $d.IpAddress -ne '-') { $d.IpAddress } else { 'local:' + $d.TargetUserName }
        $k = $src + '|' + $e.TimeCreated.ToString('yyyyMMddHH')
        $perHour[$k] = 1 + [int]$perHour[$k]; $perSrc[$src] = 1 + [int]$perSrc[$src]
    }
    $bursts = @($perHour.GetEnumerator() | Where-Object { $_.Value -ge $BruteForcePerHour })
    M 'brute_force_bursts' $bursts.Count
    $ok = Get-EvX 'Security' "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $WindowMs]]] and *[EventData[Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]" 10000
    $remote = @($ok | ForEach-Object { $d = EvData $_; if ($d.IpAddress -and $d.IpAddress -notin '-', '::1', '127.0.0.1') { [pscustomobject]@{ T = $_.TimeCreated; Ip = $d.IpAddress; User = $d.TargetUserName; Type = $d.LogonType } } })
    $susp = @($remote | Where-Object { [int]$perSrc[$_.Ip] -ge 5 })
    M 'remote_logons_window' $remote.Count
    M 'success_after_failures' $susp.Count
    E "Password minimum length $($script:M['password_min_length']); lockout after $($script:M['lockout_threshold']) attempts (0 = never) for $($script:M['lockout_duration_minutes']) min"
    E "Last user hidden: $($script:M['last_user_hidden']); Ctrl+Alt+Del required: $($script:M['ctrl_alt_del_required']); RDP $(if ($script:M['rdp_enabled']) { 'enabled' } else { 'disabled' }), NLA $($script:M['rdp_nla_required'])"
    E "$($fails.Count) failed logons, $($lock.Count) lockouts, $($remote.Count) remote logons in $WindowDays days; failed-logon auditing $(if ($script:M['logon_failures_audited']) { 'on' } else { 'OFF - failures are not recorded' })"
    $top = $perSrc.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
    if ($top) { E ("Top failing sources: " + (($top | ForEach-Object { "$($_.Key) ($($_.Value))" }) -join ', ')) }
    if ($bursts.Count) { E "$($bursts.Count) brute-force bursts (>= $BruteForcePerHour failures in one hour from one source)" }
    foreach ($s in ($susp | Select-Object -First 5)) { E "$(Iso $s.T) successful logon for $($s.User) from $($s.Ip) after $($perSrc[$s.Ip]) failures" }
}

$Controls['A.8.6'] = {
    $rows = @(); $worst = 100.0
    foreach ($d in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3')) {
        if ($d.Size) { $free = [math]::Round(100.0 * $d.FreeSpace / $d.Size, 1); $worst = [math]::Min($worst, $free); $rows += "$($d.DeviceID) $free% free of $([math]::Round($d.Size / 1GB)) GB" }
    }
    M 'min_volume_free_pct' $worst
    $os = Get-CimInstance Win32_OperatingSystem
    M 'memory_available_pct' (Pct $os.FreePhysicalMemory $os.TotalVisibleMemorySize)
    $low = Get-Ev 'System' 2013 -Provider 'srv'
    $mem = Get-Ev 'System' 2004 -Provider 'Microsoft-Windows-Resource-Exhaustion-Detector'
    M 'disk_full_events_window' $low.Count
    M 'low_memory_events_window' $mem.Count
    E ("Volumes: " + ($rows -join '; '))
    E "Memory available $($script:M['memory_available_pct'])%; $($low.Count) low-disk and $($mem.Count) low-memory warnings in $WindowDays days"
    foreach ($e in (@($low) + @($mem) | Select-Object -First 5)) { E "$(Iso $e.TimeCreated) $($e.Message.Split("`n")[0])" }
}

$Controls['A.8.7'] = {
    $s = $null; try { $s = Get-MpComputerStatus -ErrorAction Stop } catch {}
    $third = @()
    foreach ($p in @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)) {
        $st = [int]$p.productState
        $third += [pscustomobject]@{ Name = $p.displayName; On = ((($st -shr 12) -band 0xF) -eq 1); Current = ((($st -shr 4) -band 0xF) -eq 0) }
    }
    $defOn = [bool]($s -and $s.AntivirusEnabled -and $s.RealTimeProtectionEnabled -and $s.AMRunningMode -ne 'Passive Mode')
    $other = @($third | Where-Object { $_.On -and $_.Name -notmatch 'Defender' })
    M 'av_running' ($defOn -or [bool]$other.Count)
    M 'av_product' $(if ($defOn) { 'Microsoft Defender' } elseif ($other.Count) { $other[0].Name } else { 'none' })
    if ($s) {
        M 'realtime_protection' ([bool]$s.RealTimeProtectionEnabled)
        M 'behavior_monitoring' ([bool]$s.BehaviorMonitorEnabled)
        M 'tamper_protection' ([bool]$s.IsTamperProtected)
        M 'signature_age_days' $(if ($s.AntivirusSignatureAge -lt 65535) { [int]$s.AntivirusSignatureAge } else { $null })
        $q = if ($s.QuickScanAge -lt 65535) { [int]$s.QuickScanAge } else { $null }
        $f = if ($s.FullScanAge -lt 65535) { [int]$s.FullScanAge } else { $null }
        M 'last_scan_age_days' $(if ($null -ne $q -and $null -ne $f) { [math]::Min($q, $f) } elseif ($null -ne $q) { $q } else { $f })
        M 'last_full_scan_age_days' $f
    } elseif ($other.Count) {
        M 'signature_age_days' $(if ($other[0].Current) { 0 } else { 30 })
    }
    $log = 'Microsoft-Windows-Windows Defender/Operational'
    $det = Get-Ev $log 1116; $act = Get-Ev $log 1117; $actFail = Get-Ev $log 1118, 1119
    $off = Get-Ev $log 5001, 5010, 5012; $updFail = Get-Ev $log 2001, 2003, 2006
    M 'detections_window' $det.Count
    M 'remediations_window' $act.Count
    M 'remediation_failures_window' $actFail.Count
    M 'protection_disabled_events_window' $off.Count
    M 'signature_update_failures_window' $updFail.Count
    $active = @(); try { $active = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.ThreatStatusID -notin 2, 3, 4, 5, 6, 106 -and $_.InitialDetectionTime -ge $Since }) } catch {}
    M 'unresolved_threats' $active.Count
    E "Anti-malware: $($script:M['av_product']); real-time $($script:M['realtime_protection']), behaviour monitoring $($script:M['behavior_monitoring']), tamper protection $($script:M['tamper_protection'])"
    E "Signatures $($script:M['signature_age_days']) days old; last scan $($script:M['last_scan_age_days']) days ago (full scan $($script:M['last_full_scan_age_days']))"
    E "In $WindowDays days: $($det.Count) detections, $($act.Count) remediated, $($actFail.Count) remediation failures, $($off.Count) protection-disabled events, $($updFail.Count) update failures; $($active.Count) unresolved"
    foreach ($e in ($det | Select-Object -First 5)) { $d = EvData $e; E "$(Iso $e.TimeCreated) detected $($d.'Threat Name') in $($d.Path)" }
    foreach ($t in $third) { E "Security Center: $($t.Name) enabled $($t.On), up to date $($t.Current)" }
}

$Controls['A.8.8'] = {
    $wu = Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue
    $noAuto = RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
    M 'auto_updates_enabled' ([bool]($wu -and $wu.StartMode -ne 'Disabled' -and $noAuto -ne 1))
    $lastInstall = $null; $lastSearch = $null
    try {
        $r = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results
        if ($r.LastInstallationSuccessDate -gt [datetime]'2000-01-01') { $lastInstall = $r.LastInstallationSuccessDate.ToLocalTime() }
        if ($r.LastSearchSuccessDate -gt [datetime]'2000-01-01') { $lastSearch = $r.LastSearchSuccessDate.ToLocalTime() }
    } catch {}
    $ok = Get-Ev 'System' 19 -Provider 'Microsoft-Windows-WindowsUpdateClient'
    $bad = Get-Ev 'System' 20 -Provider 'Microsoft-Windows-WindowsUpdateClient'
    if ($ok.Count -and (-not $lastInstall -or $ok[0].TimeCreated -gt $lastInstall)) { $lastInstall = $ok[0].TimeCreated }
    if (-not $lastInstall) { $hf = Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($hf) { $lastInstall = $hf.InstalledOn } }
    M 'days_since_last_upgrade' (AgeD $lastInstall)
    M 'days_since_metadata_refresh' (AgeD $lastSearch)
    M 'update_installs_window' $ok.Count
    M 'update_failures_window' $bad.Count
    M 'update_success_rate_pct' (Pct $ok.Count ($ok.Count + $bad.Count))
    M 'reboot_required' ((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'))
    # Pending updates from the local Windows Update agent (bounded so a slow search can't stall the run).
    $job = Start-Job { try { $s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher(); $r = $s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'"); @($r.Updates | ForEach-Object { "{0}|{1}|{2}" -f $_.MsrcSeverity, (($_.Categories | ForEach-Object { $_.Name }) -join ','), $_.Title }) } catch { 'ERROR|' + $_.Exception.Message } }
    if (Wait-Job $job -Timeout 240) {
        $lines = @(Receive-Job $job)
        if ($lines.Count -and $lines[0] -like 'ERROR|*') { E "Pending-update search failed: $($lines[0].Substring(6))" }
        else {
            $sec = @($lines | Where-Object { $_ -match '^(Critical|Important)\|' -or $_ -match '\|[^|]*Security Updates' })
            M 'pending_updates' $lines.Count
            M 'pending_security_updates' $sec.Count
            foreach ($l in ($lines | Select-Object -First 5)) { E "Pending: $($l.Split('|')[2]) [$($l.Split('|')[0])]" }
        }
    } else { E 'Pending-update search timed out (240 s)' }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    E "Windows Update service $($wu.StartMode)$(if ($noAuto -eq 1) { ', automatic updates disabled by policy' }); OS $(RegV $cv 'DisplayVersion') build $(RegV $cv 'CurrentBuild').$(RegV $cv 'UBR')"
    E "Last successful update install $(Iso $lastInstall) ($($script:M['days_since_last_upgrade']) days ago); last successful update check $(Iso $lastSearch)"
    E "In $WindowDays days: $($ok.Count) updates installed, $($bad.Count) failed; restart pending: $($script:M['reboot_required'])"
    foreach ($e in ($bad | Select-Object -First 5)) { $d = EvData $e; E "$(Iso $e.TimeCreated) FAILED $($d.updateTitle) (error $($d.errorCode))" }
}

$Controls['A.8.13'] = {
    $mech = @(); $runs = @()
    # 1. Scheduled tasks that run backup software (incl. Windows Backup / Server Backup tasks).
    $taskLog = 'Microsoft-Windows-TaskScheduler/Operational'
    $taskLogOn = $false; try { $taskLogOn = (Get-WinEvent -ListLog $taskLog -ErrorAction Stop).IsEnabled } catch {}
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
        $text = "$($t.TaskPath)$($t.TaskName) $actions"
        $builtinBackup = $t.TaskPath -match '\\Microsoft\\Windows\\(WindowsBackup|Backup)\\' -and $t.TaskName -notmatch 'Monitor|ConfigNotification'
        if (-not $builtinBackup -and ($t.TaskPath -like '\Microsoft\*' -or $text -notmatch $BackupPattern)) { continue }
        $iv = Get-TaskIntervalHours $t
        $info = Get-ScheduledTaskInfo -InputObject $t -ErrorAction SilentlyContinue
        $mech += [pscustomobject]@{ Name = "$($t.TaskPath)$($t.TaskName)"; Type = 'scheduled task'; IntervalH = $iv }
        $full = "$($t.TaskPath)$($t.TaskName)"
        $hist = 0
        if ($taskLogOn) {
            foreach ($e in (Get-EvX $taskLog "*[System[(EventID=201 or EventID=203 or EventID=103 or EventID=101) and TimeCreated[timediff(@SystemTime) <= $WindowMs]]] and *[EventData[Data[@Name='TaskName']='$full']]")) {
                $d = EvData $e
                $runs += [pscustomobject]@{ Time = $e.TimeCreated; Ok = ($e.Id -eq 201 -and [int64]$d.ResultCode -eq 0); Job = $full }
                $hist++
            }
        }
        if (-not $hist -and $info -and $info.LastRunTime -gt $Since) {
            $runs += [pscustomobject]@{ Time = $info.LastRunTime; Ok = ($info.LastTaskResult -eq 0); Job = $full }
        }
        E "Task $full ($($t.State)): every $iv h; last run $(Iso $info.LastRunTime) result 0x$('{0:X}' -f [int64]$info.LastTaskResult); missed runs $($info.NumberOfMissedRuns); $hist runs in task history"
    }
    if (-not $taskLogOn) { E 'Task Scheduler history log is disabled: only the last run of each task can be verified' }
    # 2. Windows Server Backup / wbadmin.
    $wsb = Get-Ev 'Microsoft-Windows-Backup' 4, 5, 8, 9, 14, 17, 18, 19, 20, 21, 22, 49, 50, 52, 100, 517, 518, 521, 527, 528
    foreach ($e in $wsb) { $runs += [pscustomobject]@{ Time = $e.TimeCreated; Ok = ($e.Id -in 4, 14); Job = 'Windows Server Backup' } }
    if ($wsb.Count) { $mech += [pscustomobject]@{ Name = 'Windows Server Backup'; Type = 'wbadmin'; IntervalH = $null }; E "Windows Server Backup: $(@($wsb | Where-Object { $_.Id -in 4, 14 }).Count) successful and $(@($wsb | Where-Object { $_.Id -notin 4, 14 }).Count) failed operations logged" }
    # 3. File History (per user).
    $fhLogs = @(Get-WinEvent -ListLog '*FileHistory*' -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount })
    foreach ($p in @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Special })) {
        $cfg = Join-Path $p.LocalPath 'AppData\Local\Microsoft\Windows\FileHistory\Configuration\Config1.xml'
        if (-not (Test-Path $cfg)) { continue }
        $x = Get-Content $cfg -Raw -ErrorAction SilentlyContinue
        $freq = if ($x -match '<DPFrequency>(\d+)</DPFrequency>') { [math]::Round([int]$Matches[1] / 3600, 2) } else { 1 }
        $target = if ($x -match '<TargetUrl>([^<]+)</TargetUrl>') { $Matches[1] } else { '?' }
        $mech += [pscustomobject]@{ Name = "File History ($($p.LocalPath))"; Type = 'File History'; IntervalH = $freq }
        $cat = Get-ChildItem (Split-Path $cfg) -Filter 'Catalog*.edb' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($cat -and $cat.LastWriteTime -gt $Since) { $runs += [pscustomobject]@{ Time = $cat.LastWriteTime; Ok = $true; Job = 'File History' } }
        E "File History for $($p.LocalPath): every $freq h to $target; catalog last updated $(Iso $cat.LastWriteTime)"
    }
    foreach ($l in $fhLogs) {
        $errs = @(Get-Ev $l.LogName | Where-Object { $_.Level -in 1, 2 })
        foreach ($e in $errs) { $runs += [pscustomobject]@{ Time = $e.TimeCreated; Ok = $false; Job = 'File History' } }
        if ($errs.Count) { E "$($errs.Count) File History errors in $($l.LogName)" }
    }
    # 4. OneDrive folder backup (Known Folder Move): continuous sync, no per-run log.
    foreach ($h in Get-UserHives) {
        $od = @(Get-ChildItem ($h.Hive + '\Software\Microsoft\OneDrive\Accounts') -ErrorAction SilentlyContinue | ForEach-Object { RegV $_.PSPath 'UserFolder' } | Where-Object { $_ })
        if (-not $od.Count) { continue }
        $sf = $h.Hive + '\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        $moved = @(foreach ($n in 'Desktop', 'Personal', 'My Pictures') { $v = [Environment]::ExpandEnvironmentVariables("$(RegV $sf $n)"); foreach ($o in $od) { if ($v -like "$o*") { $n } } })
        if ($moved.Count) {
            $mech += [pscustomobject]@{ Name = "OneDrive folder backup ($($h.Path))"; Type = 'cloud sync'; IntervalH = $null }
            E "OneDrive folder backup for $($h.Path): $($moved -join ', ') synced continuously to $($od -join ', ') (no backup run log; sync is not verified)"
        }
    }
    # 5. Veeam Agent.
    $veeam = Get-Ev 'Veeam Agent' 190
    foreach ($e in $veeam) { $runs += [pscustomobject]@{ Time = $e.TimeCreated; Ok = ($e.Message -notmatch 'Failed'); Job = 'Veeam Agent' } }
    if ($veeam.Count -or (Svc 'VeeamEndpointBackupSvc')) { $mech += [pscustomobject]@{ Name = 'Veeam Agent'; Type = 'Veeam'; IntervalH = $null }; E "Veeam Agent: $($veeam.Count) job results logged" }
    # 6. Status log written by any backup job.
    if (Test-Path $BackupStatusLog) {
        $n = 0
        foreach ($l in (Get-Content $BackupStatusLog -ErrorAction SilentlyContinue)) {
            if ($l -match '^(\S+)\s+(SUCCESS|FAILURE)\b(?:.*job=(\S+))?') {
                $t = $null; try { $t = [datetime]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture) } catch {}
                if ($t) { $runs += [pscustomobject]@{ Time = $t; Ok = ($Matches[2] -eq 'SUCCESS'); Job = $(if ($Matches[3]) { $Matches[3] } else { 'status-log' }) }; $n++ }
            }
        }
        if ($n) { $mech += [pscustomobject]@{ Name = 'backup status log'; Type = 'status log'; IntervalH = $null }; E "$n results in $BackupStatusLog" }
    }
    $shadow = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)
    M 'restore_points' $shadow.Count
    Backup-Stats $mech $runs
    if (-not $mech.Count) { $script:EV.Insert(0, 'No backup found: no backup scheduled task, Windows/Server Backup, File History, OneDrive folder backup, Veeam or status log') }
    E "Expected $($script:M['backup_runs_expected']) runs in $WindowDays days (interval $($script:M['backup_interval_hours']) h, $($script:M['backup_interval_source'])); $($script:M['backup_runs_success']) succeeded, $($script:M['backup_runs_failed']) failed; last success $($script:M['backup_last_success'])"
    E "$($shadow.Count) restore points / shadow copies (same disk: not a backup)"
    foreach ($r in (@($runs | Where-Object { -not $_.Ok -and $_.Time -ge $Since } | Sort-Object Time -Descending) | Select-Object -First 5)) { E "$(Iso $r.Time) FAILED $($r.Job)" }
}

$AuditRequired = [ordered]@{
    'Credential Validation' = @('0CCE923F', 3); 'Logon' = @('0CCE9215', 3); 'Logoff' = @('0CCE9216', 1)
    'Account Lockout' = @('0CCE9217', 2); 'Special Logon' = @('0CCE921B', 1); 'User Account Management' = @('0CCE9235', 1)
    'Security Group Management' = @('0CCE9237', 1); 'Audit Policy Change' = @('0CCE922F', 1); 'Authentication Policy Change' = @('0CCE9230', 1)
    'Process Creation' = @('0CCE922B', 1); 'Sensitive Privilege Use' = @('0CCE9228', 3); 'Security State Change' = @('0CCE9210', 1)
    'Security System Extension' = @('0CCE9211', 1); 'System Integrity' = @('0CCE9212', 3); 'Removable Storage' = @('0CCE9245', 3)
    'Other Object Access Events' = @('0CCE9227', 3); 'Plug and Play Events' = @('0CCE9248', 1)
}

$Controls['A.8.15'] = {
    $sec = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
    M 'security_log_max_mb' $(if ($sec) { [math]::Round($sec.MaximumSizeInBytes / 1MB) } else { $null })
    M 'security_log_mode' "$($sec.LogMode)"
    $oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
    $newest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
    M 'log_retention_days' (AgeD $oldest.TimeCreated)
    M 'logging_alive' ([bool]($newest -and $newest.TimeCreated -gt $Now.AddDays(-1)))
    $span = if ($oldest) { [math]::Max(1, ($Now - $oldest.TimeCreated).TotalDays) } else { 1 }
    M 'security_events_per_day' $(if ($sec) { [math]::Round($sec.RecordCount / $span) } else { $null })
    $cleared = @(Get-Ev 'Security' 1102) + @(Get-Ev 'System' 104 -Provider 'Microsoft-Windows-Eventlog')
    $full = Get-Ev 'Security' 1104; $stop = Get-Ev 'Security' 1100
    M 'log_cleared_window' $cleared.Count
    M 'log_loss_events_window' ($full.Count)
    M 'logging_stopped_window' $stop.Count
    $missing = @(); $have = 0
    foreach ($k in $AuditRequired.Keys) {
        $want = $AuditRequired[$k][1]
        if (((Get-AuditSetting ($AuditRequired[$k][0] + '-69AE-11D9-BED3-505054503030')) -band $want) -eq $want) { $have++ } else { $missing += $k }
    }
    M 'audit_coverage_pct' ([math]::Round(100.0 * $have / $AuditRequired.Count))
    M 'scriptblock_logging' ((RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1)
    E "Security log: max $($script:M['security_log_max_mb']) MB, mode $($sec.LogMode), $($sec.RecordCount) records (~$($script:M['security_events_per_day'])/day); oldest record $(Iso $oldest.TimeCreated) = $($script:M['log_retention_days']) days retained"
    E "Audit policy coverage $($script:M['audit_coverage_pct'])% ($have of $($AuditRequired.Count) subcategories); missing: $(if ($missing.Count) { $missing -join ', ' } else { 'none' })"
    E "In $WindowDays days: $($cleared.Count) log-cleared events, $($full.Count) log-full events, $($stop.Count) logging shutdowns"
    foreach ($e in ($cleared | Select-Object -First 5)) { $d = EvData $e; E "$(Iso $e.TimeCreated) log CLEARED (event $($e.Id)) by $($d.SubjectUserName)$($d.SubjectUserName2)" }
}

$Controls['A.8.16'] = {
    $st = Get-Content (Join-Path (Get-AgentDir) 'wazuh-agent.state') -Raw -ErrorAction SilentlyContinue
    M 'wazuh_connected' ([bool]($st -match "status='connected'"))
    if ($st -match "last_keepalive='([^']+)'") {
        try { M 'keepalive_age_minutes' ([math]::Round(($Now - [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd HH:mm:ss', $null)).TotalMinutes, 1)) } catch {}
    }
    $conf = Get-WazuhConf
    $want = 'Security', 'System', 'Application', 'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational'
    $have = @($want | Where-Object { $conf -match ('<location>' + [regex]::Escape($_) + '</location>') })
    M 'monitored_channels_pct' ([math]::Round(100.0 * $have.Count / $want.Count))
    M 'security_log_monitored' ($have -contains 'Security')
    M 'scriptblock_logging' ((RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -eq 1)
    $sys = @(Svc 'Sysmon64') + @(Svc 'Sysmon') | Where-Object { $_ }
    M 'sysmon_running' ([bool]($sys | Where-Object { $_.Status -eq 'Running' }))
    M 'sysmon_events_24h' (Get-Ev 'Microsoft-Windows-Sysmon/Operational' -Days 1 -Max 20000).Count
    M 'scriptblock_events_window' (Get-Ev 'Microsoft-Windows-PowerShell/Operational' 4104 -Max 20000).Count
    E "Wazuh agent $(if ($script:M['wazuh_connected']) { 'connected' } else { 'NOT connected' }); last keepalive $($script:M['keepalive_age_minutes']) min ago"
    E "Event channels collected by Wazuh: $($have -join ', '); not collected: $(($want | Where-Object { $have -notcontains $_ }) -join ', ')"
    E "PowerShell script-block logging $(if ($script:M['scriptblock_logging']) { 'on' } else { 'off' }) ($($script:M['scriptblock_events_window']) events in $WindowDays days); Sysmon $(if ($script:M['sysmon_running']) { 'running' } else { 'not installed/running' }) ($($script:M['sysmon_events_24h']) events in 24 h)"
}

$Controls['A.8.17'] = {
    $svc = Get-CimInstance Win32_Service -Filter "Name='W32Time'" -ErrorAction SilentlyContinue
    M 'time_service_running' ([bool]($svc -and $svc.State -eq 'Running'))
    M 'time_service_start' "$($svc.StartMode)"
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    $type = "$(RegV $p 'Type')"; $server = "$(RegV $p 'NtpServer')"
    M 'ntp_enabled' ($type -in 'NTP', 'NT5DS', 'AllSync')
    M 'time_source' $server
    $first = ($server -split '[ ,]')[0]
    $offset = $null
    if ($first) {
        $out = w32tm.exe /stripchart /computer:$first /samples:1 /dataonly 2>&1 | Out-String
        if ($out -match '([+-]\d+[.,]\d+)s') { $offset = [math]::Abs([double]($Matches[1] -replace ',', '.')) }
        else { E "Offset measurement against $first failed: $(($out -split "`n" | Where-Object { $_ -match 'error' } | Select-Object -First 1))" }
    }
    M 'clock_offset_seconds' $(if ($null -ne $offset) { [math]::Round($offset, 4) } else { $null })
    $okEv = Get-Ev 'System' 35, 37 -Provider 'Microsoft-Windows-Time-Service'
    $badEv = Get-Ev 'System' 24, 29, 36, 38, 46, 47, 129, 134, 142 -Provider 'Microsoft-Windows-Time-Service'
    $last = if ($okEv.Count) { $okEv[0].TimeCreated } else { $null }
    $st = w32tm.exe /query /status 2>&1 | Out-String
    if ($st -match 'Last Successful Sync Time:\s*(.+)') { try { $t = [datetime]::Parse($Matches[1].Trim(), [Globalization.CultureInfo]::CurrentCulture); if (-not $last -or $t -gt $last) { $last = $t } } catch {} }
    $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Time Synchronization\' -TaskName 'SynchronizeTime' -ErrorAction SilentlyContinue
    if ($task) { $ti = Get-ScheduledTaskInfo -InputObject $task -ErrorAction SilentlyContinue; if ($ti -and $ti.LastTaskResult -eq 0 -and $ti.LastRunTime -gt [datetime]'2000-01-01' -and (-not $last -or $ti.LastRunTime -gt $last)) { $last = $ti.LastRunTime } }
    M 'last_sync_age_hours' (AgeH $last)
    M 'sync_failures_window' $badEv.Count
    $jumps = @(); foreach ($e in (Get-Ev 'System' 1 -Provider 'Microsoft-Windows-Kernel-General')) { $d = EvData $e; try { $delta = [math]::Abs(([datetime]$d.NewTime - [datetime]$d.OldTime).TotalSeconds); if ($delta -lt 86400) { $jumps += $delta } } catch {} }
    M 'max_clock_correction_seconds' $(if ($jumps.Count) { [math]::Round(($jumps | Measure-Object -Maximum).Maximum, 3) } else { $null })
    M 'clock_steps_window' @($jumps | Where-Object { $_ -ge 1 }).Count
    E "Windows Time service $($svc.State) ($($svc.StartMode)); type $type; servers $server"
    E "Current offset from $first $($script:M['clock_offset_seconds']) s; last successful sync $(Iso $last) ($($script:M['last_sync_age_hours']) h ago)"
    E "In $WindowDays days: $($badEv.Count) sync failures; $($jumps.Count) clock corrections, largest $($script:M['max_clock_correction_seconds']) s"
    foreach ($e in ($badEv | Select-Object -First 4)) { E "$(Iso $e.TimeCreated) event $($e.Id): $($e.Message.Split("`n")[0])" }
}

$Controls['A.8.18'] = {
    $rr = Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction SilentlyContinue
    M 'remote_registry_disabled' ([bool](-not $rr -or $rr.StartMode -eq 'Disabled'))
    $wr = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction SilentlyContinue
    M 'winrm_running' ([bool]($wr -and $wr.State -eq 'Running'))
    $ps2 = $null; try { $ps2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop).State -eq 'Enabled' } catch { $ps2 = [bool](RegV 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion') }
    M 'powershell_v2_enabled' ([bool]$ps2)
    M 'psexec_service_present' ([bool](Svc 'PSEXESVC'))
    $dbg = "$(Get-SecPol 'SeDebugPrivilege')"
    M 'debug_privilege_restricted' ($dbg -eq '' -or $dbg -eq '*S-1-5-32-544')
    $new = Get-Ev 'System' 7045 -Provider 'Service Control Manager'
    M 'services_installed_window' $new.Count
    E "Remote Registry $($rr.StartMode); WinRM $($wr.State); PowerShell 2.0 engine $(if ($ps2) { 'ENABLED' } else { 'disabled/removed' }); PsExec service present: $($script:M['psexec_service_present'])"
    E "Debug-programs right held by: $(if ($dbg) { $dbg } else { 'nobody' })"
    E "$($new.Count) services installed in $WindowDays days"
    foreach ($e in ($new | Select-Object -First 8)) { $d = EvData $e; E "$(Iso $e.TimeCreated) service '$($d.ServiceName)' $($d.ImagePath) as $($d.AccountName)" }
}

$Controls['A.8.19'] = {
    $aie = (RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated') -eq 1
    foreach ($h in Get-UserHives) { if ((RegV ($h.Hive + '\Software\Policies\Microsoft\Windows\Installer') 'AlwaysInstallElevated') -eq 1) { $aie = $true } }
    M 'always_install_elevated' $aie
    $sac = RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState'
    M 'smart_app_control' $(switch ($sac) { 1 { 'on' } 2 { 'evaluation' } 0 { 'off' } default { 'unsupported' } })
    $al = $false; try { $al = [bool]((Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop) -match 'EnforcementMode="Enabled"') } catch {}
    M 'applocker_enforced' $al
    M 'application_control' ($al -or $sac -eq 1)
    $inst = Get-Ev 'Application' 11707, 1033 -Provider 'MsiInstaller'
    $fail = Get-Ev 'Application' 11708 -Provider 'MsiInstaller'
    $rem = Get-Ev 'Application' 11724, 1034 -Provider 'MsiInstaller'
    $sinceStr = $Since.ToString('yyyyMMdd')
    $newSw = @(Get-Software | Where-Object { "$($_.InstallDate)" -match '^\d{8}$' -and $_.InstallDate -ge $sinceStr } | Sort-Object InstallDate -Descending)
    M 'software_installs_window' ([math]::Max($newSw.Count, @($inst | Where-Object { $_.Id -eq 11707 }).Count))
    M 'software_install_failures_window' $fail.Count
    M 'software_removals_window' @($rem | Where-Object { $_.Id -eq 11724 }).Count
    E "AlwaysInstallElevated $(if ($aie) { 'ENABLED' } else { 'off' }); Smart App Control $($script:M['smart_app_control']); AppLocker enforced: $al"
    E "In $WindowDays days: $($script:M['software_installs_window']) programs installed, $($fail.Count) failed installs, $($script:M['software_removals_window']) removed"
    foreach ($s in ($newSw | Select-Object -First 8)) { E "Installed $($s.InstallDate): $($s.DisplayName) $($s.DisplayVersion) ($($s.Publisher))" }
}

$Controls['A.8.20'] = {
    $prof = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
    M 'firewall_all_profiles_enabled' ([bool]($prof.Count -and -not ($prof | Where-Object { -not $_.Enabled })))
    M 'default_inbound_block' ([bool]($prof.Count -and -not ($prof | Where-Object { $_.DefaultInboundAction -ne 'Block' })))
    M 'firewall_logs_drops' ([bool]($prof.Count -and -not ($prof | Where-Object { $_.LogBlocked -ne 'True' })))
    $pub = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { "$($_.Profile)" -match 'Public|Any' })
    M 'inbound_allow_rules_public' $pub.Count
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' -and $_.LocalPort -lt 49152 })
    $procs = @{}; foreach ($l in $listen) { if (-not $procs[$l.OwningProcess]) { $procs[$l.OwningProcess] = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
    $svcs = @($listen | ForEach-Object { "$($_.LocalPort)/$($procs[$_.OwningProcess])" } | Sort-Object -Unique)
    M 'exposed_listening_services' $svcs.Count
    $cats = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)=$($_.NetworkCategory)" })
    $fwlog = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
    $chg = Get-Ev $fwlog 2003, 2004, 2005, 2006, 2097, 2099, 2052, 2071, 2073
    $stop = Get-Ev 'Security' 5025, 5034
    M 'firewall_rule_changes_window' $chg.Count
    M 'firewall_stopped_events_window' $stop.Count
    foreach ($p in $prof) { E "Profile $($p.Name): enabled $($p.Enabled), inbound $($p.DefaultInboundAction), log dropped $($p.LogBlocked) to $($p.LogFileName)" }
    E "Networks: $($cats -join ', '); $($pub.Count) inbound allow rules apply on Public networks"
    E "Listening on the network ($($svcs.Count)): $($svcs -join ', ')"
    E "In $WindowDays days: $($chg.Count) firewall setting/rule changes, $($stop.Count) firewall-stopped events"
}

$Controls['A.8.21'] = {
    $smb = $null; try { $smb = Get-SmbServerConfiguration -ErrorAction Stop } catch {}
    M 'smb1_server_enabled' ([bool]($smb -and $smb.EnableSMB1Protocol))
    $c = RegV 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'
    M 'smb1_client_enabled' ([bool]($null -ne $c -and $c -ne 4))
    M 'smb_encrypt_data' ([bool]($smb -and $smb.EncryptData))
    M 'llmnr_disabled' ((RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0)
    $ad = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue)
    M 'netbios_disabled_pct' $(if ($ad.Count) { [math]::Round(100.0 * @($ad | Where-Object { $_.TcpipNetbiosOptions -eq 2 }).Count / $ad.Count) } else { 100 })
    M 'rdp_enabled' ((RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0)
    $legacy = @(foreach ($v in 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') { if ((RegV "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$v\Server" 'Enabled') -eq 1) { $v } })
    M 'legacy_tls_enabled' ([bool]$legacy.Count)
    M 'smb1_access_attempts_window' (Get-Ev 'Microsoft-Windows-SMBServer/Audit' 3000).Count
    E "SMBv1 server $(if ($script:M['smb1_server_enabled']) { 'ENABLED' } else { 'off' }), client $(if ($script:M['smb1_client_enabled']) { 'ENABLED' } else { 'off' }); SMB encryption $($script:M['smb_encrypt_data'])"
    E "LLMNR disabled: $($script:M['llmnr_disabled']); NetBIOS disabled on $($script:M['netbios_disabled_pct'])% of adapters; RDP $(if ($script:M['rdp_enabled']) { 'enabled' } else { 'disabled' })"
    E "Legacy TLS/SSL explicitly enabled for servers: $(if ($legacy.Count) { $legacy -join ', ' } else { 'none' }); $($script:M['smb1_access_attempts_window']) SMBv1 connection attempts in $WindowDays days"
}

$Controls['A.8.23'] = {
    $sys = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    $pol = RegV $sys 'EnableSmartScreen'
    $exp = RegV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled'
    M 'windows_smartscreen' ($pol -eq 1 -or ($null -eq $pol -and $exp -ne 'Off'))
    $edge = RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled'
    M 'edge_smartscreen_enforced' ($edge -eq 1)
    M 'edge_smartscreen_on' ($edge -ne 0)
    $np = $null; try { $np = (Get-MpPreference -ErrorAction Stop).EnableNetworkProtection } catch {}
    M 'network_protection' $(switch ($np) { 1 { 'block' } 2 { 'audit' } default { 'off' } })
    $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique)
    M 'filtering_dns' ([bool]@($dns | Where-Object { $FilteringDns -contains $_ }).Count)
    $proxy = $false
    foreach ($h in Get-UserHives) { $is = $h.Hive + '\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; if ((RegV $is 'ProxyEnable') -eq 1 -or (RegV $is 'AutoConfigURL')) { $proxy = $true } }
    $wh = RegV 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' 'WinHttpSettings'
    if ($wh -and $wh.Length -gt 12 -and $wh[12] -gt 0) { $proxy = $true }
    M 'proxy_configured' $proxy
    $agents = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match $WebFilterProcesses } | ForEach-Object { $_.ProcessName } | Sort-Object -Unique)
    M 'web_filter_agent' ([bool]$agents.Count)
    M 'filtering_layer' ($agents.Count -or $proxy -or $script:M['filtering_dns'] -or $np -eq 1)
    $blocks = Get-Ev 'Microsoft-Windows-Windows Defender/Operational' 1125, 1126
    M 'web_blocks_window' $blocks.Count
    E "Windows SmartScreen $(if ($script:M['windows_smartscreen']) { 'on' } else { 'OFF' }); Edge SmartScreen $(if ($edge -eq 1) { 'enforced by policy' } elseif ($edge -eq 0) { 'DISABLED by policy' } else { 'default (user can turn off)' }); Defender network protection $($script:M['network_protection'])"
    E "DNS servers: $($dns -join ', ') ($(if ($script:M['filtering_dns']) { 'includes' } else { 'no' }) known filtering resolver); proxy $(if ($proxy) { 'configured' } else { 'none' }); web-filter agents: $(if ($agents.Count) { $agents -join ', ' } else { 'none' })"
    E "$($blocks.Count) network-protection block/audit events in $WindowDays days"
}

$Controls['A.8.24'] = {
    $vols = @(Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue)
    $fixed = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { $_.DeviceID })
    $methods = @{ 0 = 'None'; 1 = 'AES-128-Diffuser'; 2 = 'AES-256-Diffuser'; 3 = 'AES-128'; 4 = 'AES-256'; 5 = 'Hardware'; 6 = 'XTS-AES-128'; 7 = 'XTS-AES-256' }
    $prot = 0; $susp = 0; $strong = $true; $recovery = $true; $osProt = $false; $count = 0
    foreach ($v in $vols) {
        if ($fixed -notcontains $v.DriveLetter) { continue }
        $count++
        $ps = (Invoke-CimMethod -InputObject $v -MethodName GetProtectionStatus -ErrorAction SilentlyContinue).ProtectionStatus
        $cs = Invoke-CimMethod -InputObject $v -MethodName GetConversionStatus -ErrorAction SilentlyContinue
        $em = [int](Invoke-CimMethod -InputObject $v -MethodName GetEncryptionMethod -ErrorAction SilentlyContinue).EncryptionMethod
        $rp = @((Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]3 } -ErrorAction SilentlyContinue).VolumeKeyProtectorID).Count
        $tpm = @((Invoke-CimMethod -InputObject $v -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = [uint32]1 } -ErrorAction SilentlyContinue).VolumeKeyProtectorID).Count
        if ($ps -eq 1) { $prot++; if ($v.DriveLetter -eq $env:SystemDrive) { $osProt = $true } }
        elseif ($cs.ConversionStatus -eq 1) { $susp++ }
        if ($ps -eq 1 -and $em -notin 6, 7, 5) { $strong = $false }
        if ($ps -eq 1 -and -not $rp) { $recovery = $false }
        E "$($v.DriveLetter) protection $(switch ($ps) { 1 { 'ON' } 0 { 'off' } default { 'unknown' } }), $($cs.EncryptionPercentage)% encrypted, method $($methods[$em]), TPM protector $([bool]$tpm), recovery password $([bool]$rp)"
    }
    if (-not $vols.Count) { E 'BitLocker/device encryption is not available on this edition or could not be queried' }
    M 'os_volume_protected' $osProt
    M 'fixed_volumes' $count
    M 'fixed_volumes_protected_pct' $(if ($count) { [math]::Round(100.0 * $prot / $count) } else { 0 })
    M 'protection_suspended_volumes' $susp
    M 'strong_encryption_method' ($prot -gt 0 -and $strong)
    M 'recovery_password_protector' ($prot -gt 0 -and $recovery)
    $tpmObj = Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    M 'tpm_present' ([bool]($tpmObj -and $tpmObj.IsEnabled_InitialValue))
    M 'smb_server_signing_required' ((RegV 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature') -eq 1)
    M 'smb_client_signing_required' ((RegV 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature') -eq 1)
    $legacy = @(foreach ($v in 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') { foreach ($r in 'Server', 'Client') { if ((RegV "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$v\$r" 'Enabled') -eq 1) { "$v $r" } } })
    M 'legacy_tls_allowed' ([bool]$legacy.Count)
    E "TPM present: $($script:M['tpm_present']); SMB signing required - server $($script:M['smb_server_signing_required']), client $($script:M['smb_client_signing_required'])"
    E "Legacy TLS/SSL explicitly enabled: $(if ($legacy.Count) { $legacy -join ', ' } else { 'none' })"
}

$Controls['A.8.31'] = {
    $ak = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock'
    M 'developer_mode' ((RegV $ak 'AllowDevelopmentWithoutDevLicense') -eq 1)
    $tools = @(Get-Software | Where-Object { $_.DisplayName -match '^(Microsoft Visual Studio|Visual Studio|Python \d|Git$|Git version|Node\.js|Docker Desktop|Java\(TM\) SE Development|JDK|Android Studio|Postman|JetBrains|IntelliJ|PyCharm|Microsoft Visual Studio Code|MSYS2|Cygwin)' } | ForEach-Object { $_.DisplayName } | Sort-Object -Unique)
    M 'dev_tools_present' $tools.Count
    $wsl = @(); foreach ($h in Get-UserHives) { $wsl += @(Get-ChildItem ($h.Hive + '\Software\Microsoft\Windows\CurrentVersion\Lxss') -ErrorAction SilentlyContinue | ForEach-Object { RegV $_.PSPath 'DistributionName' } | Where-Object { $_ }) }
    M 'wsl_distributions' $wsl.Count
    E "Developer Mode $(if ($script:M['developer_mode']) { 'ON' } else { 'off' })"
    E "Development tools installed ($($tools.Count)): $($tools -join ', ')"
    E "WSL distributions: $(if ($wsl.Count) { $wsl -join ', ' } else { 'none' })"
}

$Controls['A.8.32'] = {
    $conf = Get-WazuhConf
    $sc = ([regex]::Matches($conf, '(?s)<syscheck>(.*?)</syscheck>') | ForEach-Object { $_.Groups[1].Value }) -join ' '
    M 'fim_configured' ([bool]($sc -and $sc -notmatch '^\s*<disabled>yes'))
    $checks = [ordered]@{ 'System32' = '(?i)(%WINDIR%|C:\\Windows)\\(System32|SysNative)'; 'Startup folder' = '(?i)Start Menu\\Programs\\Startup'
                          'Program Files' = '(?i)Program Files'; 'Run keys' = '(?i)CurrentVersion\\Run'; 'Services key' = '(?i)CurrentControlSet\\Services' }
    $cov = @($checks.Keys | Where-Object { $sc -match $checks[$_] })
    M 'fim_critical_coverage_pct' ([math]::Round(100.0 * $cov.Count / $checks.Count))
    M 'fim_realtime' ([bool]($sc -match 'realtime="yes"|whodata="yes"'))
    $upd = (Get-Ev 'System' 19 -Provider 'Microsoft-Windows-WindowsUpdateClient').Count
    $msi = (Get-Ev 'Application' 11707, 11724 -Provider 'MsiInstaller').Count
    $svc = (Get-Ev 'System' 7045 -Provider 'Service Control Manager').Count
    $tasks = (Get-Ev 'Security' 4698).Count + (Get-Ev 'Microsoft-Windows-TaskScheduler/Operational' 106).Count
    M 'changes_window' ($upd + $msi + $svc + $tasks)
    $aud = @(@('0CCE9211', 1), @('0CCE9227', 1), @('0CCE922F', 1) | Where-Object { ((Get-AuditSetting ($_[0] + '-69AE-11D9-BED3-505054503030')) -band $_[1]) -eq $_[1] })
    M 'change_audit_pct' ([math]::Round(100.0 * $aud.Count / 3))
    E "Wazuh FIM $(if ($script:M['fim_configured']) { 'configured' } else { 'NOT configured' }); covers: $(if ($cov.Count) { $cov -join ', ' } else { 'none of the critical paths' }); real-time/who-data: $($script:M['fim_realtime'])"
    E "Changes recorded in $WindowDays days: $upd updates, $msi program installs/removals, $svc new services, $tasks new scheduled tasks"
    E "Change auditing (service installs, scheduled tasks, policy changes): $($script:M['change_audit_pct'])% configured"
}

$Controls['A.8.34'] = {
    M 'audit_policy_change_audited' ([bool]((Get-AuditSetting '0CCE922F-69AE-11D9-BED3-505054503030') -band 1))
    $chg = Get-Ev 'Security' 4719
    M 'audit_policy_changes_window' $chg.Count
    M 'log_cleared_window' ((Get-Ev 'Security' 1102).Count)
    $sp = "$(Get-SecPol 'SeSecurityPrivilege')"
    M 'security_privilege_restricted' ($sp -eq '*S-1-5-32-544')
    E "Audit-policy changes audited: $($script:M['audit_policy_change_audited']); 'Manage auditing and security log' right held by: $sp"
    E "In $WindowDays days: $($chg.Count) audit-policy changes, $($script:M['log_cleared_window']) security-log clears"
    foreach ($e in ($chg | Select-Object -First 5)) { $d = EvData $e; E "$(Iso $e.TimeCreated) audit policy changed by $($d.SubjectUserName): $($d.SubcategoryGuid) $($d.AuditPolicyChanges)" }
}

$Controls['A.7.10'] = {
    $exp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    M 'autorun_disabled' ((RegV $exp 'NoDriveTypeAutoRun') -eq 255 -or (RegV $exp 'NoAutorun') -eq 1)
    M 'usb_storage_disabled' ((RegV 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start') -eq 4)
    $rs = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
    M 'removable_write_denied' ((RegV $rs 'Deny_All') -eq 1 -or (RegV "$rs\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" 'Deny_Write') -eq 1)
    M 'removable_encryption_required' ((RegV 'HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE' 'RDVDenyWriteAccess') -eq 1)
    M 'removable_control' ($script:M['usb_storage_disabled'] -or $script:M['removable_write_denied'] -or $script:M['removable_encryption_required'])
    $ins = Get-Ev 'Microsoft-Windows-Partition/Diagnostic' 1006
    $usb = @($ins | Where-Object { (EvData $_).BusType -eq '7' })
    M 'usb_storage_insertions_window' $(if ($ins.Count) { $usb.Count } else { 0 })
    $ever = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue } | ForEach-Object { RegV $_.PSPath 'FriendlyName' } | Where-Object { $_ })
    M 'usb_storage_devices_ever' $ever.Count
    M 'removable_storage_audited' ((Get-AuditSetting '0CCE9245-69AE-11D9-BED3-505054503030') -ne 0)
    E "AutoRun disabled: $($script:M['autorun_disabled']); USB storage driver disabled: $($script:M['usb_storage_disabled']); write to removable disks denied: $($script:M['removable_write_denied']); BitLocker To Go required: $($script:M['removable_encryption_required'])"
    E "$($script:M['usb_storage_insertions_window']) USB storage connections in $WindowDays days; $($ever.Count) USB storage devices ever connected; removable-storage auditing $(if ($script:M['removable_storage_audited']) { 'on' } else { 'off' })"
    foreach ($e in ($usb | Select-Object -First 5)) { $d = EvData $e; E "$(Iso $e.TimeCreated) $($d.Manufacturer) $($d.Model) serial $($d.SerialNumber)" }
}

# ------------------------------------------------------------------ main
foreach ($id in $Controls.Keys) {
    if ($Only -and $Only -notcontains $id) { continue }
    $script:M = [ordered]@{}; $script:EV = New-Object 'System.Collections.Generic.List[string]'
    $errors = @(); $sw = [Diagnostics.Stopwatch]::StartNew()
    try { & $Controls[$id] } catch { $errors += ("{0}: {1}" -f $_.Exception.GetType().Name, $_.Exception.Message) }
    $ev = @($script:EV | Select-Object -First 15 | ForEach-Object { if ($_.Length -gt 300) { $_.Substring(0, 300) } else { $_ } })
    $doc = [ordered]@{ iso27001 = [ordered]@{ type = 'evidence'; collector = 'windows'; version = $Version; control = $id
            window_days = $WindowDays; collected_at = $Collected; duration_s = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            metrics = $script:M; evidence = $ev; errors = $errors } }
    [Console]::Out.WriteLine(($doc | ConvertTo-Json -Depth 5 -Compress))
}
