#!/usr/bin/env python3
"""ISO/IEC 27001:2022 evidence collector for Linux (wazuh-iso27001-sca-pack).

Run as root by the Wazuh command wodle. For every Annex A control mapped in
the Linux policy it reads the relevant configuration *and* the logs over the
last WINDOW_DAYS days, and prints one JSON line:

  {"iso27001": {"type": "evidence", "collector": "linux", "control": "A.8.13",
                "metrics": {...}, "evidence": [...], "errors": [...]}}

Metrics are raw measurements (counts, ages, percentages, booleans). Scoring
against thresholds happens on the manager (evidence/controls.yml), so the
thresholds live in one place for every OS.

Optional overrides: a JSON file next to this script named
iso27001_collect.json, e.g. {"window_days": 60, "backup_exclude": ["foo"]}.
Standard library only; read-only (it changes nothing on the host).
"""
import glob, gzip, json, os, pwd, re, shutil, socket, stat, subprocess, sys, time
from datetime import datetime, timezone

VERSION = "1.0"
CFG = {
    "window_days": 30,
    # Unit / cron command names that indicate a data backup job.
    "backup_pattern": r"backup|borg|restic|rsnapshot|duplicity|duplicati|kopia|bacula|bareos|"
                      r"timeshift|urbackup|rclone|veeam|amanda|burp|rdiff",
    # Matches that are not data backups (dpkg-db-backup only saves package state).
    "backup_exclude": ["dpkg-db-backup"],
    # Any backup tool can report here: one line per run, "<ISO-8601 time> SUCCESS|FAILURE [job=name]".
    "backup_status_log": "/var/lib/iso27001/backup-status.log",
    "backup_marker": "/var/lib/iso27001/last-backup-ok",
    "stale_account_days": 90,
    "brute_force_per_hour": 10,
    "filtering_dns": ["1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", "9.9.9.9", "149.112.112.112",
                      "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
                      "185.228.168.9", "185.228.169.9", "76.76.2.1"],
    "web_filter_processes": ["squid", "zscaler", "zsatunnel", "netskope", "nsclient", "umbrella",
                             "dnscrypt-proxy", "websense", "forcepoint", "pihole-FTL", "adguardhome"],
    "standard_suid": ["chfn", "chsh", "gpasswd", "mount", "newgrp", "passwd", "su", "sudo", "umount",
                      "pkexec", "fusermount", "fusermount3", "ssh-keysign", "dbus-daemon-launch-helper",
                      "polkit-agent-helper-1", "unix_chkpwd", "chrome-sandbox", "Xorg.wrap", "ntfs-3g",
                      "mount.nfs", "mount.cifs", "pppd", "vmware-user-suid-wrapper", "kismet_cap_linux_wifi",
                      "kismet_cap_linux_bluetooth", "kismet_cap_nrf_51822", "kismet_cap_nxp_kw41z",
                      "kismet_cap_rz_killerbee", "kismet_cap_ti_cc_2531", "kismet_cap_ti_cc_2540",
                      "kismet_cap_ubertooth_one", "kismet_cap_nrf_mousejack", "kismet_cap_nrf_52840",
                      "kismet_cap_hak5_wifi_coconut", "kismet_cap_linux_wifi", "snap-confine", "ksu"],
}
try:
    CFG.update(json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "iso27001_collect.json"))))
except (OSError, ValueError):
    pass

NOW = time.time()
WINDOW = CFG["window_days"] * 86400
SINCE = NOW - WINDOW
SINCE_STR = datetime.fromtimestamp(SINCE).strftime("%Y-%m-%d %H:%M:%S")
ENV = dict(os.environ, LC_ALL="C", LANG="C")
EVIDENCE_MAX = 15


# ---------------------------------------------------------------- helpers
def run(cmd, timeout=60):
    """Run a command (list, no shell); return stdout ('' if missing/failed to start)."""
    if not shutil.which(cmd[0]) and not os.path.exists(cmd[0]):
        return ""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=ENV,
                              errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def read(path, default=""):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return default


def read_lines_rotated(base):
    """Lines of a log and its rotations (.1, .2.gz, ...), oldest first."""
    files = sorted(glob.glob(base + ".*"), key=lambda p: os.path.getmtime(p)) + [base]
    for p in files:
        if not os.path.isfile(p) or os.path.getmtime(p) < SINCE:
            continue
        try:
            opener = gzip.open if p.endswith(".gz") else open
            with opener(p, "rt", errors="replace") as f:
                yield from f
        except OSError:
            continue


def read_lines_all(base):
    """Like read_lines_rotated but without the window cut-off."""
    for p in sorted(glob.glob(base + ".*"), key=os.path.getmtime) + [base]:
        try:
            with (gzip.open if p.endswith(".gz") else open)(p, "rt", errors="replace") as f:
                yield from f
        except OSError:
            continue


def active(unit):
    return run(["systemctl", "is-active", unit]).strip() == "active"


def enabled(unit):
    return run(["systemctl", "is-enabled", unit]).strip() in ("enabled", "static", "alias")


def unit_exists(unit):
    return "LoadState=loaded" in run(["systemctl", "show", "-p", "LoadState", unit])


def journal(*match, since=None, extra=()):
    """journalctl JSON entries (ts, entry) for the window."""
    out = run(["journalctl", "-q", "--no-pager", "-o", "json", "--since",
               since or SINCE_STR, *extra, *match], timeout=180)
    res = []
    for line in out.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        msg = e.get("MESSAGE")
        if isinstance(msg, list):  # binary message
            continue
        res.append((int(e.get("__REALTIME_TIMESTAMP", 0)) / 1e6, e))
    return res


SYSLOG_TS = re.compile(r"^(?:(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S*|([A-Z][a-z]{2}\s+\d+\s\d\d:\d\d:\d\d))\s+\S+\s+"
                       r"([\w./-]+)(?:\[\d+\])?:\s?(.*)")


def syslog_events(idents, files=("/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
                                 "/var/log/messages")):
    """Fallback when journald has no history: parse classic syslog files."""
    year = datetime.now().year
    res = []
    for base in files:
        for line in read_lines_rotated(base):
            m = SYSLOG_TS.match(line)
            if not m or m.group(3) not in idents:
                continue
            try:
                if m.group(1):
                    ts = datetime.fromisoformat(m.group(1)).timestamp()
                else:
                    ts = datetime.strptime(f"{year} {m.group(2)}", "%Y %b %d %H:%M:%S").timestamp()
                    if ts > NOW + 86400:
                        ts = datetime.strptime(f"{year - 1} {m.group(2)}", "%Y %b %d %H:%M:%S").timestamp()
            except ValueError:
                continue
            if ts >= SINCE:
                res.append((ts, m.group(3), m.group(4).strip()))
    return res


def log_events(idents):
    """(ts, identifier, message) from journald, else from syslog files."""
    args = []
    for i in idents:
        args.append("SYSLOG_IDENTIFIER=" + i)
    ev = [(ts, e.get("SYSLOG_IDENTIFIER", ""), e.get("MESSAGE", "")) for ts, e in journal(*args)]
    return ev or syslog_events(set(idents))


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


def hours_since(ts):
    return round((NOW - ts) / 3600, 1) if ts else None


def sysctl(key):
    return read("/proc/sys/" + key.replace(".", "/")).strip()


def sshd_settings():
    out = run(["sshd", "-T"]) or run(["/usr/sbin/sshd", "-T"])
    s = {}
    for line in out.splitlines():
        k, _, v = line.partition(" ")
        s.setdefault(k.lower(), v.strip())
    return s


def human_users():
    login_defs = read("/etc/login.defs")
    m = re.search(r"^\s*UID_MIN\s+(\d+)", login_defs, re.M)
    uid_min = int(m.group(1)) if m else 1000
    shells_ok = lambda sh: not sh.endswith(("nologin", "false", "sync", "shutdown", "halt"))
    return [p for p in pwd.getpwall() if (p.pw_uid >= uid_min and p.pw_uid != 65534 or p.pw_uid == 0)
            and shells_ok(p.pw_shell)]


def shadow():
    res = {}
    for line in read("/etc/shadow").splitlines():
        f = line.split(":")
        if len(f) >= 8:
            res[f[0]] = f
    return res


def last_logins():
    """user -> last login epoch from wtmp/lastlog (best effort)."""
    res = {}
    out = run(["last", "-F", "-w", "--time-format", "iso"]) or run(["last", "-w", "--time-format", "iso"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] in ("reboot", "wtmp", "shutdown"):
            continue
        for p in parts[1:]:
            try:
                ts = datetime.fromisoformat(p).timestamp()
            except ValueError:
                continue
            res[parts[0]] = max(res.get(parts[0], 0), ts)
            break
    out = run(["lastlog2"]) or ""
    for line in out.splitlines()[1:]:
        parts = line.split()
        m = re.search(r"(\w{3} \w{3} +\d+ \d\d:\d\d:\d\d [+-]\d{4} \d{4})", line)
        if parts and m:
            try:
                ts = datetime.strptime(m.group(1), "%a %b %d %H:%M:%S %z %Y").timestamp()
                res[parts[0]] = max(res.get(parts[0], 0), ts)
            except ValueError:
                pass
    return res


def ss_listeners():
    """[(proto, addr, port, process)] for sockets listening on non-loopback addresses."""
    res = []
    for line in run(["ss", "-Hlntup"]).splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        local = f[4]
        addr, _, port = local.rpartition(":")
        addr = addr.strip("[]").split("%")[0]
        if addr.startswith(("127.", "::ffff:127.")) or addr == "::1":
            continue
        proc = re.search(r'"([^"]+)"', line)
        res.append((f[0], addr, port, proc.group(1) if proc else "?"))
    return res


def pgrep(names):
    found = []
    for p in glob.glob("/proc/[0-9]*/comm"):
        c = read(p).strip()
        for n in names:
            if n.lower() in c.lower():
                found.append(c)
    return sorted(set(found))


def wazuh_conf():
    return read("/var/ossec/etc/ossec.conf") + read("/var/ossec/etc/shared/agent.conf") + \
        "".join(read(p) for p in glob.glob("/var/ossec/etc/shared/*/agent.conf"))


def is_manager():
    return os.path.exists("/var/ossec/bin/wazuh-analysisd")


def cron_interval_hours(spec):
    """Interval (hours) between runs of a 5-field cron schedule, via simulation over 62 days."""
    macros = {"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *",
              "@weekly": "0 0 * * 0", "@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *",
              "@annually": "0 0 1 1 *"}
    spec = macros.get(spec, spec)
    names = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9,
             "oct": 10, "nov": 11, "dec": 12, "sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4,
             "fri": 5, "sat": 6}

    def field(expr, lo, hi):
        vals = set()
        for part in expr.lower().split(","):
            step = 1
            if "/" in part:
                part, s = part.split("/")
                step = int(s)
            if part == "*":
                a, b = lo, hi
            elif "-" in part:
                a, b = (int(names.get(x, x)) for x in part.split("-"))
            else:
                a = b = int(names.get(part, part))
                if step > 1:
                    b = hi
            vals.update(range(a, b + 1, step))
        return vals
    try:
        mi, hr, dom, mon, dow = spec.split()[:5]
        M, H, D, MO = field(mi, 0, 59), field(hr, 0, 23), field(dom, 1, 31), field(mon, 1, 12)
        W = {d % 7 for d in field(dow, 0, 7)}
    except (ValueError, KeyError):
        return None
    times, t = [], int(NOW // 60) * 60
    end = t + 62 * 86400
    while t < end and len(times) < 4:
        lt = time.localtime(t)
        if lt.tm_min in M and lt.tm_hour in H and lt.tm_mon in MO:
            d_ok, w_ok = lt.tm_mday in D, (lt.tm_wday + 1) % 7 in W
            restricted = dom != "*" and dow != "*"
            if (d_ok or w_ok) if restricted else (d_ok and w_ok):
                times.append(t)
        t += 60 if lt.tm_hour in H else 3600 - lt.tm_min * 60
    if len(times) < 2:
        return 24 * 30 if times else None
    return round(min(b - a for a, b in zip(times, times[1:])) / 3600, 2)


def timespan_hours(s):
    units = {"us": 1e-6 / 3600, "ms": 1e-3 / 3600, "s": 1 / 3600, "sec": 1 / 3600, "min": 1 / 60, "m": 1 / 60,
             "h": 1, "hr": 1, "d": 24, "day": 24, "w": 168, "week": 168, "month": 730, "y": 8760}
    total = 0
    for num, unit in re.findall(r"([\d.]+)\s*([a-z]+)", s):
        total += float(num) * units.get(unit, units.get(unit.rstrip("s"), 0))
    return round(total, 2) or None


def calendar_interval_hours(spec):
    out = run(["systemd-analyze", "calendar", "--iterations=3", spec])
    ts = []
    for m in re.finditer(r"(?:Next elapse|Iteration #\d+): \w+ (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", out):
        ts.append(datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").timestamp())
    if len(ts) >= 2:
        return round(min(b - a for a, b in zip(ts, ts[1:])) / 3600, 2)
    return None


def capped(items):
    return [str(i)[:300] for i in items[:EVIDENCE_MAX]]


# ---------------------------------------------------------------- controls
CONTROLS = {}


def control(cid):
    def deco(fn):
        CONTROLS[cid] = fn
        return fn
    return deco


@control("A.5.9")
def inventory():
    m, ev = {}, []
    m["wazuh_running"] = active("wazuh-agent") or active("wazuh-manager")
    m["wazuh_role"] = "manager" if is_manager() else "agent"
    osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', read("/etc/os-release"), re.M))
    m["os"] = osr.get("PRETTY_NAME", "")
    m["kernel"] = os.uname().release
    m["hostname"] = socket.gethostname()
    serial = read("/sys/class/dmi/id/product_serial").strip()
    m["hardware_serial_recorded"] = bool(serial) and serial.lower() not in ("none", "0", "default string",
                                                                           "to be filled by o.e.m.")
    m["hardware_model"] = (read("/sys/class/dmi/id/sys_vendor").strip() + " " +
                           read("/sys/class/dmi/id/product_name").strip()).strip()
    pkgs = run(["dpkg-query", "-W", "-f", "${Package}\n"]) or run(["rpm", "-qa"])
    m["software_packages"] = len(pkgs.split())
    m["syscollector_enabled"] = bool(re.search(r'<wodle name="syscollector">\s*<disabled>no', wazuh_conf()))
    m["inventory_complete"] = bool(m["os"] and m["software_packages"] and m["hardware_serial_recorded"])
    ev += [f"OS {m['os']}, kernel {m['kernel']}, host {m['hostname']}",
           f"Hardware {m['hardware_model'] or 'unknown'}, serial {'recorded' if m['hardware_serial_recorded'] else 'not available'}",
           f"{m['software_packages']} installed packages; Wazuh syscollector {'on' if m['syscollector_enabled'] else 'off'}"]
    return m, ev


@control("A.5.17")
def authentication_information():
    m, ev = {}, []
    sh = shadow()
    users = {u.pw_name for u in human_users()}
    empty = [u for u, f in sh.items() if f[1] == ""]
    weak = [u for u, f in sh.items() if f[1].startswith(("$1$", "$2a$")) or
            (len(f[1]) == 13 and not f[1].startswith(("!", "*")))]
    m["empty_password_accounts"] = len(empty)
    m["weak_hash_accounts"] = len(weak)
    ld = read("/etc/login.defs")
    g = lambda k: (re.search(rf"^\s*{k}\s+(\S+)", ld, re.M) or [None, None])[1]
    m["encrypt_method"] = g("ENCRYPT_METHOD") or "unknown"
    try:
        m["pass_max_days"] = int(g("PASS_MAX_DAYS") or 99999)
    except ValueError:
        m["pass_max_days"] = 99999
    nonexpiring = [u for u in users if u in sh and sh[u][1][:1] not in "!*" and
                   (sh[u][4] in ("", "99999"))]
    m["passwords_never_expire"] = len(nonexpiring)
    st = os.stat("/etc/shadow")
    m["shadow_mode"] = oct(st.st_mode & 0o777)
    m["shadow_protected"] = (st.st_mode & 0o007) == 0 and st.st_uid == 0
    m["ssh_permit_empty_passwords"] = sshd_settings().get("permitemptypasswords", "no") == "yes"
    changes = [e for e in log_events(["passwd", "chpasswd", "chage"]) if "changed" in e[2] or "password" in e[2]]
    m["password_changes_window"] = len(changes)
    ev.append(f"/etc/shadow mode {m['shadow_mode']}; hash method {m['encrypt_method']}; PASS_MAX_DAYS {m['pass_max_days']}")
    if empty:
        ev.append("Accounts with empty password: " + ", ".join(empty))
    if weak:
        ev.append("Accounts with weak (MD5/DES) hashes: " + ", ".join(weak))
    if nonexpiring:
        ev.append("Login accounts whose password never expires: " + ", ".join(sorted(nonexpiring)))
    ev.append(f"{len(changes)} password change events in {CFG['window_days']} days")
    return m, ev


@control("A.5.18")
def access_rights():
    m, ev = {}, []
    out = run(["useradd", "-D"])
    mm = re.search(r"INACTIVE=(-?\d+)", out)
    m["inactive_days_default"] = int(mm.group(1)) if mm else -1
    sh, logins = shadow(), last_logins()
    stale, never, active_users = [], [], []
    for u in human_users():
        f = sh.get(u.pw_name)
        if not f or f[1][:1] in "!*":
            continue  # locked
        active_users.append(u.pw_name)
        ts = logins.get(u.pw_name)
        if ts is None:
            never.append(u.pw_name)
        elif NOW - ts > CFG["stale_account_days"] * 86400:
            stale.append(u.pw_name)
    m["enabled_login_accounts"] = len(active_users)
    m["stale_accounts"] = len(stale)
    m["never_logged_in_accounts"] = len(never)
    ev_acct = log_events(["useradd", "userdel", "usermod", "groupadd", "groupdel", "gpasswd"])
    m["account_changes_window"] = len(ev_acct)
    ev.append(f"Enabled login accounts: {', '.join(active_users) or 'none'}")
    ev.append(f"New-account inactivity lock: {m['inactive_days_default']} days (-1 = never)")
    if stale:
        ev.append(f"Not logged in for {CFG['stale_account_days']}+ days: " + ", ".join(stale))
    if never:
        ev.append("Never logged in (per wtmp): " + ", ".join(never))
    ev += capped([f"{iso(t)} {i}: {msg}" for t, i, msg in ev_acct[-8:]])
    return m, ev


@control("A.7.10")
def storage_media():
    m, ev = {}, []
    modconf = "".join(read(p) for p in glob.glob("/etc/modprobe.d/*.conf") + glob.glob("/usr/lib/modprobe.d/*.conf"))
    m["usb_storage_blocked"] = bool(re.search(r"^\s*(blacklist\s+usb[-_]storage|install\s+usb[-_]storage\s+/bin/(true|false))",
                                              modconf, re.M))
    m["usb_storage_loaded"] = "usb_storage" in read("/proc/modules")
    m["usbguard_active"] = active("usbguard")
    m["removable_control"] = m["usb_storage_blocked"] or m["usbguard_active"]
    kern = journal("-k", "--grep", "usb-storage|USB Mass Storage|New USB device found")
    inserts = [(ts, e["MESSAGE"]) for ts, e in kern if "Mass Storage" in e["MESSAGE"] or "usb-storage" in e["MESSAGE"]]
    m["usb_storage_insertions_window"] = len(inserts)
    mounted = [l for l in run(["lsblk", "-rno", "NAME,TRAN,MOUNTPOINT"]).splitlines() if " usb " in f" {l} "]
    m["usb_storage_mounted_now"] = len(mounted)
    ev.append(f"usb-storage module {'blocked' if m['usb_storage_blocked'] else 'allowed'}"
              f" ({'loaded' if m['usb_storage_loaded'] else 'not loaded'}); USBGuard {'active' if m['usbguard_active'] else 'inactive'}")
    ev.append(f"{len(inserts)} USB mass-storage connections in {CFG['window_days']} days")
    ev += capped([f"{iso(t)} {msg}" for t, msg in inserts[-5:]])
    return m, ev


@control("A.8.2")
def privileged_access():
    m, ev = {}, []
    uid0 = [p.pw_name for p in pwd.getpwall() if p.pw_uid == 0]
    m["uid0_accounts"] = len(uid0)
    s = sshd_settings()
    m["ssh_root_login"] = s.get("permitrootlogin", "unknown")
    m["ssh_root_login_restricted"] = m["ssh_root_login"] in ("no", "prohibit-password", "without-password",
                                                             "forced-commands-only")
    sudoers = read("/etc/sudoers") + "".join(read(p) for p in glob.glob("/etc/sudoers.d/*"))
    nopw = [l.strip() for l in sudoers.splitlines() if "NOPASSWD" in l and not l.strip().startswith("#")]
    m["sudo_nopasswd_entries"] = len(nopw)
    priv = set()
    for grp in ("sudo", "wheel", "admin"):
        mm = re.search(rf"^{grp}:[^:]*:\d+:(.*)$", read("/etc/group"), re.M)
        if mm:
            priv.update(x for x in mm.group(1).split(",") if x)
    m["privileged_users"] = len(priv)
    events = log_events(["sudo", "su"])
    uses = [e for e in events if "COMMAND=" in e[2]]
    fails = [e for e in events if "incorrect password" in e[2] or "authentication failure" in e[2]
             or "NOT in sudoers" in e[2] or "FAILED SU" in e[2]]
    m["sudo_commands_window"] = len(uses)
    m["privilege_failures_window"] = len(fails)
    m["not_in_sudoers_window"] = sum("NOT in sudoers" in e[2] for e in fails)
    by_user = {}
    for _, _, msg in uses:
        u = msg.split(":")[0].strip()
        by_user[u] = by_user.get(u, 0) + 1
    ev.append(f"UID 0 accounts: {', '.join(uid0)}; SSH PermitRootLogin {m['ssh_root_login']}")
    ev.append(f"sudo/wheel/admin members: {', '.join(sorted(priv)) or 'none'}")
    ev += capped(["NOPASSWD: " + l for l in nopw])
    ev.append(f"{len(uses)} sudo commands in {CFG['window_days']} days by: " +
              ", ".join(f"{u} ({n})" for u, n in sorted(by_user.items(), key=lambda x: -x[1])) if uses else
              f"No sudo commands logged in {CFG['window_days']} days")
    ev += capped([f"{iso(t)} {i}: {msg}" for t, i, msg in fails[-5:]])
    return m, ev


def ssh_auth_events():
    ev = log_events(["sshd", "sshd-session"])
    fail_re = re.compile(r"(Failed password|Invalid user|authentication failure|Failed publickey).*?from (\S+)")
    ok_re = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
    fails, oks = [], []
    for ts, _, msg in ev:
        f = fail_re.search(msg)
        if f:
            fails.append((ts, f.group(2)))
            continue
        o = ok_re.search(msg)
        if o:
            oks.append((ts, o.group(3), o.group(2), o.group(1)))
    return fails, oks


@control("A.8.5")
def secure_authentication():
    m, ev = {}, []
    s = sshd_settings()
    m["ssh_password_auth"] = s.get("passwordauthentication", "unknown") == "yes"
    m["ssh_max_auth_tries"] = int(s.get("maxauthtries", "6") or 6)
    pam = "".join(read(p) for p in glob.glob("/etc/pam.d/*"))
    pwq = read("/etc/security/pwquality.conf") + "".join(read(p) for p in glob.glob("/etc/security/pwquality.conf.d/*"))
    mm = re.search(r"^\s*minlen\s*=\s*(\d+)", pwq, re.M) or re.search(r"pam_(?:pwquality|cracklib)\.so.*minlen=(\d+)", pam)
    m["pam_quality_configured"] = bool(re.search(r"^\s*password\s+\S+\s+pam_(pwquality|cracklib)\.so", pam, re.M))
    m["password_min_length"] = int(mm.group(1)) if mm else (8 if m["pam_quality_configured"] else 0)
    fl = read("/etc/security/faillock.conf")
    dm = re.search(r"^\s*deny\s*=\s*(\d+)", fl, re.M) or re.search(r"pam_(?:faillock|tally2)\.so.*deny=(\d+)", pam)
    m["lockout_configured"] = bool(re.search(r"pam_(faillock|tally2)\.so", pam)) and bool(dm)
    m["lockout_threshold"] = int(dm.group(1)) if dm else 0
    m["fail2ban_active"] = active("fail2ban")
    fails, oks = ssh_auth_events()
    m["failed_logons_window"] = len(fails)
    m["successful_logons_window"] = len(oks)
    per_hour = {}
    for ts, ip in fails:
        k = (ip, int(ts // 3600))
        per_hour[k] = per_hour.get(k, 0) + 1
    bursts = {k: n for k, n in per_hour.items() if n >= CFG["brute_force_per_hour"]}
    m["brute_force_bursts"] = len(bursts)
    burst_ips = {ip for ip, _ in bursts}
    fail_count = {}
    for _, ip in fails:
        fail_count[ip] = fail_count.get(ip, 0) + 1
    compromised = [(ts, ip, u) for ts, ip, u, _ in oks if fail_count.get(ip, 0) >= 5]
    m["success_after_failures"] = len(compromised)
    m["password_logins_window"] = sum(1 for o in oks if o[3] == "password")
    top = sorted(fail_count.items(), key=lambda x: -x[1])[:5]
    ev.append(f"SSH PasswordAuthentication {'yes' if m['ssh_password_auth'] else 'no'}, MaxAuthTries {m['ssh_max_auth_tries']}")
    ev.append(f"Password quality {'configured' if m['pam_quality_configured'] else 'not configured'} (minlen {m['password_min_length']}); "
              f"lockout {'deny=' + str(m['lockout_threshold']) if m['lockout_configured'] else 'not configured'}; "
              f"fail2ban {'active' if m['fail2ban_active'] else 'inactive'}")
    ev.append(f"{len(fails)} failed and {len(oks)} successful SSH logins in {CFG['window_days']} days")
    if top:
        ev.append("Top failing sources: " + ", ".join(f"{ip} ({n})" for ip, n in top))
    if bursts:
        ev.append(f"{len(bursts)} brute-force bursts (>= {CFG['brute_force_per_hour']} failures/hour) from: " + ", ".join(sorted(burst_ips)))
    ev += capped([f"{iso(t)} successful login for {u} from {ip} after {fail_count[ip]} failures" for t, ip, u in compromised])
    return m, ev


@control("A.8.6")
def capacity():
    m, ev = {}, []
    worst, worst_inode, rows = 0, 0, []
    for line in run(["df", "-P", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay",
                     "-x", "efivarfs"]).splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[4].endswith("%"):
            pct = int(f[4][:-1])
            worst = max(worst, pct)
            rows.append(f"{f[5]} {pct}% used")
    for line in run(["df", "-Pi", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay",
                     "-x", "efivarfs"]).splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[4].endswith("%"):
            worst_inode = max(worst_inode, int(f[4][:-1]))
    m["max_filesystem_used_pct"] = worst
    m["max_inode_used_pct"] = worst_inode
    mem = dict(re.findall(r"^(\w+):\s+(\d+)", read("/proc/meminfo"), re.M))
    if mem.get("MemTotal"):
        m["memory_available_pct"] = round(int(mem.get("MemAvailable", 0)) * 100 / int(mem["MemTotal"]), 1)
    load = os.getloadavg()[2]
    m["load15_per_cpu"] = round(load / (os.cpu_count() or 1), 2)
    oom = journal("-k", "--grep", "Out of memory|oom-kill|invoked oom-killer")
    enospc = journal("--grep", "No space left on device")
    m["oom_events_window"] = len(oom)
    m["disk_full_events_window"] = len(enospc)
    ev.append("Filesystems: " + "; ".join(rows))
    ev.append(f"Max inode use {worst_inode}%; memory available {m.get('memory_available_pct')}%; 15-min load per CPU {m['load15_per_cpu']}")
    ev.append(f"{len(oom)} out-of-memory and {len(enospc)} 'no space left' events in {CFG['window_days']} days")
    ev += capped([f"{iso(t)} {e['MESSAGE']}" for t, e in (oom + enospc)[-5:]])
    return m, ev


@control("A.8.7")
def malware():
    m, ev = {}, []
    engines = {u: active(u) for u in ("clamav-daemon", "clamd@scan", "clamonacc", "mdatp", "wdavdaemon",
                                      "sophos-spl", "falcon-sensor", "sentinelone", "cbagentd")}
    running = [u for u, a in engines.items() if a]
    m["av_running"] = bool(running)
    m["on_access_scanning"] = engines.get("clamonacc") or engines.get("mdatp") or engines.get("wdavdaemon") or \
        engines.get("falcon-sensor") or engines.get("sentinelone") or False
    sig_ts = 0
    for p in glob.glob("/var/lib/clamav/*.c[lv]d"):
        sig_ts = max(sig_ts, os.path.getmtime(p))
    if shutil.which("mdatp"):
        out = run(["mdatp", "health", "--field", "definitions_updated"])
        mm = re.search(r"(\d{10,})", out)
        if mm:
            sig_ts = max(sig_ts, int(mm.group(1)[:10]))
        m["on_access_scanning"] = m["on_access_scanning"] or "true" in run(["mdatp", "health", "--field",
                                                                             "real_time_protection_enabled"])
    m["signature_age_days"] = round((NOW - sig_ts) / 86400, 1) if sig_ts else None
    upd = log_events(["freshclam"])
    m["signature_update_failures_window"] = sum(("ERROR" in e[2] or "failed" in e[2].lower()) for e in upd)
    scans = []
    for base in ("/var/log/clamav/clamav.log", "/var/log/clamav/clamscan.log"):
        for line in read_lines_rotated(base):
            if "FOUND" in line or "Scanned files" in line or "SCAN SUMMARY" in line:
                scans.append(line.strip())
    detections = [l for l in scans if "FOUND" in l] + \
                 [e[2] for e in log_events(["clamd", "clamonacc", "mdatp"]) if "FOUND" in e[2] or "threat" in e[2].lower()]
    m["detections_window"] = len(detections)
    last_scan = 0
    for p in glob.glob("/var/log/clamav/*.log"):
        if "freshclam" not in p:
            last_scan = max(last_scan, os.path.getmtime(p))
    m["last_scan_age_days"] = round((NOW - last_scan) / 86400, 1) if last_scan else None
    m["rootcheck_enabled"] = bool(re.search(r"<rootcheck>\s*<disabled>no", wazuh_conf()))
    ev.append(f"Anti-malware running: {', '.join(running) or 'none'}; on-access scanning {'yes' if m['on_access_scanning'] else 'no'}")
    ev.append(f"Signatures {m['signature_age_days']} days old; {m['signature_update_failures_window']} update failures in {CFG['window_days']} days"
              if sig_ts else "No signature database found")
    ev.append(f"Last scan log {m['last_scan_age_days']} days ago" if last_scan else "No scan log found")
    ev.append(f"{len(detections)} detections in {CFG['window_days']} days; Wazuh rootcheck {'on' if m['rootcheck_enabled'] else 'off'}")
    ev += capped(detections[-5:])
    return m, ev


@control("A.8.8")
def vulnerabilities():
    m, ev = {}, []
    auto = enabled("unattended-upgrades") or active("dnf-automatic.timer") or active("dnf-automatic-install.timer") \
        or active("yum-cron")
    apt_auto = re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', "".join(read(p) for p in glob.glob("/etc/apt/apt.conf.d/*")))
    m["auto_updates_enabled"] = bool(auto and (apt_auto or not shutil.which("apt-get")))
    last_upgrade, installs, removes, upgrades, failures = 0, 0, 0, 0, 0
    start = None
    for line in read_lines_rotated("/var/log/apt/history.log"):
        if line.startswith("Start-Date:"):
            try:
                start = datetime.strptime(line.split(": ", 1)[1].strip(), "%Y-%m-%d  %H:%M:%S").timestamp()
            except ValueError:
                start = None
        elif start and start >= SINCE:
            if line.startswith("Upgrade:"):
                upgrades += line.count("),") + 1
                last_upgrade = max(last_upgrade, start)
            elif line.startswith("Install:"):
                installs += line.count("),") + 1
            elif line.startswith("Remove:") or line.startswith("Purge:"):
                removes += line.count("),") + 1
            elif line.startswith("Error:"):
                failures += 1
    if not last_upgrade:  # last upgrade is older than the window
        hist = "".join(read_lines_all("/var/log/apt/history.log"))
        for mm in re.finditer(r"Start-Date: (\S+  \S+)\n(?:(?!Start-Date).*\n)*?Upgrade:", hist):
            try:
                last_upgrade = max(last_upgrade, datetime.strptime(mm.group(1), "%Y-%m-%d  %H:%M:%S").timestamp())
            except ValueError:
                pass
    if shutil.which("dnf") and not shutil.which("apt-get"):
        for line in run(["dnf", "history", "list"]).splitlines():
            mm = re.search(r"\|\s*(\d{4}-\d\d-\d\d \d\d:\d\d)\s*\|\s*(\S+)", line)
            if mm and re.search(r"U|Upgrade|Update", mm.group(2)):
                last_upgrade = max(last_upgrade, datetime.strptime(mm.group(1), "%Y-%m-%d %H:%M").timestamp())
    for line in read_lines_rotated("/var/log/unattended-upgrades/unattended-upgrades.log"):
        if "ERROR" in line or "Traceback" in line:
            failures += 1
    m["days_since_last_upgrade"] = round((NOW - last_upgrade) / 86400, 1) if last_upgrade else None
    m["packages_upgraded_window"] = upgrades
    m["packages_installed_window"] = installs
    m["packages_removed_window"] = removes
    m["update_failures_window"] = failures
    stamp = max([os.path.getmtime(p) for p in ("/var/lib/apt/periodic/update-success-stamp",
                                               "/var/cache/apt/pkgcache.bin", "/var/lib/apt/lists")
                 if os.path.exists(p)] or [0])
    m["days_since_metadata_refresh"] = round((NOW - stamp) / 86400, 1) if stamp else None
    pending_total, pending_sec = 0, 0
    if shutil.which("apt-get"):
        for line in run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"], timeout=180).splitlines():
            if line.startswith("Inst "):
                pending_total += 1
                if "security" in line.lower():
                    pending_sec += 1
        has_security_pocket = "security" in "".join(read(p) for p in glob.glob("/etc/apt/sources.list*") +
                                                    glob.glob("/etc/apt/sources.list.d/*"))
    elif shutil.which("dnf"):
        pending_sec = len([l for l in run(["dnf", "-q", "updateinfo", "list", "--security"], timeout=300).splitlines() if l.strip()])
        pending_total = len([l for l in run(["dnf", "-q", "check-update"], timeout=300).splitlines() if l.strip()])
        has_security_pocket = True
    else:
        has_security_pocket = False
    m["pending_updates"] = pending_total
    m["pending_security_updates"] = pending_sec if has_security_pocket else pending_total
    m["reboot_required"] = os.path.exists("/var/run/reboot-required")
    running = os.uname().release
    kernels = sorted(glob.glob("/boot/vmlinuz-*"), key=os.path.getmtime)
    newest = kernels[-1].split("vmlinuz-", 1)[1] if kernels else running
    m["running_latest_kernel"] = newest == running
    ev.append(f"Automatic updates {'enabled' if m['auto_updates_enabled'] else 'not enabled'}")
    ev.append(f"Last package upgrade {m['days_since_last_upgrade']} days ago; package lists refreshed {m['days_since_metadata_refresh']} days ago")
    ev.append(f"In {CFG['window_days']} days: {upgrades} upgraded, {installs} installed, {removes} removed, {failures} update errors")
    ev.append(f"Pending updates: {pending_total} ({pending_sec} from a security source"
              f"{'' if has_security_pocket else '; no separate security repository, all counted'})")
    ev.append(f"Running kernel {running}; newest installed {newest}; reboot required: {m['reboot_required']}")
    return m, ev


@control("A.8.12")
def data_leakage():
    m, ev = {}, []
    m["suid_dumpable"] = int(sysctl("fs.suid_dumpable") or -1)
    limits = read("/etc/security/limits.conf") + "".join(read(p) for p in glob.glob("/etc/security/limits.d/*"))
    m["core_hard_limit_zero"] = bool(re.search(r"^\s*\*\s+hard\s+core\s+0", limits, re.M))
    cd = read("/etc/systemd/coredump.conf") + "".join(read(p) for p in glob.glob("/etc/systemd/coredump.conf.d/*"))
    m["coredump_storage_none"] = bool(re.search(r"^\s*Storage\s*=\s*none", cd, re.M))
    m["core_dumps_restricted"] = m["core_hard_limit_zero"] or m["coredump_storage_none"]
    dumps = [l for l in run(["coredumpctl", "list", "--no-pager", "--no-legend", "--since", SINCE_STR]).splitlines() if l.strip()]
    m["core_dumps_window"] = len(dumps)
    ev.append(f"fs.suid_dumpable={m['suid_dumpable']}; '* hard core 0' {'set' if m['core_hard_limit_zero'] else 'not set'}; "
              f"systemd-coredump Storage=none {'set' if m['coredump_storage_none'] else 'not set'}")
    ev.append(f"{len(dumps)} core dumps captured in {CFG['window_days']} days")
    ev += capped(dumps[-5:])
    return m, ev


def backup_stats(mechanisms, runs):
    """Shared A.8.13 arithmetic: schedule adherence and success from run records."""
    m = {}
    intervals = [x["interval_h"] for x in mechanisms if x.get("interval_h")]
    runs = sorted(r for r in runs if r[0] >= SINCE)
    ok = [r[0] for r in runs if r[1]]
    bad = [r for r in runs if not r[1]]
    interval, source = (min(intervals), "configured") if intervals else (None, None)
    if not interval and len(ok) >= 2:
        gaps = sorted(b - a for a, b in zip(ok, ok[1:]))
        interval, source = round(gaps[len(gaps) // 2] / 3600, 2), "inferred from logs"
    m["backup_mechanisms"] = len(mechanisms)
    m["backup_configured"] = bool(mechanisms)
    m["backup_interval_hours"] = interval
    m["backup_interval_source"] = source
    m["backup_runs_success"] = len(ok)
    m["backup_runs_failed"] = len(bad)
    m["backup_log_verified"] = bool(runs)
    m["backup_success_rate_pct"] = round(len(ok) * 100 / len(runs), 1) if runs else None
    if interval:
        expected = max(1, int(WINDOW / 3600 // interval))
        m["backup_runs_expected"] = expected
        m["backup_adherence_pct"] = round(min(100, len(ok) * 100 / expected), 1)
        gaps = [b - a for a, b in zip(ok, ok[1:])] + ([NOW - ok[-1]] if ok else [])
        m["backup_missed_runs"] = sum(max(0, round(g / 3600 / interval) - 1) for g in gaps) if ok else expected
        m["backup_max_gap_hours"] = round(max(gaps) / 3600, 1) if gaps else None
    m["backup_last_success"] = iso(ok[-1]) if ok else None
    m["backup_last_success_age_hours"] = hours_since(ok[-1]) if ok else None
    m["backup_last_failure"] = iso(bad[-1][0]) if bad else None
    if ok and interval:
        m["backup_last_success_age_ratio"] = round((NOW - ok[-1]) / 3600 / interval, 2)
    return m


@control("A.8.13")
def backup():
    ev, mechanisms, runs = [], [], []
    pat, excl = re.compile(CFG["backup_pattern"], re.I), CFG["backup_exclude"]
    is_backup = lambda s: bool(pat.search(s)) and not any(x in s for x in excl)
    # systemd timers
    for line in run(["systemctl", "list-units", "--type=timer", "--all", "--no-legend", "--plain"]).splitlines():
        timer = line.split()[0] if line.split() else ""
        if not timer:
            continue
        props = dict(l.split("=", 1) for l in run(["systemctl", "show", timer, "-p", "Unit", "-p", "TimersCalendar",
                                                   "-p", "TimersMonotonic", "-p", "ActiveState"]).splitlines() if "=" in l)
        svc = props.get("Unit", "")
        if not (is_backup(timer) or is_backup(svc)):
            continue
        cal = re.search(r"OnCalendar=([^;]+?) ;", props.get("TimersCalendar", ""))
        mono = re.search(r"On(?:UnitActive|UnitInactive|Boot|Startup)USec=([^;]+?) ;", props.get("TimersMonotonic", ""))
        interval = calendar_interval_hours(cal.group(1).strip()) if cal else timespan_hours(mono.group(1)) if mono else None
        mechanisms.append({"name": timer, "type": "systemd timer", "interval_h": interval,
                           "active": props.get("ActiveState") == "active"})
        entries = journal("UNIT=" + svc, "_SYSTEMD_UNIT=" + svc, "+", "UNIT=" + svc)
        starts = sorted(ts for ts, e in entries if e.get("JOB_TYPE") == "start" and e.get("JOB_RESULT"))
        fails = sorted(ts for ts, e in entries if e.get("UNIT_RESULT") or
                       e.get("JOB_RESULT") not in (None, "done"))
        for i, st in enumerate(starts):
            nxt = starts[i + 1] if i + 1 < len(starts) else NOW + 1
            failed = any(st <= f < nxt for f in fails)
            runs.append((st, not failed, svc))
        ev.append(f"systemd timer {timer} -> {svc}: every {interval} h, {'active' if props.get('ActiveState') == 'active' else 'INACTIVE'}; "
                  f"{len(starts)} runs logged, {sum(1 for s in starts if any(s <= f for f in fails))} with failures")
    # cron
    cron_files = ["/etc/crontab"] + glob.glob("/etc/cron.d/*") + glob.glob("/var/spool/cron/crontabs/*") + \
        glob.glob("/var/spool/cron/*")
    for p in cron_files:
        if not os.path.isfile(p):
            continue
        sysfmt = p.startswith("/etc/")
        for line in read(p).splitlines():
            line = line.strip()
            if not line or line.startswith("#") or re.match(r"^\w+=", line) or not is_backup(line):
                continue
            f = line.split()
            if f[0].startswith("@"):
                spec, cmd = f[0], " ".join(f[2 if sysfmt else 1:])
            else:
                spec, cmd = " ".join(f[:5]), " ".join(f[6 if sysfmt else 5:])
            if spec == "@reboot":
                continue
            interval = cron_interval_hours(spec)
            mechanisms.append({"name": f"cron {os.path.basename(p)}: {cmd[:80]}", "type": "cron", "interval_h": interval})
            ev.append(f"cron job in {p}: '{spec}' (every {interval} h) {cmd[:120]}")
    for period, hours in (("daily", 24), ("weekly", 168), ("monthly", 730)):
        for p in glob.glob(f"/etc/cron.{period}/*"):
            if is_backup(os.path.basename(p)) or is_backup(read(p)[:4000]):
                mechanisms.append({"name": p, "type": "cron." + period, "interval_h": hours})
                ev.append(f"cron.{period} script {p}")
    cron_runs = [e for e in log_events(["CRON", "cron", "crond"]) if "CMD" in e[2] and is_backup(e[2])]
    if cron_runs:
        ev.append(f"{len(cron_runs)} backup cron executions logged (exit status is not logged by cron)")
    # Tool logs
    for line in read_lines_rotated("/var/log/rsnapshot.log"):
        mm = re.match(r"\[(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", line) or re.match(r"\[(\d\d/\w{3}/\d{4}:\d\d:\d\d:\d\d)\]", line)
        if not mm:
            continue
        try:
            ts = datetime.fromisoformat(mm.group(1)).timestamp() if "T" in mm.group(1) else \
                datetime.strptime(mm.group(1), "%d/%b/%Y:%H:%M:%S").timestamp()
        except ValueError:
            continue
        if "completed successfully" in line:
            runs.append((ts, True, "rsnapshot"))
        elif "ERROR" in line or "completed, but with some errors" in line:
            runs.append((ts, False, "rsnapshot"))
    # Generic status log written by any backup job
    status_runs = 0
    for line in read_lines_rotated(CFG["backup_status_log"]):
        mm = re.match(r"(\S+)\s+(SUCCESS|FAILURE)\b(?:.*job=(\S+))?", line)
        if mm:
            try:
                ts = datetime.fromisoformat(mm.group(1)).timestamp()
            except ValueError:
                continue
            runs.append((ts, mm.group(2) == "SUCCESS", mm.group(3) or "status-log"))
            status_runs += 1
    if status_runs:
        mechanisms.append({"name": "backup status log", "type": "status log", "interval_h": None})
        ev.append(f"{status_runs} results in {CFG['backup_status_log']}")
    if os.path.exists(CFG["backup_marker"]):
        ts = os.path.getmtime(CFG["backup_marker"])
        runs.append((ts, True, "marker"))
        ev.append(f"Success marker {CFG['backup_marker']} updated {iso(ts)}")
    m = backup_stats(mechanisms, runs)
    if not mechanisms:
        ev.insert(0, "No backup job found (systemd timers, cron, status log or marker)")
    if m["backup_interval_hours"]:
        ev.append(f"Expected {m['backup_runs_expected']} runs in {CFG['window_days']} days "
                  f"(every {m['backup_interval_hours']} h, {m['backup_interval_source']}); "
                  f"{m['backup_runs_success']} succeeded, {m['backup_runs_failed']} failed")
    else:
        ev.append(f"No backup schedule known; {m['backup_runs_success']} successful and "
                  f"{m['backup_runs_failed']} failed runs logged in {CFG['window_days']} days")
    if m.get("backup_last_success"):
        ev.append(f"Last successful backup {m['backup_last_success']} ({m['backup_last_success_age_hours']} h ago)")
    ev += capped([f"{iso(t)} FAILED {job}" for t, ok_, job in sorted(runs) if not ok_][-5:])
    return m, ev


AUDIT_KEYS = {"identity": r"/etc/(passwd|shadow|group|gshadow)", "sudoers": r"/etc/sudoers",
              "login_logs": r"/var/log/(lastlog|faillog|wtmp|btmp)|/var/run/utmp", "time_change": r"adjtimex|settimeofday|clock_settime",
              "privileged_exec": r"execve", "audit_config": r"/etc/audit/", "modules": r"init_module|delete_module|finit_module",
              "mounts": r"\bmount\b", "permissions": r"chmod|chown|setxattr", "network_config": r"sethostname|/etc/hosts"}


@control("A.8.15")
def logging_():
    m, ev = {}, []
    m["auditd_active"] = active("auditd")
    rules = run(["auditctl", "-l"]) if shutil.which("auditctl") else ""
    rule_lines = [l for l in rules.splitlines() if l.startswith("-")]
    m["audit_rules_loaded"] = len(rule_lines)
    status = run(["auditctl", "-s"]) if shutil.which("auditctl") else ""
    m["audit_rules_immutable"] = "enabled 2" in status
    mm = re.search(r"lost (\d+)", status)
    m["audit_events_lost"] = int(mm.group(1)) if mm else None
    covered = [k for k, rx in AUDIT_KEYS.items() if re.search(rx, rules)]
    m["audit_coverage_pct"] = round(len(covered) * 100 / len(AUDIT_KEYS))
    oldest = 0
    for p in glob.glob("/var/log/audit/audit.log*"):
        first = read(p)[:200]
        mm = re.search(r"msg=audit\((\d+)\.", first)
        if mm:
            oldest = min(oldest or int(mm.group(1)), int(mm.group(1)))
    jm = None
    if shutil.which("journalctl"):
        with subprocess.Popen(["journalctl", "-q", "--no-pager", "-o", "short-unix"], stdout=subprocess.PIPE,
                              text=True, env=ENV, errors="replace") as pj:
            jm = re.match(r"(\d+)\.", pj.stdout.readline())
            pj.kill()
    journal_oldest = int(jm.group(1)) if jm else 0
    m["journal_persistent"] = os.path.isdir("/var/log/journal") and any(os.scandir("/var/log/journal")) or \
        bool(re.search(r"^\s*Storage\s*=\s*persistent", read("/etc/systemd/journald.conf"), re.M))
    candidates = [t for t in (oldest, journal_oldest if m["journal_persistent"] else 0) if t]
    m["log_retention_days"] = round((NOW - min(candidates)) / 86400, 1) if candidates else 0
    newest = journal("-n", "1", since="-1d")
    m["logging_alive"] = bool(newest)
    m["auth_log_present"] = any(os.path.exists(p) for p in ("/var/log/auth.log", "/var/log/secure")) or \
        bool(journal("SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10", since="-7d", extra=("-n", "1")))
    kern = journal("-k", "--grep", "audit: backlog limit exceeded|audit_lost|audit: rate limit exceeded")
    jr = journal("_COMM=systemd-journald", "--grep", "Suppressed|Missed|dropped")
    m["log_loss_events_window"] = len(kern) + len(jr)
    acfg = read("/etc/audit/auditd.conf")
    g = lambda k: (re.search(rf"^\s*{k}\s*=\s*(\S+)", acfg, re.M) or [None, ""])[1]
    m["audit_disk_full_action"] = g("disk_full_action") or None
    ev.append(f"auditd {'active' if m['auditd_active'] else 'inactive'}, {len(rule_lines)} rules, "
              f"{'immutable' if m['audit_rules_immutable'] else 'mutable'}; lost events: {m['audit_events_lost']}")
    ev.append(f"Audit rule coverage {m['audit_coverage_pct']}%: covers {', '.join(covered) or 'nothing'}; "
              f"missing {', '.join(k for k in AUDIT_KEYS if k not in covered) or 'nothing'}")
    ev.append(f"Journal persistent: {m['journal_persistent']}; oldest log record {m['log_retention_days']} days old")
    if acfg:
        ev.append(f"auditd.conf max_log_file={g('max_log_file')} num_logs={g('num_logs')} "
                  f"max_log_file_action={g('max_log_file_action')} disk_full_action={g('disk_full_action')}")
    ev.append(f"{m['log_loss_events_window']} log-loss events (audit backlog/rate limit, journald suppression) in {CFG['window_days']} days")
    return m, ev


@control("A.8.16")
def monitoring():
    m, ev = {}, []
    conf = wazuh_conf()
    if is_manager():
        m["wazuh_connected"] = active("wazuh-manager")
        state = "manager"
    else:
        st = read("/var/ossec/var/run/wazuh-agentd.state")
        m["wazuh_connected"] = "status='connected'" in st
        mm = re.search(r"last_keepalive='([^']+)'", st)
        state = mm.group(1) if mm else "unknown"
        try:
            m["keepalive_age_minutes"] = round((NOW - datetime.strptime(state, "%Y-%m-%d %H:%M:%S").timestamp()) / 60, 1)
        except ValueError:
            pass
    m["auth_logs_monitored"] = bool(re.search(r"<location>(/var/log/(auth\.log|secure)|journald)</location>|<log_format>journald</log_format>", conf))
    m["audit_log_monitored"] = "/var/log/audit/audit.log" in conf
    rs = read("/etc/rsyslog.conf") + "".join(read(p) for p in glob.glob("/etc/rsyslog.d/*.conf"))
    m["remote_forwarding"] = bool(re.search(r"^\s*[^#].*(@@?[\w.\[]|omfwd|target=)", rs, re.M))
    m["central_collection"] = m["wazuh_connected"] or m["remote_forwarding"]
    errs = journal("SYSLOG_IDENTIFIER=rsyslogd", "--grep", "suspended|omfwd.*error|connection refused")
    m["forwarding_errors_window"] = len(errs)
    m["fail2ban_active"] = active("fail2ban")
    m["active_response_enabled"] = "<active-response>" in conf and "<disabled>yes</disabled>" not in \
        conf.split("<active-response>")[1][:200] if "<active-response>" in conf else False
    ev.append(f"Wazuh {'manager running' if is_manager() else 'agent ' + ('connected' if m['wazuh_connected'] else 'NOT connected') + ', last keepalive ' + state}")
    ev.append(f"Wazuh collects auth logs: {m['auth_logs_monitored']}; audit log: {m['audit_log_monitored']}")
    ev.append(f"rsyslog remote forwarding {'configured' if m['remote_forwarding'] else 'not configured'}; "
              f"{len(errs)} forwarding errors in {CFG['window_days']} days; fail2ban {'active' if m['fail2ban_active'] else 'inactive'}")
    return m, ev


@control("A.8.17")
def clock():
    m, ev = {}, []
    td = dict(l.split("=", 1) for l in run(["timedatectl", "show"]).splitlines() if "=" in l)
    m["ntp_enabled"] = td.get("NTP") == "yes"
    m["ntp_synchronized"] = td.get("NTPSynchronized") == "yes"
    offset, server, source = None, "", ""
    if shutil.which("chronyc") and active("chronyd") or active("chrony"):
        f = run(["chronyc", "-c", "tracking"]).split(",")
        if len(f) > 4:
            server, offset, source = f[1], abs(float(f[4])), "chrony"
    if offset is None:
        ts = run(["timedatectl", "timesync-status"])
        mm = re.search(r"Offset:\s*([+-]?[\d.]+)(us|ms|s|min)", ts)
        if mm:
            offset = abs(float(mm.group(1))) * {"us": 1e-6, "ms": 1e-3, "s": 1, "min": 60}[mm.group(2)]
            source = "systemd-timesyncd"
        sm = re.search(r"Server:\s*(\S+)", ts)
        server = sm.group(1) if sm else server
    if offset is None and shutil.which("ntpq"):
        for line in run(["ntpq", "-pn"]).splitlines():
            if line.startswith("*"):
                f = line.split()
                server, offset, source = f[0][1:], abs(float(f[8])) / 1000, "ntpd"
    m["clock_offset_seconds"] = round(offset, 4) if offset is not None else None
    m["time_source"] = server or None
    stamp = "/var/lib/systemd/timesync/clock"
    last_sync = os.path.getmtime(stamp) if os.path.exists(stamp) else 0
    events = log_events(["systemd-timesyncd", "chronyd", "ntpd"])
    ok_ev = [e for e in events if re.search(r"Contacted time server|Initial synchronization|Selected source|synchronized to", e[2], re.I)]
    bad_ev = [e for e in events if re.search(r"Timed out|no selectable sources|Can't synchronise|unreachable|failed", e[2], re.I)]
    jumps = [e for e in events if re.search(r"clock wrong by|System clock jumped|stepped", e[2], re.I)]
    if ok_ev:
        last_sync = max(last_sync, ok_ev[-1][0])
    m["last_sync_age_hours"] = max(0.0, hours_since(last_sync)) if last_sync else None
    m["sync_failures_window"] = len(bad_ev)
    m["clock_steps_window"] = len(jumps)
    ev.append(f"NTP {'enabled' if m['ntp_enabled'] else 'disabled'}, synchronized: {m['ntp_synchronized']}; "
              f"source {server or 'unknown'} via {source or 'unknown'}; offset {m['clock_offset_seconds']} s")
    ev.append(f"Last successful sync {m['last_sync_age_hours']} h ago; {len(bad_ev)} sync failures and {len(jumps)} clock steps in {CFG['window_days']} days")
    ev += capped([f"{iso(t)} {i}: {msg}" for t, i, msg in (bad_ev + jumps)[-5:]])
    return m, ev


@control("A.8.18")
def privileged_utilities():
    m, ev = {}, []
    sudoers = read("/etc/sudoers") + "".join(read(p) for p in glob.glob("/etc/sudoers.d/*"))
    active_lines = "\n".join(l for l in sudoers.splitlines() if not l.strip().startswith("#"))
    m["sudo_use_pty"] = bool(re.search(r"Defaults\s+.*use_pty", active_lines))
    m["sudo_logging"] = bool(re.search(r"Defaults\s+.*(logfile=|log_input|log_output|syslog=)", active_lines)) or \
        bool(log_events(["sudo"]))
    suid = []
    for d in ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin", "/usr/lib", "/usr/libexec", "/opt"):
        for root, dirs, files in os.walk(d):
            if root.count("/") > 6:
                dirs[:] = []
            for f in files:
                p = os.path.join(root, f)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_ISUID:
                    suid.append(p)
    suid = sorted(set(os.path.realpath(p) for p in suid))
    unexpected = [p for p in suid if os.path.basename(p) not in CFG["standard_suid"]]
    m["suid_binaries"] = len(suid)
    m["unexpected_suid_binaries"] = len(unexpected)
    m["pkexec_present"] = any(p.endswith("/pkexec") for p in suid)
    ev.append(f"sudo use_pty {'on' if m['sudo_use_pty'] else 'off'}; sudo logging {'on' if m['sudo_logging'] else 'off'}")
    ev.append(f"{len(suid)} setuid binaries, {len(unexpected)} outside the standard list")
    ev += capped(["Unexpected setuid: " + p for p in unexpected])
    return m, ev


@control("A.8.20")
def network_security():
    m, ev = {}, []
    fw = {"nftables": active("nftables"), "firewalld": active("firewalld"), "ufw": active("ufw")}
    ruleset = run(["nft", "list", "ruleset"]) if shutil.which("nft") else ""
    ipt = run(["iptables-save"]) if shutil.which("iptables-save") else ""
    m["firewall_active"] = any(fw.values()) or bool(re.search(r"hook input", ruleset)) or ":INPUT DROP" in ipt
    m["default_inbound_deny"] = bool(re.search(r"hook input.*policy drop", ruleset)) or ":INPUT DROP" in ipt or \
        "Default: deny (incoming)" in run(["ufw", "status", "verbose"]) or \
        (fw["firewalld"] and "target: default" in run(["firewall-cmd", "--list-all"]))
    m["firewall_rules"] = len(re.findall(r"^\s+(?:ip|tcp|udp|ct|iif|meta|counter|accept|drop)", ruleset, re.M)) + \
        len(re.findall(r"^-A ", ipt, re.M))
    m["firewall_logs_drops"] = bool(re.search(r"\blog\b", ruleset)) or "-j LOG" in ipt
    keys = {"net.ipv4.conf.all.accept_source_route": "0", "net.ipv4.conf.all.accept_redirects": "0",
            "net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.all.rp_filter": "1",
            "net.ipv4.tcp_syncookies": "1", "net.ipv4.icmp_echo_ignore_broadcasts": "1",
            "net.ipv6.conf.all.accept_redirects": "0"}
    good = [k for k, v in keys.items() if sysctl(k) in (v, "2" if v == "1" and "rp_filter" in k else v)]
    m["kernel_network_hardening_pct"] = round(len(good) * 100 / len(keys))
    listeners = ss_listeners()
    m["exposed_listening_services"] = len({(p, port) for p, _, port, _ in listeners})
    drops = journal("-k", "--grep", "DROP|REJECT|BLOCK", extra=("-n", "2000"))
    m["dropped_packet_log_entries_window"] = len(drops)
    ev.append(f"Firewall active: {m['firewall_active']} ({', '.join(k for k, v in fw.items() if v) or 'kernel ruleset only'}); "
              f"default inbound deny: {m['default_inbound_deny']}; {m['firewall_rules']} rules; drop logging {m['firewall_logs_drops']}")
    ev.append(f"Kernel network hardening {m['kernel_network_hardening_pct']}%; not hardened: "
              f"{', '.join(k for k in keys if k not in good) or 'none'}")
    ev.append(f"{m['exposed_listening_services']} services listening on non-loopback addresses")
    ev += capped([f"{p} {a}:{port} {proc}" for p, a, port, proc in listeners])
    return m, ev


@control("A.8.21")
def network_services():
    m, ev = {}, []
    pkgs = run(["dpkg-query", "-W", "-f", "${Package} ${Status}\n"])
    installed = {l.split()[0] for l in pkgs.splitlines() if "install ok installed" in l} or set(run(["rpm", "-qa", "--qf", "%{NAME}\n"]).split())
    legacy = sorted(p for p in installed if re.match(r"^(telnetd|inetutils-telnetd|telnet-server|rsh-server|rsh-redone-server|"
                                                     r"tftpd|tftpd-hpa|atftpd|tftp-server|nis|ypserv|talkd|xinetd|vsftpd)$", p))
    m["legacy_services_installed"] = len(legacy)
    plain_ports = {"21": "ftp", "23": "telnet", "69": "tftp", "110": "pop3", "143": "imap", "512": "rexec",
                   "513": "rlogin", "514": "rsh", "389": "ldap", "80": "http"}
    plaintext = [(port, proc) for _, _, port, proc in ss_listeners() if port in plain_ports]
    m["plaintext_listeners"] = len(plaintext)
    s = sshd_settings()
    weak = []
    for k in ("ciphers", "macs", "kexalgorithms"):
        weak += [a for a in s.get(k, "").split(",") if re.search(r"cbc|arcfour|hmac-md5|hmac-sha1$|hmac-sha1-|group1-|group14-sha1|3des", a)]
    m["ssh_weak_algorithms"] = len(weak)
    m["ssh_x11_forwarding"] = s.get("x11forwarding", "no") == "yes"
    smb = read("/etc/samba/smb.conf") if shutil.which("smbd") else ""
    if smb:
        # Samba 4.11+ defaults to SMB2_02; only an explicit legacy value re-enables SMB1.
        mm = re.search(r"^\s*server min protocol\s*=\s*(\S+)", smb, re.M | re.I)
        m["smb_min_protocol_ok"] = not (mm and mm.group(1).upper() in ("NT1", "LANMAN1", "LANMAN2", "CORE", "COREPLUS"))
        m["samba_running"] = active("smbd")
    exports = read("/etc/exports")
    m["nfs_insecure_exports"] = len(re.findall(r"no_root_squash|insecure\b", exports))
    ev.append(f"Legacy service packages: {', '.join(legacy) or 'none'}")
    ev.append(f"Plaintext protocol listeners: {', '.join(f'{plain_ports[p]}/{p} ({proc})' for p, proc in plaintext) or 'none'}")
    ev.append(f"SSH weak algorithms enabled: {', '.join(weak) or 'none'}; X11Forwarding {s.get('x11forwarding', '?')}")
    if smb:
        ev.append(f"Samba {'running' if m['samba_running'] else 'installed'}; SMB1 refused: {m['smb_min_protocol_ok']}")
    if exports.strip():
        ev.append(f"{m['nfs_insecure_exports']} NFS exports with no_root_squash/insecure")
    return m, ev


@control("A.8.22")
def segregation():
    m, ev = {}, []
    m["ipv4_forwarding"] = sysctl("net.ipv4.ip_forward") == "1"
    m["ipv6_forwarding"] = sysctl("net.ipv6.conf.all.forwarding") == "1"
    addrs = run(["ip", "-o", "-4", "addr", "show", "scope", "global"]).splitlines()
    ifaces = sorted({l.split()[1] for l in addrs})
    virt = [i for i in ifaces if re.match(r"docker|br-|virbr|veth|cni|flannel|vmnet|tun|tap|wg", i)]
    phys = [i for i in ifaces if i not in virt]
    m["physical_networks"] = len(phys)
    m["virtual_networks"] = len(virt)
    m["multi_homed_with_forwarding"] = m["ipv4_forwarding"] and len(phys) > 1
    routes = [l for l in run(["ip", "route", "show", "default"]).splitlines() if l.strip()]
    m["default_routes"] = len(routes)
    ev.append(f"IPv4 forwarding {'on' if m['ipv4_forwarding'] else 'off'}; IPv6 forwarding {'on' if m['ipv6_forwarding'] else 'off'}")
    ev.append(f"Interfaces with global IPv4: {', '.join(phys) or 'none'}; virtual/container: {', '.join(virt) or 'none'}")
    ev += capped(["Default route: " + r for r in routes] + [a.split("inet ")[1].split()[0] + " on " + a.split()[1] for a in addrs])
    return m, ev


@control("A.8.23")
def web_filtering():
    m, ev = {}, []
    procs = pgrep(CFG["web_filter_processes"])
    m["web_filter_agent"] = bool(procs)
    env = read("/etc/environment") + "".join(read(p) for p in glob.glob("/etc/profile.d/*.sh")) + \
        "".join(read(p) for p in glob.glob("/etc/apt/apt.conf.d/*"))
    m["proxy_configured"] = bool(re.search(r"(https?_proxy\s*=|Acquire::https?::Proxy)", env, re.I))
    dns = re.findall(r"^nameserver\s+(\S+)", read("/etc/resolv.conf"), re.M)
    rs = run(["resolvectl", "dns"])
    dns += re.findall(r"(\d+\.\d+\.\d+\.\d+)", rs)
    dns = sorted(set(dns))
    m["filtering_dns"] = any(d in CFG["filtering_dns"] for d in dns)
    m["filtering_layer"] = m["web_filter_agent"] or m["proxy_configured"] or m["filtering_dns"]
    denied = 0
    for line in read_lines_rotated("/var/log/squid/access.log"):
        if "TCP_DENIED" in line:
            denied += 1
    m["blocked_requests_window"] = denied
    ev.append(f"Web-filter processes: {', '.join(procs) or 'none'}; system proxy {'set' if m['proxy_configured'] else 'not set'}")
    ev.append(f"DNS servers: {', '.join(dns) or 'none'} ({'includes' if m['filtering_dns'] else 'no'} known filtering resolver)")
    if denied:
        ev.append(f"{denied} requests denied by squid in {CFG['window_days']} days")
    return m, ev


@control("A.8.24")
def cryptography():
    m, ev = {}, []
    tree = run(["lsblk", "-rno", "NAME,TYPE,MOUNTPOINT,FSTYPE", "-s"])
    lsblk = json.loads(run(["lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINTS,FSTYPE,PATH"]) or '{"blockdevices": []}')

    def walk(nodes, chain):
        for n in nodes:
            c = chain + [n]
            yield n, c
            yield from walk(n.get("children", []), c)
    root_enc, swap_enc, swap_any, luks = False, False, False, []
    for n, chain in walk(lsblk["blockdevices"], []):
        mps = [x for x in (n.get("mountpoints") or []) if x]
        crypt = any(x.get("type") == "crypt" for x in chain)
        if "/" in mps:
            root_enc = crypt
        if "[SWAP]" in mps:
            swap_any = True
            swap_enc = swap_enc or crypt
        if n.get("fstype") == "crypto_LUKS":
            luks.append(n["path"])
    m["root_encrypted"] = root_enc
    m["swap_encrypted_or_absent"] = swap_enc or not swap_any
    weak_luks = []
    for dev in luks:
        dump = run(["cryptsetup", "luksDump", dev])
        cipher = re.search(r"cipher:\s*(\S+)|Cipher name:\s*(\S+)", dump)
        ks = re.search(r"Key:\s*(\d+) bits|MK bits:\s*(\d+)", dump)
        c = (cipher.group(1) or cipher.group(2)) if cipher else "?"
        bits = int(ks.group(1) or ks.group(2)) if ks else 0
        ver = re.search(r"Version:\s*(\d)", dump)
        ev.append(f"LUKS{ver.group(1) if ver else '?'} {dev}: {c}, {bits}-bit key")
        if "xts" in c and bits < 512 or "cbc" in c or bits < 256:
            weak_luks.append(dev)
    m["luks_volumes"] = len(luks)
    m["weak_luks_volumes"] = len(weak_luks)
    keys = []
    for root, _, files in os.walk("/etc"):
        for f in files:
            if f.endswith((".key", ".pem")) or f.startswith("ssh_host_") and not f.endswith(".pub"):
                p = os.path.join(root, f)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if st.st_mode & 0o004 and "PRIVATE KEY" in read(p)[:200]:
                    keys.append(p)
    m["world_readable_private_keys"] = len(keys)
    hostkeys = glob.glob("/etc/ssh/ssh_host_*_key.pub")
    weak_host = [k for k in hostkeys if "dsa_" in k and "ecdsa" not in k]
    for k in hostkeys:
        if "rsa" in k:
            mm = re.match(r"(\d+)", run(["ssh-keygen", "-l", "-f", k]))
            if mm and int(mm.group(1)) < 3072:
                weak_host.append(k)
    m["weak_ssh_host_keys"] = len(weak_host)
    osl = read("/etc/ssl/openssl.cnf")
    mm = re.search(r"^\s*MinProtocol\s*=\s*(\S+)", osl, re.M)
    m["tls_min_protocol"] = mm.group(1) if mm else "library default"
    m["legacy_tls_allowed"] = bool(mm and mm.group(1) in ("TLSv1", "TLSv1.1", "SSLv3"))
    pol = run(["update-crypto-policies", "--show"]).strip()
    if pol:
        m["crypto_policy"] = pol
        m["legacy_tls_allowed"] = m["legacy_tls_allowed"] or pol == "LEGACY"
    ev.insert(0, f"Root filesystem on encrypted volume: {root_enc}; swap encrypted or absent: {m['swap_encrypted_or_absent']}")
    ev.append(f"{len(keys)} world-readable private keys under /etc; {len(weak_host)} weak SSH host keys")
    ev.append(f"OpenSSL MinProtocol {m['tls_min_protocol']}" + (f"; crypto policy {pol}" if pol else ""))
    ev += capped(["World-readable key: " + k for k in keys] + ["Weak host key: " + k for k in weak_host])
    return m, ev


@control("A.8.26")
def application_security():
    m, ev = {}, []
    root_apps = []
    for p in glob.glob("/proc/[0-9]*"):
        comm = read(p + "/comm").strip()
        if comm in ("nginx", "httpd", "apache2", "tomcat", "node", "java", "php-fpm", "gunicorn", "uwsgi", "python3"):
            status = read(p + "/status")
            uid = re.search(r"^Uid:\s+(\d+)", status, re.M)
            cmd = read(p + "/cmdline").replace("\0", " ")
            is_master = "master process" in cmd or comm in ("python3",)
            if uid and uid.group(1) == "0" and not is_master and (comm != "python3"):
                root_apps.append(f"{comm} (pid {p.split('/')[-1]})")
    m["app_workers_as_root"] = len(root_apps)
    web = ""
    for pat in ("/etc/nginx/**/*.conf", "/etc/nginx/sites-enabled/*", "/etc/apache2/**/*.conf", "/etc/httpd/**/*.conf"):
        web += "".join(read(p) for p in glob.glob(pat, recursive=True))
    m["web_server_installed"] = bool(web)
    if web:
        m["web_legacy_tls"] = bool(re.search(r"^\s*(ssl_protocols|SSLProtocol)\s+[^;\n]*(TLSv1(\.1)?\b|SSLv3)(?![.\d])", web, re.M))
        m["web_version_disclosure"] = not re.search(r"^\s*(server_tokens\s+off|ServerTokens\s+Prod)", web, re.M | re.I)
    ev.append(f"Application workers running as root: {', '.join(root_apps) or 'none'}")
    if web:
        ev.append(f"Web server config: legacy TLS enabled {m['web_legacy_tls']}; version disclosure {m['web_version_disclosure']}")
    return m, ev


@control("A.8.31")
def dev_separation():
    m, ev = {}, []
    tools = [t for t in ("gcc", "cc", "make", "gdb", "clang", "go", "rustc", "javac", "strace", "ltrace") if shutil.which(t)]
    m["dev_tools_present"] = len(tools)
    m["core_dev_tools_present"] = len([t for t in tools if t in ("gcc", "make", "gdb")])
    m["container_runtime"] = bool(shutil.which("docker") or shutil.which("podman"))
    hn = socket.gethostname().lower()
    m["environment_label"] = "dev" if re.search(r"dev|test|lab|stag", hn) else "unspecified"
    ev.append(f"Development/debug tools installed: {', '.join(tools) or 'none'}")
    ev.append(f"Container runtime: {m['container_runtime']}; hostname suggests environment: {m['environment_label']}")
    return m, ev


@control("A.8.32")
def change_management():
    m, ev = {}, []
    m["package_history_available"] = any(os.path.exists(p) for p in ("/var/log/apt/history.log", "/var/log/dnf.rpm.log",
                                                                     "/var/log/yum.log", "/var/log/dnf.log"))
    conf = wazuh_conf()
    sc = "".join(re.findall(r"<syscheck>(.*?)</syscheck>", conf, re.S))
    dirs = " ".join(re.findall(r"<directories[^>]*>([^<]+)</directories>", sc))
    critical = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/boot"]
    covered = [d for d in critical if re.search(rf"(^|[ ,]){re.escape(d)}([ ,]|$)", dirs)]
    m["fim_configured"] = bool(sc) and "<disabled>yes</disabled>" not in sc[:300]
    m["fim_critical_coverage_pct"] = round(len(covered) * 100 / len(critical))
    m["fim_realtime"] = bool(re.search(r'realtime="yes"|whodata="yes"', sc))
    changes, start = [], None
    for line in read_lines_rotated("/var/log/apt/history.log"):
        if line.startswith("Start-Date:"):
            start = line.split(": ", 1)[1].strip()
        elif line.startswith("Commandline:") and start:
            changes.append(f"{start} {line.split(': ', 1)[1].strip()[:120]}")
    recent = [c for c in changes if c[:10] >= datetime.fromtimestamp(SINCE).strftime("%Y-%m-%d")]
    m["package_changes_window"] = len(recent)
    m["etc_version_controlled"] = os.path.isdir("/etc/.git") or os.path.isdir("/etc/.etckeeper")
    ev.append(f"Package history available: {m['package_history_available']}; {len(recent)} package transactions in {CFG['window_days']} days")
    ev.append(f"Wazuh FIM {'configured' if m['fim_configured'] else 'not configured'}; critical paths covered: "
              f"{', '.join(covered) or 'none'}; real-time/who-data: {m['fim_realtime']}")
    ev.append(f"/etc under version control (etckeeper/git): {m['etc_version_controlled']}")
    ev += capped(recent[-6:])
    return m, ev


@control("A.8.34")
def audit_protection():
    m, ev = {}, []
    p = shutil.which("auditctl") or "/usr/sbin/auditctl"
    if os.path.exists(p):
        st = os.stat(p)
        m["audit_tools_restricted"] = (st.st_mode & 0o022) == 0 and st.st_uid == 0
        ev.append(f"{p} mode {oct(st.st_mode & 0o777)}")
    else:
        m["audit_tools_restricted"] = None
        ev.append("auditctl not installed")
    if os.path.isdir("/var/log/audit"):
        st = os.stat("/var/log/audit")
        logs_ok = (st.st_mode & 0o027) == 0
        for f in glob.glob("/var/log/audit/audit.log*"):
            logs_ok = logs_ok and (os.stat(f).st_mode & 0o137) == 0
        m["audit_logs_protected"] = logs_ok
        ev.append(f"/var/log/audit mode {oct(st.st_mode & 0o777)}; log files protected: {logs_ok}")
    else:
        m["audit_logs_protected"] = None
    rules = run(["auditctl", "-l"]) if shutil.which("auditctl") else ""
    m["audit_config_watched"] = "/etc/audit" in rules
    changes = run(["ausearch", "-m", "CONFIG_CHANGE", "--start", datetime.fromtimestamp(SINCE).strftime("%m/%d/%Y"),
                   "--format", "text"]) if shutil.which("ausearch") else ""
    m["audit_config_changes_window"] = len([l for l in changes.splitlines() if l.strip()])
    stops = journal("_SYSTEMD_UNIT=auditd.service", "--grep", "Stopped|terminated|stopping")
    m["audit_service_stops_window"] = len(stops)
    ev.append(f"Audit configuration watched by audit rules: {m['audit_config_watched']}")
    ev.append(f"{m['audit_config_changes_window']} audit configuration changes and {len(stops)} auditd stops in {CFG['window_days']} days")
    return m, ev


# ---------------------------------------------------------------- main
def main():
    only = set(sys.argv[1:])
    collected = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for cid, fn in CONTROLS.items():
        if only and cid not in only:
            continue
        started = time.time()
        metrics, evidence, errors = {}, [], []
        try:
            metrics, evidence = fn()
        except Exception as e:  # one broken probe must not stop the others
            errors.append(f"{type(e).__name__}: {e}"[:300])
        doc = {"iso27001": {"type": "evidence", "collector": "linux", "version": VERSION, "control": cid,
                            "window_days": CFG["window_days"], "collected_at": collected,
                            "duration_s": round(time.time() - started, 1), "metrics": metrics,
                            "evidence": capped(evidence) if len(evidence) > EVIDENCE_MAX else [str(e)[:300] for e in evidence],
                            "errors": errors}}
        print(json.dumps(doc, separators=(",", ":"), default=str), flush=True)


if __name__ == "__main__":
    main()
