# Evidence collectors and control ratings

SCA checks answer "is this setting right?". The collectors here also answer
"is the control actually operating?" by reading configuration **and logs**
over the last 30 days, then the manager rates each Annex A control.

Example, A.8.13 Information backup: the collector finds backup jobs (scheduled
tasks, Windows/Server Backup, File History, OneDrive folder backup, Veeam,
systemd timers, cron, a status log), reads their configured frequency, reads
every run from the logs (Task Scheduler history, backup event logs, journald,
tool logs), and reports expected vs. successful vs. failed runs, missed runs,
the longest gap and the age of the last good backup. The manager turns that
into a score and a rating with the reason for every lost point.

## Data flow

```
endpoint: collector (wodle "command", every 6 h, SYSTEM/root, read-only)
   -> one JSON line per control  -> Wazuh agent -> manager
manager: JSON decoder + rule 122950 -> alerts.json
   -> wazuh-iso27001-state-sync (cron, 15 min): latest evidence per agent+control
      + SCA results from wazuh-db, scored with /etc/wazuh-iso27001/controls.yml
   -> indexer: wazuh-iso27001-state-controls (rating per control)
               wazuh-iso27001-state-criteria (every criterion: measured, required, result)
               wazuh-iso27001-state-history  (rating changes)
   -> dashboard "ISO 27001:2022 Evidence"
```

What each control is rated on: [CONTROLS.md](CONTROLS.md). Change thresholds
(backup frequency, patch SLA, log retention, ...) in `controls.yml` on the
manager; nothing changes on the agents.

## Files

| File | Runs on | Installed to |
|---|---|---|
| `windows/iso27001_collect.ps1` | Windows agents | group folder, e.g. `/var/ossec/etc/shared/windows-iso/` (arrives as `shared\iso27001_collect.ps1`) |
| `linux/iso27001_collect.py` | Linux agents / the manager | group folder (arrives as `/var/ossec/etc/shared/iso27001_collect.py`), or `/var/ossec/etc/iso27001/` on the manager |
| `controls.yml` | manager | `/etc/wazuh-iso27001/controls.yml` |
| `../manager-rules/063-iso27001-evidence.xml` | manager | `/var/ossec/etc/rules/` |

## Enabling on agents

The collector is started by the command wodle in the group's `agent.conf`
(see `shared-config/`). Agents only run commands from a centrally pushed
config when allowed locally, so on each agent add to
`local_internal_options.conf` and restart the agent:

```
wazuh_command.remote_commands=1
```

To see what a collector reports, run it by hand (elevated PowerShell / root):

```
powershell -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\shared\iso27001_collect.ps1" A.8.13
python3 /var/ossec/etc/shared/iso27001_collect.py A.8.13
```

## Feeding backup results from any tool

If your backup product has no log the collector understands, have its job
append one line per run to `C:\ProgramData\iso27001\backup-status.log` or
`/var/lib/iso27001/backup-status.log`:

```
2026-10-14T01:30:00+05:30 SUCCESS job=nightly-nas
2026-10-15T01:30:00+05:30 FAILURE job=nightly-nas
```

## Limits

* Ratings are technical evidence for the auditor, not certification.
* Some sources are best effort: OneDrive folder backup has no run log (it
  counts as configured but unverified); Task Scheduler history is off by
  default on Windows, so only each task's last run is known until it is
  enabled; Home editions lack AppLocker/BitLocker management.
* Windows clocks on laptops sync about weekly by default, which the A.8.17
  last-sync criterion will show.
