# ISO 27001:2022 Evidence dashboard

Builds a Wazuh dashboard ("ISO 27001:2022 Evidence") from this pack's SCA results: latest score per agent, score trend, currently failing checks with remediation, control status by agent, and the evidence alert log.

## Why a sync job

SCA raises alerts only for some result changes. Results that reach the manager via integrity sync update wazuh-db without an alert, so an alert-based view drifts from the real state. `wazuh-iso27001-state-sync` copies the current results from wazuh-db into the `wazuh-iso27001-state` index. The current-status panels read that index; score and trend panels read `wazuh-alerts-*`.

## Install (on the Wazuh manager, as root)

Put the admin credentials (`admin:password`) in a root-only file, for example `install -m 600 /dev/null /root/.wazuh-dash` and edit it. Then:

```sh
python3 setup_state_index.py /root/.wazuh-dash        # role, user iso27001-sync, index
install -m 755 wazuh-iso27001-state-sync /usr/local/bin/
install -m 644 wazuh-iso27001-state.cron /etc/cron.d/wazuh-iso27001-state
/usr/local/bin/wazuh-iso27001-state-sync               # first sync
python3 build_dashboard.py /root/.wazuh-dash           # dashboard objects
shred -u /root/.wazuh-dash
```

Set `WAZUH_INDEXER_URL` or `WAZUH_DASHBOARD_URL` if they aren't on `https://127.0.0.1:9200` and `https://127.0.0.1`. Open the dashboard at `/app/dashboards#/view/iso27001-evidence`.

The sync runs every 15 minutes and logs to `/var/log/wazuh-iso27001-sync.log`. It only needs `/etc/wazuh-iso27001-sync.conf`; the admin password is not stored.

Tested with Wazuh 4.14.8 (dashboard 2.19.6).
