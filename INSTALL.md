# Installation

1. Copy `manager-rules/*.xml` to `/var/ossec/etc/rules/`, run `/var/ossec/bin/wazuh-analysisd -t`, and restart the manager.
2. Create manager agent groups such as `linux-iso` and `windows-iso`; copy the matching policy into `/var/ossec/etc/shared/<group>/` and merge the matching `agent.conf`.
3. Run `/var/ossec/bin/verify-agent-conf -f /var/ossec/etc/shared/<group>/agent.conf`.
4. Because these policies contain `c:` command checks, set `sca.remote_commands=1` locally in each agent's `local_internal_options.conf`, review all commands, and restart the agent.
5. Keep the Wazuh-preinstalled OS-specific CIS/audit policy enabled. Do not edit the installed `ruleset/sca` copy because upgrades may replace it.
6. Optional, recommended: control ratings from configuration and log evidence (see `evidence/README.md`).
   - Copy `evidence/windows/iso27001_collect.ps1` and/or `evidence/linux/iso27001_collect.py` into the group folder next to the policy; the `agent.conf` files in `shared-config/` already start them.
   - On each agent add `wazuh_command.remote_commands=1` to `local_internal_options.conf` and restart it.
   - On the manager: `install -D -m 644 evidence/controls.yml /etc/wazuh-iso27001/controls.yml`, and to rate the manager itself copy the Linux collector to `/var/ossec/etc/iso27001/` and add the same `<wodle name="command">` block to `ossec.conf` with that path.
   - The dashboard sync job (`tools/dashboard/`) scores the evidence; re-run `build_dashboard.py` for the rating panels.

