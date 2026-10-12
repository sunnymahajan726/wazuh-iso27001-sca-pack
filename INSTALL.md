# Installation

1. Copy `manager-rules/*.xml` to `/var/ossec/etc/rules/`, run `/var/ossec/bin/wazuh-analysisd -t`, and restart the manager.
2. Create manager agent groups such as `linux-iso` and `windows-iso`; copy the matching policy into `/var/ossec/etc/shared/<group>/` and merge the matching `agent.conf`.
3. Run `/var/ossec/bin/verify-agent-conf -f /var/ossec/etc/shared/<group>/agent.conf`.
4. Because these policies contain `c:` command checks, set `sca.remote_commands=1` locally in each agent's `local_internal_options.conf`, review all commands, and restart the agent.
5. Keep the Wazuh-preinstalled OS-specific CIS/audit policy enabled. Do not edit the installed `ruleset/sca` copy because upgrades may replace it.
