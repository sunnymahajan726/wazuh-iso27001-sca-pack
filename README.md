# Wazuh ISO/IEC 27001:2022 Native SCA Pack

Includes 33 Linux checks, 31 Windows checks, 133 manager XML rules, and 27 endpoint-testable Annex A controls.

Run the custom overlay alongside the applicable Wazuh-bundled CIS/audit policy. Vendor policies are referenced in `mappings/predefined-policy-reuse.csv` and are not copied or modified.

SCA results are technical evidence, not certification. Review every threshold, service, path, backup product, encryption requirement, and applicability decision before production.

Custom groups include `iso27001_2022`, `iso27001_A8_15`, `iso27001_sca`, `evidence_pass`, and `evidence_fail`.

Evidence collectors in `evidence/` go beyond pass/fail settings: they read configuration and 30 days of logs per control (e.g. backup schedule vs. actual successful runs) and the manager rates every control Compliant / Largely / Partially / Non-compliant with the reason for each lost point. See `evidence/README.md` and `evidence/CONTROLS.md`.

An optional Wazuh dashboard for these results is in `tools/dashboard/` (see its README).
