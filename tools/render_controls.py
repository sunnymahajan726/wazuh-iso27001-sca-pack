#!/usr/bin/env python3
"""Render evidence/controls.yml as evidence/CONTROLS.md (what each control is rated on)."""
from pathlib import Path
import yaml

r = Path(__file__).resolve().parents[1]
cfg = yaml.safe_load((r / "evidence/controls.yml").read_text())


def need(c):
    if "eq" in c:
        v = c["eq"]
        return "yes" if v is True else "no" if v is False else str(v)
    if "in" in c:
        return " / ".join(c["in"]) + (f" (half: {' / '.join(c['partial_in'])})" if c.get("partial_in") else "")
    if "range" in c:
        return f"{c['range'][0]}-{c['range'][1]}"
    if "max" in c:
        return f"≤ {c['max']}" + (f" (half ≤ {c['partial']})" if "partial" in c else "")
    if "min" in c:
        return f"≥ {c['min']}" + (f" (half ≥ {c['partial']})" if "partial" in c else "")
    return "-"


out = ["# What each control is rated on", "",
       "Generated from `evidence/controls.yml` by `tools/render_controls.py`. Each endpoint collector measures the metrics "
       "from configuration and logs (window: 30 days); the manager scores them. Score = points earned / points available "
       f"× 100, including the SCA checks mapped to the control (weight {cfg['sca_weight']}).", "",
       "Ratings: " + ", ".join(f"{b['rating']} ≥ {b['min']}" for b in cfg["ratings"]) +
       f". Evidence older than {cfg['evidence_max_age_hours']} h is flagged stale.", ""]
for cid, spec in cfg["controls"].items():
    out += [f"## {cid} {spec['name']}", "", "| OS | Criterion | Metric | Required | Weight |", "|---|---|---|---|---|"]
    for c in spec["criteria"]:
        out.append(f"| {c.get('os', 'both')} | {c['desc']} | `{c['metric']}` | {need(c) if c.get('weight') else 'shown only'} | {c.get('weight', 0)} |")
    out.append("")
(r / "evidence/CONTROLS.md").write_text("\n".join(out))
print(f"wrote evidence/CONTROLS.md ({len(cfg['controls'])} controls)")
