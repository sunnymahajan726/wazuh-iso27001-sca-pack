"""Create/overwrite the ISO 27001:2022 Conformity Report dashboard in Wazuh dashboard (OSD 2.x).

Usage: build_dashboard.py CRED_FILE [--dry-run]
  CRED_FILE  file whose first line is admin:password for the Wazuh dashboard
  --dry-run  build and validate the saved objects without contacting the API
             (CRED_FILE is optional in this mode)
Env: WAZUH_DASHBOARD_URL (default https://127.0.0.1)

Re-running updates the existing objects (fixed ids). Run setup_state_index.py
and the state sync first so the wazuh-iso27001-state* panels have data.
"""
import json, os, ssl, urllib.request, base64, sys

DRY = "--dry-run" in sys.argv
args = [a for a in sys.argv[1:] if a != "--dry-run"]
if len(args) != (0 if DRY else 1) and not (DRY and len(args) <= 1):
    sys.exit(__doc__)
CRED = open(args[0]).readline().strip() if args else ""
BASE = os.environ.get("WAZUH_DASHBOARD_URL", "https://127.0.0.1").rstrip("/")
IP = "wazuh-alerts-*"
VER = "2.19.6"
CTX = ssl._create_unverified_context()
AUTH = "Basic " + base64.b64encode(CRED.encode()).decode()

ISO = "rule.groups:iso27001_sca"
STATE_IP = "wazuh-iso27001-state"
HISTORY_IP = "wazuh-iso27001-state-history"
CONTROLS_IP = "wazuh-iso27001-state-controls"
CRITERIA_IP = "wazuh-iso27001-state-criteria"
SUMMARY = "data.sca.type:summary and data.sca.policy:ISO*"


def api(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": AUTH, "osd-xsrf": "true",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=CTX) as r:
        return json.load(r)


def source(query):
    return {"searchSourceJSON": json.dumps({
        "query": {"query": query, "language": "kuery"}, "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})}


IDX_REF = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": IP}]


def vis(oid, title, vtype, params, aggs, query="", desc="", ip=None):
    ref = [dict(IDX_REF[0], id=ip)] if ip else IDX_REF
    return {"type": "visualization", "id": oid,
            "attributes": {"title": title, "description": desc, "version": 1, "uiStateJSON": "{}",
                           "visState": json.dumps({"title": title, "type": vtype, "params": params, "aggs": aggs}),
                           "kibanaSavedObjectMeta": source(query) if query is not None else
                           {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}},
            "references": ref if query is not None else []}


def terms(aid, field, schema, size=20, order="asc", label=None):
    p = {"field": field, "size": size, "order": order, "orderBy": "_key",
         "otherBucket": False, "missingBucket": False}
    if label:
        p["customLabel"] = label
    return {"id": aid, "enabled": True, "type": "terms", "schema": schema, "params": p}


def latest(aid, field, label, sort="timestamp"):
    return {"id": aid, "enabled": True, "type": "top_hits", "schema": "metric",
            "params": {"field": field, "aggregate": "concat", "size": 1,
                       "sortField": sort, "sortOrder": "desc", "customLabel": label}}


def date_hist(aid):
    return {"id": aid, "enabled": True, "type": "date_histogram", "schema": "segment",
            "params": {"field": "timestamp", "interval": "auto", "min_doc_count": 1,
                       "extended_bounds": {}, "drop_partials": False, "useNormalizedOpenSearchInterval": True}}


TABLE = {"perPage": 25, "showPartialRows": False, "showMetricsAtAllLevels": False,
         "showTotal": False, "totalFunc": "sum", "percentageCol": ""}


def xy(chart, horizontal=False, mode="normal", ytitle="Count"):
    cat_pos, val_pos = ("left", "bottom") if horizontal else ("bottom", "left")
    return {"type": chart, "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": cat_pos, "show": True,
                              "style": {}, "scale": {"type": "linear"},
                              "labels": {"show": True, "rotate": 0, "filter": not horizontal, "truncate": 200},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": val_pos,
                           "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": ytitle}}],
            "seriesParams": [{"show": True, "type": "line" if chart == "line" else "histogram", "mode": mode,
                              "data": {"label": ytitle, "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True,
                              "interpolate": "linear"}],
            "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [],
            "addTimeMarker": False, "labels": {"show": False},
            "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}}


COUNT = {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}

# --- Executive KPI tiles --------------------------------------------------
# Score bands mirror the rating thresholds; high score -> green (invert).
SCORE_RANGES = [{"from": 0, "to": 40}, {"from": 40, "to": 70},
                {"from": 70, "to": 90}, {"from": 90, "to": 100.1}]
# "zero is good": 0 -> green, anything >0 -> red (no invert).
ZERO_GOOD = [{"from": 0, "to": 0.5}, {"from": 0.5, "to": 1000000}]


def metric(oid, title, agg, ranges=None, invert=True, subtext="", font=48, query="", ip=None):
    m = {"percentageMode": False, "useRanges": bool(ranges), "colorSchema": "Green to Red",
         "metricColorMode": "Background" if ranges else "None",
         "colorsRange": ranges or [{"from": 0, "to": 100}], "labels": {"show": True},
         "invertColors": invert,
         "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                   "subText": subtext, "fontSize": font}}
    return vis(oid, title, "metric", {"addTooltip": True, "addLegend": False, "type": "metric", "metric": m},
               [agg], query=query, ip=ip)


def agg(atype, field=None, label=None):
    p = {"customLabel": label} if label else {}
    if field:
        p["field"] = field
    return {"id": "1", "enabled": True, "type": atype, "schema": "metric", "params": p}


def md(oid, title, text, font=13):
    return vis(oid, title, "markdown",
               {"markdown": text, "fontSize": font, "openLinksInNewTab": False}, [], query=None)


INTRO = """**Technical assessment of Annex A controls from live configuration and 30-day log evidence.**

| | |
|---|---|
| **Standard** | ISO/IEC 27001:2022, Annex A |
| **Scope** | Endpoints enrolled in Wazuh (Windows & Linux) |
| **Basis** | Configuration + log evidence scored against `controls.yml`, combined with Wazuh SCA checks |
| **Rating bands** | Compliant ≥ 90 · Largely compliant ≥ 70 · Partially compliant ≥ 40 · Non-compliant < 40 |
| **Period** | Score, trend and change panels follow the time picker; status tiles reflect the latest sync |
| **Source** | wazuh-iso27001-sca-pack |

This report presents **technical evidence, not certification.** Governance controls that cannot be measured from an endpoint are listed in `UNMAPPED-GOVERNANCE-CONTROLS.md`."""

objs = [
    {"type": "index-pattern", "id": HISTORY_IP,
     "attributes": {"title": HISTORY_IP + "*", "timeFieldName": "changed_at"}, "references": []},
    {"type": "index-pattern", "id": STATE_IP,
     "attributes": {"title": STATE_IP}, "references": []},
    {"type": "index-pattern", "id": CONTROLS_IP,
     "attributes": {"title": CONTROLS_IP}, "references": []},
    {"type": "index-pattern", "id": CRITERIA_IP,
     "attributes": {"title": CRITERIA_IP}, "references": []},
    vis("iso27001-rating-heatmap", "ISO 27001 - Control score by agent (0-100)", "heatmap",
        {"type": "heatmap", "addTooltip": True, "addLegend": True, "enableHover": False, "legendPosition": "right",
         "times": [], "colorsNumber": 4, "colorSchema": "Green to Red", "invertColors": True, "percentageMode": False,
         "setColorRange": True, "colorsRange": [{"from": 0, "to": 40}, {"from": 40, "to": 70},
                                                 {"from": 70, "to": 90}, {"from": 90, "to": 100.1}],
         "valueAxes": [{"show": False, "id": "ValueAxis-1", "type": "value",
                        "scale": {"type": "linear", "defaultYExtents": False},
                        "labels": {"show": True, "rotate": 0, "overwriteColor": False, "color": "black"}}]},
        [{"id": "1", "enabled": True, "type": "max", "schema": "metric", "params": {"field": "score", "customLabel": "Score"}},
         terms("2", "control", "segment", size=60, label="Control"),
         terms("3", "agent.name", "group", label="Agent")],
        query="", ip=CONTROLS_IP),
    vis("iso27001-ratings", "ISO 27001 - Control ratings (configuration + logs)", "table", TABLE,
        [latest("1", "rating", "Rating", sort="synced_at"),
         latest("5", "score", "Score", sort="synced_at"),
         latest("6", "summary", "What is missing", sort="synced_at"),
         latest("7", "evidence_status", "Evidence", sort="synced_at"),
         terms("2", "agent.name", "bucket", label="Agent"),
         terms("3", "control", "bucket", size=60, label="Control"),
         terms("4", "control_name", "bucket", size=60, label="Name")],
        query="", ip=CONTROLS_IP),
    vis("iso27001-criteria", "ISO 27001 - Why: every criterion behind each rating", "table", dict(TABLE, perPage=30),
        [latest("1", "value", "Measured", sort="synced_at"),
         latest("5", "expected", "Required", sort="synced_at"),
         latest("6", "status", "Result", sort="synced_at"),
         latest("7", "points", "Points", sort="synced_at"),
         latest("8", "weight", "Of", sort="synced_at"),
         terms("2", "agent.name", "bucket", label="Agent"),
         terms("3", "control", "bucket", size=60, label="Control"),
         terms("4", "description", "bucket", size=40, label="Criterion")],
        query="", ip=CRITERIA_IP),
    vis("iso27001-evidence-detail", "ISO 27001 - Evidence collected per control", "table", dict(TABLE, perPage=15),
        [latest("1", "evidence", "Evidence from configuration and logs", sort="synced_at"),
         latest("4", "collected_at", "Collected", sort="synced_at"),
         terms("2", "agent.name", "bucket", label="Agent"),
         terms("3", "control", "bucket", size=60, label="Control")],
        query="", ip=CONTROLS_IP),
    vis("iso27001-intro", "ISO/IEC 27001:2022 Conformity Report", "markdown",
        {"markdown": INTRO, "fontSize": 13, "openLinksInNewTab": False}, [], query=None),
    vis("iso27001-score-latest", "ISO 27001 - Latest score per agent", "table", TABLE,
        [latest("1", "data.sca.score", "Score %"),
         latest("4", "data.sca.passed", "Passed"),
         latest("5", "data.sca.failed", "Failed"),
         latest("6", "data.sca.invalid", "Not evaluated"),
         terms("2", "agent.name", "bucket", label="Agent"),
         terms("3", "data.sca.policy", "bucket", label="Policy")],
        query=SUMMARY),
    vis("iso27001-score-trend", "ISO 27001 - Score over time", "line",
        xy("line", ytitle="Score %"),
        [{"id": "1", "enabled": True, "type": "max", "schema": "metric",
          "params": {"field": "data.sca.score", "customLabel": "Score %"}},
         date_hist("2"), terms("3", "agent.name", "group", label="Agent")],
        query=SUMMARY),
    vis("iso27001-failing-now", "ISO 27001 - Currently failing checks", "table", TABLE,
        [latest("1", "check.remediation", "How to fix", sort="synced_at"),
         terms("2", "agent.name", "bucket", label="Agent"),
         terms("3", "control", "bucket", size=60, label="Annex A control"),
         terms("4", "check.title", "bucket", size=100, label="Check")],
        query="check.result:failed", ip=STATE_IP),
    vis("iso27001-control-matrix", "ISO 27001 - Control status by agent", "table", TABLE,
        [latest("1", "check.result", "Current result", sort="synced_at"),
         terms("2", "control", "bucket", size=60, label="Annex A control"),
         terms("3", "agent.name", "bucket", label="Agent"),
         terms("4", "check.title", "bucket", size=100, label="Check")],
        query="", ip=STATE_IP),
    vis("iso27001-check-basis", "ISO 27001 - How each check is tested", "table", TABLE,
        [latest("1", "check.basis", "Basis (what is checked, when it passes)", sort="synced_at"),
         latest("5", "check.rule", "Exact Wazuh rule", sort="synced_at"),
         terms("2", "control", "bucket", size=60, label="Annex A control"),
         terms("3", "policy.name", "bucket", label="Policy"),
         terms("4", "check.title", "bucket", size=100, label="Check")],
        query="", ip=STATE_IP),
    vis("iso27001-fail-by-control", "ISO 27001 - Currently failing checks by control", "horizontal_bar",
        xy("histogram", horizontal=True, mode="stacked", ytitle="Failing checks"),
        [dict(COUNT, params={"customLabel": "Failing checks"}),
         dict(terms("2", "control", "segment", size=30, label="Control"),
              params={"field": "control", "size": 30, "order": "desc",
                      "orderBy": "1", "otherBucket": False, "missingBucket": False, "customLabel": "Control"}),
         terms("3", "agent.name", "group", label="Agent")],
        query="check.result:failed", ip=STATE_IP),
    vis("iso27001-pass-fail-trend", "ISO 27001 - Pass/fail events over time", "histogram",
        xy("histogram", mode="stacked", ytitle="Events"),
        [dict(COUNT, params={"customLabel": "Events"}), date_hist("2"),
         {"id": "3", "enabled": True, "type": "filters", "schema": "group",
          "params": {"filters": [
              {"input": {"query": "rule.groups:evidence_pass", "language": "kuery"}, "label": "Passed"},
              {"input": {"query": "rule.groups:evidence_fail", "language": "kuery"}, "label": "Failed"}]}}],
        query=ISO),
    {"type": "search", "id": "iso27001-changes",
     "attributes": {"title": "ISO 27001 - Control changes (failed / passed)", "description": "", "version": 1,
                    "columns": ["agent.name", "control", "check.title", "from", "to"],
                    "sort": [["changed_at", "desc"]],
                    "kibanaSavedObjectMeta": source("")},
     "references": [dict(IDX_REF[0], id=HISTORY_IP)]},
    {"type": "search", "id": "iso27001-events",
     "attributes": {"title": "ISO 27001 - Evidence events", "description": "", "version": 1,
                    "columns": ["agent.name", "data.sca.check.compliance.iso_27001_2022",
                                "data.sca.check.title", "data.sca.check.result"],
                    "sort": [["timestamp", "desc"]],
                    "kibanaSavedObjectMeta": source(ISO)},
     "references": IDX_REF},
]

# Executive-summary KPI tiles and section dividers (markdown panels act as
# titled section bands; data panels get a clean display title via the layout).
objs += [
    md("iso27001-sec-exec", "Executive summary",
       "Compliance posture across every assessed endpoint. Tiles are colour-coded against the rating "
       "bands — **red needs attention**. The heatmap shows each control's score per endpoint."),
    metric("iso27001-kpi-score", "ISO 27001 - Overall compliance score",
           agg("avg", "score", "Overall compliance score"),
           ranges=SCORE_RANGES, invert=True, subtext="avg control score / 100", ip=CONTROLS_IP),
    metric("iso27001-kpi-endpoints", "ISO 27001 - Endpoints in scope",
           agg("cardinality", "agent.name", "Endpoints in scope"), ip=CONTROLS_IP),
    metric("iso27001-kpi-controls", "ISO 27001 - Annex A controls assessed",
           agg("cardinality", "control", "Annex A controls assessed"), ip=CONTROLS_IP),
    metric("iso27001-kpi-compliant", "ISO 27001 - Compliant results",
           agg("count", None, "Compliant results"), ip=CONTROLS_IP, query='rating:"Compliant"'),
    metric("iso27001-kpi-noncompliant", "ISO 27001 - Non-compliant results",
           agg("count", None, "Non-compliant results"),
           ranges=ZERO_GOOD, invert=False, ip=CONTROLS_IP, query='rating:"Non-compliant"'),
    metric("iso27001-kpi-findings", "ISO 27001 - Open findings",
           agg("count", None, "Open findings"),
           ranges=ZERO_GOOD, invert=False, ip=STATE_IP, query="check.result:failed"),
    md("iso27001-sec-ratings", "Control ratings register",
       "Every Annex A control rated from configuration and log evidence. *What is missing* summarises "
       "the gap; *Evidence* shows whether the data is current."),
    md("iso27001-sec-findings", "Findings & nonconformities",
       "Controls and individual checks that are currently failing, with the exact remediation — "
       "the nonconformities to close first."),
    md("iso27001-sec-evidence", "Evidence",
       "The measured criteria behind each rating (measured value vs. requirement, with points) and the "
       "raw evidence each collector gathered on the endpoint."),
    md("iso27001-sec-method", "Methodology, scoring & change history",
       "How each check is tested and the exact Wazuh rule, the SCA score per endpoint and its trend, "
       "and every control result change over the selected period."),
]

# 48-column grid: (object id, type, x, y, w, h, display title | None for markdown)
layout = [("iso27001-intro", "visualization", 0, 0, 48, 12, None),
          ("iso27001-sec-exec", "visualization", 0, 12, 48, 4, None),
          ("iso27001-kpi-score", "visualization", 0, 16, 8, 9, "Overall compliance score"),
          ("iso27001-kpi-endpoints", "visualization", 8, 16, 8, 9, "Endpoints in scope"),
          ("iso27001-kpi-controls", "visualization", 16, 16, 8, 9, "Annex A controls assessed"),
          ("iso27001-kpi-compliant", "visualization", 24, 16, 8, 9, "Compliant results"),
          ("iso27001-kpi-noncompliant", "visualization", 32, 16, 8, 9, "Non-compliant results"),
          ("iso27001-kpi-findings", "visualization", 40, 16, 8, 9, "Open findings"),
          ("iso27001-rating-heatmap", "visualization", 0, 25, 48, 14, "Control score by endpoint (0–100)"),
          ("iso27001-sec-ratings", "visualization", 0, 39, 48, 4, None),
          ("iso27001-ratings", "visualization", 0, 43, 48, 22, "Annex A control ratings"),
          ("iso27001-sec-findings", "visualization", 0, 65, 48, 4, None),
          ("iso27001-failing-now", "visualization", 0, 69, 48, 16, "Failing checks & remediation"),
          ("iso27001-fail-by-control", "visualization", 0, 85, 48, 14, "Failing checks by control"),
          ("iso27001-sec-evidence", "visualization", 0, 99, 48, 4, None),
          ("iso27001-criteria", "visualization", 0, 103, 48, 26, "Rating criteria — measured vs. required"),
          ("iso27001-evidence-detail", "visualization", 0, 129, 48, 22, "Evidence collected per control"),
          ("iso27001-sec-method", "visualization", 0, 151, 48, 4, None),
          ("iso27001-check-basis", "visualization", 0, 155, 48, 24, "How each check is tested"),
          ("iso27001-control-matrix", "visualization", 0, 179, 48, 24, "Check status by endpoint"),
          ("iso27001-score-latest", "visualization", 0, 203, 24, 12, "Latest SCA score per endpoint"),
          ("iso27001-score-trend", "visualization", 24, 203, 24, 12, "SCA score over time"),
          ("iso27001-pass-fail-trend", "visualization", 0, 215, 24, 16, "Pass / fail events over time"),
          ("iso27001-changes", "search", 24, 215, 24, 16, "Control result changes"),
          ("iso27001-events", "search", 0, 231, 48, 16, "Evidence events")]
panels, refs = [], []
for n, (oid, otype, x, y, w, h, dt) in enumerate(layout):
    pid = str(n + 1)
    ec = {"title": dt} if dt else {}
    panels.append({"version": VER, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                   "panelIndex": pid, "embeddableConfig": ec, "panelRefName": f"panel_{n}"})
    refs.append({"name": f"panel_{n}", "type": otype, "id": oid})

objs.append({"type": "dashboard", "id": "iso27001-evidence",
             "attributes": {"title": "ISO/IEC 27001:2022 Conformity Report",
                            "description": "ISO/IEC 27001:2022 Annex A conformity report: executive summary, control ratings, findings and evidence from configuration and log evidence, plus Wazuh SCA results",
                            "panelsJSON": json.dumps(panels),
                            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
                            "version": 1, "timeRestore": True, "timeFrom": "now-30d", "timeTo": "now",
                            "refreshInterval": {"pause": True, "value": 0},
                            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                                {"query": {"query": "", "language": "kuery"}, "filter": []})}},
             "references": refs})

if DRY:
    # Validate that every object serialises and report the plan; no API calls.
    payload = json.dumps(objs)
    kinds = {}
    for o in objs:
        kinds[o["type"]] = kinds.get(o["type"], 0) + 1
    print(f"dry-run OK: {len(objs)} saved objects ({payload.__len__()} bytes), "
          + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    print(f"dashboard panels: {len(panels)}")
    for o in objs:
        print(" ", o["type"], o["id"])
    sys.exit(0)

# Store the state index's field list so its panels can aggregate immediately.
for o in objs[:4]:
    fields = api("GET", "/api/index_patterns/_fields_for_wildcard?pattern=" + o["attributes"]["title"] +
                 "&meta_fields=_source&meta_fields=_id&meta_fields=_type&meta_fields=_index&meta_fields=_score")["fields"]
    o["attributes"]["fields"] = json.dumps(fields)

res = api("POST", "/api/saved_objects/_bulk_create?overwrite=true", objs)
bad = [o for o in res["saved_objects"] if "error" in o]
for o in res["saved_objects"]:
    print(o["type"], o["id"], "ERROR " + json.dumps(o["error"]) if "error" in o else "ok")
sys.exit(1 if bad else 0)
