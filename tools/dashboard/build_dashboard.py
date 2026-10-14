"""Create/overwrite the ISO 27001:2022 Evidence dashboard in Wazuh dashboard (OSD 2.x).

Usage: build_dashboard.py CRED_FILE
  CRED_FILE  file whose first line is admin:password for the Wazuh dashboard
Env: WAZUH_DASHBOARD_URL (default https://127.0.0.1)

Re-running updates the existing objects (fixed ids). Run setup_state_index.py
and the state sync first so the wazuh-iso27001-state* panels have data.
"""
import json, os, ssl, urllib.request, base64, sys

if len(sys.argv) != 2:
    sys.exit(__doc__)
CRED = open(sys.argv[1]).readline().strip()
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

INTRO = """### ISO/IEC 27001:2022 technical evidence
Results from the **wazuh-iso27001-sca-pack** (Linux and Windows), mapped to Annex A controls.

* **Control ratings** combine configuration *and* log evidence. A collector on each endpoint measures every control (e.g. A.8.13: backup schedule vs. backup runs and their success in the logs over 30 days); the manager scores the measurements against `controls.yml` together with the SCA checks. Ratings: Compliant ≥ 90, Largely compliant ≥ 70, Partially compliant ≥ 40, else Non-compliant.\n* **Why** lists every criterion behind a rating: measured value, required value, result and points. **Evidence collected** shows what the collector found.

* **How each check is tested** shows what every check looks at, when it passes, and the exact rule Wazuh runs.\n* **Control changes** lists every result change per control (e.g. failed → passed) with its scan time; it follows the time picker.\n* **Current status** panels (failing checks, control status, failures by control) read `wazuh-iso27001-state`, which is refreshed from the Wazuh manager every 15 minutes and matches *Endpoint security → Configuration Assessment*. They ignore the time picker.
* **Score** and **trend** panels read the alert history and follow the time picker.
* SCA results are technical evidence, **not certification**. Governance controls are listed in `UNMAPPED-GOVERNANCE-CONTROLS.md`."""

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
    vis("iso27001-intro", "ISO 27001 - About", "markdown",
        {"markdown": INTRO, "fontSize": 12, "openLinksInNewTab": False}, [], query=None),
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

# 48-column grid: (object id, type, x, y, w, h)
layout = [("iso27001-intro", "visualization", 0, 0, 48, 10),
          ("iso27001-rating-heatmap", "visualization", 0, 10, 48, 14),
          ("iso27001-ratings", "visualization", 0, 24, 48, 22),
          ("iso27001-criteria", "visualization", 0, 46, 48, 26),
          ("iso27001-evidence-detail", "visualization", 0, 72, 48, 22),
          ("iso27001-score-latest", "visualization", 0, 94, 20, 12),
          ("iso27001-score-trend", "visualization", 20, 94, 28, 12),
          ("iso27001-failing-now", "visualization", 0, 106, 48, 16),
          ("iso27001-changes", "search", 0, 122, 48, 16),
          ("iso27001-control-matrix", "visualization", 0, 138, 48, 24),
          ("iso27001-check-basis", "visualization", 0, 162, 48, 24),
          ("iso27001-fail-by-control", "visualization", 0, 186, 24, 16),
          ("iso27001-pass-fail-trend", "visualization", 24, 186, 24, 16),
          ("iso27001-events", "search", 0, 202, 48, 16)]
panels, refs = [], []
for n, (oid, otype, x, y, w, h) in enumerate(layout):
    pid = str(n + 1)
    panels.append({"version": VER, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                   "panelIndex": pid, "embeddableConfig": {}, "panelRefName": f"panel_{n}"})
    refs.append({"name": f"panel_{n}", "type": otype, "id": oid})

objs.append({"type": "dashboard", "id": "iso27001-evidence",
             "attributes": {"title": "ISO 27001:2022 Evidence",
                            "description": "ISO/IEC 27001:2022 Annex A control ratings from configuration and log evidence, plus Wazuh SCA results",
                            "panelsJSON": json.dumps(panels),
                            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
                            "version": 1, "timeRestore": True, "timeFrom": "now-30d", "timeTo": "now",
                            "refreshInterval": {"pause": True, "value": 0},
                            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                                {"query": {"query": "", "language": "kuery"}, "filter": []})}},
             "references": refs})

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
