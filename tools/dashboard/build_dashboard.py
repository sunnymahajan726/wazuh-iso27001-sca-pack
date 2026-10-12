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
Results from the **wazuh-iso27001-sca-pack** SCA policies (Linux and Windows), mapped to Annex A controls.

* **Current status** panels (failing checks, control status, failures by control) read `wazuh-iso27001-state`, which is refreshed from the Wazuh manager every 15 minutes and matches *Endpoint security → Configuration Assessment*. They ignore the time picker.
* **Score** and **trend** panels read the alert history and follow the time picker.
* SCA results are technical evidence, **not certification**. Governance controls are listed in `UNMAPPED-GOVERNANCE-CONTROLS.md`."""

objs = [
    {"type": "index-pattern", "id": STATE_IP,
     "attributes": {"title": STATE_IP + "*"}, "references": []},
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
    {"type": "search", "id": "iso27001-events",
     "attributes": {"title": "ISO 27001 - Evidence events", "description": "", "version": 1,
                    "columns": ["agent.name", "data.sca.check.compliance.iso_27001_2022",
                                "data.sca.check.title", "data.sca.check.result"],
                    "sort": [["timestamp", "desc"]],
                    "kibanaSavedObjectMeta": source(ISO)},
     "references": IDX_REF},
]

# 48-column grid: (object id, type, x, y, w, h)
layout = [("iso27001-intro", "visualization", 0, 0, 48, 8),
          ("iso27001-score-latest", "visualization", 0, 8, 20, 12),
          ("iso27001-score-trend", "visualization", 20, 8, 28, 12),
          ("iso27001-failing-now", "visualization", 0, 20, 48, 16),
          ("iso27001-control-matrix", "visualization", 0, 36, 48, 24),
          ("iso27001-fail-by-control", "visualization", 0, 60, 24, 16),
          ("iso27001-pass-fail-trend", "visualization", 24, 60, 24, 16),
          ("iso27001-events", "search", 0, 76, 48, 16)]
panels, refs = [], []
for n, (oid, otype, x, y, w, h) in enumerate(layout):
    pid = str(n + 1)
    panels.append({"version": VER, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                   "panelIndex": pid, "embeddableConfig": {}, "panelRefName": f"panel_{n}"})
    refs.append({"name": f"panel_{n}", "type": otype, "id": oid})

objs.append({"type": "dashboard", "id": "iso27001-evidence",
             "attributes": {"title": "ISO 27001:2022 Evidence",
                            "description": "ISO/IEC 27001:2022 Annex A technical evidence from Wazuh SCA",
                            "panelsJSON": json.dumps(panels),
                            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
                            "version": 1, "timeRestore": True, "timeFrom": "now-30d", "timeTo": "now",
                            "refreshInterval": {"pause": True, "value": 0},
                            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                                {"query": {"query": "", "language": "kuery"}, "filter": []})}},
             "references": refs})

# Store the state index's field list so its panels can aggregate immediately.
fields = api("GET", "/api/index_patterns/_fields_for_wildcard?pattern=" + STATE_IP + "*"
             "&meta_fields=_source&meta_fields=_id&meta_fields=_type&meta_fields=_index&meta_fields=_score")["fields"]
objs[0]["attributes"]["fields"] = json.dumps(fields)

res = api("POST", "/api/saved_objects/_bulk_create?overwrite=true", objs)
bad = [o for o in res["saved_objects"] if "error" in o]
for o in res["saved_objects"]:
    print(o["type"], o["id"], "ERROR " + json.dumps(o["error"]) if "error" in o else "ok")
sys.exit(1 if bad else 0)
