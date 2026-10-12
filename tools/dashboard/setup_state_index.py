"""One-time setup for the ISO 27001 current-state index.

Usage: setup_state_index.py ADMIN_CRED_FILE
  ADMIN_CRED_FILE  file whose first line is admin:password for the Wazuh indexer
Env: WAZUH_INDEXER_URL (default https://127.0.0.1:9200)

Creates the indexer role iso27001_state_writer (write access to
wazuh-iso27001-state* only), the internal user iso27001-sync with a random
password written to /etc/wazuh-iso27001-sync.conf (mode 600), and the
wazuh-iso27001-state index. Re-running rotates the sync user's password.
"""
import base64, json, os, secrets, ssl, sys, urllib.error, urllib.request

if len(sys.argv) != 2:
    sys.exit(__doc__)
ADMIN = open(sys.argv[1]).readline().strip()
INDEXER = os.environ.get("WAZUH_INDEXER_URL", "https://127.0.0.1:9200").rstrip("/")
INDEX = "wazuh-iso27001-state"
CONF = "/etc/wazuh-iso27001-sync.conf"
CTX = ssl._create_unverified_context()


def call(method, path, body, cred=ADMIN):
    req = urllib.request.Request(INDEXER + path, method=method, data=json.dumps(body).encode(), headers={
        "Authorization": "Basic " + base64.b64encode(cred.encode()).decode(),
        "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=CTX) as r:
            return r.status
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:300]
        if e.code == 400 and "resource_already_exists_exception" in detail:
            return "exists"
        sys.exit(f"{method} {path} failed: {e.code} {detail}")


print("role", call("PUT", "/_plugins/_security/api/roles/iso27001_state_writer", {
    "cluster_permissions": ["cluster_composite_ops"],
    "index_permissions": [{"index_patterns": [INDEX + "*"],
                           "allowed_actions": ["crud", "create_index", "manage_aliases",
                                               "indices:admin/mapping/put"]}]}))
password = secrets.token_urlsafe(24)
print("user", call("PUT", "/_plugins/_security/api/internalusers/iso27001-sync", {
    "password": password, "description": "Writes ISO 27001 SCA state for the dashboard"}))
print("role mapping", call("PUT", "/_plugins/_security/api/rolesmapping/iso27001_state_writer",
                           {"users": ["iso27001-sync"]}))
fd = os.open(CONF, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, f"iso27001-sync:{password}\n".encode())
os.close(fd)

kw = {"type": "keyword"}
print("index", call("PUT", "/" + INDEX, {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {"properties": {
        "agent": {"properties": {"id": kw, "name": kw, "os": kw, "status": kw}},
        "policy": {"properties": {"id": kw, "name": kw, "score": {"type": "integer"},
                                  "scan_end": {"type": "date", "format": "epoch_second"}}},
        "check": {"properties": {"id": kw, "title": kw, "result": kw,
                                 "reason": {"type": "text"}, "remediation": {"type": "text"}}},
        "control": kw, "synced_at": {"type": "date"}}}},
    cred=f"iso27001-sync:{password}"))
print(f"sync credentials written to {CONF}")
