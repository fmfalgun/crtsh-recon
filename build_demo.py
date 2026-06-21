import subprocess
import sys
import json
import os
from pathlib import Path
from datetime import datetime, timezone

TARGET      = "nmap.org"
DOMAIN_FILE = Path("web/data/domains/nmap.org.json")
INDEX_FILE  = Path("web/data/index.json")
SCRIPT      = "crtsh-recon.py"

def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

print(f"[build_demo] running {SCRIPT} for {TARGET}")

Path("web/data/domains").mkdir(parents=True, exist_ok=True)

result = subprocess.run(
    [sys.executable, SCRIPT, "-d", TARGET, "-o", str(DOMAIN_FILE), "--no-cache"],
    cwd=Path(__file__).parent,
)

if result.returncode != 0:
    print(f"[build_demo] ERROR: {SCRIPT} exited with code {result.returncode}")
    raise SystemExit(result.returncode)

if not DOMAIN_FILE.exists():
    print(f"[build_demo] ERROR: output file not found: {DOMAIN_FILE}")
    raise SystemExit(1)

with open(DOMAIN_FILE) as f:
    data = json.load(f)

data["display_name"]   = "fmfalgun"
data["display_loc"]    = "Chennai, India"
data["last_refreshed"] = data.get("queried_at", now_utc())

with open(DOMAIN_FILE, "w") as f:
    json.dump(data, f, indent=2)

# Update index.json
now = now_utc()
if INDEX_FILE.exists():
    with open(INDEX_FILE) as f:
        index = json.load(f)
else:
    index = {"generated_at": now, "total_domains": 0, "total_certs": 0, "domains": []}

summary = data.get("summary", {})
entry = {
    "domain":            TARGET,
    "display_name":      "fmfalgun",
    "display_loc":       "Chennai, India",
    "queried_at":        data.get("queried_at", now),
    "last_refreshed":    data.get("last_refreshed", now),
    "cert_count":        data.get("cert_count", 0),
    "direct_subdomains": summary.get("direct_subdomains", 0),
    "wildcards":         summary.get("wildcards", 0),
    "san_leaks":         summary.get("san_leaks", 0),
}

domains = [d for d in index["domains"] if d["domain"] != TARGET]
domains.append(entry)
domains.sort(key=lambda x: x["domain"])

index["domains"]       = domains
index["total_domains"] = len(domains)
index["total_certs"]   = sum(d.get("cert_count", 0) for d in domains)
index["generated_at"]  = now

with open(INDEX_FILE, "w") as f:
    json.dump(index, f, indent=2)

cert_count  = data.get("cert_count", 0)
name_count  = summary.get("unique_names", 0)
print(f"[build_demo] {TARGET} → {cert_count} certs, {name_count} unique names")
