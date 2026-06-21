#!/usr/bin/env python3

import sys
import json
import sqlite3
import argparse
import urllib.request
import urllib.error
from datetime import datetime, timezone

CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
TIMEOUT   = 45
CACHE_DB  = "cache.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS crtsh_cache (
    domain     TEXT PRIMARY KEY,
    fetched_at TEXT NOT NULL,
    cert_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS crtsh_certs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    apex_domain     TEXT NOT NULL,
    crtsh_id        INTEGER,
    name_value      TEXT NOT NULL,
    name_type       TEXT NOT NULL,
    issuer_name     TEXT,
    not_before      TEXT,
    not_after       TEXT,
    entry_timestamp TEXT,
    serial_number   TEXT,
    fetched_at      TEXT NOT NULL,
    UNIQUE(apex_domain, crtsh_id, name_value)
);

CREATE TABLE IF NOT EXISTS crtsh_san_leaks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    apex_domain     TEXT NOT NULL,
    leaked_hostname TEXT NOT NULL,
    issuer_name     TEXT,
    entry_timestamp TEXT,
    cert_serial     TEXT,
    fetched_at      TEXT NOT NULL,
    UNIQUE(apex_domain, leaked_hostname, cert_serial)
);
"""

def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def get_db(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    db.commit()
    return db

def is_cached(db, domain, ttl_hours):
    row = db.execute("SELECT fetched_at FROM crtsh_cache WHERE domain=?", (domain,)).fetchone()
    if not row:
        return False
    age = datetime.now(timezone.utc) - datetime.fromisoformat(row["fetched_at"].replace("Z", "+00:00"))
    return age.total_seconds() < ttl_hours * 3600

def fetch_crtsh(domain):
    url = CRTSH_URL.format(domain=domain)
    print(f"[>] GET {url}", file=sys.stderr)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "crtsh-recon/1.0 (security research, passive query)"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP {e.code} from crt.sh for {domain}", file=sys.stderr)
        return []
    except urllib.error.URLError as e:
        print(f"[!] Network error querying crt.sh for {domain}: {e.reason}", file=sys.stderr)
        return []
    except TimeoutError:
        print(f"[!] Timeout after {TIMEOUT}s querying crt.sh for {domain}", file=sys.stderr)
        return []

    if not raw or raw.strip() == b"[]":
        print(f"[i] crt.sh returned no certs for {domain}", file=sys.stderr)
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[!] JSON parse error for {domain} ({len(raw)//1024} KB): {e}", file=sys.stderr)
        return []

    if not isinstance(data, list):
        print(f"[!] Unexpected crt.sh response format for {domain}", file=sys.stderr)
        return []

    print(f"[+] {len(data)} cert records ({len(raw)//1024} KB)", file=sys.stderr)
    return data

def classify_names(names, apex):
    wildcards  = []
    subdomains = []
    san_leaks  = []
    apex_lower = apex.lower()

    for raw_name in names:
        name = raw_name.strip().lower()
        if not name:
            continue
        if name.startswith("*."):
            base = name[2:]
            if base == apex_lower or base.endswith("." + apex_lower):
                wildcards.append(name)
            else:
                san_leaks.append(name)
        elif name == apex_lower or name.endswith("." + apex_lower):
            subdomains.append(name)
        else:
            san_leaks.append(name)

    return wildcards, subdomains, san_leaks

def store_cert(db, apex, entry, name_value, name_type, ts):
    try:
        db.execute(
            """
            INSERT INTO crtsh_certs
                (apex_domain, crtsh_id, name_value, name_type, issuer_name,
                 not_before, not_after, entry_timestamp, serial_number, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                apex,
                entry.get("id"),
                name_value,
                name_type,
                entry.get("issuer_name"),
                entry.get("not_before"),
                entry.get("not_after"),
                entry.get("entry_timestamp"),
                entry.get("serial_number"),
                ts,
            )
        )
        return True
    except sqlite3.IntegrityError:
        return False

def store_san_leak(db, apex, leaked, entry, ts):
    try:
        db.execute(
            """
            INSERT INTO crtsh_san_leaks
                (apex_domain, leaked_hostname, issuer_name,
                 entry_timestamp, cert_serial, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                apex,
                leaked,
                entry.get("issuer_name"),
                entry.get("entry_timestamp"),
                entry.get("serial_number"),
                ts,
            )
        )
        return True
    except sqlite3.IntegrityError:
        return False

def load_from_cache(db, domain):
    rows = db.execute(
        "SELECT name_value, name_type, issuer_name, not_before, not_after, crtsh_id "
        "FROM crtsh_certs WHERE apex_domain=? ORDER BY name_value",
        (domain,)
    ).fetchall()
    return rows

def build_result(domain, entries_raw, cached, ts):
    all_entries = []
    seen_names  = set()
    direct_count   = 0
    wildcard_count = 0
    leak_count     = 0

    for entry in entries_raw:
        raw_name_value = entry.get("name_value", "")
        names = [n.strip() for n in raw_name_value.split("\n") if n.strip()]
        wildcards, subdomains, san_leaks = classify_names(names, domain)

        for name in wildcards:
            seen_names.add(name)
            wildcard_count += 1
            all_entries.append({
                "name":       name,
                "type":       "wildcard",
                "issuer":     entry.get("issuer_name"),
                "not_before": entry.get("not_before"),
                "not_after":  entry.get("not_after"),
                "crtsh_id":   entry.get("id"),
            })
        for name in subdomains:
            seen_names.add(name)
            direct_count += 1
            all_entries.append({
                "name":       name,
                "type":       "direct",
                "issuer":     entry.get("issuer_name"),
                "not_before": entry.get("not_before"),
                "not_after":  entry.get("not_after"),
                "crtsh_id":   entry.get("id"),
            })
        for name in san_leaks:
            seen_names.add(name)
            leak_count += 1
            all_entries.append({
                "name":       name,
                "type":       "leak",
                "issuer":     entry.get("issuer_name"),
                "not_before": entry.get("not_before"),
                "not_after":  entry.get("not_after"),
                "crtsh_id":   entry.get("id"),
            })

    return {
        "domain":     domain,
        "queried_at": ts,
        "cached":     cached,
        "cert_count": len(entries_raw),
        "entries":    all_entries,
        "summary": {
            "total_certs":       len(entries_raw),
            "unique_names":      len(seen_names),
            "direct_subdomains": direct_count,
            "wildcards":         wildcard_count,
            "san_leaks":         leak_count,
        },
    }

def build_result_from_cache(db, domain, ts):
    rows = load_from_cache(db, domain)
    cache_row = db.execute(
        "SELECT cert_count FROM crtsh_cache WHERE domain=?", (domain,)
    ).fetchone()
    cert_count = cache_row["cert_count"] if cache_row else 0

    entries     = []
    seen_names  = set()
    direct_count   = 0
    wildcard_count = 0
    leak_count     = 0

    for row in rows:
        name      = row["name_value"]
        name_type = row["name_type"]
        seen_names.add(name)
        if name_type == "direct":
            direct_count += 1
        elif name_type == "wildcard":
            wildcard_count += 1
        else:
            leak_count += 1
        entries.append({
            "name":       name,
            "type":       name_type,
            "issuer":     row["issuer_name"],
            "not_before": row["not_before"],
            "not_after":  row["not_after"],
            "crtsh_id":   row["crtsh_id"],
        })

    return {
        "domain":     domain,
        "queried_at": ts,
        "cached":     True,
        "cert_count": cert_count,
        "entries":    entries,
        "summary": {
            "total_certs":       cert_count,
            "unique_names":      len(seen_names),
            "direct_subdomains": direct_count,
            "wildcards":         wildcard_count,
            "san_leaks":         leak_count,
        },
    }

def print_summary(result):
    s = result["summary"]
    src = "cache" if result["cached"] else "live"
    print(f"\n{'─'*60}")
    print(f"  Domain     : {result['domain']}")
    print(f"  Source     : {src}")
    print(f"  Queried at : {result['queried_at']}")
    print(f"  Certs      : {s['total_certs']}")
    print(f"  Unique names: {s['unique_names']}")
    print(f"  Direct      : {s['direct_subdomains']}")
    print(f"  Wildcards   : {s['wildcards']}")
    print(f"  SAN leaks   : {s['san_leaks']}")

    by_type = {}
    for e in result["entries"]:
        by_type.setdefault(e["type"], []).append(e["name"])

    for label, key in [("Direct subdomains", "direct"), ("Wildcards", "wildcard"), ("SAN leaks", "leak")]:
        names = sorted(set(by_type.get(key, [])))
        if names:
            print(f"\n  {label}:")
            for n in names:
                print(f"    {n}")
    print()

def main():
    ap = argparse.ArgumentParser(description="crt.sh certificate transparency recon — standalone")
    ap.add_argument("-d", "--domain",   required=True, help="target apex domain (e.g. nmap.org)")
    ap.add_argument("-o", "--output",   help="write JSON output to this file")
    ap.add_argument("--no-cache",       action="store_true", help="bypass TTL, always fetch fresh")
    ap.add_argument("--ttl",            type=int, default=24, help="cache TTL in hours (default: 24)")
    args = ap.parse_args()

    domain = args.domain.lower().strip()
    db     = get_db(CACHE_DB)
    ts     = now_utc()

    if not args.no_cache and is_cached(db, domain, args.ttl):
        result = build_result_from_cache(db, domain, ts)
    else:
        raw_entries = fetch_crtsh(domain)
        fetch_ts    = now_utc()

        if raw_entries:
            # store each classified name row individually so cache reads are typed
            for entry in raw_entries:
                raw_name_value = entry.get("name_value", "")
                names = [n.strip() for n in raw_name_value.split("\n") if n.strip()]
                wildcards, subdomains, san_leaks = classify_names(names, domain)
                for name in wildcards:
                    store_cert(db, domain, entry, name, "wildcard", fetch_ts)
                for name in subdomains:
                    store_cert(db, domain, entry, name, "direct", fetch_ts)
                for name in san_leaks:
                    store_cert(db, domain, entry, name, "leak", fetch_ts)
                    store_san_leak(db, domain, name, entry, fetch_ts)

        db.execute(
            "INSERT OR REPLACE INTO crtsh_cache (domain, fetched_at, cert_count) VALUES (?, ?, ?)",
            (domain, fetch_ts, len(raw_entries))
        )
        db.commit()

        result = build_result(domain, raw_entries, False, fetch_ts)

    print_summary(result)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[+] JSON written to {args.output}", file=sys.stderr)

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
