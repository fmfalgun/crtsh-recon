CT log subdomain discovery via crt.sh — classifies results into direct subdomains, wildcards, and SAN leaks.

Live demo: https://fmfalgun.github.io/crtsh-recon

---

## What it finds

Queries the crt.sh API for all certificates logged against a domain. Each Subject Alternative Name (SAN) entry is classified as:

- **direct** — a subdomain of the target (e.g. `api.nmap.org`)
- **wildcard** — a wildcard cert (e.g. `*.nmap.org`)
- **san_leak** — a hostname from a different root domain on the same certificate, which reveals infrastructure relationships (e.g. a cert for `nmap.org` that also covers `seclists.org` tells you both domains share the same hosting or certificate authority account)

Results are cached locally in SQLite with a configurable TTL. Second run is instant.

---

## Install

```bash
git clone https://github.com/fmfalgun/crtsh-recon
cd crtsh-recon
python crtsh-recon.py -d example.com
```

No pip install required. stdlib only.

---

## Usage

```bash
python crtsh-recon.py -d nmap.org
python crtsh-recon.py -d nmap.org -o results.json
python crtsh-recon.py -d nmap.org --no-cache
python crtsh-recon.py -d nmap.org --ttl 48
```

**Flags:**

| Flag | Description |
|------|-------------|
| `-d / --domain` | Target domain (required) |
| `-o / --output FILE` | Write JSON output to file (always prints to stdout as well) |
| `--no-cache` | Bypass cache, always fetch fresh from crt.sh |
| `--ttl HOURS` | Cache lifetime in hours (default: 24) |

**Sample run:**

```
[*] Target: nmap.org
[>] GET https://crt.sh/?q=%.nmap.org&output=json
[+] 52 cert records returned (41 KB)

[✓] nmap.org — results:
    Cert records   : 52 total, 52 newly fetched
    Unique names   : 17
    Wildcards      : 2
    Direct subs    : 10
    SAN leaks      : 5

    Wildcards:
      *.nmap.org

    SAN leaks:
      insecure.org
      nmap.com
      seclists.org
      sectools.org
      www.seclists.org
```

---

## Output schema

```json
{
  "domain": "nmap.org",
  "queried_at": "2026-06-20T02:00:00Z",
  "cached": false,
  "cert_count": 52,
  "entries": [
    {
      "name": "scanme.nmap.org",
      "type": "direct",
      "issuer": "Let's Encrypt",
      "not_before": "2025-01-15",
      "not_after": "2025-04-15",
      "crtsh_id": 12345678
    }
  ],
  "summary": {
    "total_certs": 52,
    "unique_names": 17,
    "direct_subdomains": 10,
    "wildcards": 2,
    "san_leaks": 5
  }
}
```

Each entry in `entries` corresponds to a unique SAN name. `type` is one of `direct`, `wildcard`, or `san_leak`.

---

## Caching

Results are stored in `cache.db` (SQLite, auto-created in the working directory) with a default TTL of 24 hours. Use `--ttl 0` or `--no-cache` to always fetch fresh data. The cache is keyed by domain; running against a different domain does not invalidate existing entries.

---

## License

MIT
