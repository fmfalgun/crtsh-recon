import subprocess
import sys
import json
import os
from pathlib import Path

TARGET = "nmap.org"
OUTPUT = "web/data/demo.json"
SCRIPT = "crtsh-recon.py"

print(f"[build_demo] running {SCRIPT} for {TARGET}")

result = subprocess.run(
    [sys.executable, SCRIPT, "-d", TARGET, "-o", OUTPUT, "--no-cache"],
    cwd=Path(__file__).parent,
)

if result.returncode != 0:
    print(f"[build_demo] ERROR: {SCRIPT} exited with code {result.returncode}")
    raise SystemExit(result.returncode)

output_path = Path(__file__).parent / OUTPUT

if not output_path.exists():
    print(f"[build_demo] ERROR: output file not found: {output_path}")
    raise SystemExit(1)

with open(output_path) as f:
    data = json.load(f)

cert_count = data.get("cert_count", 0)
name_count = data.get("summary", {}).get("unique_names", 0)

print(f"[build_demo] {TARGET} → {cert_count} certs, {name_count} unique names")
