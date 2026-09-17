#!/usr/bin/env python3
"""Audit npm packages via OSV (npm audit endpoint is blocked here)."""
import json, sys, urllib.request

lock_path = sys.argv[1]
lock = json.load(open(lock_path))
pkgs = []
seen = set()
for key, info in lock.get("packages", {}).items():
    if not key or not key.startswith("node_modules/"):
        continue
    name = key[len("node_modules/"):]
    if "/node_modules/" in name:  # nested, use full path-ish name
        name = name.split("/node_modules/")[-1]
    ver = info.get("version")
    if not ver or (name, ver) in seen:
        continue
    seen.add((name, ver))
    pkgs.append({"package": {"name": name, "ecosystem": "npm"}, "version": ver})

print(f"auditing {len(pkgs)} packages from {lock_path}", file=sys.stderr)

def query_batch(batch):
    import time
    for attempt in range(5):
        try:
            req = urllib.request.Request(
                "https://api.osv.dev/v1/querybatch",
                data=json.dumps({"queries": batch}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)["results"]
        except Exception as e:
            if attempt == 4:
                raise
            print(f"  (batch retry {attempt+1}: {e})", file=sys.stderr)
            time.sleep(3 * (attempt + 1))

vulns = {}  # (name, version) -> list of (id, summary, severity)
for i in range(0, len(pkgs), 200):
    for q, res in zip(pkgs[i:i+200], query_batch(pkgs[i:i+200])):
        for v in res.get("vulns", []):
            sev = ""
            for s in v.get("severity", []):
                if s.get("type") == "CVSS_V3":
                    sev = s.get("score", "")
            vulns.setdefault((q["package"]["name"], q["version"]), []).append(
                (v["id"], (v.get("summary") or v.get("details", ""))[:110].replace("\n", " "), sev))

def vuln_detail(vid):
    import time
    for attempt in range(4):
        try:
            req = urllib.request.Request(f"https://api.osv.dev/v1/vulns/{vid}")
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except Exception as e:
            if attempt == 3:
                return {"id": vid, "summary": f"(detail fetch failed: {e})"}
            time.sleep(2 * (attempt + 1))

if not vulns:
    print("No known vulnerabilities found.")
else:
    details = {}
    for vs in vulns.values():
        for vid, _, _ in vs:
            if vid not in details:
                details[vid] = vuln_detail(vid)
    print(f"\n{len(vulns)} vulnerable packages:\n")
    for (name, ver), vs in sorted(vulns.items()):
        for vid, _, _ in vs:
            d = details[vid]
            summary = (d.get("summary") or d.get("details", "") or "").split("\n")[0][:110]
            sev = ""
            fixed = ""
            for aff in d.get("affected", []):
                for r in aff.get("ranges", []):
                    for e in r.get("events", []):
                        if "fixed" in e:
                            fixed = e["fixed"]
                for s in aff.get("severity", []):
                    if s.get("type") == "CVSS_V3":
                        sev = s.get("score", "")
            print(f"  {name}@{ver}  [CVSS {sev or 'n/a'}] {vid} (fixed in {fixed or '?'}): {summary}")
