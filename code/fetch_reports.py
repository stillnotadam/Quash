"""Fetch curl HackerOne reports: AI-slop list (Stenberg gist) and genuine CVE reports (curl vuln.json).

Writes one JSON per report to data/h1/<id>.json and an index data/index.csv with labels.
Only public, disclosed reports are fetched. Polite rate limit.
"""
import csv, json, os, re, sys, time
import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
OUT = os.path.join(ROOT, "data", "h1")
os.makedirs(OUT, exist_ok=True)

S = requests.Session()
S.headers.update({"Accept": "application/json", "User-Agent": "grounded-slop-research (public disclosed reports only)"})


def fetch(rid):
    path = os.path.join(OUT, f"{rid}.json")
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    for attempt in range(4):
        r = S.get(f"https://hackerone.com/reports/{rid}.json", timeout=30)
        if r.status_code == 200:
            d = r.json()
            json.dump(d, open(path, "w", encoding="utf-8"), indent=1)
            time.sleep(1.0)
            return d
        if r.status_code in (429, 503):
            time.sleep(10 * (attempt + 1))
            continue
        print("fail", rid, r.status_code, file=sys.stderr)
        return None
    return None


def main():
    rows = []
    gist = open(os.path.join(RAW, "slopgist.md"), encoding="utf-8").read()
    slop_ids = sorted(set(re.findall(r"hackerone\.com/reports/(\d+)", gist)))
    for rid in slop_ids:
        rows.append({"id": rid, "label": "slop_natural", "cve": ""})
    vulns = json.load(open(os.path.join(RAW, "vuln.json"), encoding="utf-8"))
    for v in vulns:
        m = re.search(r"hackerone\.com/reports/(\d+)", v["database_specific"].get("issue", ""))
        if m:
            rows.append({"id": m.group(1), "label": "genuine", "cve": v["aliases"][0] if v.get("aliases") else v["id"]})
    seen = set()
    out = []
    for row in rows:
        if row["id"] in seen:
            continue
        seen.add(row["id"])
        d = fetch(row["id"])
        if not d:
            row["status"] = "unavailable"
        else:
            vi = d.get("vulnerability_information") or ""
            row.update(status="ok" if vi.strip() else "no_body", title=d.get("title", ""),
                       substate=d.get("substate", ""), created=d.get("created_at", ""), body_len=len(vi))
        out.append(row)
        print(row["id"], row["label"], row.get("status"), row.get("body_len"))
    with open(os.path.join(ROOT, "data", "index.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "label", "cve", "status", "title", "substate", "created", "body_len"])
        w.writeheader()
        w.writerows(out)


if __name__ == "__main__":
    main()
