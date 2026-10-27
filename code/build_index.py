"""Master index of every disclosed curl HackerOne report with a label.

label:
  genuine        report linked from a curl CVE (curl.se/docs/vuln.json)
  resolved       resolved by curl but no CVE (real bug, not a vulnerability, or hardening)
  slop           listed in Daniel Stenberg's AI-slop gist
  invalid        not-applicable / informative / spam / duplicate and not in the gist
"""
import csv, json, os, re
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = os.path.join(ROOT, "data")

gist = open(os.path.join(D, "raw", "slopgist.md"), encoding="utf-8").read()
slop = set(re.findall(r"hackerone\.com/reports/(\d+)", gist))
cve = {}
for v in json.load(open(os.path.join(D, "raw", "vuln.json"), encoding="utf-8")):
    m = re.search(r"hackerone\.com/reports/(\d+)", v["database_specific"].get("issue", ""))
    if m:
        cve[m.group(1)] = {"cve": v["aliases"][0] if v.get("aliases") else v["id"],
                           "cwe": v["database_specific"].get("CWE", {}).get("id", ""),
                           "severity": v["database_specific"].get("severity", ""),
                           "summary": v.get("summary", "")}
ids = set(pd.read_csv(os.path.join(D, "hacktivity.csv"), dtype=str).databaseId) | slop | set(cve)
rel = pd.read_csv(os.path.join(D, "raw", "releases.csv"), sep=";", header=None, usecols=[1, 3], names=["v", "d"])
rel["d"] = pd.to_datetime(rel.d)
rel = rel.sort_values("d")
rows = []
for rid in sorted(ids, key=int):
    p = os.path.join(D, "h1", f"{rid}.json")
    if not os.path.exists(p):
        continue
    d = json.load(open(p, encoding="utf-8"))
    body = d.get("vulnerability_information") or ""
    sub = d.get("substate", "")
    if rid in cve:
        lab = "genuine"
    elif rid in slop:
        lab = "slop"
    elif sub == "resolved":
        lab = "resolved"
    else:
        lab = "invalid"
    created = d.get("submitted_at") or d.get("created_at")
    c = pd.Timestamp(created).tz_localize(None)
    prior = rel[rel.d <= c]
    rows.append({"id": rid, "label": lab, "substate": sub, "created": created,
                 "release": prior.v.iloc[-1] if len(prior) else "",
                 "title": d.get("title", ""), "body_len": len(body),
                 "weakness": (d.get("weakness") or {}).get("name", ""),
                 "assistant": d.get("submitted_with_assistant"),
                 **cve.get(rid, {"cve": "", "cwe": "", "severity": "", "summary": ""})})
df = pd.DataFrame(rows)
df.to_csv(os.path.join(D, "master.csv"), index=False)
print(df.label.value_counts())
print(pd.crosstab(df.created.str[:4], df.label))
