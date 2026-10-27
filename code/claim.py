"""Turn a vulnerability report into a formal claim skeleton for refutation.

A claim skeleton is report-level metadata plus, per cited product function, the ingredients a refutation query
needs. We do NOT try to reconstruct an exploit; we extract the structural assertion the report makes:
  family      bounds | integer | reachability | uaf | logic | other  (what kind of refutation applies)
  func/file   the cited product function(s) that exist in the release the report targets
  caps        integer literals the report ties to a buffer/limit (candidate bounds C)
  lines       cited (file,line) pairs (sink candidates)
  cwe         from the H1 weakness field or title
This is heuristic and deliberately conservative: it marks a report in_scope only when it cites a product
function that exists in the targeted release (from reach.csv), so refutation has something to bind to.
"""
import csv, json, os, re, sys
from collections import defaultdict
from cite_extract import extract

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CWE_KW = [
    ("bounds", r"buffer overflow|stack[- ]?based|out[- ]of[- ]bounds|overflow in|strcpy|memcpy|stack buffer|oob write|oob read|over-?read"),
    ("integer", r"integer overflow|integer underflow|size calculation|multiplication overflow|wraps around|truncat"),
    ("uaf", r"use[- ]after[- ]free|double free|dangling|freed memory|uaf"),
    ("reachability", r"test server|test suite|tests/|example|only.*debug|DEBUGBUILD"),
    ("logic", r"reuse|redirect|bypass|validation|authentication|certificate|mixup|confusion|toctou|race|leak|smuggl|traversal"),
]


def classify(title, weakness, body):
    t = f"{title} {weakness} {body[:400]}".lower()
    for fam, pat in CWE_KW:
        if re.search(pat, t):
            return fam
    return "other"


def caps_near_buffers(body):
    caps = set()
    # a size literal attached to a buffer/array/length context
    for m in re.finditer(r"\[(\d{1,7})\]", body):          # char buf[2048]
        caps.add(int(m.group(1)))
    for m in re.finditer(r"(?:size|len|length|max|MAX|buffer|bytes|limit)\D{0,20}?(\d{2,7})", body):
        caps.add(int(m.group(1)))
    for m in re.finditer(r"\b(\d{2,7})\s*(?:bytes|-byte| byte)", body):
        caps.add(int(m.group(1)))
    return sorted(c for c in caps if 2 <= c <= 1 << 20)


def load_reach():
    r = {}
    for row in csv.DictReader(open(os.path.join(ROOT, "results", "reach.csv"), encoding="utf-8")):
        r[row["id"]] = row
    return r


def func_file_map():
    """(release,func) -> file, parsed from reach fstat and the per-report cited funcs is not enough; use nodes."""
    m = defaultdict(dict)
    for f in os.listdir(os.path.join(ROOT, "results", "cg")):
        if not f.startswith("cg-"):
            continue
        v = f[3:-5]
        d = json.load(open(os.path.join(ROOT, "results", "cg", f)))
        for n in d["nodes"].values():
            m[v].setdefault(n["name"], n["file"])
    return m


def main():
    master = list(csv.DictReader(open(os.path.join(ROOT, "data", "master.csv"), encoding="utf-8")))
    reach = load_reach()
    ff = func_file_map()
    claims = []
    targets = set()
    for row in master:
        rid = row["id"]
        d = json.load(open(os.path.join(ROOT, "data", "h1", f"{rid}.json"), encoding="utf-8"))
        body = d.get("vulnerability_information") or ""
        c = extract(body, scoped=True)
        rel = row.get("release_built") or row.get("release")
        fam = classify(row.get("title", ""), row.get("weakness", ""), body)
        fmap = ff.get(rel, {})
        prod_funcs = [f for f in c["funcs"] if f in fmap]
        # reachability-family: report cites only non-product/absent funcs but names a product path
        verdict = reach.get(rid, {}).get("verdict", "")
        caps = caps_near_buffers(body)
        lines = [(p.split("/")[-1], a, b) for (p, a, b) in c["lines"]]
        for fn in (prod_funcs or [None]):
            file = fmap.get(fn) if fn else ""
            claim = {"id": rid, "label": row["label"], "release": rel, "family": fam, "cwe": row.get("weakness", ""),
                     "func": fn or "", "file": file, "verdict_reach": verdict,
                     "caps": "|".join(map(str, caps[:8])),
                     "sink_lines": "|".join(f"{f}:{a}" for (f, a, b) in lines if not fn or f == file)[:200],
                     "n_prod_funcs": len(prod_funcs), "in_scope": int(bool(fn))}
            claims.append(claim)
            if fn and file.endswith(".c"):
                targets.add((rel, file))
    keys = ["id", "label", "release", "family", "cwe", "func", "file", "verdict_reach", "caps", "sink_lines",
            "n_prod_funcs", "in_scope"]
    with open(os.path.join(ROOT, "results", "claims.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(claims)
    with open(os.path.join(ROOT, "data", "gimple_targets.txt"), "w", newline="\n") as f:
        for rel, file in sorted(targets):
            f.write(f"{rel}\t{file}\n")
    import pandas as pd
    df = pd.DataFrame(claims)
    ins = df[df.in_scope == 1]
    print("claims:", len(df), "in-scope rows:", len(ins), "unique in-scope reports:", ins.id.nunique())
    print(pd.crosstab(ins.label, ins.family))
    print("gimple targets (release,file):", len(targets))


if __name__ == "__main__":
    main()
