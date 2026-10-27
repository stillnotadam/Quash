"""Orchestrator: run CRDS refutation per in-scope report and emit a verdict, then build the main comparison.

Families:
  reuse    : run the equality/reuse refuter over every matcher-shaped function in the report's release; a claim
             "reused across dimension D" is refuted if some matcher forces equality in D on all its success paths.
  reachability: from results/reach.csv; a claim is refuted if the cited sink is not reachable from any entry.
  bounds   : from a curated claims file (results/bounds_claims.csv) when present (sink/cap/var); else abstain.
Output: results/triage.csv (per report: family, refuted_by, dims, verdict) and a printed main table.
"""
import csv, glob, json, os, re, sys
from collections import defaultdict
from gimple_parse import parse
from refute_reuse import ReuseEncoder

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GDIR = os.path.join(ROOT, "results", "gimple")

DIM_KW = {
    "host":        (r"\b(host|hostname|destination|different (site|server|domain|host))\b", ["host", "origin", "via_peer", "destination", "peer"]),
    "port":        (r"\bport\b", ["port"]),
    "scheme":      (r"\b(scheme|cross[- ]?protocol)\b", ["scheme"]),
    "interface":   (r"(interface|CURLOPT_INTERFACE|bindlocal|source (address|interface)|--interface|if!|host!)", ["interface", "localdev", "bind", "device"]),
    "credentials": (r"(credential|user ?name|password|passwd|\bnetrc\b|\bauth\b|login)", ["user", "passwd", "creds", "pwd", "login", "secret", "key"]),
    "tls":         (r"(tls|ssl|certificate|\bcert\b|verifypeer|verifyhost|cipher|pinned|\bca[- ]?cert)", ["ssl", "cert", "verify", "cipher", "pinned", "cacert", "tls", "primary"]),
    "proxy":       (r"\bproxy\b", ["proxy"]),
    "service":     (r"(sasl|service|gss|kerberos|spnego|principal|realm)", ["service", "sasl", "gss", "krb", "principal", "realm"]),
}
MATCHER_RE = re.compile(r"(match|_same|_equal|_matches|config_match|peer_same|creds_same|reuse)", re.I)
PTR_PARAM = re.compile(r"struct \w+ \*")


def matcher_funcs(fns):
    out = []
    for name, fn in fns.items():
        if not MATCHER_RE.search(name):
            continue
        if len(PTR_PARAM.findall(fn["sig"])) >= 1:   # has at least one struct pointer param
            out.append(name)
    return out


_rel_cache = {}


def release_refutable_dims(rel):
    """For a release, the set of dimensions some matcher provably forces equal on success. Cached."""
    if rel in _rel_cache:
        return _rel_cache[rel]
    dims = set()
    hits = defaultdict(list)
    for dump in glob.glob(os.path.join(GDIR, f"{rel}-gimple_*.ssa")):
        try:
            fns = parse(dump)
        except Exception:
            continue
        for mf in matcher_funcs(fns):
            enc_fn = fns[mf]
            for dim, (_, fields) in DIM_KW.items():
                try:
                    enc = ReuseEncoder(enc_fn)
                    v, t, u = enc.refute2(fields)
                except Exception:
                    continue
                if v == "refuted":
                    dims.add(dim)
                    hits[dim].append(mf)
    _rel_cache[rel] = (dims, hits)
    return _rel_cache[rel]


def report_dims(body, title):
    t = (title + "\n" + body).lower()
    return [d for d, (kw, _) in DIM_KW.items() if re.search(kw, t)]


def load(name):
    return list(csv.DictReader(open(os.path.join(ROOT, name), encoding="utf-8")))


def main():
    claims = load("results/claims.csv")
    reach = {r["id"]: r for r in load("results/reach.csv")}
    master = {r["id"]: r for r in load("data/master.csv")}
    bounds = {}
    bf = os.path.join(ROOT, "results", "bounds_claims.csv")
    if os.path.exists(bf):
        for r in load("results/bounds_claims.csv"):
            bounds[r["id"]] = r
    by_report = defaultdict(lambda: {"families": set(), "dims": set(), "refuted_by": [], "verdict": "abstain"})
    seen = set()
    rel_reports = defaultdict(list)
    for c in claims:
        if c["in_scope"] != "1":
            continue
        rid = c["id"]
        rel_reports[c["release"]].append(c)
    for rel, cs in rel_reports.items():
        dims_refutable, hits = release_refutable_dims(rel)
        for c in cs:
            rid = c["id"]
            rec = by_report[rid]
            d = json.load(open(os.path.join(ROOT, "data", "h1", f"{rid}.json"), encoding="utf-8"))
            body = d.get("vulnerability_information") or ""
            title = master[rid].get("title", "")
            if c["family"] in ("logic",):
                dims = report_dims(body, title)
                rec["dims"] |= set(dims)
                refd = [dd for dd in dims if dd in dims_refutable]
                if refd:
                    rec["verdict"] = "refuted"
                    rec["refuted_by"] += [f"reuse:{dd}({','.join(hits[dd][:2])})" for dd in refd]
            # reachability family
            rv = reach.get(rid, {}).get("verdict", "")
            if rv in ("unreachable", "non_product", "gated_platform"):
                rec["verdict"] = "refuted"
                rec["refuted_by"].append(f"reach:{rv}")
            if rid in bounds and bounds[rid].get("verdict") == "refuted":
                rec["verdict"] = "refuted"
                rec["refuted_by"].append("bounds")
            rec["families"].add(c["family"])
    # write and tabulate
    rows = []
    for rid, rec in by_report.items():
        rows.append({"id": rid, "label": master[rid]["label"], "families": "|".join(sorted(rec["families"])),
                     "dims": "|".join(sorted(rec["dims"])), "verdict": rec["verdict"],
                     "refuted_by": ";".join(rec["refuted_by"])[:200]})
    with open(os.path.join(ROOT, "results", "triage.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "label", "families", "dims", "verdict", "refuted_by"])
        w.writeheader()
        w.writerows(rows)
    import pandas as pd
    df = pd.DataFrame(rows)
    print("in-scope reports:", len(df))
    print(pd.crosstab(df.label, df.verdict, margins=True))
    for lab in ("slop", "genuine", "invalid", "resolved"):
        sub = df[df.label == lab]
        if len(sub):
            print(f"{lab}: refuted {(sub.verdict=='refuted').mean():.1%} ({(sub.verdict=='refuted').sum()}/{len(sub)})")


if __name__ == "__main__":
    main()
