"""Sound, chain-based reuse refutation over the whole corpus, with a zero-false-reject design.

Rule: a connection-reuse report is REFUTED iff the dimensions it could be about are all already enforced by the
release's reuse key (claimed_dims is non-empty and a subset of forced_dims(release)). Then there is no unenforced
dimension in which a real reuse bug could live, so the claim cannot be genuine. Dimension extraction is HIGH-RECALL
(every plausibly mentioned dimension), so the subset test is hard to satisfy by accident: we err toward abstaining.
We measure genuine-lost (must be ~0) and yield on slop/invalid. forced_dims is the sound under-approximation from
refute_chain.py. Verdict-only.
"""
import csv, json, os, re
from collections import defaultdict
from refute_chain import forced_dims, DIM_FIELDS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIM_RE = {
    "host": r"\b(host|hostname|different (site|server|domain|host)|cross-origin|origin|destination|ip address)\b",
    "port": r"\bport\b",
    "scheme": r"\b(scheme|cross[- ]?protocol)\b",
    "interface": r"(interface|CURLOPT_INTERFACE|bindlocal|source (address|interface)|local (ip|address|port)|--interface)",
    "credentials": r"(credential|user ?name|password|passwd|\bnetrc\b|\bauth\b|login|oauth|bearer|ntlm|negotiate|gssapi|kerberos|sasl)",
    "tls": r"(\btls\b|\bssl\b|certificate|\bcert\b|verifypeer|verifyhost|cipher|pinned|\bca[- ]?(cert|file|path)|issuer|client[- ]?cert|mtls|native ca)",
    "proxy": r"\bproxy\b",
    "service": r"(sasl service|\bservice\b|starttls|\bsmb\b|\bftp\b|\bimap\b|protocol family)",
}


def report_dims(text):
    t = text.lower()
    return {d for d, pat in DIM_RE.items() if re.search(pat, t, re.I)}


def load(p):
    return list(csv.DictReader(open(os.path.join(ROOT, p), encoding="utf-8")))


def main():
    master = {r["id"]: r for r in load("data/master.csv")}
    claims = [c for c in load("results/claims.csv") if c["in_scope"] == "1" and c["family"] == "logic"]
    fd_cache = {}
    rows = []
    reuse_re = re.compile(r"reuse|re-use|mixup|mix-up|connection|reused|shared connection|too eager|wrong (connection|proxy|host)", re.I)
    for c in {c["id"]: c for c in claims}.values():
        rid = c["id"]
        d = json.load(open(os.path.join(ROOT, "data", "h1", f"{rid}.json"), encoding="utf-8"))
        body = (master[rid].get("title", "") + "\n" + (d.get("vulnerability_information") or ""))
        if not reuse_re.search(body):
            continue  # restrict to connection-reuse-class reports (where the forced-dims rule applies)
        rel = c["release"]
        if rel not in fd_cache:
            try:
                fd_cache[rel] = forced_dims(rel)[0]
            except Exception:
                fd_cache[rel] = set()
        forced = fd_cache[rel]
        dims = report_dims(body)
        refuted = bool(dims) and dims.issubset(forced)
        rows.append({"id": rid, "label": master[rid]["label"], "release": rel,
                     "claimed_dims": "|".join(sorted(dims)), "forced_dims": "|".join(sorted(forced)),
                     "verdict": "refuted" if refuted else "abstain"})
    with open(os.path.join(ROOT, "results", "triage_chain.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "label", "release", "claimed_dims", "forced_dims", "verdict"])
        w.writeheader()
        w.writerows(rows)
    import pandas as pd
    df = pd.DataFrame(rows)
    print("reuse-class in-scope reports:", len(df))
    print(pd.crosstab(df.label, df.verdict, margins=True))
    for lab in ("slop", "genuine", "invalid", "resolved"):
        sub = df[df.label == lab]
        if len(sub):
            print(f"{lab}: refuted {(sub.verdict=='refuted').mean():.1%} ({(sub.verdict=='refuted').sum()}/{len(sub)})")
    glost = df[(df.label == "genuine") & (df.verdict == "refuted")]
    print("\nGENUINE LOST (must be ~0):", len(glost))
    for _, r in glost.iterrows():
        print("  ", r.id, r.claimed_dims, "| forced:", r.forced_dims)


if __name__ == "__main__":
    main()
