"""Corpus-scale evaluation of claim-carrying triage, head to head against prose triage.

For every connection-reuse-class report we form a claim two ways and run the reference checker:

  PROSE binding      : no carried location; refute iff every dimension the report mentions (high recall) is
                       enforced somewhere by the release's reuse-key chain (the best sound prose-only refuter).
  CLAIM-CARRYING     : bind to the decision-point function the report names (a url_match_*/match_*/ConnectionExists
                       entry, excluding leaf comparators like Curl_creds_same); refute iff the claimed dimensions
                       are forced by THAT function. This is what a submitter supplies in a claim-carrying report.

We report, per label, REFUTED / ESCALATE rates and, crucially, genuine-lost (genuine reports wrongly REFUTED) for
each binding. The thesis predicts claim-carrying drives genuine-lost to zero while still refuting slop. Every
authored claim is written to results/ccvr_claims/ so the mapping from report to claim can be audited. Verdict-only.
"""
import csv, glob, json, os, re
from collections import defaultdict
from gimple_parse import parse
from refute_reuse import ReuseEncoder
from refute_chain import forced_dims, DIM_FIELDS
from triage_chain import DIM_RE, report_dims

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GD = os.path.join(ROOT, "results", "gimple")
CLAIMDIR = os.path.join(ROOT, "results", "ccvr_claims")
os.makedirs(CLAIMDIR, exist_ok=True)

# decision-point matcher entries (bind here) vs leaf comparators (never the decision point)
ENTRY_RE = re.compile(r"(url_match_\w+|match_\w*config|ConnectionExists|\w+_cf_connect|cpool_|url_match_conn)", re.I)
LEAF_RE = re.compile(r"^(Curl_peer_same\w*|Curl_peer_equal|Curl_creds_same|blobcmp|Curl_safecmp|curl_strequal|"
                     r"Curl_timestrcmp|strcasecompare|Curl_ssl_config_matches|match_ssl_primary_config)$")
REUSE_RE = re.compile(r"reuse|re-use|mixup|mix-up|connection|reused|shared connection|too eager|wrong (connection|proxy|host)", re.I)

_dumps = {}


def rel_fns(rel):
    if rel not in _dumps:
        fns = {}
        for p in glob.glob(os.path.join(GD, f"{rel}-gimple_*.ssa")):
            try:
                fns.update(parse(p))
            except Exception:
                pass
        _dumps[rel] = fns
    return _dumps[rel]


def enforced_tokens(forced):
    return {p.lower() for p in forced if p}


def dim_enforced(dim, forced_lower):
    toks = DIM_FIELDS.get(dim, [dim])
    return any(any(t in p for t in toks) for p in forced_lower)


def load(p):
    return list(csv.DictReader(open(os.path.join(ROOT, p), encoding="utf-8")))


def main():
    from cite_extract import extract
    master = {r["id"]: r for r in load("data/master.csv")}
    claims = {c["id"]: c for c in load("results/claims.csv") if c["in_scope"] == "1" and c["family"] == "logic"}
    fd_cache = {}
    rows = []
    for rid, c in claims.items():
        d = json.load(open(os.path.join(ROOT, "data", "h1", f"{rid}.json"), encoding="utf-8"))
        body = (master[rid].get("title", "") + "\n" + (d.get("vulnerability_information") or ""))
        if not REUSE_RE.search(body):
            continue
        rel = c["release"]
        dims = report_dims(body)
        if not dims:
            continue
        fns = rel_fns(rel)
        # PROSE binding: chain forced dims
        if rel not in fd_cache:
            try:
                fd_cache[rel] = forced_dims(rel)[0]
            except Exception:
                fd_cache[rel] = set()
        prose_forced = fd_cache[rel]
        prose_ref = bool(dims) and dims.issubset(prose_forced)
        # CLAIM-CARRYING binding: decision-point functions the report names
        cited = extract(body, scoped=True)["funcs"]
        entries = [f for f in cited if ENTRY_RE.search(f) and not LEAF_RE.match(f) and f in fns]
        carried_forced_lower = set()
        bound = []
        for f in entries:
            try:
                ff, _ = ReuseEncoder(fns[f]).forced_fields()
                carried_forced_lower |= enforced_tokens(ff)
                bound.append(f)
            except Exception:
                pass
        if bound:
            carry_ref = all(dim_enforced(dm, carried_forced_lower) for dm in dims)
            carry_mode = "bound:" + ",".join(bound[:3])
        else:
            # no decision-point function carried: the checker cannot bind -> ESCALATE (sound)
            carry_ref = False
            carry_mode = "no-entry-cited"
        claim = {"id": rid, "label": master[rid]["label"], "target": {"version": rel},
                 "claimed_dims": sorted(dims), "carried_functions": bound,
                 "prose_disposition": "REFUTED" if prose_ref else "ESCALATE",
                 "claim_carrying_disposition": "REFUTED" if carry_ref else "ESCALATE", "carry_mode": carry_mode}
        json.dump(claim, open(os.path.join(CLAIMDIR, f"{rid}.json"), "w"), indent=1)
        rows.append(claim)
    with open(os.path.join(ROOT, "results", "ccvr_eval.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "label", "prose_disposition", "claim_carrying_disposition",
                                          "carry_mode", "claimed_dims", "carried_functions"])
        w.writeheader()
        for r in rows:
            w.writerow({"id": r["id"], "label": r["label"], "prose_disposition": r["prose_disposition"],
                        "claim_carrying_disposition": r["claim_carrying_disposition"], "carry_mode": r["carry_mode"],
                        "claimed_dims": "|".join(r["claimed_dims"]), "carried_functions": "|".join(r["carried_functions"])})
    import pandas as pd
    df = pd.DataFrame(rows)
    print("reuse-class reports evaluated:", len(df))
    for mode, col in [("PROSE", "prose_disposition"), ("CLAIM-CARRYING", "claim_carrying_disposition")]:
        print(f"\n=== {mode} ===")
        for lab in ("slop", "genuine", "invalid", "resolved"):
            sub = df[df.label == lab]
            if len(sub):
                r = (sub[col] == "REFUTED").sum()
                print(f"  {lab:9s}: REFUTED {r}/{len(sub)} ({r/len(sub):.0%})")
        gl = df[(df.label == "genuine") & (df[col] == "REFUTED")]
        print(f"  GENUINE LOST: {len(gl)}  {list(gl.id)}")


if __name__ == "__main__":
    main()
