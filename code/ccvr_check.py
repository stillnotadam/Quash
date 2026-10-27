"""Reference checker for Claim-Carrying Vulnerability Reports (CCVR).

Input: a claim-carrying report (JSON per paper/claim_schema.json).
Output: a disposition with a machine-checkable certificate:
  REFUTED   the claim's predicate is impossible against the program; certificate = the guards/fields that force it.
  ESCALATE  cannot refute (the claim names an unenforced path, as a genuine bug does, or is out of the fragment).
  CONFIRMED only if a witness is carried AND a witness-runner is enabled (disabled here: we never run inputs).
  ERROR     the claimed function/version could not be analyzed.

This is the engine the paper proposes: pointed at a carried, field-precise claim, refutation is sound (Section 5),
so the checker never rejects a genuine report whose claim names an unenforced path. It emits verdicts and
certificates only; it never synthesizes an input.

Usage: python ccvr_check.py <claim.json> [--gimple-dir DIR]
Equality/reuse and reachability claims run on existing GIMPLE dumps / call graphs for the curl releases in the
artifact. Bounds claims reuse the Z3 path-condition encoder.
"""
import glob, json, os, re, sys
from gimple_parse import parse
from refute_reuse import ReuseEncoder
from refute_chain import DIM_FIELDS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GD = os.path.join(ROOT, "results", "gimple")


def find_dump(func, version):
    """Find a GIMPLE dump for <version> that defines <func>. Returns (path, fnobj) or (None, None)."""
    for p in glob.glob(os.path.join(GD, f"{version}-gimple_*.ssa")):
        try:
            fns = parse(p)
        except Exception:
            continue
        if func in fns:
            return p, fns[func]
    return None, None


def expand_fields(dimension_fields):
    """Map claim dimension_fields (names or dimension words) to the field tokens the checker matches on."""
    out = set()
    for f in dimension_fields:
        if f in DIM_FIELDS:
            out.update(DIM_FIELDS[f])
        else:
            out.add(f)
    return out


def check_equality_reuse(claim):
    func = claim["location"]["function"]
    ver = claim["target"]["version"]
    path, fn = find_dump(func, ver)
    if not fn:
        return {"disposition": "ERROR", "reason": f"no GIMPLE for {func}@{ver} in artifact"}
    forced, npaths = ReuseEncoder(fn).forced_fields()
    forced = {f for f in forced if f}
    want = claim["claim"].get("dimension_fields", [])

    def enforced_by(item):
        toks = DIM_FIELDS.get(item, [item])  # a dimension word expands to representatives; a field name is itself
        return sorted(p for p in forced if any(t.lower() in p.lower() for t in toks))
    hit = {w: enforced_by(w) for w in want}
    if want and all(hit[w] for w in want):
        cert = ReuseEncoder(fn).refute_certificate(want)
        return {"disposition": "REFUTED",
                "certificate": {"kind": "reuse-key-equality", "function": func, "version": ver,
                                "success_paths": npaths, "enforced_fields": {w: hit[w] for w in want},
                                "smt2": cert.get("smt2", []), "enforced_by": cert.get("enforced_by"),
                                "statement": f"{func} forces equality of {want} (via {sorted({p for w in want for p in hit[w]})}) "
                                             f"on all {npaths} match-success paths, so reuse across them cannot occur."}}
    return {"disposition": "ESCALATE",
            "reason": "a claimed field is not unconditionally forced on the match-success path "
                      "(an unenforced field is exactly where a real reuse bug lives); human triage required.",
            "forced_fields_sample": sorted(forced)[:20], "unenforced_claimed": [w for w in want if not hit[w]]}


def check_bounds(claim):
    try:
        from claim_encode import Encoder
    except Exception as e:
        return {"disposition": "ERROR", "reason": f"bounds encoder unavailable: {e}"}
    func = claim["location"]["function"]
    ver = claim["target"]["version"]
    path, fn = find_dump(func, ver)
    if not fn:
        return {"disposition": "ERROR", "reason": f"no GIMPLE for {func}@{ver}"}
    p = claim["claim"].get("predicate_bound")  # {"var":..,"op":">","cap":..,"sink_line":..}
    if not p:
        return {"disposition": "ESCALATE", "reason": "bounds claim lacks a (var,op,cap,sink) predicate"}
    enc = Encoder(fn)
    sink = None
    for bid, b in fn["blocks"].items():
        for s in b["stmts"]:
            if s["loc"] and s["loc"][1] == p.get("sink_line"):
                sink = bid
    if sink is None:
        return {"disposition": "ESCALATE", "reason": "sink line not found in function"}
    cert = enc.refute_certificate(sink, [(p["var"], p.get("op", ">"), p["cap"])])
    if cert.get("verdict") == "refuted":
        return {"disposition": "REFUTED",
                "certificate": {"kind": "spatial-bound", "function": func, "version": ver,
                                "smt2": cert["smt2"], "guards": cert["guards"],
                                "statement": f"on all {cert['n_paths']} paths to the sink, the guards force "
                                             f"NOT({p['var']} {p.get('op','>')} {p['cap']})."}}
    return {"disposition": "ESCALATE", "reason": "the bound is not forced on all paths to the sink"}


def independently_verify(smt2_scripts):
    """Re-check each SMT-LIB proof obligation in a FRESH solver context (no trust in our encoder). Returns
    'verified-unsat' only if every script parses and is UNSAT."""
    try:
        import z3
    except Exception:
        return "z3-unavailable"
    for script in smt2_scripts:
        try:
            s = z3.Solver()
            s.add(z3.parse_smt2_string(script))
            if s.check() != z3.unsat:
                return "FAILED"
        except Exception as e:
            return f"parse-error:{e}"
    return "verified-unsat" if smt2_scripts else "no-proof"


def main():
    claim = json.load(open(sys.argv[1], encoding="utf-8"))
    fam = claim["claim"]["family"]
    if claim.get("witness"):
        # we deliberately do not run carried witnesses in this reference checker (no input execution).
        pass
    if fam == "equality_reuse":
        res = check_equality_reuse(claim)
    elif fam == "bounds":
        res = check_bounds(claim)
    else:
        res = {"disposition": "ESCALATE", "reason": f"family '{fam}' not in the decidable fragment"}
    res["claim_id"] = claim.get("id", os.path.basename(sys.argv[1]))
    if res.get("disposition") == "REFUTED":
        res["independent_verification"] = independently_verify(res.get("certificate", {}).get("smt2", []))
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
