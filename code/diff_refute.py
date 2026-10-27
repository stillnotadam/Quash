"""Driver: run a refutation query against one function in one or more GIMPLE-SSA dumps.

A claim spec (JSON) names the function, a sink (by source line, or by a stmt-text regex), the length/size SSA
variable the report says reaches the sink (matched by name prefix, e.g. "len" or "hostname_len"), and the cap the
report claims can be exceeded. We report only the verdict (refuted / cannot_refute) and the guard count that forms
the unsat core. No witness is ever produced.

Usage: python diff_refute.py <claim.json> <dump1.ssa> [dump2.ssa ...]
claim.json: {"func":"suboption","sink_line":1030,"len_prefix":"len","cap":2048,"op":">"}
"""
import json, re, sys
from gimple_parse import parse
from claim_encode import Encoder, IDENT


def find_sink_bb(fn, spec):
    for bid, b in fn["blocks"].items():
        for s in b["stmts"]:
            if "sink_line" in spec and s["loc"] and s["loc"][1] == spec["sink_line"]:
                return bid
            if "sink_re" in spec and re.search(spec["sink_re"], s["text"]):
                return bid
    return None


def pick_var(fn, prefix, near_bb):
    """SSA name with the given prefix that is used at or before the sink; prefer the one in the sink block."""
    cands = set()
    for b in fn["blocks"].values():
        for s in b["stmts"]:
            cands.update(re.findall(rf"\b({re.escape(prefix)}\w*_\d+|{re.escape(prefix)}_\d+)\b", s["text"]))
        if b["cond"]:
            cands.update(re.findall(rf"\b({re.escape(prefix)}\w*_\d+)\b", b["cond"]["expr"]))
    return sorted(cands)[0] if cands else None


def main():
    spec = json.load(open(sys.argv[1], encoding="utf-8"))
    for dump in sys.argv[2:]:
        fns = parse(dump)
        fn = fns.get(spec["func"])
        tag = re.search(r"(\d+\.\d+\.\d+)", dump)
        tag = tag.group(1) if tag else dump
        if not fn:
            print(f"{tag}: function {spec['func']} not found")
            continue
        sink = find_sink_bb(fn, spec)
        if sink is None:
            print(f"{tag}: sink not found")
            continue
        var = spec.get("len_var") or pick_var(fn, spec["len_prefix"], sink)
        enc = Encoder(fn)
        verdict, npaths, nunsat = enc.refute(sink, [(var, spec.get("op", ">"), spec["cap"])])
        print(f"{tag}: func={spec['func']} sink_bb={sink} claimvar={var} "
              f"claim=({var} {spec.get('op','>')} {spec['cap']}) -> {verdict} "
              f"[paths={npaths} unsat={nunsat}]")


if __name__ == "__main__":
    main()
