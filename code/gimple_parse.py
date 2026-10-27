"""Parse a GCC GIMPLE-SSA dump into per-function CFGs of typed SSA statements.

This is a program-analysis front end for refutation-based triage. It reads the *.NNNt.ssa dump GCC emits with
-fdump-tree-ssa-lineno and turns each function into basic blocks, SSA assignments, phi nodes, branch guards and
calls, each tagged with its source location (file:line:col). Downstream code (claim_encode.py) walks a path to a
named sink and builds the Z3 path condition; nothing here constructs inputs or reasons about exploitation.

We deliberately keep this at the level of guards and integer/size relations: the claims we refute are of the form
"size relation R can hold at sink S" (e.g. a length can exceed a fixed buffer). We never synthesize bytes.
"""
import re, sys, json
from collections import OrderedDict

FUNC_RE = re.compile(r";; Function (\S+) \(")
SIG_RE = re.compile(r"^[A-Za-z_].*\b([A-Za-z_]\w*) \(")
BB_RE = re.compile(r"^\s*<bb (\d+)> ?:")
LABEL_RE = re.compile(r"^\s*(?:\[[^\]]*\]\s*)?<(L\d+)>:")
LOC = re.compile(r"\[([^\]\[]+?):(\d+):(\d+)\]")
GOTO = re.compile(r"goto <bb (\d+)>")
IFLINE = re.compile(r"\bif \((.+)\)\s*$")
SWITCH = re.compile(r"\bswitch \((.+?)\) <(.+)>")


def strip_loc(s):
    return LOC.sub("", s).strip()


def first_loc(s):
    m = LOC.search(s)
    return (m.group(1), int(m.group(2)), int(m.group(3))) if m else None


def parse(path):
    funcs = OrderedDict()
    cur = None
    name = None
    pending_label = None
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().split("\n")
    i = 0
    while i < len(lines):
        raw = lines[i]
        m = FUNC_RE.search(raw)
        if m:
            name = m.group(1)
            # the C signature line follows after the ;; Function header block
            cur = {"name": name, "params": [], "decls": [], "blocks": OrderedDict(), "sig": ""}
            funcs[name] = cur
            # find signature line (next non-;; line starting at col 0 with the name and a paren)
            j = i + 1
            while j < len(lines) and (lines[j].startswith(";;") or lines[j].strip() == ""):
                j += 1
            if j < len(lines):
                cur["sig"] = lines[j].strip()
            i = j + 1
            continue
        if cur is None:
            i += 1
            continue
        bbm = BB_RE.match(raw)
        if bbm:
            bid = int(bbm.group(1))
            cur["blocks"][bid] = {"id": bid, "labels": [], "stmts": [], "succ": [], "cond": None, "switch": None}
            curbb = cur["blocks"][bid]
            if pending_label:
                curbb["labels"].append(pending_label)
                pending_label = None
            i += 1
            # consume block body until blank line or next bb/function
            while i < len(lines):
                s = lines[i]
                if BB_RE.match(s) or FUNC_RE.search(s) or s.startswith(";; Function"):
                    break
                t = s.strip()
                if t == "":
                    i += 1
                    continue
                lm = LABEL_RE.match(s)
                if lm:
                    curbb["labels"].append(lm.group(1))
                    i += 1
                    continue
                ifm = IFLINE.search(t)
                if ifm:
                    curbb["cond"] = {"expr": strip_loc(ifm.group(1)), "loc": first_loc(s)}
                    # next two gotos are true/false targets
                    tgs = []
                    j = i + 1
                    while j < len(lines) and len(tgs) < 2:
                        g = GOTO.search(lines[j])
                        if g:
                            tgs.append(int(g.group(1)))
                        if lines[j].strip().startswith("else") or g:
                            j += 1
                            continue
                        break
                    curbb["cond"]["true"], curbb["cond"]["false"] = (tgs + [None, None])[:2]
                    i = j
                    continue
                swm = SWITCH.search(t)
                if swm:
                    cases = re.findall(r"(?:case (\d+)|default): <(L\d+)>", swm.group(2))
                    curbb["switch"] = {"expr": strip_loc(swm.group(1)),
                                       "cases": [(c, l) for c, l in cases]}
                    i += 1
                    continue
                gm = GOTO.search(t)
                if gm and "if" not in t:
                    curbb["succ"].append(int(gm.group(1)))
                    i += 1
                    continue
                curbb["stmts"].append({"text": strip_loc(t), "loc": first_loc(s)})
                i += 1
            continue
        i += 1
    # resolve label targets to bb ids and fallthrough successors
    label_to_bb = {}
    for b in cur_iter(funcs):
        for lab in b["labels"]:
            label_to_bb[lab] = b["id"]
    for fn in funcs.values():
        bbs = list(fn["blocks"].values())
        for k, b in enumerate(bbs):
            succ = set(b["succ"])
            if b["cond"]:
                for key in ("true", "false"):
                    if b["cond"][key] is not None:
                        succ.add(b["cond"][key])
            if b["switch"]:
                for _, lab in b["switch"]["cases"]:
                    if lab in label_to_bb:
                        succ.add(label_to_bb[lab])
            if not succ and not b["switch"] and not b["cond"] and k + 1 < len(bbs):
                succ.add(bbs[k + 1]["id"])  # fallthrough
            b["succ"] = sorted(succ)
    return funcs


def cur_iter(funcs):
    for fn in funcs.values():
        for b in fn["blocks"].values():
            yield b


if __name__ == "__main__":
    fs = parse(sys.argv[1])
    out = {n: {"sig": f["sig"], "nblocks": len(f["blocks"]),
               "nstmts": sum(len(b["stmts"]) for b in f["blocks"].values())} for n, f in fs.items()}
    if len(sys.argv) > 2:
        json.dump({n: fs[n] for n in sys.argv[2:] if n in fs}, open("gimple_fn.json", "w"), indent=1, default=str)
    print(json.dumps(out, indent=1))
