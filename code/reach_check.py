"""Reachability verdict for each report, against the call graph of the curl release current when it was filed.

For every claim-scoped citation (cite_extract.extract(scoped=True)):
  path classes   product (lib/, src/, include/) or non-product (tests/, docs/, packages/, projects/, scripts/ ...)
  function       typed-reachable from the public API or tool main, defined-but-unreachable, not compiled in the
                 evaluation build (then: platform-gated or backend-gated by the file it lives in), or not found
Report verdict (first match wins):
  reachable      some cited product function is reachable
  gated_backend  cited code lives only in TLS/HTTP2/SSH/QUIC/zlib backends absent from the eval build: abstain
  gated_platform cited code compiles only on niche platforms (AmigaOS, OS/400, VMS, MS-DOS, Windows-only)
  unreachable    cites product functions that are compiled but unreachable from any entry point
  non_product    every cited path is outside the shipped product and no product function is cited
  no_target      nothing locatable is cited: abstain
Optional line-level coverage (8.23.0 only): fraction of cited product lines executed by curl's test suite.
Runs in WSL. Usage: reach_check.py <repo> <reports_dir> <index.csv> <cg_dir> <out.csv> [--release-col release]
"""
import csv, json, os, re, subprocess, sys
from collections import defaultdict
from cite_extract import extract

PRODUCT = re.compile(r"^(lib|src|include)/")
PLATFORM = re.compile(r"amiga|os400|vms|msdos|win32|windows|schannel|sectransp|sspi|riscos|plan9|vxworks|symbian|"
                      r"netware|nwlib|nwos|macos|apple|cygwin|mingw|watt|lwip|wince|ldap\.c$|setup-os400|ccsidcurl", re.I)
BACKEND = re.compile(r"(^|/)(vtls|vssh|vquic|vauth)/|http2\.c|content_encoding\.c|ws\.c|cf-h2-proxy|curl_ntlm|"
                     r"openldap|socks_gssapi|socks_sspi|krb5|gsasl|psl\.c|idn\.c|curl_rtmp|hsts\.c", re.I)

REPO = None
_DBG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "debug_only_funcs.json")
DEBUG_ONLY = set(json.load(open(_DBG))) if os.path.exists(_DBG) else set()


def git(*a):
    return subprocess.run(["git", "-C", REPO, *a], capture_output=True).stdout.decode("utf-8", errors="replace")


def tag_of(v):
    return "curl-" + v.replace(".", "_")


_defs = {}


def def_files(tag, name):
    """Files at <tag> that contain a definition-shaped line for function <name>."""
    k = (tag, name)
    if k not in _defs:
        out = git("grep", "-l", "-E", rf"^[A-Za-z_].*[^A-Za-z0-9_]\*?{re.escape(name)}\s*\(|^{re.escape(name)}\s*\(", tag, "--", "*.c")
        _defs[k] = [l.split(":", 1)[1] for l in out.split("\n") if ":" in l]
    return _defs[k]


_graphs = {}


def graph(cg_dir, v):
    if v not in _graphs:
        p = os.path.join(cg_dir, f"cg-{v}.json")
        if not os.path.exists(p):
            _graphs[v] = None
        else:
            r = json.load(open(p))
            by_name = defaultdict(set)
            files = set()
            r["nodes"] = {t: n for t, n in r["nodes"].items() if not n["name"].startswith("_sub_")}  # gcov ctors
            for t, n in r["nodes"].items():
                by_name[n["name"]].add(t)
                files.add(n["file"])
            _graphs.clear()
            _graphs[v] = {"by_name": by_name, "typed": set(r["reach_typed"]), "files": files,
                          "nodes": r["nodes"], "lines_cov": r.get("lines_cov", {}), "extents": r.get("func_extents", {})}
    return _graphs[v]


def classify(body, v, cg_dir):
    g = graph(cg_dir, v)
    if g is None:
        return {"verdict": "no_graph"}
    c = extract(body, scoped=True)
    tag = tag_of(v)
    paths = [p for p in c["paths"]]
    prod_paths = [p for p in paths if PRODUCT.match(p) or (p.startswith("*/") and p[2:] in g["files"])]
    # only explicit repo paths count as non-product evidence; an unknown bare name (poc_x.c) is not a claim
    nonprod_paths = [p for p in paths if p not in prod_paths and not p.startswith("*/")]
    fstat = {}
    cited_bases = {p.split("/")[-1] for p in paths}
    for f in c["funcs"]:
        if f in DEBUG_ONLY:
            fstat[f] = "debug_only"  # compiled only with --enable-debug; never in a shipped build
            continue
        if f in g["by_name"]:
            # same name may be defined in several files under different #ifdefs (Curl_ipv4_resolve_r lives in
            # both hostip4.c and amigaos.c). If the report points at a file whose copy is not compiled, judge that copy.
            node_files = {g["nodes"][t]["file"] for t in g["by_name"][f]}
            alt = [x for x in def_files(tag, f) if x.split("/")[-1] in cited_bases and x.split("/")[-1] not in node_files]
            if alt and not (cited_bases & node_files):
                x = alt[0]
                fstat[f] = ("nonproduct_def" if not PRODUCT.match(x) else "gated_backend" if BACKEND.search(x)
                            else "gated_platform" if PLATFORM.search(x) else "gated_other")
                continue
            fstat[f] = "reachable" if g["by_name"][f] & g["typed"] else "unreachable"
            continue
        files = def_files(tag, f)
        if not files:
            fstat[f] = "absent"  # not a function definition in this release (macro, variable, field, or invented)
            continue
        prod = [x for x in files if PRODUCT.match(x)]
        if not prod:
            fstat[f] = "nonproduct_def"
        elif any(BACKEND.search(x) for x in prod):
            fstat[f] = "gated_backend"
        elif any(PLATFORM.search(x) for x in prod):
            fstat[f] = "gated_platform"
        else:
            fstat[f] = "gated_other"  # compiled out by a feature #ifdef in the eval build
    # cited (file, line) pairs: judge the function whose body encloses that line
    starts = defaultdict(list)
    for t, n in g["nodes"].items():
        starts[n["file"]].append((n["line"], t))
    for p, a, b in c["lines"]:
        fn = p.split("/")[-1]
        if fn in starts and (PRODUCT.match(p) or p.startswith("*/")):
            cand = [x for x in sorted(starts[fn]) if x[0] <= a]
            if cand:
                t = cand[-1][1]
                fstat["#" + t] = "reachable" if t in g["typed"] else "unreachable"
    # files cited by path but with no cited function: judge the file itself
    for p in prod_paths:
        b = p.split("/")[-1]
        if b.endswith(".c") and b not in g["files"]:
            fstat["@" + p] = "gated_backend" if BACKEND.search(p) else ("gated_platform" if PLATFORM.search(p) else "gated_other")
    vals = set(fstat.values())
    if "reachable" in vals:
        verdict = "reachable"
    elif "gated_backend" in vals:
        verdict = "gated_backend"
    elif "gated_platform" in vals:
        verdict = "gated_platform"
    elif "unreachable" in vals or "gated_other" in vals or "debug_only" in vals:
        verdict = "unreachable"
    elif nonprod_paths or "nonproduct_def" in vals:
        verdict = "non_product"
    else:
        verdict = "no_target"
    # line-level coverage of cited product lines, when coverage exists for this release
    cov_n = cov_hit = 0
    if g["lines_cov"]:
        for p, a, b in c["lines"]:
            fn = p.split("/")[-1]
            if fn in g["lines_cov"]:
                lc = g["lines_cov"][fn]
                for ln in range(a, min(b, a + 30) + 1):
                    if str(ln) in lc:
                        cov_n += 1
                        cov_hit += lc[str(ln)] > 0
    n_reach = sum(1 for x in fstat.values() if x == "reachable")
    return {"verdict": verdict, "n_funcs": len(fstat), "n_reach": n_reach,
            "frac_reach": round(n_reach / len(fstat), 3) if fstat else "",
            "n_prod_paths": len(prod_paths), "n_nonprod_paths": len(nonprod_paths),
            "cov_lines": cov_n, "cov_hit": cov_hit,
            "fstat": ";".join(f"{k}={v}" for k, v in sorted(fstat.items()))[:900]}


def main():
    global REPO
    REPO, rdir, idx, cg_dir, out = sys.argv[1:6]
    relcol = sys.argv[sys.argv.index("--release-col") + 1] if "--release-col" in sys.argv else "release"
    rows = list(csv.DictReader(open(idx, encoding="utf-8")))
    rows.sort(key=lambda r: r[relcol])
    res = []
    for r in rows:
        p = os.path.join(rdir, f"{r['id']}.json")
        d = json.load(open(p, encoding="utf-8"))
        body = d.get("vulnerability_information") or ""
        v = r[relcol] if os.path.exists(os.path.join(cg_dir, f"cg-{r[relcol]}.json")) else None
        out_r = {"id": r["id"], "release": r[relcol]}
        out_r.update(classify(body, v, cg_dir) if v else {"verdict": "no_graph"})
        res.append(out_r)
    keys = ["id", "release", "verdict", "n_funcs", "n_reach", "frac_reach", "n_prod_paths", "n_nonprod_paths",
            "cov_lines", "cov_hit", "fstat"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(res)
    from collections import Counter
    print(Counter(r["verdict"] for r in res))


if __name__ == "__main__":
    main()
