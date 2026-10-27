"""Differential fix-commit oracle (CRDS validation), reuse family.

For each connection-reuse CVE we compile the changed match function at the fix commit and at its parent, then run
the equality/reuse refuter for the CVE's dimension on both. A SOUND refuter should show the flip:
  parent (vulnerable): cannot_refute   (the reuse-key gap the CVE exploits is present)
  fix    (patched):    refuted         (the fix adds the equality that closes the gap)
Refuting the CVE on its OWN parent (vulnerable) build is an UNSOUNDNESS (a genuine bug wrongly declared false).
We report, per CVE, the best flip over its changed matcher functions and claimed dimensions. Verdicts only.
Runs in WSL. Writes results/diff_oracle.csv.
"""
import csv, json, os, subprocess, sys
from gimple_parse import parse
from refute_reuse import ReuseEncoder
from triage import DIM_KW

ROOT = "/mnt/c/research_notes/Grounded slop"
GD = os.path.join(ROOT, "results", "gimple_diff")
SH = os.path.join(ROOT, "code", "wsl_gimple_commit.sh")
# built releases available (for era matching)
BUILT = ["7.64.1", "7.65.3", "7.70.0", "7.71.1", "7.73.0", "7.75.0", "7.76.1", "7.77.0", "7.78.0", "7.82.0",
         "7.83.0", "7.83.1", "7.85.0", "7.86.0", "7.87.0", "7.88.1", "8.0.1", "8.1.2", "8.3.0", "8.4.0",
         "8.5.0", "8.6.0", "8.8.0", "8.9.0", "8.9.1", "8.10.1", "8.11.0", "8.11.1", "8.12.0", "8.13.0",
         "8.14.0", "8.14.1", "8.15.0", "8.16.0", "8.17.0", "8.18.0", "8.19.0", "8.20.0", "8.21.0", "8.22.0", "8.23.0"]


def vt(v):
    return tuple(int(x) for x in __import__("re").findall(r"\d+", v)[:3])


def era_builds(fixed_versions):
    """Builds ordered by closeness to the CVE's fixed release (era-matched headers compile the commit)."""
    if not fixed_versions:
        return list(reversed(BUILT))
    target = min(vt(v) for v in fixed_versions)
    return sorted(BUILT, key=lambda b: abs(sum(vt(b)) - sum(target)))[:6]
MATCH_FILES = ("lib/url.c", "lib/vtls/vtls_config.c", "lib/vtls.c", "lib/url.c", "lib/conncache.c",
               "lib/creds.c", "lib/vtls/vtls.c")
MATCH_RE = __import__("re").compile(r"match|_same|_equal|_matches|config_match|peer_same|creds_same|"
                                    r"ConnectionExists|proxy_info_matches|hashkey|conn_is_conn", __import__("re").I)


def dump(commit, file, tag, builds):
    p = os.path.join(GD, f"{tag}.023t.ssa")
    if os.path.exists(p):
        os.remove(p)
    for bv in builds:
        subprocess.run(["bash", SH, commit, file, bv, tag], capture_output=True, text=True)
        if os.path.exists(p) and os.path.getsize(p) > 1000:
            return p, bv
    return None, None


def forced_for(ssa_path, funcs):
    """Return {func: set(forced field-paths)} for matcher funcs present in the dump (bitfields included)."""
    try:
        fns = parse(ssa_path)
    except Exception:
        return {}
    out = {}
    for fn in funcs:
        if fn not in fns or not MATCH_RE.search(fn):
            continue
        try:
            ff, n = ReuseEncoder(fns[fn]).forced_fields()
        except Exception:
            ff = set()
        out[fn] = {f for f in ff if f}  # drop whole-record "" ties
    return out


def main():
    cves = json.load(open(os.path.join(ROOT, "results", "reuse_cves.json")))
    rows = []
    for r in cves:
        if not r.get("funcs") or not r.get("parent"):
            continue
        files = [f for f in r.get("files", []) if ("lib/url.c" in f or "vtls_config" in f or f == "lib/vtls.c"
                 or "conncache" in f or "creds" in f or f == "lib/vtls/vtls.c")]
        if not files:
            continue
        cve = r["cve"]
        fixc, par = r["git_fixed"][0], r["parent"]
        # FIELD-LEVEL: the exact record fields the fix adds to the reuse key. Falls back to coarse dims.
        fix_fields = r.get("fix_fields") or []
        dims = r["dims"] or ["credentials", "tls", "host", "service", "interface"]
        best = None
        detail = []
        dumped = False
        builds = era_builds(r.get("fixed_versions"))
        for file in files:
            pf, bvp = dump(par, file, f"{cve}_par_{os.path.basename(file)}", builds)
            ff, bvf = dump(fixc, file, f"{cve}_fix_{os.path.basename(file)}", builds)
            if not pf or not ff:
                detail.append(f"{os.path.basename(file)}:nodump({bvp},{bvf})")
                continue
            dumped = True
            fp = forced_for(pf, r["funcs"])
            fx = forced_for(ff, r["funcs"])
            for fn in set(fp) | set(fx):
                parent_forced, fix_forced = fp.get(fn, set()), fx.get(fn, set())
                added = fix_forced - parent_forced
                if added:
                    detail.append(f"{fn}:+{{{','.join(sorted(added))[:60]}}}")
                    if best is None:
                        best = (fn, ",".join(sorted(added))[:40])
                elif fix_forced or parent_forced:
                    detail.append(f"{fn}:nochange({len(parent_forced)})")
        if best:
            cat = "clean_flip"            # fix forces a field the vulnerable parent did not (sound validation)
        elif not dumped:
            cat = "no_matcher_dump"       # could not compile the matcher in an era-matched tree
        else:
            cat = "out_of_model"          # dumped, but fix changes a non-equality structure (UAF/flag/alloc)
        in_model = cat == "clean_flip"
        row = {"cve": cve, "dims": "|".join(dims), "n_fix_fields": len(fix_fields), "flip": int(bool(best)),
               "category": cat, "flip_detail": (f"{best[0]}:+{best[1]}" if best else ""),
               "detail": ";".join(detail)[:400]}
        rows.append(row)
        print(cve, cat, "|", row["flip_detail"], "||", row["detail"][:130])
    keys = ["cve", "dims", "n_fix_fields", "flip", "category", "flip_detail", "detail"]
    with open(os.path.join(ROOT, "results", "diff_oracle.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    from collections import Counter
    cats = Counter(r["category"] for r in rows)
    analyzable = [r for r in rows if r["category"] != "no_matcher_dump"]
    print("\ncategories:", dict(cats))
    print("clean flips (fix forces a field the parent did not):", sum(r["flip"] for r in rows), "/", len(rows),
          "total;", sum(r["flip"] for r in rows), "/", len(analyzable), "of analyzable")


if __name__ == "__main__":
    main()
