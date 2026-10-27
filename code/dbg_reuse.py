"""Debug a missed differential flip: show the matcher's two-record detection, success paths, forced ties, and the
refute2 verdict for a given field, on the fix build. Usage: dbg_reuse.py <cve> <func> <field>"""
import json, os, subprocess, sys
from gimple_parse import parse
from refute_reuse import ReuseEncoder

ROOT = "/mnt/c/research_notes/Grounded slop"
cve, func, field = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(os.path.join(ROOT, "results", "reuse_cves.json")))
r = [x for x in d if x["cve"] == cve][0]
fixc = r["git_fixed"][0]
file = [f for f in r["files"] if "url.c" in f or "vtls_config" in f or "creds" in f or f == "lib/vtls.c"][0]
tag = "DBG"
subprocess.run(["bash", os.path.join(ROOT, "code", "wsl_gimple_commit.sh"), fixc, file, "8.23.0", tag],
               capture_output=True, text=True)
# try era builds if 8.23 failed
p = os.path.join(ROOT, "results", "gimple_diff", f"{tag}.023t.ssa")
if not os.path.exists(p):
    for bv in ["8.16.0", "8.20.0", "8.14.1", "8.22.0", "8.21.0", "7.83.1"]:
        subprocess.run(["bash", os.path.join(ROOT, "code", "wsl_gimple_commit.sh"), fixc, file, bv, tag],
                       capture_output=True, text=True)
        if os.path.exists(p):
            break
fns = parse(p)
print("file", file, "funcs with field:", [f for f in fns if func in f])
fn = fns.get(func)
if not fn:
    print("function not in dump; matcher funcs:", [f for f in fns if "match" in f.lower() or "same" in f.lower()][:20])
    sys.exit()
enc = ReuseEncoder(fn)
enc.analyze_calls()
print("records:", enc.records)
print("eqcalls:", {k: (v[0], v[1], v[2]) for k, v in list(enc.eqcalls.items())[:12]})
ret_ssa, phi = enc.phi_sources()
print("ret_ssa", ret_ssa, "phi", phi)
print("field-load terms containing", field, ":", [(rec, path) for (rec, path) in
      [enc.resolve(s) or ("", "") for s in enc.assign] if field in path][:10])
# scan assign for the field
for ssa, rhs in enc.assign.items():
    if field in rhs:
        print("  assign", ssa, "=", rhs[:80])
print("refute2:", enc.refute2([field]))
