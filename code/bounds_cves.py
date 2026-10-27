"""Extract spatial-overflow CVEs whose fix adds an explicit length/bounds guard, for the bounds differential oracle.

From each fix diff we pull an ADDED guard of the form `if(VAR </<=/>/>= CAP)` (CAP numeric or sizeof(...)) that
the fix introduces, plus the changed function and file. The bounds oracle then checks, at the function, whether
"VAR exceeds CAP" is satisfiable: parent (no guard) cannot_refute, fix (guard added) refuted. Verdict-only.
Runs in WSL. Writes results/bounds_cves.json.
"""
import json, os, re, subprocess

ROOT = "/mnt/c/research_notes/Grounded slop"
REPO = os.path.expanduser("~/gslop/curl")
SPATIAL = ("CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-126", "CWE-787", "CWE-190", "CWE-191", "CWE-193", "CWE-131")
GUARD = re.compile(r"\bif\s*\(\s*!?\(?\s*([A-Za-z_][\w.\->\[\]]*)\s*(<=|>=|<|>)\s*([A-Za-z_0-9][\w.\->\(\) ]*?)\s*\)?\s*\)")


def git(*a):
    return subprocess.run(["git", "-C", REPO, *a], capture_output=True, text=True, errors="replace").stdout


def main():
    d = json.load(open(os.path.join(ROOT, "data", "raw", "vuln.json")))
    out = []
    for v in d:
        cwe = v["database_specific"].get("CWE", {}).get("id", "")
        s = (v.get("summary", "") + " " + v.get("details", "")).lower()
        if cwe not in SPATIAL and not re.search(r"overflow|out of bounds|out-of-bounds|over-?read|buffer", s):
            continue
        cve = v["aliases"][0] if v.get("aliases") else v["id"]
        aff = v["affected"][0]["ranges"]
        gitf = [e["fixed"] for r in aff if r["type"] == "GIT" for e in r["events"] if "fixed" in e]
        semf = [e["fixed"] for r in aff if r["type"] == "SEMVER" for e in r["events"] if "fixed" in e]
        rec = {"cve": cve, "cwe": cwe, "summary": v.get("summary", ""), "git_fixed": gitf, "fixed_versions": semf}
        if gitf and git("cat-file", "-t", gitf[0]).strip() == "commit":
            commit = gitf[0]
            rec["parent"] = git("rev-parse", commit + "^").strip()
            diff = git("show", "--unified=2", "--no-color", commit, "--", "lib/*.c")
            files, funcs, guards = set(), set(), []
            for line in diff.split("\n"):
                if line.startswith("+++ b/") and line.endswith(".c"):
                    files.add(line[6:])
                m = re.search(r"@@.*@@\s*(?:static\s+|UNITTEST\s+)?[\w \*]+?\b(\w+)\s*\(", line)
                if m:
                    funcs.add(m.group(1))
                if line.startswith("+") and not line.startswith("+++"):
                    for gm in GUARD.finditer(line):
                        var, op, cap = gm.group(1), gm.group(2), gm.group(3).strip()
                        # keep guards whose cap is numeric or sizeof(...) (a real bound)
                        if re.fullmatch(r"\d+", cap) or "sizeof" in cap or re.fullmatch(r"[A-Z_][A-Z0-9_]+", cap):
                            guards.append({"var": var, "op": op, "cap": cap})
            rec["files"], rec["funcs"], rec["guards"] = sorted(files), sorted(funcs), guards
        out.append(rec)
    json.dump(out, open(os.path.join(ROOT, "results", "bounds_cves.json"), "w"), indent=1)
    withg = [r for r in out if r.get("guards")]
    print("spatial CVEs:", len(out), "with extractable added guard:", len(withg))
    for r in withg[:30]:
        print(r["cve"], r["cwe"], "|", ",".join(f"{g['var']}{g['op']}{g['cap']}" for g in r["guards"][:3]),
              "| funcs:", ",".join(r["funcs"][:3]))


if __name__ == "__main__":
    main()
