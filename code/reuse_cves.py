"""Extract connection-reuse CVEs with their exact fix commit and the match function(s) the fix changed.

For each reuse-class CVE in vuln.json we read the GIT fixed commit, diff it against its parent, and record the
lib/*.c files and C function names whose bodies the fix touched (candidate match functions), plus a dimension
guess from the summary. This feeds the differential oracle: refutation should flip from not-refuted (parent) to
refuted (fix) for the CVE's dimension at the changed matcher.
Runs in WSL (needs git). Writes results/reuse_cves.json.
"""
import json, os, re, subprocess, sys

ROOT = "/mnt/c/research_notes/Grounded slop"
REPO = os.path.expanduser("~/gslop/curl")
REUSE = re.compile(r"reuse|re-use|mixup|mix-up|wrong connection|connection.*(reuse|match)|"
                   r"different (host|credential|user|interface|service)|too eager|not[- ]checked", re.I)
DIMS = [("interface", r"interface|local (ip|address)|bindlocal|source"),
        ("credentials", r"credential|user|password|netrc|ntlm|oauth|bearer|negotiate|gss|sasl|auth"),
        ("tls", r"\bTLS\b|\bSSL\b|certificate|client[- ]cert|CA |OCSP|session|cipher|mTLS|verif"),
        ("service", r"service|STARTTLS|protocol|SMB|FTP|SSH|scheme"),
        ("host", r"host|proxy|origin|IPv6|destination|cross-origin")]


def git(*a):
    return subprocess.run(["git", "-C", REPO, *a], capture_output=True, text=True, errors="replace").stdout


def changed_funcs(commit):
    """lib functions the commit changed, plus the struct fields it newly compares/copies in match/clone code.
    fix_fields are the record fields the fix adds to the reuse/match key (what the method should now force equal)."""
    diff = git("show", "--unified=3", "--no-color", commit, "--", "lib/*.c")
    files, funcs, fields = set(), set(), set()
    for line in diff.split("\n"):
        if line.startswith("+++ b/"):
            cf = line[6:]
            if cf.endswith(".c"):
                files.add(cf)
        m = re.search(r"@@.*@@\s*(?:static\s+|UNITTEST\s+)?[\w \*]+?\b(\w+)\s*\(", line)
        if m:
            funcs.add(m.group(1))
        if line.startswith("+") and not line.startswith("+++"):
            body = line[1:]
            # fields newly used in a comparison / match helper on an added line = fields added to the reuse key
            if re.search(r"(==|!=|strcase|strcmp|strequal|safecmp|blobcmp|Curl_timestrcmp|match|same)", body):
                for fm in re.finditer(r"(?:->|\.)\s*([A-Za-z_]\w{2,})", body):
                    f = fm.group(1)
                    if f not in ("next", "prev", "data", "conn", "head", "size", "len", "needle", "set", "state"):
                        fields.add(f)
    return sorted(files), sorted(funcs), sorted(fields)


def dim_of(text):
    t = text.lower()
    return [d for d, pat in DIMS if re.search(pat, text, re.I)]


def main():
    d = json.load(open(os.path.join(ROOT, "data", "raw", "vuln.json")))
    out = []
    for v in d:
        s = v.get("summary", "") + " " + v.get("details", "")
        if not REUSE.search(s):
            continue
        cve = v["aliases"][0] if v.get("aliases") else v["id"]
        aff = v["affected"][0]["ranges"]
        git_fixed = [e["fixed"] for r in aff if r["type"] == "GIT" for e in r["events"] if "fixed" in e]
        sem = [r for r in aff if r["type"] == "SEMVER"]
        fixed_v = [e["fixed"] for r in sem for e in r["events"] if "fixed" in e]
        rec = {"cve": cve, "summary": v.get("summary", ""), "cwe": v["database_specific"].get("CWE", {}).get("id", ""),
               "git_fixed": git_fixed, "fixed_versions": fixed_v, "dims": dim_of(s),
               "h1": v["database_specific"].get("issue", "")}
        if git_fixed:
            commit = git_fixed[0]
            if git("cat-file", "-t", commit).strip() == "commit":
                files, funcs, fields = changed_funcs(commit)
                rec["files"], rec["funcs"], rec["fix_fields"] = files, funcs, fields
                rec["parent"] = git("rev-parse", commit + "^").strip()
        out.append(rec)
    json.dump(out, open(os.path.join(ROOT, "results", "reuse_cves.json"), "w"), indent=1)
    done = [r for r in out if r.get("funcs")]
    print("reuse CVEs:", len(out), "with fix-commit funcs:", len(done))
    for r in done:
        print(r["cve"], r["dims"], "| funcs:", ",".join(r["funcs"][:6]), "| files:", ",".join(os.path.basename(f) for f in r.get("files", [])[:4]))


if __name__ == "__main__":
    main()
