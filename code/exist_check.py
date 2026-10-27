"""MINT-style existence grounding: do the paths, lines, functions and code a report cites exist in curl
at the revision the reporter was looking at?

Revision: the commit in a github.com/curl/curl/blob/<sha>/ permalink if the report has one, otherwise the last
master commit before the report's submission time.

Per report we emit counts of cited/missing entities and a snippet-fidelity score (fraction of substantive lines
in C code blocks that appear verbatim, modulo whitespace, somewhere in the tree). Runs in WSL (git + stdlib).
Usage: python3 exist_check.py <repo> <reports_dir> <reports.csv> <out.csv>   (reports.csv needs id, created)
"""
import csv, json, os, re, subprocess, sys
from cite_extract import extract

REPO = None


def git(*a, inp=None):
    return subprocess.run(["git", "-C", REPO, *a], capture_output=True, input=inp).stdout


_rev_cache = {}


def rev_before(ts):
    day = ts[:19]
    if day not in _rev_cache:
        _rev_cache[day] = git("rev-list", "-1", f"--before={day}Z", "origin/master").decode().strip() or \
            git("rev-list", "-1", f"--before={day}Z", "HEAD").decode().strip()
    return _rev_cache[day]


def valid_rev(r):
    return git("cat-file", "-t", r).decode().strip() == "commit"


_tree = {}


def tree(rev):
    """{path: text} for C sources and docs at rev, plus a set of normalized code lines."""
    if rev in _tree:
        return _tree[rev]
    names = git("ls-tree", "-r", "--name-only", rev).decode(errors="replace").split("\n")
    names = [n for n in names if n]
    want = [n for n in names if re.search(r"\.(c|h)$", n)]
    blob = git("cat-file", "--batch", inp="".join(f"{rev}:{n}\n" for n in want).encode())
    files, i = {}, 0
    for n in want:
        j = blob.index(b"\n", i)
        hdr = blob[i:j].split()
        size = int(hdr[2]) if len(hdr) == 3 else 0
        files[n] = blob[j + 1:j + 1 + size].decode("utf-8", errors="replace")
        i = j + 1 + size + 1
    norm = set()
    idents = set()
    for n, t in files.items():
        for line in t.split("\n"):
            s = re.sub(r"\s+", "", line)
            if len(s) >= 10:
                norm.add(s)
        idents.update(re.findall(r"[A-Za-z_]\w{2,}", t))
    bases = {}
    for n in names:
        bases.setdefault(os.path.basename(n), []).append(n)
    _tree.clear()  # keep memory bounded: one revision at a time (reports are processed in date order)
    _tree[rev] = (set(names), files, norm, idents, bases)
    return _tree[rev]


def nlines(rev, path, files):
    if path in files:
        return files[path].count("\n") + 1
    out = git("show", f"{rev}:{path}")
    return out.count(b"\n") + 1 if out else 0


TRIVIAL = re.compile(r"^[\s{}();,]*$|^\s*(//|/\*|\*|#include)")


def check(rid, body, created, scoped=False):
    c = extract(body, scoped=scoped)
    rev = None
    for ref, p, a, b in c["permalinks"]:
        if re.fullmatch(r"[0-9a-fA-F]{7,40}", ref) and valid_rev(ref):
            rev = ref
            break
    rev = rev or rev_before(created)
    names, files, norm, idents, bases = tree(rev)
    row = {"id": rid, "rev": rev[:12]}
    # paths
    miss_p = []
    for p in c["paths"]:
        if p.startswith("*/"):
            ok = p[2:] in bases
        else:
            ok = p in names
        if not ok:
            miss_p.append(p)
    # lines
    miss_l = []
    for p, a, b in c["lines"]:
        cand = bases.get(p[2:], []) if p.startswith("*/") else ([p] if p in names else [])
        if not cand or all(max(a, b) > nlines(rev, q, files) for q in cand):
            miss_l.append(f"{p}:{a}")
    # functions / identifiers
    miss_f = [f for f in c["funcs"] if f not in idents]
    # snippets
    tot = hit = 0
    for s in c["snippets"]:
        for line in s.split("\n"):
            if TRIVIAL.match(line):
                continue
            k = re.sub(r"\s+", "", line)
            k = re.sub(r"//.*$", "", k)
            if len(k) < 10:
                continue
            tot += 1
            hit += k in norm
    row.update(n_paths=len(c["paths"]), miss_paths=len(miss_p), n_lines=len(c["lines"]), miss_lines=len(miss_l),
               n_funcs=len(c["funcs"]), miss_funcs=len(miss_f), snip_lines=tot, snip_hit=hit,
               fidelity=round(hit / tot, 3) if tot else "",
               missing=";".join(miss_p + miss_l + miss_f)[:500],
               cited_paths=";".join(c["paths"])[:500], cited_funcs=";".join(c["funcs"])[:800])
    n_cited = len(c["paths"]) + len(c["funcs"]) + len(c["lines"])
    row["n_cited"] = n_cited
    row["grounded"] = int(n_cited > 0 and not miss_p and not miss_l and not miss_f and (not tot or hit / tot >= 0.5))
    row["any_ungrounded"] = int(bool(miss_p or miss_l or miss_f) or (tot > 0 and hit / tot < 0.5))
    return row


def main():
    global REPO
    REPO, rdir, idx, out = sys.argv[1:5]
    scoped = len(sys.argv) > 5 and sys.argv[5] == "scoped"
    rows = list(csv.DictReader(open(idx, encoding="utf-8")))
    rows.sort(key=lambda r: r["created"])
    res = []
    for k, r in enumerate(rows):
        d = json.load(open(os.path.join(rdir, f"{r['id']}.json"), encoding="utf-8"))
        res.append(check(r["id"], d.get("vulnerability_information") or "", r["created"], scoped))
        if k % 50 == 0:
            print(k, file=sys.stderr)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(res[0].keys()))
        w.writeheader()
        w.writerows(res)


if __name__ == "__main__":
    main()
