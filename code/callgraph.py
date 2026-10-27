"""Whole-program call graph and reachability for a curl build.

Inputs (a curl build tree compiled with -O0 -fcallgraph-info -ffunction-sections --coverage, test suite run):
  lib/*.ci, src/*.ci   GCC call-graph dumps: direct edges plus __indirect_call sites with source locations
  lib/*.o, src/*.o     object files; non-call relocations give the address-taken function set
  gcovj/*.json.gz      gcov JSON for the shipped library (libcurl_la) and tool (src); unit-test lib excluded

Indirect calls are resolved three ways, from most to least precise:
  type      the call goes through a struct field or variable whose function-pointer type is known; targets are
            address-taken functions with an identical normalized signature (first-layer type matching, as in
            Lu and Hu, "Where Does It Go?", CCS 2019)
  arity     no type found; targets are address-taken functions with the same parameter count as the call
  coarse    every address-taken function (sound over-approximation, used as the "definitely unreachable" check)

Entry points: libcurl functions declared CURL_EXTERN in include/curl/*.h, plus the curl tool's main().
"""
import glob, gzip, json, os, re, subprocess, sys
from collections import defaultdict, deque

NODE_RE = re.compile(r'node: \{ title: "([^"]+)" label: "([^"\\]+)\\n([^:"]+):(\d+):(\d+)')
EDGE_RE = re.compile(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"(?: label: "([^:"]+):(\d+):(\d+)")?')
GRAPH_RE = re.compile(r'graph: \{ title: "([^"]+)"')
NOISE = re.compile(r"^(__asan|__ubsan|__gcov|__sanitizer|__builtin|__stack_chk)")


def srcfiles(root, exts=("c", "h")):
    out = []
    for d in ("lib", "src", "include"):
        for e in exts:
            out += glob.glob(os.path.join(root, d, "**", "*." + e), recursive=True)
    return out


_SRC = {}


def src_index(root):
    if not _SRC:
        for p in srcfiles(root):
            _SRC.setdefault(os.path.basename(p), p)
    return _SRC


_LINES = {}


def lines_of(path):
    if path not in _LINES:
        try:
            _LINES[path] = open(path, encoding="utf-8", errors="replace").read().split("\n")
        except OSError:
            _LINES[path] = []
    return _LINES[path]


def parse_ci(root):
    nodes, edges, isites = {}, defaultdict(set), []
    for ci in glob.glob(os.path.join(root, "lib", "**", "*.ci"), recursive=True) + \
            glob.glob(os.path.join(root, "src", "**", "*.ci"), recursive=True):
        if os.path.basename(ci).startswith("libcurlu_la-"):
            continue  # unit-test build of the library, not shipped
        unit = "src" if os.sep + "src" + os.sep in ci else "lib"
        tu = None
        for line in open(ci, encoding="utf-8", errors="replace"):
            m = GRAPH_RE.match(line)
            if m:
                tu = os.path.basename(m.group(1))
                continue
            m = NODE_RE.match(line)
            if m:
                title, name, f, ln = m.group(1), m.group(2), m.group(3), int(m.group(4))
                defined = os.path.basename(f) == tu
                if title not in nodes or defined:
                    nodes[title] = {"name": name, "file": os.path.basename(f), "line": ln, "unit": unit, "defined": defined}
                continue
            m = EDGE_RE.match(line)
            if m:
                s, t = m.group(1), m.group(2)
                if NOISE.match(t):
                    continue
                if t == "__indirect_call":
                    if m.group(3):
                        isites.append((s, os.path.basename(m.group(3)), int(m.group(4)), int(m.group(5))))
                else:
                    edges[s].add(t)
    return nodes, edges, isites


# ---------- C signature normalization ----------
def strip_comments(txt):
    txt = re.sub(r"/\*.*?\*/", " ", txt, flags=re.S)
    return re.sub(r"//[^\n]*", " ", txt)


def norm_type(t):
    t = re.sub(r"\b(const|volatile|register|restrict|CURL_EXTERN|UNITTEST|static|inline|WARN_UNUSED_RESULT)\b", " ", t)
    t = re.sub(r"\bstruct\s+", "struct_", t)
    t = re.sub(r"\s*\*\s*", "*", t)
    return re.sub(r"\s+", " ", t).strip()


def norm_param(p):
    p = p.strip()
    if p in ("", "void"):
        return None
    p = re.sub(r"\[[^\]]*\]", "*", p)
    if "(" in p:  # function pointer parameter
        return "fnptr"
    m = re.match(r"(.*?)([A-Za-z_]\w*)\s*$", p)
    if m and re.search(r"[A-Za-z_*]", m.group(1)) and m.group(1).strip() not in ("struct", "unsigned", "signed", "enum"):
        p = m.group(1)
    return norm_type(p)


def split_params(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return tuple(x for x in (norm_param(p) for p in out) if x is not None)


DEF_RE = re.compile(r"^(?:static\s+|UNITTEST\s+|CURL_EXTERN\s+)*([A-Za-z_][\w \t\*]*?)[\s\*]+\**\s*([A-Za-z_]\w*)\s*\(([^;{}()]*(?:\([^()]*\)[^;{}()]*)*)\)\s*\{",
                    re.M | re.S)
TYPEDEF_FN = re.compile(r"typedef\s+([\w \t\*]+?)\s*\(?\s*\*?\s*([A-Za-z_]\w*)\s*\)?\s*\(([^;]*?)\)\s*;", re.S)
MEMBER_TD = re.compile(r"^\s*(?:const\s+)?([A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)\s*;", re.M)
MEMBER_FP = re.compile(r"([\w \t\*]+?)\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(([^;]*?)\)\s*;", re.S)
MEMBER_TDV = re.compile(r"^\s*(?:const\s+)?([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;", re.M)


def signatures(root):
    fsig, tdefs, fields = {}, {}, defaultdict(set)
    texts = {p: strip_comments(open(p, encoding="utf-8", errors="replace").read()) for p in srcfiles(root)}
    for p, txt in texts.items():
        for m in TYPEDEF_FN.finditer(txt):
            tdefs[m.group(2)] = (norm_type(m.group(1)), split_params(m.group(3)))
    for p, txt in texts.items():
        if p.endswith(".c"):
            for m in DEF_RE.finditer(txt):
                ret, name, params = m.group(1), m.group(2), m.group(3)
                if name in ("if", "while", "for", "switch", "return", "sizeof"):
                    continue
                fsig.setdefault(name, (norm_type(ret), split_params(params)))
        for m in MEMBER_FP.finditer(txt):
            fields[m.group(2)].add((norm_type(m.group(1)), split_params(m.group(3))))
        for m in MEMBER_TD.finditer(txt):
            if m.group(1) in tdefs:
                fields[m.group(2)].add(tdefs[m.group(1)])
        for m in MEMBER_TDV.finditer(txt):  # pointer typedefs: curl_write_callback fwrite_func;
            if m.group(1) in tdefs:
                fields[m.group(2)].add(tdefs[m.group(1)])
    return fsig, tdefs, fields


def site_call(root, f, ln, col):
    """Return (field_or_var, nargs) for the call expression starting at the recorded location."""
    path = src_index(root).get(f)
    if not path:
        return None, None
    L = lines_of(path)
    if ln - 1 >= len(L):
        return None, None
    text = "\n".join(L[ln - 1:ln + 6])
    seg = text[max(col - 1, 0):]
    m = re.match(r"\s*\(?\s*\*?\s*([A-Za-z_][\w]*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*|\[[^\]]*\])*)\s*\)?\s*\(", seg)
    if not m:
        return None, None
    expr = m.group(1)
    # count top-level arguments
    i, depth, n, nonempty = m.end(), 1, 0, False
    while i < len(seg) and depth:
        ch = seg[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 1:
            n += 1
        if depth and not ch.isspace():
            nonempty = True
        i += 1
    nargs = n + 1 if nonempty else 0
    fm = re.search(r"(?:->|\.)\s*([A-Za-z_]\w*)\s*$", expr)
    return (fm.group(1) if fm else "var:" + expr.strip()), nargs


def address_taken(root, refs=None):
    """Address-taken functions, plus refs[F] = functions whose address is used inside function F's code."""
    taken = set()
    objs = [o for o in glob.glob(os.path.join(root, "lib", "**", "*.o"), recursive=True) +
            glob.glob(os.path.join(root, "src", "**", "*.o"), recursive=True)
            if not os.path.basename(o).startswith("libcurlu_la-")]
    for o in objs:
        out = subprocess.run(["readelf", "-rW", o], capture_output=True, text=True).stdout
        cur_sec = ""
        for line in out.split("\n"):
            if line.startswith("Relocation section"):
                cur_sec = line.split("'")[1]
                continue
            parts = line.split()
            if len(parts) < 5 or not parts[2].startswith("R_X86_64"):
                continue
            rtype, sym = parts[2], parts[4]
            if rtype == "R_X86_64_PLT32" or cur_sec.startswith(".rela.debug") or cur_sec.startswith(".rela.eh_frame"):
                continue
            tgt = sym[len(".text."):] if sym.startswith(".text.") else (None if sym.startswith(".") else sym)
            if not tgt:
                continue
            if refs is not None and cur_sec.startswith(".rela.text."):
                refs[cur_sec[len(".rela.text."):]].add(tgt)
            if rtype == "R_X86_64_PC32" and cur_sec.startswith(".rela.text."):
                continue  # GAS form of a call to a local function; handled through refs
            taken.add(tgt)
    return taken


def public_api(root):
    api = set()
    for h in glob.glob(os.path.join(root, "include", "curl", "*.h")):
        txt = strip_comments(open(h, encoding="utf-8", errors="replace").read())
        txt = re.sub(r'"(?:\\.|[^"\\])*"', '""', txt)
        # declarations may carry CURL_DEPRECATED(...) between the type and the name
        for decl in re.findall(r"CURL_EXTERN\b(.*?);", txt, re.S):
            names = re.findall(r"\b(curl_\w+)\s*\(", decl)
            if names:
                api.add(names[0])
    return api


def coverage(root):
    """{file: {line: count}}, {file: [(start, end, name, count)]} from gcov JSON."""
    lines_cov, funcs = defaultdict(dict), defaultdict(list)
    for j in glob.glob(os.path.join(root, "gcovj", "*.json.gz")):
        d = json.load(gzip.open(j, "rt"))
        for f in d["files"]:
            fn = os.path.basename(f["file"])
            if fn.endswith(".h"):
                pass
            for l in f["lines"]:
                n = l["line_number"]
                lines_cov[fn][n] = max(lines_cov[fn].get(n, 0), l["count"])
            for fu in f["functions"]:
                funcs[fn].append((fu["start_line"], fu["end_line"], fu["name"], fu["execution_count"]))
    for fn in funcs:
        funcs[fn] = sorted(set(funcs[fn]))
    return lines_cov, funcs


def bfs(starts, edges):
    seen, q = set(starts), deque(starts)
    while q:
        u = q.popleft()
        for v in edges.get(u, ()):
            if v not in seen:
                seen.add(v)
                q.append(v)
    return seen


def main(root, out):
    nodes, edges, isites = parse_ci(root)
    name_to_titles = defaultdict(set)
    for t, n in nodes.items():
        if n["defined"]:
            name_to_titles[n["name"]].add(t)
    # calls to non-static functions are recorded by bare name; static ones as file:name
    defined = {t for t, n in nodes.items() if n["defined"]}
    fsig, tdefs, fields = signatures(root)
    # GAS turns calls to local symbols into section-relative PC32 relocations, so relocations alone overstate
    # address-taking. Keep a function only if the source also mentions it outside call syntax.
    mention = set()
    for p in srcfiles(root, ("c",)):
        txt = strip_comments(open(p, encoding="utf-8", errors="replace").read())
        txt = re.sub(r"'(?:\\.|[^'\\])'", "0", txt)  # char literals such as '"' would desync string stripping
        txt = re.sub(r'"(?:\\.|[^"\\\n])*"', '""', txt)
        for m in re.finditer(r"(?<![\w.>])([A-Za-z_]\w*)\b(?!\s*\()", txt):
            mention.add(m.group(1))
    refs = defaultdict(set)
    taken = {n for n in address_taken(root, refs) if n in name_to_titles and n in mention}
    taken_titles = {t for n in taken for t in name_to_titles[n]}
    by_sig, by_arity = defaultdict(set), defaultdict(set)
    for n in taken:
        if n in fsig:
            by_sig[fsig[n]] |= name_to_titles[n]
            by_arity[len(fsig[n][1])] |= name_to_titles[n]
    api = public_api(root) & set(name_to_titles)
    # a function whose address is used inside F (callback handed to qsort, pthread_create, a hash table...)
    # is treated as callable from F
    for fname, tg in refs.items():
        for src_t in name_to_titles.get(fname, ()):
            for n in tg:
                if n in mention:
                    edges[src_t] |= name_to_titles.get(n, set())
    typed = defaultdict(set, {k: set(v) for k, v in edges.items()})
    coarse = defaultdict(set, {k: set(v) for k, v in edges.items()})
    stats = defaultdict(int)
    site_info = []
    for s, f, ln, col in isites:
        fld, nargs = site_call(root, f, ln, col)
        tg, how = set(), "coarse"
        if fld and not fld.startswith("var:") and fld in fields:
            for sig in fields[fld]:
                tg |= by_sig.get(sig, set())
            how = "type" if tg else how
        if not tg and nargs is not None and nargs in by_arity:
            tg, how = set(by_arity[nargs]), "arity"
        if not tg:
            tg = set(taken_titles)
        stats[how] += 1
        typed[s] |= tg
        coarse[s] |= taken_titles
        site_info.append({"caller": s, "loc": f"{f}:{ln}:{col}", "field": fld, "nargs": nargs, "how": how, "n": len(tg),
                          "targets": sorted(tg)[:200]})
    entries = {t for n in api for t in name_to_titles[n]} | \
              {t for t in name_to_titles.get("main", set()) if nodes[t]["unit"] == "src"}
    r_direct = bfs(entries, edges) & defined
    r_typed = bfs(entries, typed) & defined
    r_coarse = bfs(entries, coarse) & defined
    lines_cov, funcs = coverage(root)
    covered_funcs = sorted({f"{fn}:{name}" for fn, lst in funcs.items() for a, b, name, c in lst if c > 0})
    res = {
        "root": root, "n_defined": len(defined), "n_direct_edges": sum(len(v) for v in edges.values()),
        "n_indirect_sites": len(isites), "resolution": dict(stats), "n_address_taken": len(taken),
        "n_entries": len(entries), "n_with_sig": len(fsig),
        "nodes": {t: nodes[t] for t in defined},
        "reach_direct": sorted(r_direct), "reach_typed": sorted(r_typed), "reach_coarse": sorted(r_coarse),
        "covered_funcs": covered_funcs,
        "func_extents": {fn: lst for fn, lst in funcs.items()},
        "lines_cov": {k: {str(n): c for n, c in v.items()} for k, v in lines_cov.items()},
        "indirect_sites": site_info,
    }
    json.dump(res, open(out, "w"))
    print(json.dumps({k: res[k] for k in ("n_defined", "n_direct_edges", "n_indirect_sites", "resolution",
                                          "n_address_taken", "n_entries", "n_with_sig")}))
    print("reachable direct/typed/coarse:", len(r_direct), len(r_typed), len(r_coarse), "of", len(defined))
    print("functions executed by test suite:", len(covered_funcs))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
