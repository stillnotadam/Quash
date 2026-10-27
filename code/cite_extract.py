"""Extract code citations from a vulnerability report body.

Pure stdlib (runs on Windows and in WSL). A citation is one of:
  path      a repo-relative path like lib/cookie.c (or a bare basename like cookie.c)
  line      a (path, line) pair from path:123, #L123, or "line 123" near a path
  func      a C identifier presented as code (backticks, call syntax, or in a fenced block header)
  snippet   a fenced code block that looks like C (used for verbatim-fidelity checks)
  permalink github.com/curl/curl/blob/<ref>/<path>#Lx
"""
import re

PATH_RE = re.compile(r"(?<![\w/.-])((?:lib|src|include|tests|docs|packages|scripts|projects|m4|winbuild|plan9|\.github)"
                     r"/[\w./+-]+?\.(?:c|h|pl|pm|py|md|txt|am|cmake|in|sh|yml))(?::(\d+)(?:-(\d+))?)?(?![\w])")
BARE_RE = re.compile(r"(?<![\w/.-])([a-z][\w-]*\.[ch])(?::(\d+)(?:-(\d+))?)?(?![\w.])")
PERMA_RE = re.compile(r"github\.com/curl/curl/blob/([0-9a-fA-F]{7,40}|[\w.-]+)/([\w./+-]+)(?:#L(\d+)(?:-L(\d+))?)?")
FENCE_RE = re.compile(r"```[ \t]*([\w+-]*)[^\n]*\n(.*?)```", re.S)
TICK_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]{2,})(?:\(\))?`")
CALL_RE = re.compile(r"(?<![\w.>])([A-Za-z_][A-Za-z0-9_]{3,})\s*\(")

# Identifiers that are not evidence of grounding: libc, POSIX, C keywords, common English and macro noise.
STOP = set("""
if for while switch return sizeof else case break do goto typedef struct union enum static const volatile
int char long short unsigned signed void bool size_t ssize_t
malloc calloc realloc free strcpy strncpy strcat strncat strlen strnlen strcmp strncmp strcasecmp strncasecmp
memcpy memmove memset memcmp memchr strchr strrchr strstr strtok strtol strtoul strtoll strtoull strdup strndup
sprintf snprintf vsnprintf vsprintf printf fprintf vfprintf sscanf scanf fscanf fopen fclose fread fwrite fgets
fputs puts getenv setenv atoi atol abort exit assert perror open close read write recv send socket connect bind
listen accept select poll getaddrinfo freeaddrinfo gethostbyname inet_ntop inet_pton time localtime gmtime
main test func function example foo bar print echo python bash curl wget http https main_loop
gcc clang make cmake grep sed awk ifdef ifndef endif define include pragma defined
Python import from def class self lambda range print len socket bytes str
ASAN UBSAN NULL TRUE FALSE CURLE_OK
""".split())

C_HINT = re.compile(r"[;{}]|->|\b(?:int|char|size_t|struct|static|return|if|while|for)\b")


def looks_c(lang, body):
    if lang.lower() in ("c", "cpp", "c++", "h", "diff"):
        return True
    if lang.lower() in ("", "text", "plaintext") and len(C_HINT.findall(body)) >= 3:
        return True
    return False


SYS_HDR = set("""assert.h ctype.h errno.h fcntl.h float.h inttypes.h limits.h locale.h math.h netdb.h poll.h
pthread.h setjmp.h signal.h stdarg.h stdbool.h stddef.h stdint.h stdio.h stdlib.h string.h strings.h time.h
unistd.h windows.h winsock2.h ws2tcpip.h malloc.h dlfcn.h sched.h""".split())
ARTIFACT = re.compile(r"((poc|exploit|repro|harness|fuzz|dummy|crash|server|client|attack|payload|test|main|calc|"
                      r"vg_replace|sysdeps|my|evil|malicious|trigger)\w*|\w*(poc|exploit|repro|harness|shim))\.[ch]$", re.I)
HARNESS = re.compile(r"\bmain\s*\(|#include\s*<curl/curl\.h>|curl_easy_init\s*\(|#include\s*<stdio\.h>|LLVMFuzzerTestOneInput")
DEFINES = re.compile(r"(?:^|\n)\s*(?:static\s+)?(?:[\w\*]+\s+)+\**([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{|"
                     r"\bdef\s+([A-Za-z_]\w*)|\bclass\s+([A-Za-z_]\w*)|\bfunction\s+([A-Za-z_]\w*)")


def extract(text, scoped=False):
    """scoped=True keeps only citations the report presents as being curl's code: drops the reporter's own
    PoC files, system headers, identifiers the report itself defines, and harness (PoC) code blocks."""
    r = _extract(text)
    if not scoped:
        return r
    text = text or ""
    own = set()
    blocks = [(m.group(1), m.group(2)) for m in FENCE_RE.finditer(text)]
    for lang, body in blocks:
        for m in DEFINES.finditer(body):
            own.update(g for g in m.groups() if g)
    nonc = set()
    for lang, body in blocks:
        if not looks_c(lang, body):
            nonc.update(re.findall(r"[A-Za-z_]\w{2,}", body))
    prose = FENCE_RE.sub(" ", text)
    in_prose = set(re.findall(r"[A-Za-z_]\w{2,}", prose))
    target_snips = [s for s in r["snippets"] if not HARNESS.search(s)]
    harness_ids = set()
    for s in r["snippets"]:
        if HARNESS.search(s):
            harness_ids.update(re.findall(r"[A-Za-z_]\w{2,}", s))
    target_ids = set()
    for s in target_snips:
        target_ids.update(c.group(1) for c in CALL_RE.finditer(s))

    def keep_path(p):
        b = p.split("/")[-1]
        if b in SYS_HDR:
            return False
        if p.startswith("*/") and ARTIFACT.match(b):
            return False
        return True
    paths = {p: n for p, n in r["paths"].items() if keep_path(p)}
    lines = [l for l in r["lines"] if keep_path(l[0])]
    funcs = []
    for f in r["funcs"]:
        if f in own or re.fullmatch(r"[0-9a-f]{7,40}", f):
            continue
        # an identifier that only appears inside harness or non-C (python, shell) blocks is the reporter's
        if f not in in_prose and f not in target_ids and (f in harness_ids or f in nonc):
            continue
        funcs.append(f)
    return {"paths": paths, "lines": lines, "funcs": funcs, "snippets": target_snips, "permalinks": r["permalinks"]}


def _extract(text):
    text = text or ""
    paths, lines, funcs, snippets, perma = {}, [], set(), [], []
    for m in PERMA_RE.finditer(text):
        ref, p, a, b = m.group(1), m.group(2), m.group(3), m.group(4)
        perma.append((ref, p, int(a) if a else None, int(b) if b else None))
        paths[p] = paths.get(p, 0) + 1
        if a:
            lines.append((p, int(a), int(b) if b else int(a)))
    for m in PATH_RE.finditer(text):
        p = m.group(1).rstrip(".")
        paths[p] = paths.get(p, 0) + 1
        if m.group(2):
            a = int(m.group(2))
            lines.append((p, a, int(m.group(3)) if m.group(3) else a))
    for m in BARE_RE.finditer(text):
        p = m.group(1)
        if any(k.endswith("/" + p) for k in paths):
            continue
        paths["*/" + p] = paths.get("*/" + p, 0) + 1
        if m.group(2):
            a = int(m.group(2))
            lines.append(("*/" + p, a, int(m.group(3)) if m.group(3) else a))
    # "line 123" mentions attach to the single most-cited path, if there is one
    near = re.findall(r"\b[Ll]ines?\s+(\d{2,5})(?:\s*(?:-|to|–)\s*(\d{2,5}))?", text)
    if near and paths:
        top = max(paths, key=paths.get)
        for a, b in near:
            lines.append((top, int(a), int(b) if b else int(a)))
    prose = FENCE_RE.sub(" ", text)
    for m in TICK_RE.finditer(text):
        funcs.add(m.group(1))
    for m in CALL_RE.finditer(prose):
        # prose "word (aside)" is not a call; require code-shaped identifiers
        if re.search(r"_|\d|[a-z][A-Z]", m.group(1)):
            funcs.add(m.group(1))
    for m in FENCE_RE.finditer(text):
        lang, body = m.group(1), m.group(2)
        if looks_c(lang, body):
            snippets.append(body)
            # function definitions/calls inside C snippets are citations too
            for c in CALL_RE.finditer(body):
                funcs.add(c.group(1))
    funcs = {f for f in funcs if f not in STOP and not f.isupper() and not re.fullmatch(r"[A-Z][a-z]+", f)}
    return {"paths": paths, "lines": lines, "funcs": sorted(funcs), "snippets": snippets, "permalinks": perma}


if __name__ == "__main__":
    import json, sys
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    r = extract(d.get("vulnerability_information"))
    r["snippets"] = [s[:80] for s in r["snippets"]]
    print(json.dumps(r, indent=1))
