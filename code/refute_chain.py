"""Chain-aware reuse-key analysis: which destination dimensions does a curl release's connection-reuse key
UNCONDITIONALLY enforce? Compose forced_fields() over the mandatory gate chain of the top reuse matcher.

Soundness argument: curl's top matcher (url_match_conn in modern curl, ConnectionExists in older) is a sequence of
mandatory boolean gates; a full match requires every gate to report a match, so the reuse key forces the UNION of
the fields each gate forces on its match path (and forced_fields() takes the intersection over a gate's own success
paths, so each contributed field is itself unconditional within that gate). We follow matcher-named callees one bounded
transitive step (e.g. url_match_ssl_config -> match_ssl_primary_config). We do NOT follow conditional auth sub-checks
(url_match_auth_ntlm/nego), so the forced set is a conservative UNDER-approximation: it can only cause us to abstain,
never to wrongly refute a genuine report. That is the property we need for a zero-false-reject flood measurement.
"""
import glob, os, re
from collections import defaultdict
from gimple_parse import parse
from refute_reuse import ReuseEncoder
MATCHER_RE = re.compile(r"match|_same|_equal|_matches|config_match|peer_same|creds_same|ConnectionExists", re.I)

GDIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results", "gimple")
TOP = ["url_match_conn", "ConnectionExists"]
CALL = re.compile(r"=\s*(\w+)\s*\(")
# conditional sub-checks we do NOT treat as unconditional gates (would need predication to be sound)
CONDITIONAL = re.compile(r"auth_ntlm|auth_nego|auth_digest|multiplex|http_version|http_multiplex", re.I)

DIM_FIELDS = {
    "host": ["host", "origin", "via_peer", "destination", "peer"],
    "port": ["port"],
    "scheme": ["scheme"],
    "interface": ["interface", "localdev", "bind", "device", "local"],
    "credentials": ["user", "passwd", "creds", "pwd", "login", "secret", "sasl_authzid", "oauth", "bearer", "ntlm", "gss"],
    "tls": ["ssl", "cert", "verify", "cipher", "pinned", "cacert", "cafile", "capath", "issuercert", "tls", "primary", "clientcert", "key_blob", "key_passwd", "curves", "native_ca"],
    "proxy": ["proxy", "socks"],
    "service": ["service", "sasl_service", "proto", "handler"],
}


def release_fns(rel):
    """name -> fn across all of a release's GIMPLE dumps (last definition wins)."""
    fns = {}
    for dump in glob.glob(os.path.join(GDIR, f"{rel}-gimple_*.ssa")):
        try:
            for n, fn in parse(dump).items():
                fns[n] = fn
        except Exception:
            continue
    return fns


def forced_fields_chain(rel, maxdepth=2):
    fns = release_fns(rel)
    top = next((t for t in TOP if t in fns), None)
    if not top:
        return set(), None, []
    forced = set()
    chain = []
    seen = set()

    def visit(name, depth):
        if name in seen or depth > maxdepth or name not in fns:
            return
        seen.add(name)
        fn = fns[name]
        try:
            ff, npaths = ReuseEncoder(fn).forced_fields()
        except Exception:
            ff, npaths = set(), 0
        if ff:
            forced.update(ff)
            chain.append((name, sorted(ff)))
        # follow matcher-named, non-conditional callees
        for b in fn["blocks"].values():
            for s in b["stmts"]:
                m = CALL.search(s["text"])
                if m:
                    callee = m.group(1)
                    if MATCHER_RE.search(callee) and not CONDITIONAL.search(callee) and callee in fns:
                        visit(callee, depth + 1)
    visit(top, 0)
    return forced, top, chain


def forced_dims(rel):
    ff, top, chain = forced_fields_chain(rel)
    dims = set()
    for path in ff:
        pl = path.lower()
        for dim, toks in DIM_FIELDS.items():
            if any(t in pl for t in toks):
                dims.add(dim)
    return dims, top, chain, ff


if __name__ == "__main__":
    import sys
    rel = sys.argv[1] if len(sys.argv) > 1 else "8.23.0"
    dims, top, chain, ff = forced_dims(rel)
    print(f"release {rel}: top matcher = {top}")
    print("forced dimensions:", sorted(dims))
    print("forced field-paths:", sorted(ff)[:40])
    print("chain gates contributing:")
    for name, flds in chain:
        print(f"   {name}: {flds[:8]}")
