"""Equality/reuse refutation family (CRDS family 2).

A connection-reuse (or config-match) report claims: a connection/context established for destination A is reused
for a destination B that differs in some dimension D (host, port, scheme, credentials, TLS config, interface...).
We refute the claim when the match function's SUCCESS path provably forces equality of A and B in dimension D.

Model: a match function takes two record pointers (its struct params, or param->needle). Every field-load chain
base->f->g becomes a symbolic integer term keyed by (record, "f.g"). A call to an equality-like comparator from
EQLIB on two terms, when it must be TRUE on the success path, asserts the two argument terms equal AND, for any
later-created subfield terms under those arguments, the corresponding subfields equal (prefix equality). The claim
predicate phi asserts the two records differ in D (term_A(D) != term_B(D)). Refuted iff success-path AND phi UNSAT.
We only ever read sat/unsat; no model is extracted.

Soundness: comparator semantics are modeled as "success implies equality of the compared (sub)fields", which is
true for the curl comparators in EQLIB (documented assumption). Anything else is a free value, so an unmodeled
check only causes abstention, never a false refutation.
"""
import re
try:
    from z3 import Solver, Int, Bool, Implies, Not, And, Or, sat, unsat, unknown, IntVal
except ImportError:
    Solver = None  # refute2 and _guard_tie are pure-Python; only the legacy refute() needs z3

EQLIB = {
    "Curl_peer_same_destination", "Curl_peer_same", "Curl_peer_equal", "Curl_creds_same",
    "curl_strequal", "Curl_strcasecompare", "strcasecompare", "Curl_safecmp", "blobcmp",
    "Curl_ssl_conn_config_match", "match_ssl_primary_config", "Curl_ssl_config_matches",
    "Curl_timestrcmp", "curl_strnequal", "Curl_str_casecompare",
}
# comparators whose TRUE result means "equal"; Curl_timestrcmp returns 0 when equal (handled by caller guard)

FIELD = re.compile(r"^(\w+(?:\.\d+)?_\d+|\w+_\d+\(D\)|\w+)\s*->\s*(\w+)$")
CALL = re.compile(r"^(\w+)\s*\((.*)\)$")


DIM_ALIASES = {
    "host": ["host", "origin", "via_peer", "destination", "peer"], "port": ["port"], "scheme": ["scheme"],
    "interface": ["interface", "localdev", "bind", "device"],
    "credentials": ["creds", "user", "passwd", "oauth", "bearer", "sasl", "ntlm", "gss", "login"],
    "tls": ["ssl", "cert", "verify", "cipher", "pinned", "cafile", "capath", "issuercert", "key", "bit"],
    "proxy": ["proxy", "socks"], "service": ["service", "proto", "handler"],
}


def split_args(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


class ReuseEncoder:
    def __init__(self, fn):
        self.fn = fn
        self.blocks = fn["blocks"]
        self.assign = {}
        for b in self.blocks.values():
            for s in b["stmts"]:
                m = re.match(r"^(\w+(?:\.\d+)?_\d+|_\d+)\s*=\s*(.+?);?$", s["text"])
                if m:
                    self.assign[m.group(1)] = m.group(2).strip()
        self.records = {}     # root ssa -> record id (int)
        self.terms = {}       # (record, path) -> Z3 Int
        self.term_of_ssa = {} # ssa temp -> (record, path)
        self.eqcalls = {}     # ssa temp (bool result) -> (termx, termy, predname)
        self._n = 0

    def record_id(self, root):
        root = re.sub(r"\(D\)$", "", root)
        if root not in self.records:
            self.records[root] = len(self.records)
        return self.records[root]

    def term(self, rec, path):
        k = (rec, path)
        if k not in self.terms:
            self.terms[k] = Int(f"t{rec}_{re.sub(chr(92)+'W','_',path)}_{len(self.terms)}")
        return self.terms[k]

    def resolve(self, ssa, depth=0):
        """Map an SSA temp to a (record, path) term by following field loads. Returns (rec,path) or None."""
        base = re.sub(r"\(D\)$", "", ssa)
        if depth > 30 or ssa not in self.assign:
            # a bare pointer param like conn_24 or m_25: it is a record root
            if re.match(r"^\w+_\d+$", base) or re.match(r"^\w+$", base):
                return (self.record_id(base), "")
            return None
        rhs = self.assign[ssa]
        # bitfield / boolean capability field: BIT_FIELD_REF <*cN(D)|MEM...[(void*)cN(D)], size, offset>
        bf = re.match(r"^BIT_FIELD_REF\s*<.*?(\w+_\d+)\(D\).*?,\s*\d+,\s*(\d+)>$", rhs)
        if bf:
            base = self.resolve(bf.group(1), depth + 1)
            if base is None:
                return None
            np = (base[1] + ".bit" + bf.group(2)).lstrip(".")
            self.term_of_ssa[ssa] = (base[0], np)
            return (base[0], np)
        fm = FIELD.match(rhs)
        if fm:
            base = self.resolve(fm.group(1), depth + 1)
            if base is None:
                return None
            rec, path = base
            np = (path + "." + fm.group(2)).lstrip(".")
            self.term_of_ssa[ssa] = (rec, np)
            return (rec, np)
        # pointer copy
        if re.match(r"^\w+(?:\.\d+)?_\d+(\(D\))?$", rhs):
            return self.resolve(rhs, depth + 1)
        return None

    def analyze_calls(self):
        for ssa, rhs in self.assign.items():
            cm = CALL.match(rhs)
            if cm and cm.group(1) in EQLIB:
                args = [a.strip() for a in split_args(cm.group(2))]
                ts = [self.resolve(a) for a in args[:2]]
                if len(ts) == 2 and ts[0] and ts[1]:
                    self.eqcalls[ssa] = (ts[0], ts[1], cm.group(1))

    def phi_sources(self):
        """Parse '# _x = PHI <_a(bb), ...>' into {return_bb: {pred_bb: value}} and the returned ssa."""
        ret_ssa = None
        for b in self.blocks.values():
            for s in b["stmts"]:
                m = re.match(r"return (\w+);?$", s["text"])
                if m:
                    ret_ssa = m.group(1)
        phi = {}
        if ret_ssa:
            for b in self.blocks.values():
                for s in b["stmts"]:
                    mm = re.search(rf"{re.escape(ret_ssa)}\s*=\s*PHI\s*<(.+)>", s["text"])
                    if mm:
                        for val, bb in re.findall(r"(\w+)\((\d+)\)", mm.group(1)):
                            phi[int(bb)] = val
        return ret_ssa, phi

    def forced_pred(self, result_ssa):
        """Return (termX,termY) if result_ssa is an EQLIB call result, following ~ negation wrappers."""
        if result_ssa in self.eqcalls:
            tx, ty, _ = self.eqcalls[result_ssa]
            return (tx, ty)
        return None

    def refute2(self, dim_fields):
        """Refuted iff on EVERY success return path, the path forces equality of the two records in dimension D.
        'Forces equality' = an EQLIB comparator tied to dimension D must be TRUE on the path (via the terminal
        success value or a path guard), or a field==field guard in D is taken equal. Sound: unmodeled => abstain."""
        self.analyze_calls()
        ret_ssa, phi = self.phi_sources()
        # return-block id
        ret_bb = None
        for bid, b in self.blocks.items():
            if any(st["text"].startswith("return") for st in b["stmts"]):
                ret_bb = bid
        if ret_bb is None:
            return ("no_success_path", 0, 0)
        raw = self._paths_to_pred(ret_bb)
        succ_paths = []
        for guards, pred_bb in raw:
            val = phi.get(pred_bb, ret_ssa if not phi else None)
            if val is None:
                # single return without PHI: treat as success-capable
                val = ret_ssa
            cval = val
            seen = 0
            while cval in self.assign and re.fullmatch(r"\w+", self.assign[cval]) and seen < 10:
                cval = self.assign[cval]
                seen += 1
            if re.fullmatch(r"\d+", str(cval)) and int(cval) == 0:
                continue  # failure return (return 0/FALSE)
            succ_paths.append((guards, pred_bb, val))
        if not succ_paths:
            return ("no_success_path", 0, 0)
        tested = refuted = 0
        for guards, pred_bb, val in succ_paths:
            ties = []  # (pathX, pathY) forced equal on this success path
            # terminal success predicate
            fp = self.forced_pred(val)
            if fp:
                ties.append((fp[0][1], fp[1][1]))
            # guard-forced equalities
            for (e, truth) in guards:
                t = self._guard_tie(e, truth)
                if t:
                    ties.append(t)
            tested += 1
            if any(any(df in px or df in py for df in dim_fields) for (px, py) in ties):
                refuted += 1
        verdict = "refuted" if refuted == tested and tested > 0 else "cannot_refute"
        return (verdict, tested, refuted)

    def forced_fields(self):
        """Set of record field-paths that EVERY match-success path forces equal (intersection over success paths).
        Sound notion of 'this matcher unconditionally forces equality in these fields when it reports a match'.
        Returns (forced:set[str], n_success_paths:int)."""
        self.analyze_calls()
        ret_ssa, phi = self.phi_sources()
        ret_bb = None
        for bid, b in self.blocks.items():
            if any(st["text"].startswith("return") for st in b["stmts"]):
                ret_bb = bid
        if ret_bb is None:
            return (set(), 0)
        raw = self._paths_to_pred(ret_bb)
        per_path = []
        for guards, pred_bb in raw:
            val = phi.get(pred_bb, ret_ssa if not phi else None) or ret_ssa
            cval, seen = val, 0
            while cval in self.assign and re.fullmatch(r"\w+", self.assign[cval]) and seen < 10:
                cval = self.assign[cval]
                seen += 1
            if re.fullmatch(r"\d+", str(cval)) and int(cval) == 0:
                continue  # failure return (no match)
            ties = set()
            fp = self.forced_pred(val)
            if fp:
                ties.add(fp[0][1]); ties.add(fp[1][1])
            for (e, truth) in guards:
                t = self._guard_tie(e, truth)
                if t:
                    ties.add(t[0]); ties.add(t[1])
            per_path.append(ties)
        if not per_path:
            return (set(), 0)
        forced = set.intersection(*per_path) if len(per_path) > 1 else per_path[0]
        return (forced, len(per_path))

    def _xor_pair(self, ssa, depth=0):
        """If ssa traces to (A ^ B) possibly wrapped in &mask or a cast, return (resolve(A), resolve(B))."""
        if depth > 8 or ssa not in self.assign:
            return None
        rhs = self.assign[ssa]
        cm = re.match(r"^\(.*?\)\s*(\w+)$", rhs)      # cast
        if cm:
            return self._xor_pair(cm.group(1), depth + 1)
        am = re.match(r"^(\w+)\s*&\s*\w+$", rhs)      # & mask
        if am:
            return self._xor_pair(am.group(1), depth + 1)
        xm = re.match(r"^(\w+)\s*\^\s*(\w+)$", rhs)   # the XOR of two (bit)field loads
        if xm:
            a, b = self.resolve(xm.group(1)), self.resolve(xm.group(2))
            if a and b:
                return (a, b)
        return None

    def forced_with_prov(self):
        """forced_fields plus provenance: {field_path: source} where source is the comparator or guard that
        forces that equality on every success path. Used to build faithful SMT certificates."""
        self.analyze_calls()
        ret_ssa, phi = self.phi_sources()
        ret_bb = None
        for bid, b in self.blocks.items():
            if any(st["text"].startswith("return") for st in b["stmts"]):
                ret_bb = bid
        if ret_bb is None:
            return {}, 0
        per_path = []
        for guards, pred_bb in self._paths_to_pred(ret_bb):
            val = phi.get(pred_bb, ret_ssa if not phi else None) or ret_ssa
            cval, seen = val, 0
            while cval in self.assign and re.fullmatch(r"\w+", self.assign[cval]) and seen < 10:
                cval = self.assign[cval]; seen += 1
            if re.fullmatch(r"\d+", str(cval)) and int(cval) == 0:
                continue
            prov = {}
            fp = self.forced_pred(val)
            if fp:
                comp = self.eqcalls[val][2] if val in self.eqcalls else "comparator"
                prov[fp[0][1]] = comp
                prov[fp[1][1]] = comp
            for (e, truth) in guards:
                t = self._guard_tie(e, truth)
                if t:
                    prov.setdefault(t[0], "guard")
                    prov.setdefault(t[1], "guard")
            per_path.append(prov)
        if not per_path:
            return {}, 0
        common = set.intersection(*[set(p) for p in per_path]) if len(per_path) > 1 else set(per_path[0])
        prov = {k: per_path[0].get(k, "guard") for k in common}
        return prov, len(per_path)

    def refute_certificate(self, dim_fields):
        """On a refuted reuse claim, return an SMT-LIB proof with explicit comparator equality axioms, plus the
        comparators/guards that justify them. Any SMT solver re-checks UNSAT; the maintainer checks the axioms."""
        prov, npaths = self.forced_with_prov()
        forced = {f for f in prov if f}
        chosen = None
        for d in dim_fields:
            toks = [d] if d not in DIM_ALIASES else DIM_ALIASES[d]
            for f in sorted(forced):
                if any(t.lower() in f.lower() for t in toks):
                    chosen = (d, f, prov[f])
                    break
            if chosen:
                break
        if not chosen:
            return {"verdict": "cannot_refute"}
        dim, field, src = chosen
        sa, sb = "A_" + re.sub(r"\W", "_", field), "B_" + re.sub(r"\W", "_", field)
        smt = (f"; claim: connections differing in '{dim}' (field '{field}') are matched/reused\n"
               f"; axiom: on all {npaths} match-success paths, '{src}' forces equality of this field\n"
               f"(declare-const {sa} Int)\n(declare-const {sb} Int)\n"
               f"(assert (= {sa} {sb})) ; <- enforced by {src}\n"
               f"(assert (not (= {sa} {sb}))) ; <- the report's claim\n(check-sat)\n")
        return {"verdict": "refuted", "n_paths": npaths, "field": field, "enforced_by": src, "smt2": [smt]}

    def _guard_tie(self, expr, truth):
        """If guard forces an equality in some dimension, return (pathX,pathY); else None."""
        # packed bitfield-group equality idiom: (A ^ B) & mask == 0  (success takes the ==0 branch)
        xz = re.match(r"^(\w+)\s*(==|!=)\s*0$", expr)
        if xz:
            xp = self._xor_pair(xz.group(1))
            if xp:
                equal_branch = (xz.group(2) == "==") == truth  # (x==0) true on equal; (x!=0) false on equal
                if equal_branch:
                    return (xp[0][1], xp[1][1])
        # EQLIB result used as _r != 0 (true) or via ~ wrapper
        m = re.match(r"^(\w+)\s*(==|!=)\s*0$", expr)
        if m:
            r = m.group(1)
            inner = self.assign.get(r, "")
            neg = False
            im = re.match(r"^~\s*(\w+)$", inner)
            if im:
                r = im.group(1)
                neg = True
            fp = self.forced_pred(r)
            if fp:
                pred_true = ((m.group(2) == "!=") == truth) != neg
                if pred_true:
                    return (fp[0][1], fp[1][1])
            return None
        # field == field forced equal
        fm = re.match(r"^(\w+(?:\.\d+)?_\d+)\s*(==|!=)\s*(\w+(?:\.\d+)?_\d+)$", expr)
        if fm:
            a = self.resolve(fm.group(1))
            b = self.resolve(fm.group(3))
            if a and b:
                equal = (fm.group(2) == "==") == truth
                if equal:
                    return (a[1], b[1])
        return None

    def _paths_to_pred(self, target, loopcap=1, maxp=4000):
        start = min(self.blocks)
        res = []

        def walk(bid, visits, guards, prev):
            if len(res) >= maxp:
                return
            if bid == target:
                res.append((list(guards), prev))
                return
            if visits.get(bid, 0) > loopcap:
                return
            b = self.blocks.get(bid)
            if not b:
                return
            v = dict(visits)
            v[bid] = v.get(bid, 0) + 1
            c = b["cond"]
            if c and c.get("true") is not None:
                walk(c["true"], v, guards + [(c["expr"], True)], bid)
                walk(c["false"], v, guards + [(c["expr"], False)], bid)
            else:
                for sb in b["succ"]:
                    walk(sb, v, guards, bid)
        walk(start, {}, [], None)
        return res

    def success_return_paths(self):
        """Paths (as guard lists) to a success return (return of a nonzero const or an EQLIB predicate result)."""
        ret_bb = None
        succ_vals = []
        for bid, b in self.blocks.items():
            for s in b["stmts"]:
                if s["text"].startswith("return"):
                    ret_bb = bid
                    m = re.match(r"return (.+?);?$", s["text"])
                    rv = m.group(1) if m else ""
                    succ_vals = self._success_sources(rv)
        if ret_bb is None:
            return []
        paths = self._paths_to(ret_bb)
        out = []
        for guards, lastpred in paths:
            out.append((guards, lastpred))
        return out

    def _success_sources(self, rv):
        # if return is a PHI, success comes from the incoming value that is nonzero / a predicate result
        return rv

    def _paths_to(self, target, loopcap=1, maxp=3000):
        start = min(self.blocks)
        res = []

        def walk(bid, visits, guards):
            if len(res) >= maxp:
                return
            if bid == target:
                res.append((list(guards), None))
                return
            if visits.get(bid, 0) > loopcap:
                return
            b = self.blocks.get(bid)
            if not b:
                return
            v = dict(visits)
            v[bid] = v.get(bid, 0) + 1
            c = b["cond"]
            if c and c.get("true") is not None:
                walk(c["true"], v, guards + [(c["expr"], True)])
                walk(c["false"], v, guards + [(c["expr"], False)])
            else:
                for s in b["succ"]:
                    walk(s, v, guards)
        walk(start, {}, [])
        return res

    def _guard_bool(self, expr, truth, s):
        """Assert a GIMPLE condition. If it references an EQLIB call result, tie it to term equality."""
        m = re.match(r"^(\w+(?:\.\d+)?_\d+|_\d+)\s*(==|!=)\s*(\w+)$", expr)
        if m and m.group(1) in self.eqcalls:
            tx, ty, pred = self.eqcalls[m.group(1)]
            b = Bool("eq_" + m.group(1))
            s.add(Implies(b, self.term(*tx) == self.term(*ty)))
            # expr like `_5 != 0` with _5 = ~_4 ; handle negation chains loosely: treat predicate truthiness
            istrue = (m.group(2) == "!=") == (truth)  # (_x != 0) true means predicate-ish true
            s.add(b if istrue else Not(b))
            return
        # negation temp: _5 = ~_4 where _4 is a predicate
        nm = re.match(r"^(_\d+)\s*(==|!=)\s*0$", expr)
        if nm and nm.group(1) in self.assign:
            inner = self.assign[nm.group(1)]
            im = re.match(r"^~\s*(\w+)$", inner)
            if im and im.group(1) in self.eqcalls:
                tx, ty, pred = self.eqcalls[im.group(1)]
                b = Bool("eq_" + im.group(1))
                s.add(Implies(b, self.term(*tx) == self.term(*ty)))
                pred_true = (nm.group(2) == "==") == truth  # _5=~_4; (_5!=0) true => _4 false
                # _5 != 0 (truth True) => ~_4 != 0 => _4 == 0 => predicate false
                pred_is_true = not (((nm.group(2) == "!=") and truth) or ((nm.group(2) == "==") and not truth))
                s.add(b if pred_is_true else Not(b))
                return
        # field-vs-field comparison (scheme != scheme, protocol family etc.)
        fm = re.match(r"^(\w+(?:\.\d+)?_\d+)\s*(==|!=)\s*(\w+(?:\.\d+)?_\d+)$", expr)
        if fm:
            a = self.resolve(fm.group(1))
            b2 = self.resolve(fm.group(3))
            if a and b2:
                rel = (self.term(*a) == self.term(*b2)) if fm.group(2) == "==" else (self.term(*a) != self.term(*b2))
                s.add(rel if truth else Not(rel))
                return
        # unknown guard: skip (sound: fewer constraints -> harder to refute -> abstain)

    def refute(self, dim_fields):
        """dim_fields: list of field-path substrings naming the claimed dimension D (e.g. ['host','origin']).
        Refuted iff on every success path, success forces equality of the two records in some dim field."""
        self.analyze_calls()
        self.success_path_setup = True
        paths = self.success_return_paths()
        if not paths:
            return ("no_success_path", 0, 0)
        # also require the terminal predicate (bb reaching the success return via an EQLIB call) to hold
        n_unsat = 0
        tested = 0
        for guards, _ in paths:
            s = Solver()
            s.set("timeout", 10000)
            for (e, truth) in guards:
                self._guard_bool(e, truth, s)
            # terminal success predicate: any EQLIB call whose result is the returned PHI source on this path
            for ssa, (tx, ty, pred) in self.eqcalls.items():
                if self._feeds_success(ssa):
                    b = Bool("eq_" + ssa)
                    s.add(Implies(b, self.term(*tx) == self.term(*ty)))
                    s.add(b)
            # phi: the two records differ in dimension D
            pair = self._two_records()
            if not pair:
                continue
            ra, rb = pair
            dis = []
            for (rec, path), t in list(self.terms.items()):
                if any(df in path for df in dim_fields):
                    other = (rb if rec == ra else ra, path)
                    dis.append(self.term(*other) != t)
            if not dis:
                # create the dimension terms explicitly on both records
                for df in dim_fields:
                    dis.append(self.term(ra, df) != self.term(rb, df))
            s.add(Or(*dis) if len(dis) > 1 else dis[0])
            # propagate prefix equality implied by EQLIB equalities already added via Implies+assert
            self._prefix_equalities(s)
            tested += 1
            if s.check() == unsat:
                n_unsat += 1
        verdict = "refuted" if tested and n_unsat == tested else "cannot_refute"
        return (verdict, tested, n_unsat)

    def _feeds_success(self, ssa):
        # the returned value is a PHI; an EQLIB result that is one of its sources feeds success
        for b in self.blocks.values():
            for s in b["stmts"]:
                if s["text"].startswith("return") or "PHI" in s["text"]:
                    if ssa in s["text"]:
                        return True
                # PHI printed on its own line starting with '#'
        for b in self.blocks.values():
            for s in b["stmts"]:
                if s["text"].lstrip().startswith("#") and "PHI" in s["text"] and ssa in s["text"]:
                    return True
        return False

    def _two_records(self):
        recs = sorted(set(self.records.values()))
        return (recs[0], recs[1]) if len(recs) >= 2 else None

    def _prefix_equalities(self, s):
        # if an EQLIB equality tied records A,B at path P, subfields P.* should be equal too
        eqpairs = []
        for ssa, (tx, ty, pred) in self.eqcalls.items():
            if self._feeds_success(ssa):
                eqpairs.append((tx, ty))
        for (ra, pa), ta in list(self.terms.items()):
            for (rb, pb), tb in list(self.terms.items()):
                if ra == rb:
                    continue
                for (tx, ty) in eqpairs:
                    (rx, px), (ry, py) = tx, ty
                    if {ra, rb} == {rx, ry} and pa == pb and (pa.startswith(px) or pa.startswith(py) or px == "" or py == ""):
                        s.add(Implies(self.term(*tx) == self.term(*ty), ta == tb))
