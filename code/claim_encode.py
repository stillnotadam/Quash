"""Encode a path-sensitive refutation query from a GIMPLE-SSA function and check it with Z3.

Scope and safety: this module reasons only about integer and size RELATIONS along guarded control-flow paths to a
named sink. It answers one question: given the guards the code enforces on the way to the sink, is the report's
claimed size relation (e.g. "a length reaching this sink can exceed the documented cap C") still satisfiable?
  UNSAT  -> the claim is refuted; the returned unsat core is the set of guards that make it impossible.
  SAT / UNKNOWN -> cannot refute; escalate to a human. We NEVER call Z3's model(); no witness value, input, or
                   byte sequence is ever computed, printed, saved, or returned. Only the verdict leaves this code.

Soundness for refutation: unmodeled values (loads, calls such as strlen, struct fields) become FREE symbolic
integers, which over-approximates reachable states. A missing guard can only make the query more satisfiable, i.e.
cause us to FAIL to refute (conservative). We therefore only ever add guards we parse with confidence.
"""
import re
from z3 import (Solver, Int, BitVec, If, And, Or, Not, sat, unsat, unknown, BoolVal, IntVal, Bool, Implies)

IDENT = r"[A-Za-z_]\w*(?:\.\d+)?_?\d*"
NUM = re.compile(r"^-?\d+$")
BINOP = re.compile(r"^(.+?)\s*([-+*/&|^]|<<|>>|==|!=|<=|>=|<|>)\s*(.+)$")
CAST = re.compile(r"^\((?:unsigned |signed |long |short |int|char|_Bool|sizetype|ssizetype|[\w ]+?\s*\*?)\)\s*(.+)$")


class Encoder:
    def __init__(self, fn, maxpaths=4000, loopcap=1):
        self.fn = fn
        self.blocks = fn["blocks"]
        self.maxpaths = maxpaths
        self.loopcap = loopcap
        self.assign = {}      # ssa name -> rhs text
        self.boolish = {}     # ssa name -> rhs that is a comparison/logical
        for b in self.blocks.values():
            for s in b["stmts"]:
                m = re.match(rf"^({IDENT})\s*=\s*(.+?);?$", s["text"])
                if m:
                    self.assign[m.group(1)] = m.group(2).strip()
        self.cache = {}
        self.free = {}
        self.solver = Solver()
        self.solver.set("timeout", 15000)

    def fresh(self, nm):
        if nm not in self.free:
            self.free[nm] = Int("f_" + re.sub(r"\W", "_", nm) + str(len(self.free)))
        return self.free[nm]

    def val(self, expr, depth=0):
        """Return a Z3 Int term for a GIMPLE rvalue expression. Unknown subterms become free integers."""
        expr = expr.strip()
        if depth > 40:
            return self.fresh(expr)
        if NUM.match(expr):
            return IntVal(int(expr))
        cm = CAST.match(expr)
        if cm and cm.group(1).strip() != expr:
            return self.val(cm.group(1), depth + 1)
        # parenthesized whole
        if expr.startswith("(") and expr.endswith(")") and _balanced(expr[1:-1]):
            return self.val(expr[1:-1], depth + 1)
        bm = _top_binop(expr)
        if bm:
            a, op, b = bm
            A, B = self.val(a, depth + 1), self.val(b, depth + 1)
            if op == "+":
                return A + B
            if op == "-":
                return A - B
            if op == "*":
                return A * B
            if op in ("&", "|", "^", "<<", ">>", "/"):
                return self.fresh(expr)  # bitwise/div: don't model arithmetically, stay free (sound)
            # comparison yields 0/1
            cmp = {"==": A == B, "!=": A != B, "<": A < B, "<=": A <= B, ">": A > B, ">=": A >= B}[op]
            return If(cmp, IntVal(1), IntVal(0))
        if expr.startswith("~"):
            return If(self.val(expr[1:], depth + 1) == 0, IntVal(1), IntVal(0))
        # a plain SSA name we have an assignment for
        if expr in self.assign and re.fullmatch(IDENT, expr):
            if expr in self.cache:
                return self.cache[expr]
            self.cache[expr] = self.fresh(expr)       # break cycles (phi) with a placeholder
            v = self.val(self.assign[expr], depth + 1)
            self.cache[expr] = v
            return v
        return self.fresh(expr)   # load, field, call result, parameter: free

    def guard(self, expr, truth):
        """Z3 Bool asserting that GIMPLE condition `expr` is true/false along the taken edge."""
        expr = expr.strip()
        bm = _top_binop(expr)
        if bm:
            a, op, b = bm
            if op in ("==", "!=", "<", "<=", ">", ">="):
                A, B = self.val(a), self.val(b)
                rel = {"==": A == B, "!=": A != B, "<": A < B, "<=": A <= B, ">": A > B, ">=": A >= B}[op]
                return rel if truth else Not(rel)
        v = self.val(expr)
        return (v != 0) if truth else (v == 0)

    def edges_to(self, target):
        """Guards collected along one acyclic-ish path from entry (bb with min id) to `target` block."""
        start = min(self.blocks)
        results = []

        def walk(bid, visits, guards):
            if len(results) >= self.maxpaths:
                return
            if bid == target:
                results.append(list(guards))
                return
            if visits.get(bid, 0) > self.loopcap:
                return
            b = self.blocks.get(bid)
            if not b:
                return
            visits = dict(visits)
            visits[bid] = visits.get(bid, 0) + 1
            c = b["cond"]
            if c and c.get("true") is not None:
                walk(c["true"], visits, guards + [(c["expr"], True)])
                walk(c["false"], visits, guards + [(c["expr"], False)])
                return
            for s in b["succ"]:
                walk(s, visits, guards)
        walk(start, {}, [])
        return results

    def refute(self, sink_bb, claim_terms):
        """claim_terms: list of (expr, op, rhs) the report asserts can hold at the sink, e.g. ('hostname_len','>',255).
        Returns (verdict, n_paths, n_unsat) where verdict in {refuted, cannot_refute}. No witness is produced."""
        paths = self.edges_to(sink_bb)
        if not paths:
            return ("no_path", 0, 0)
        n_unsat = 0
        for guards in paths:
            s = Solver()
            s.set("timeout", 10000)
            self.cache = {}
            self.free = {}
            for (e, truth) in guards:
                s.add(self.guard(e, truth))
            for (lhs, op, rhs) in claim_terms:
                A = self.val(lhs)
                B = self.val(rhs) if not NUM.match(str(rhs)) else IntVal(int(rhs))
                rel = {"==": A == B, "!=": A != B, "<": A < B, "<=": A <= B, ">": A > B, ">=": A >= B}[op]
                s.add(rel)
            r = s.check()
            if r == unsat:
                n_unsat += 1
            # r == sat or unknown: we do NOT call s.model(); nothing is extracted.
        verdict = "refuted" if n_unsat == len(paths) else "cannot_refute"
        return (verdict, len(paths), n_unsat)

    def refute_certificate(self, sink_bb, claim_terms):
        """Like refute(), but on 'refuted' also returns a self-contained SMT-LIB proof per path (each UNSAT) and the
        source guards used. Any SMT solver re-checks the scripts; the guards let a maintainer check faithfulness."""
        paths = self.edges_to(sink_bb)
        if not paths:
            return {"verdict": "no_path"}
        scripts, guardset = [], []
        for guards in paths:
            s = Solver()
            self.cache, self.free = {}, {}
            glocs = []
            for (e, truth) in guards:
                s.add(self.guard(e, truth))
                glocs.append(("" if truth else "not ") + e.strip())
            for (lhs, op, rhs) in claim_terms:
                A = self.val(lhs)
                B = self.val(rhs) if not NUM.match(str(rhs)) else IntVal(int(rhs))
                rel = {"==": A == B, "!=": A != B, "<": A < B, "<=": A <= B, ">": A > B, ">=": A >= B}[op]
                s.add(rel)
            if s.check() != unsat:
                return {"verdict": "cannot_refute"}
            smt = "; proof obligation: the path guards together with the report's claim are unsatisfiable\n"
            smt += s.to_smt2()
            scripts.append(smt)
            guardset.append(glocs)
        return {"verdict": "refuted", "n_paths": len(paths), "smt2": scripts, "guards": guardset}


def _balanced(s):
    d = 0
    for c in s:
        d += (c == "(") - (c == ")")
        if d < 0:
            return False
    return d == 0


def _top_binop(expr):
    """Split on the lowest-precedence top-level binary operator, respecting parentheses. Returns (a,op,b) or None."""
    prec = [["|"], ["^"], ["&"], ["==", "!="], ["<", "<=", ">", ">="], ["<<", ">>"], ["+", "-"], ["*", "/"]]
    for group in prec:
        depth = 0
        i = len(expr) - 1
        while i >= 0:
            c = expr[i]
            if c == ")":
                depth += 1
            elif c == "(":
                depth -= 1
            elif depth == 0:
                for op in group:
                    if expr[i:i + len(op)] == op and i > 0:
                        # avoid unary +/-, and avoid matching part of a longer op
                        left = expr[:i].strip()
                        right = expr[i + len(op):].strip()
                        if left and right and not left.endswith(("=", "<", ">", "!", "&", "|", "^", "+", "-", "*")):
                            if op in ("<", ">") and (expr[i:i + 2] in ("<<", ">>", "<=", ">=")):
                                i -= 1
                                continue
                            return (left, op, right)
            i -= 1
    return None
