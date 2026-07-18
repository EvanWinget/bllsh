#!/usr/bin/env python3
"""Semantics tests for the symbll apply surface.

The symbolic evaluator and compiler accept (a PROG ENV): both
operands are evaluated symbolically, then PROG runs as a bll program
with ENV as its environment. These tests pin the surface from both
sides. The positive cases show programs resolving environment
references against the passed environment, nesting a further apply
inside the program, and agreeing between the symbolic and compiled
paths. The negative cases pin the arity restriction (bll's apply
defaults a missing environment to the current one, which a symbol
table cannot mirror), the rejection of non-bll programs, and clean
delivery of a nested budget exhaustion. The symbolic evaluator is
off-consensus tooling, so there is no charge contract to pin here.

Run from anywhere: ./test-apply.py
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bll
import symbll
from costs import Budget, DEFAULT_BUDGET
from element import ALLOCATOR, Atom, Element, Error, SExpr
from testutil import case, report


def make_symbols(defs):
    """A symbol table built from def lines, as the repl's def does."""
    syms = symbll.SymbolTable()
    for d in defs:
        parsed = SExpr.parse(d, manypy=True)
        assert len(parsed) == 2, d
        sym, val = parsed
        if sym.is_symbol():
            syms.set(sym.val2, (Atom(0), val.bumpref()))
        else:
            assert sym.is_cons() and sym.val1.is_symbol(), d
            syms.set(sym.val1.val2, (sym.val2.bumpref(), val.bumpref()))
        Element.deref_all(sym, val)
    return syms


def sym_run(src, defs=()):
    syms = make_symbols(defs)
    r = symbll.symbolic_eval(SExpr.parse(src), syms)
    syms.deref()
    return r


def compiled_run(fname, envsrc, defs):
    """The compiled program for fname evaluated under a bll env."""
    syms = make_symbols(defs)
    prog = symbll.compile_program(fname, syms)
    syms.deref()
    se = SExpr.parse(envsrc)
    env = bll.ToBLL(se)
    se.deref()
    return bll.eval(prog, env, Budget(DEFAULT_BUDGET))


def evals(name, src, want, defs=()):
    """src evaluates symbolically to exactly the wanted rendering."""
    def fn():
        r = sym_run(src, defs)
        ok = not isinstance(r, Error) and str(r) == want
        shown = str(r)[:70]
        r.deref()
        return ok, shown
    case(name, fn)


def errs(name, src, want, defs=()):
    """src evaluates symbolically to an error carrying the message."""
    def fn():
        r = sym_run(src, defs)
        ok = isinstance(r, Error) and want in str(r)
        shown = str(r)[:70]
        r.deref()
        return ok, shown
    case(name, fn)


def sha256tree_ref(el):
    """The tree hash the SHA256TREE def computes, in Python."""
    if el.is_cons():
        return hashlib.sha256(
            b'\x02' + sha256tree_ref(el.val1) + sha256tree_ref(el.val2)
        ).digest()
    return hashlib.sha256(b'\x01' + el.val2).digest()


APPLY2_DEF = "(APPLY2 P E) (a P E)"

SHA256TREE_DEF = ("(SHA256TREE T) (if (l T)"
                  " (sha256 2 (SHA256TREE (h T)) (SHA256TREE (t T)))"
                  " (sha256 1 T))")


# ---- the positive surface ----

evals("apply/quoted-program", "(a (q 0 . 1) (q . 0))", "1")
# environment references resolve against the passed environment, not
# the symbol table the outer expression runs under
evals("apply/env-left", "(a (q . 2) (q 7 . 8))", "7")
evals("apply/env-right", "(a (q . 3) (q 7 . 8))", "8")
# both operands are symbolically evaluated before the handoff
evals("apply/computed-env", "(a (q . 2) (rc 8 7))", "7")
# the program may itself apply: (a (q 0 . 1) (q . 0)) spelled in
# opcode numbers, run as the program operand
evals("apply/nested-apply", "(a (q 1 (0 0 . 1) (0 . 0)) (q . 0))", "1")
# a user function body can carry the apply
evals("apply/in-user-func", "(APPLY2 (q 0 . 1) 9)", "1", defs=[APPLY2_DEF])


def parity(name, symsrc, fname, envsrc, defs):
    """The symbolic and compiled paths agree on a non-error result."""
    def fn():
        r0 = sym_run(symsrc, defs=defs)
        r1 = compiled_run(fname, envsrc, defs=defs)
        ok = (not isinstance(r0, Error) and not isinstance(r1, Error)
              and str(r0) == str(r1))
        shown = f"symbolic {str(r0)[:30]}, compiled {str(r1)[:30]}"
        Element.deref_all(r0, r1)
        return ok, shown
    case(name, fn)

parity("apply/compile-parity",
       "(APPLY2 (q 0 . 1) 9)", "APPLY2", "((0 . 1) . 9)", [APPLY2_DEF])


# ---- tree recursion over the program operand's shape ----

def tree_hash(name, treesrc):
    """SHA256TREE of the quoted tree matches the Python reference."""
    def fn():
        se = SExpr.parse(treesrc)
        want = "0x" + sha256tree_ref(se).hex()
        se.deref()
        r = sym_run(f"(SHA256TREE (q . {treesrc}))", defs=[SHA256TREE_DEF])
        ok = str(r) == want
        shown = str(r)[:70]
        r.deref()
        return ok, shown
    case(name, fn)

tree_hash("sha256tree/atom", "1")
tree_hash("sha256tree/pair", "(0 . 1)")
tree_hash("sha256tree/deep", "((0 . 1) 0 . 1)")


parity("sha256tree/compile-parity",
       "(SHA256TREE (q 0 . 1))", "SHA256TREE", "(0 . 1)", [SHA256TREE_DEF])


# ---- the arity restriction and other escape routes ----

errs("apply/arity-zero", "(a)",
     "a: requires a program and an environment")
errs("apply/arity-one", "(a (q 0 . 1))",
     "a: requires a program and an environment")
errs("apply/arity-three", "(a (q . 1) (q . 2) (q . 3))",
     "too many args to apply")
# the same arity error from inside a user function body, where the
# environment is a live local symbol table rather than the dummy
errs("apply/arity-three-in-user-func", "(F (q . 1))",
     "too many args to apply", defs=["(F P) (a P P P)"])
errs("apply/improper-args", "(a (q . 1) . 5)",
     "argument to a is improper list")
# a function object is not a program
errs("apply/function-object-program", "(a (partial sha256) (q . 0))",
     "cannot evaluate a function object")
# a quoted tree containing symbols is not bll, so it is not a
# program either: quoted programs must be spelled in opcode numbers
errs("apply/symbolic-program", "(a (q sha256 (0 . 1)) (q . 0))",
     "cannot evaluate a function object")
# a nested exhaustion is delivered as an ordinary error: the shift
# demand prices past the shared budget before allocating
errs("apply/nested-exhaustion",
     "(a (q 27 (0 . 1) (0 . 36893488147419103232)) (q . 0))",
     "budget exhausted")
# the symbolic evaluator's guards stay active across the nested run:
# a self-applying program hits the step allowance instead of hanging
errs("apply/nested-cost-overrun", "(a (q 1 1 1) (q 1 1 1))",
     "cost overrun, aborting")
# and a shift affordable under the budget still hits the allocation
# cap between nested steps
errs("apply/nested-memory-overrun",
     "(a (q 27 (0 . 1) (0 . 4000000)) (q . 0))",
     "memory overrun, aborting")


def compile_arity():
    """The compiler rejects apply without both operands."""
    syms = make_symbols(["(BAD P) (a P)"])
    try:
        prog = symbll.compile_program("BAD", syms)
        prog.deref()
        ok, shown = False, "compiled"
    except Exception as e:
        ok = "a requires a program and an environment" in str(e)
        shown = str(e)[:70]
    syms.deref()
    return ok, shown
case("apply/compile-arity", compile_arity)


# ---- allocator balance across success and error paths ----

def no_leaks():
    before = ALLOCATOR.x
    for src in ["(a (q 0 . 1) (q . 0))",
                "(a (q 0 . 1))",
                "(a (q . 1) (q . 2) (q . 3))",
                "(a (partial sha256) (q . 0))",
                "(a (q 27 (0 . 1) (0 . 36893488147419103232)) (q . 0))",
                "(a (q 1 1 1) (q 1 1 1))",
                "(a (q 27 (0 . 1) (0 . 4000000)) (q . 0))"]:
        r = sym_run(src)
        r.deref()
    r = sym_run("(F (q . 1))", defs=["(F P) (a P P P)"])
    r.deref()
    r = sym_run("(SHA256TREE (q 0 . 1))", defs=[SHA256TREE_DEF])
    r.deref()
    leaked = ALLOCATOR.x - before
    return leaked == 0, f"leaked {leaked} bytes"
case("apply/no-leaks", no_leaks)

report()
