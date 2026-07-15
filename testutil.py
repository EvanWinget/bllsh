"""Shared harness of the charge test suites.

Each total is written out as explicit costs.py arithmetic so a wrong
constant or a missing charge site fails the assertion, and the
boundary replay cases pin the exhaustion contract from both sides:
an evaluation that completed with charged total C completes
identically when replayed with budget C and reports exhaustion with
used C-1 when replayed with budget C-1. The suites share one harness
so the replay contract and the machine frame formula exist in one
place.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import costs
from costs import Budget, DEFAULT_BUDGET
from element import Atom, Error, Element, SExpr
import bll

results = []


def case(name, fn):
    try:
        ok, shown = fn()
        results.append((name, ok, shown))
    except Exception as e:
        results.append((name, False, f"raised {type(e).__name__}: {e}"))


def run(src, limit=None):
    se = SExpr.parse(src)
    prog = bll.ToBLL(se)
    se.deref()
    budget = Budget(DEFAULT_BUDGET if limit is None else limit)
    r = bll.eval(prog, Atom(0), budget)
    return r, budget


def mach(n):
    """Machine cost of applying one operator to n quoted arguments:
    one pop for the program, four pops per argument (the application
    step, the argument's eval, its quote and the feedback delivery)
    and one pop for the finish step."""
    return costs.STEP * (2 + 4 * n)


def total(name, src, expected, want=None):
    def fn():
        r, b = run(src)
        ok = b.used == expected and not b.exhausted
        shown = f"used {b.used}, expected {expected}"
        if want is not None:
            ok = ok and want in str(r)
            shown += f", result {str(r)[:40]}"
        r.deref()
        return ok, shown
    case(name, fn)


def replay(name, src):
    def fn():
        r0, b0 = run(src)
        c = b0.used
        r1, b1 = run(src, c)
        r2, b2 = run(src, c - 1)
        ok = (not b0.exhausted and not b1.exhausted
              and b1.used == c and str(r1) == str(r0)
              and isinstance(r1, Error) == isinstance(r0, Error)
              and b2.exhausted and b2.used == c - 1)
        shown = (f"C={c}, at C used {b1.used}, "
                 f"at C-1 {'exhausted' if b2.exhausted else 'NOT exhausted'} "
                 f"used {b2.used}")
        Element.deref_all(r0, r1, r2)
        return ok, shown
    case(name, fn)


def report():
    fails = [x for x in results if not x[1]]
    for name, ok, out in results:
        print(f"{'PASS' if ok else 'FAIL'} {name}: {out[:90]}")
    print(f"\n{len(results) - len(fails)}/{len(results)} passed")
    sys.exit(1 if fails else 0)
