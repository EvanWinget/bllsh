#!/usr/bin/env python3
"""Charge and semantics tests for the softfork opcode and the
unknown-operator rule.

Each total is written out as explicit costs.py arithmetic so a wrong
constant or a missing charge site fails the assertion. The guarded
cases pin the two declared-cost shapes: a program whose value is
handed on directly by its handler's feedback (a quote result)
consumes its standalone total plus one delivery step plus the guard
charge, while a program whose value goes through a FIN frame (an
opcode application, an atom program, a nested softfork) consumes its
standalone total plus two steps plus the guard charge, because the
FIN frame is popped inside a guard but never at top level. The
mismatch cases pin the path-stable invariant: an sf application adds
exactly its scan charges plus its declared cost to the charged total
on every path that reaches the lump charge.

Run from anywhere: ./test-softfork.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import costs
from costs import Budget, DEFAULT_BUDGET, atom_scan
from element import Atom, Error, Element
from testutil import case, mach, replay, report, run, total


def standalone(src):
    """The charged total of evaluating src on its own."""
    r, b = run(src)
    assert not b.exhausted, src
    r.deref()
    return b.used


# ---- Budget allowance mechanics ----

def allowance_routing():
    b = Budget(1000)
    steps = [b.charge(10), b.used == 10]
    b.push_allowance(50)
    steps += [b.charge(30), b.used == 10, b.allowances == [(50, 30)],
              b.charge(20), b.allowances == [(50, 50)],
              b.charge(0), b.pop_allowance(), b.used == 10,
              not b.exhausted, not b.guard_breach]
    return all(steps), f"used {b.used}"
case("budget/allowance-routing-and-exact-pop", allowance_routing)

def allowance_breach():
    b = Budget(1000)
    b.charge(10)
    b.push_allowance(50)
    steps = [not b.charge(51), b.guard_breach, not b.exhausted,
             b.used == 10, b.allowances == [(50, 0)],
             not b.charge(0), not b.charge(1)]
    b.clear_allowances()
    steps += [not b.guard_breach, b.allowances == [],
              b.charge(5), b.used == 15]
    return all(steps), f"used {b.used} breach {b.guard_breach}"
case("budget/breach-sticky-until-cleared-no-latch", allowance_breach)

def allowance_inexact_pop():
    b = Budget(1000)
    b.push_allowance(50)
    b.charge(49)
    return (not b.pop_allowance() and b.used == 0
            and not b.exhausted and not b.guard_breach), f"used {b.used}"
case("budget/inexact-pop-reports-false", allowance_inexact_pop)

def allowance_nested():
    b = Budget(1000)
    b.push_allowance(100)
    b.charge(40)
    b.push_allowance(30)
    steps = [b.charge(30), b.allowances == [(100, 40), (30, 30)],
             b.pop_allowance()]
    b.charge(60)
    steps += [b.pop_allowance(), b.used == 0]
    return all(steps), f"used {b.used}"
case("budget/nested-allowances-route-innermost", allowance_nested)


# ---- softfork hard errors: the declared cost ----

total("sf/no-arguments", "(sf)",
      2 * costs.STEP, want="softfork requires positive cost")
total("sf/zero-cost", "(sf (q . 0))",
      mach(1), want="softfork requires positive cost")
total("sf/negative-cost", "(sf (q . -5))",
      mach(1), want="softfork requires positive cost")
total("sf/pair-cost", "(sf (q 1 2))",
      mach(1), want="softfork requires positive cost")
total("sf/cost-beyond-int64", f"(sf (q . {2**63}))",
      mach(1) + atom_scan(9), want="softfork requires positive cost")
# the widest acceptable declared cost decodes but cannot be paid
# within any real budget, so the lump charge exhausts
case("sf/int64-max-exhausts",
     lambda: (lambda r, b: (b.exhausted and b.used == DEFAULT_BUDGET,
                            f"exhausted {b.exhausted} used {b.used}"))(
         *run(f"(sf (q . {2**63 - 1}) (q . 0))")))
total("sf/improper-arglist", "(sf . 5)",
      2 * costs.STEP, want="argument to opcode is improper list")


# ---- softfork opaque paths ----

total("sf/opaque-arity-1", "(sf (q . 100))", mach(1) + 100)
total("sf/opaque-arity-2", "(sf (q . 100) (q . 0))", mach(2) + 100)
total("sf/opaque-arity-3", "(sf (q . 100) (q . 0) (q . 7))", mach(3) + 100)
total("sf/opaque-arity-5", "(sf (q . 100) (q . 0) (q . 7) (q . 0) (q . 9))",
      mach(5) + 100)
total("sf/opaque-unknown-extension", "(sf (q . 100) (q . 1) (q . 7) (q . 0))",
      mach(4) + 100)
total("sf/opaque-negative-extension",
      "(sf (q . 100) (q . -1) (q . 7) (q . 0))", mach(4) + 100)
total("sf/opaque-huge-extension",
      f"(sf (q . 100) (q . {2**68}) (q . 7) (q . 0))",
      mach(4) + 100 + atom_scan(9))
total("sf/opaque-pair-extension",
      "(sf (q . 100) (q 1) (q . 7) (q . 0))", mach(4) + 100)
total("sf/wide-cost-atom-scan",
      "(sf (q . 0x640000000000000000))",
      mach(1) + atom_scan(9) + 100)
total("sf/non-minimal-operator-alias", "(0x0200 (q . 100))", mach(1) + 100)
total("sf/non-minimal-extension-alias",
      "(sf (q . 100) (q . 0x0000) (q . q) (q . 0))",
      # 0x0000 decodes to zero, so this is the recognized extension:
      # the guarded program is the bare quote returning nil
      mach(4) + 100)


# ---- softfork guarded paths ----

# The declared cost of a guarded program whose value arrives through
# a handler's feedback: standalone total plus one delivery step plus
# the guard charge.
D_QUOTE = standalone("(q . 7)") + costs.STEP + costs.GUARD
total("sf/guard-exact-handler-shape",
      f"(sf (q . {D_QUOTE}) (q . 0) (q q . 7) (q . 0))",
      mach(4) + D_QUOTE, want="nil")

# The declared cost of a guarded program that finishes as an atom:
# standalone total plus two steps plus the guard charge, because the
# FIN frame that hands the finished value over is popped inside a
# guard but never at top level.
D_ENVREF = standalone("1") + 2 * costs.STEP + costs.GUARD
total("sf/guard-exact-atom-shape",
      f"(sf (q . {D_ENVREF}) (q . 0) (q . 1) (q . 99))",
      mach(4) + D_ENVREF, want="nil")

# result discard: the guarded program returns a non-nil value and
# the sf application still delivers nil. An opcode application
# finishes through a FIN frame, so it takes the two-step shape.
D_ADD = standalone("(+ (q . 1) (q . 2))") + 2 * costs.STEP + costs.GUARD
total("sf/guard-discards-result",
      f"(sf (q . {D_ADD}) (q . 0) (q + (q . 1) (q . 2)) (q . 0))",
      mach(4) + D_ADD, want="nil")

D_UNKNOWN = standalone("(43 (q . 5))") + 2 * costs.STEP + costs.GUARD
total("sf/guard-unknown-op-inside",
      f"(sf (q . {D_UNKNOWN}) (q . 0) (q 43 (q . 5)) (q . 0))",
      mach(4) + D_UNKNOWN, want="nil")

# mismatches: the path-stable invariant holds on both failure sides
total("sf/guard-under-declared-by-one",
      f"(sf (q . {D_QUOTE - 1}) (q . 0) (q q . 7) (q . 0))",
      mach(4) + D_QUOTE - 1, want="softfork specified cost mismatch")
total("sf/guard-over-declared-by-one",
      f"(sf (q . {D_QUOTE + 1}) (q . 0) (q q . 7) (q . 0))",
      mach(4) + D_QUOTE + 1, want="softfork specified cost mismatch")
total("sf/guard-declared-below-entry-charge",
      "(sf (q . 1) (q . 0) (q q . 7) (q . 0))",
      mach(4) + 1, want="softfork specified cost mismatch")

# errors inside the guard fail the whole evaluation and still charge
# exactly the declared lump
D_X = costs.GUARD + 2 * costs.STEP + costs.CONTROL_BASE
total("sf/guard-error-inside",
      f"(sf (q . {D_X + 100}) (q . 0) (q x) (q . 0))",
      mach(4) + D_X + 100, want="Exception")

# the error-versus-mismatch precedence boundary: an error escapes the
# guard only if every charge up to and including its delivery pop
# fits the allowance. (x) consumes GUARD plus two pops plus its
# finish charge, and the error's FIN delivery pop is one more STEP:
# with exactly that much declared the error wins, one STEP less and
# the delivery pop breaches, converting the failure to the mismatch
total("sf/guard-error-delivery-fits-exactly",
      f"(sf (q . {D_X + costs.STEP}) (q . 0) (q x) (q . 0))",
      mach(4) + D_X + costs.STEP, want="Exception")
total("sf/guard-error-delivery-breaches",
      f"(sf (q . {D_X}) (q . 0) (q x) (q . 0))",
      mach(4) + D_X, want="softfork specified cost mismatch")
total("sf/guard-invalid-opcode-inside",
      f"(sf (q . {costs.GUARD + 2 * costs.STEP + 50}) (q . 0) (q -1) (q . 0))",
      mach(4) + costs.GUARD + 2 * costs.STEP + 50, want="invalid opcode")

# an error while evaluating an sf argument preempts everything: one
# pop for the program, four for the first argument, one for the
# collection step reaching (x), two for (x)'s own evaluation and one
# for the FIN frame that carries the error out
total("sf/error-in-argument", "(sf (q . 100) (x) (q . 7) (q . 0))",
      costs.STEP * 9 + costs.CONTROL_BASE, want="Exception")

# nesting: the inner guard's whole declared cost is spent from the
# outer allowance, and the inner sf's nil goes through a FIN frame
D_INNER = D_QUOTE
D_OUTER = (mach(4) + D_INNER) + 2 * costs.STEP + costs.GUARD
total("sf/nested-exact",
      f"(sf (q . {D_OUTER}) (q . 0)"
      f" (q sf (q . {D_INNER}) (q . 0) (q q . 7) (q . 0)) (q . 0))",
      mach(4) + D_OUTER, want="nil")
total("sf/nested-inner-under-declared",
      f"(sf (q . {D_OUTER}) (q . 0)"
      f" (q sf (q . {D_INNER - 1}) (q . 0) (q q . 7) (q . 0)) (q . 0))",
      mach(4) + D_OUTER, want="softfork specified cost mismatch")

# an opaque sf as an argument of another sf is just a nil argument
total("sf/opaque-sf-as-argument",
      "(sf (q . 100) (sf (q . 50)) (q . 7) (q . 0))",
      # the inner sf evaluates during collection: its own collection
      # frames plus its declared lump, then the outer opaque path
      costs.STEP * (2 + 4 * 4) + (costs.STEP * (1 + 4 * 1) + 50) + 100)


# ---- boundary replay through guards ----

replay("replay/opaque", "(sf (q . 100) (q . 1) (q . 7) (q . 0))")
replay("replay/guard-exact",
       f"(sf (q . {D_QUOTE}) (q . 0) (q q . 7) (q . 0))")
replay("replay/guard-under-declared",
       f"(sf (q . {D_QUOTE - 1}) (q . 0) (q q . 7) (q . 0))")
replay("replay/guard-over-declared",
       f"(sf (q . {D_QUOTE + 1}) (q . 0) (q q . 7) (q . 0))")
replay("replay/guard-error-inside",
       f"(sf (q . {D_X + 100}) (q . 0) (q x) (q . 0))")
replay("replay/guard-error-delivery-fits-exactly",
       f"(sf (q . {D_X + costs.STEP}) (q . 0) (q x) (q . 0))")
replay("replay/guard-error-delivery-breaches",
       f"(sf (q . {D_X}) (q . 0) (q x) (q . 0))")
replay("replay/nested-exact",
       f"(sf (q . {D_OUTER}) (q . 0)"
       f" (q sf (q . {D_INNER}) (q . 0) (q q . 7) (q . 0)) (q . 0))")
replay("replay/sf-hard-error", "(sf (q . 0))")


# ---- unknown operators ----

total("unknown/gap-0x1c-no-args", "(28)", 2 * costs.STEP + 1)
total("unknown/gap-0x1d", "(29)", 2 * costs.STEP + 1)
total("unknown/gap-0x1f", "(31)", 2 * costs.STEP + 1)
total("unknown/gap-0x2b-ignores-args", "(43 (q . 5) (q . 6))", mach(2) + 1)
total("unknown/shape0-pair-arg-accepted", "(28 (q 5 6))", mach(1) + 1)
total("unknown/shape1", "(64 (q . 5) (q . 6))",
      mach(2) + 2 * costs.ARITH_ARG + 2 * costs.ARITH_PER_BYTE)
total("unknown/shape1-zero-args-floor", "(64)", 2 * costs.STEP + 1)
total("unknown/shape2", "(128 (q . 5) (q . 6))",
      mach(2) + costs.ARITH_ARG + 2 * costs.ARITH_PER_BYTE
      + costs.MULDIV_LIMB_PER_BYTE + (1 * 1) // costs.MUL_PRODUCT_DIV)
total("unknown/shape2-single-arg-floor", "(128 (q . 5))", mach(1) + 1)
total("unknown/shape3", "(192 (q . 5) (q . 6))",
      mach(2) + 2 * costs.CAT_ARG
      + 2 * (costs.COPY_PER_BYTE + costs.MALLOC_PER_BYTE))
total("unknown/shape2-wide-atoms",
      "(128 (q . 0x0102030405060708090a) (q . 0x01020304))",
      mach(2) + costs.ARITH_ARG + costs.ARITH_PER_BYTE * (10 + 4)
      + costs.MULDIV_LIMB_PER_BYTE * 10
      + (10 * 4) // costs.MUL_PRODUCT_DIV)
total("unknown/multiplier-one", "(256)", 2 * costs.STEP + 2)
total("unknown/multiplier-two", "(512)", 2 * costs.STEP + 3)
total("unknown/multiplier-scales-shape", "(320 (q . 5) (q . 6))",
      # opnum 320 is selector 1 multiplier 1: the shape sum doubles
      mach(2) + 2 * (2 * costs.ARITH_ARG + 2 * costs.ARITH_PER_BYTE))
total("unknown/non-minimal-alias", "(0x2b00 (q . 5) (q . 6))", mach(2) + 1)
# a pair argument fails at the fold, so the finish pop of mach(1)
# never happens: five pops in all
total("unknown/shape1-pair-arg", "(64 (q 5 6))",
      costs.STEP * 5, want="unknown op requires an atom")
total("unknown/shape2-pair-arg", "(128 (q 5 6))",
      costs.STEP * 5, want="unknown op requires an atom")
total("unknown/shape3-pair-arg", "(192 (q 5 6))",
      costs.STEP * 5, want="unknown op requires an atom")
total("unknown/pair-arg-preempts-later-error", "(64 (q 5 6) (x))",
      # the fold fails on the pair before (x) is ever evaluated
      costs.STEP * 5, want="unknown op requires an atom")
total("unknown/improper-arglist", "(64 . 5)",
      2 * costs.STEP, want="argument to opcode is improper list")

# reserved and out-of-range numbers stay invalid opcodes
total("unknown/negative-reserved", "(-1)",
      costs.STEP, want="invalid opcode")
total("unknown/very-negative-reserved", "(-70000)",
      costs.STEP, want="invalid opcode")
total("unknown/at-2pow40-invalid", f"({2**40})",
      costs.STEP, want="invalid opcode")
total("unknown/beyond-int64-invalid", f"({2**68})",
      costs.STEP + atom_scan(9), want="invalid opcode")
case("unknown/below-2pow40-valid",
     lambda: (lambda r, b: (str(r) == "nil" and not b.exhausted,
                            f"result {r} used {b.used}"))(
         *run(f"({2**40 - 1})")))

# 0xff stays the assigned bigeq operator, bracketed by unknowns
total("unknown/254-is-unknown", "(254 (q . 5) (q . 5))",
      mach(2) + 2 * costs.CAT_ARG
      + 2 * (costs.COPY_PER_BYTE + costs.MALLOC_PER_BYTE))
total("assigned/255-still-bigeq", "(255 (q . 5) (q . 5))",
      mach(2) + 2 * costs.COMPARE_ARG + costs.BIGEQ_PER_NODE
      + costs.COMPARE_PER_BYTE, want="1")
total("unknown/256-is-unknown", "(256 (q . 5) (q . 5))", mach(2) + 2)

replay("replay/unknown-shape1", "(64 (q . 5) (q . 6))")
replay("replay/unknown-shape2-wide",
       "(128 (q . 0x0102030405060708090a) (q . 0x01020304))")
replay("replay/unknown-multiplier", "(320 (q . 5) (q . 6))")


# ---- partial keeps rejecting sf and unknown operators ----

def partial_rejects(opnum):
    def fn():
        r, b = run(f"(partial (q . {opnum}))")
        ok = isinstance(r, Error) and "partial: requires a normal opcode" in str(r)
        shown = str(r)[:60]
        r.deref()
        return ok, shown
    return fn
case("partial/rejects-sf", partial_rejects(2))
case("partial/rejects-unknown", partial_rejects(43))


# ---- allocator balance across every sf path ----

def no_leak_across_budgets():
    from element import ALLOCATOR
    srcs = [f"(sf (q . {D_QUOTE}) (q . 0) (q q . 7) (q . 0))",
            f"(sf (q . {D_QUOTE - 1}) (q . 0) (q q . 7) (q . 0))",
            f"(sf (q . {D_X + 100}) (q . 0) (q x) (q . 0))",
            "(sf (q . 100) (q . 1) (q . 7) (q . 0))",
            "(64 (q . 5) (q . 6))",
            f"(sf (q . {D_OUTER}) (q . 0)"
            f" (q sf (q . {D_INNER}) (q . 0) (q q . 7) (q . 0)) (q . 0))"]
    before = ALLOCATOR.x
    for src in srcs:
        r, b_full = run(src)
        r.deref()
        for limit in range(0, b_full.used + 1, 7):
            r, _ = run(src, limit)
            r.deref()
    leaked = ALLOCATOR.x - before
    return leaked == 0, f"leaked {leaked} bytes"
case("no-leak-across-budgets", no_leak_across_budgets)

report()
