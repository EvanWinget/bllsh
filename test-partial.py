#!/usr/bin/env python3
"""Semantics and charge tests for the partial restriction rule.

A partial application produces a function object, which supports
exactly three uses: binding it, passing it on, and applying it.
These tests pin both sides of that rule. The positive cases show a
function object flowing through branches, environments and nested
partial applications down to an ordinary value. The negative cases
walk every escape route: the top-level result gate, the evaluation
surface, and each operator that examines its argument. Exact totals
are written as explicit costs.py arithmetic where the machine frame
count is simple, and the boundary replay cases pin the exhaustion
contract on the paths with allowances or wide-atom scans.

Run from anywhere: ./test-partial.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import costs
from costs import atom_scan
from element import Atom, Error, Element
from testutil import case, mach, replay, report, run, total


def standalone(src):
    """The charged total of evaluating src on its own."""
    r, b = run(src)
    assert not b.exhausted, src
    r.deref()
    return b.used


def same_result(name, src, refsrc):
    """src and refsrc evaluate to the same non-error value."""
    def fn():
        r, b = run(src)
        want, _ = run(refsrc)
        ok = (not isinstance(r, Error) and not isinstance(want, Error)
              and str(r) == str(want) and not b.exhausted)
        shown = f"result {str(r)[:40]}, reference {str(want)[:40]}"
        Element.deref_all(r, want)
        return ok, shown
    case(name, fn)


def errs(name, src, want):
    """src evaluates to an error carrying the wanted message."""
    def fn():
        r, b = run(src)
        ok = isinstance(r, Error) and want in str(r) and not b.exhausted
        shown = str(r)[:70]
        r.deref()
        return ok, shown
    case(name, fn)


# A partial application in argument position costs nine frames where
# a quoted argument costs four: the dispatch, then blleval, the
# partial dispatch, its quoted argument's four frames counted as
# three here plus the delivery, the finish step, the FIN frame and
# the delivery to the receiver. The delivered function object is a
# program value, so its ELEMENT_ALLOC rides on top.
PARG = 9 * costs.STEP + costs.ELEMENT_ALLOC


# ---- the positive surface: bind, pass, apply ----

same_result("partial/finalise-applies-wrapped-opcode",
            "(partial (partial (q . 34) (q . 0x616263)))",
            "(sha256 (q . 0x616263))")
same_result("partial/zero-arity-finalise",
            "(partial (partial (q . 34)))",
            "(sha256)")
same_result("partial/extend-then-finalise",
            "(partial (partial (partial (q . 23) (q . 1)) (q . 2)))",
            "(+ (q . 1) (q . 2))")
# bind: the function object rides the environment, pass: an env
# reference hands it to partial, apply: the bare partial finalises
same_result("partial/bind-pass-apply-through-env",
            "(a (q 3 1) (partial (q . 23) (q . 1) (q . 2)))",
            "(+ (q . 1) (q . 2))")
# pass: a function object is a legal branch value of i, only the
# condition is examined
same_result("partial/i-branch-passes-function-object",
            "(partial (i (q . 1) (partial (q . 34) (q . 0x616263)) (q . 0)))",
            "(sha256 (q . 0x616263))")
# a bound function object is immutable: extending it twice from the
# same binding gives two independent results, because every fold
# copies the wrapped opcode's accumulated state, its internal
# working state (here a sha256 midstate) included
same_result("partial/bound-function-object-reused-twice",
            "(a (q rc (q . 0)"
            " (partial (partial 1 (q . 98)))"
            " (partial (partial 1 (q . 99))))"
            " (partial (q . 34) (q . 97)))",
            "(rc (q . 0) (sha256 (q . 97) (q . 98))"
            " (sha256 (q . 97) (q . 99)))")


# ---- partial's own argument checks ----

total("partial/no-arguments", "(partial)",
      2 * costs.STEP, want="partial: requires opcode argument")
total("partial/improper-arglist", "(partial . 5)",
      2 * costs.STEP, want="argument to partial is improper list")
errs("partial/rejects-quote-number", "(partial (q . 0))",
     "partial: requires a normal opcode")
errs("partial/rejects-apply-number", "(partial (q . 1))",
     "partial: requires a normal opcode")
errs("partial/rejects-own-number", "(partial (q . 3))",
     "partial: requires a normal opcode")
errs("partial/rejects-softfork-number", "(partial (q . 2))",
     "partial: requires a normal opcode")
errs("partial/rejects-unknown-number", "(partial (q . 43))",
     "partial: requires a normal opcode")
errs("partial/rejects-negative-number", "(partial (q . -1))",
     "partial: requires a normal opcode")
errs("partial/rejects-pair", "(partial (q 1 2))",
     "partial: requires a normal opcode")

# the opcode decode scan: a minimal number is free, a wide
# non-minimal alias of the same opcode charges every byte, and the
# threshold sits at machine-integer width: eight bytes scan free,
# nine charge. Each successful decode binds one charged function
# object.
total("partial/result-gate", "(partial (q . 34))",
      mach(1) + costs.ELEMENT_ALLOC,
      want="program result contains a function object")
total("partial/eight-byte-opcode-alias-scans-free",
      "(partial (q . 0x2200000000000000))",
      mach(1) + costs.ELEMENT_ALLOC,
      want="program result contains a function object")
total("partial/nine-byte-opcode-alias-charges-scan",
      "(partial (q . 0x220000000000000000))",
      mach(1) + costs.ELEMENT_ALLOC + atom_scan(9),
      want="program result contains a function object")
total("partial/wide-opcode-atom-scan",
      "(partial (q . 0x2200000000000000000000))",
      mach(1) + costs.ELEMENT_ALLOC + atom_scan(11),
      want="program result contains a function object")


# ---- the result gate ----

errs("gate/bare-function-object", "(partial (q . 34))",
     "program result contains a function object")
errs("gate/function-object-inside-pair",
     "(rc (q . 0) (partial (q . 34)))",
     "program result contains a function object")
errs("gate/function-object-via-env",
     "(a (q . 1) (partial (q . 34)))",
     "program result contains a function object")


# ---- the evaluation surface ----

errs("eval/apply-a-function-object",
     "(a (partial (q . 34)) (q . 0))",
     "cannot evaluate a function object")
errs("eval/apply-a-structure-containing-one",
     "(a (rc (q . 0) (partial (q . 34))) (q . 0))",
     "cannot evaluate a function object")
errs("eval/env-path-through-function-object",
     "(a (q . 2) (partial (q . 34)))",
     "invalid env reference")


# ---- operators that examine their argument ----

total("examine/i-condition",
      "(i (partial (q . 34)) (q . 1) (q . 2))",
      costs.STEP * 10 + PARG + 3 * costs.FIX_COLLECT + costs.CONTROL_BASE,
      want="i: condition is a function object")
total("examine/l",
      "(l (partial (q . 34)))",
      costs.STEP * 2 + PARG + costs.FIX_COLLECT + costs.CONTROL_BASE,
      want="l: argument is a function object")
errs("examine/notall", "(notall (q . 1) (partial (q . 34)))",
     "notall: argument is a function object")
errs("examine/all", "(all (q . 1) (partial (q . 34)))",
     "all: argument is a function object")
errs("examine/any", "(any (q . 0) (partial (q . 34)))",
     "any: argument is a function object")

# comparisons reject the function object on its way into the fold,
# so the check does not depend on earlier arguments
total("examine/eq",
      "(= (q . 1) (partial (q . 34)))",
      costs.STEP * 5 + PARG + 2 * costs.COMPARE_ARG,
      want="=: cannot compare a function object")
errs("examine/eq-single-argument", "(= (partial (q . 34)))",
     "=: cannot compare a function object")
errs("examine/eq-after-failed-chain",
     "(= (q . 1) (q . 2) (partial (q . 34)))",
     "=: cannot compare a function object")
errs("examine/lt-num", "(< (q . 1) (partial (q . 34)))",
     "<: cannot compare a function object")
errs("examine/lt-str", "(<s (q . 1) (partial (q . 34)))",
     "<s: cannot compare a function object")
errs("examine/bigeq-direct", "(=== (q . 1) (partial (q . 34)))",
     "===: cannot compare a function object")
errs("examine/bigeq-nested",
     "(=== (rc (q . 1) (partial (q . 34))) (rc (q . 1) (partial (q . 34))))",
     "===: cannot compare a function object")
# the === walk stops where operands already differ, so a function
# object in a region the early exit never reaches is never examined,
# the same boundary the charged serializer draws
case("examine/bigeq-early-exit-skips-unreached",
     lambda: (lambda r, b: (str(r) == "nil" and not b.exhausted,
                            f"result {r}"))(
         *run("(=== (rc (q . 2) (partial (q . 34))) (rc (q . 1) (q . 5)))")))
# the walk order is normative: head pairs are pushed before tail
# pairs and the stack pops from the top, so tails are examined
# first. A tail mismatch answers 0 before the head function object
# is reached, equal tails let the walk reach it and error
case("examine/bigeq-walk-order-tail-mismatch-first",
     lambda: (lambda r, b: (str(r) == "nil" and not b.exhausted,
                            f"result {r}"))(
         *run("(=== (rc (q . 1) (partial (q . 34))) (rc (q . 2) (q . 5)))")))
errs("examine/bigeq-walk-order-heads-reached",
     "(=== (rc (q . 1) (partial (q . 34))) (rc (q . 1) (q . 5)))",
     "===: cannot compare a function object")
# a single-argument comparison never walks, so a function object
# buried inside its one argument is never examined: === answers its
# vacuous 1 and = answers its silent nil for the pair, exactly as
# they do for any value. Only a direct function-object operand is
# rejected on entry.
case("examine/bigeq-single-arg-buried-func",
     lambda: (lambda r, b: (str(r) == "1" and not b.exhausted,
                            f"result {r}"))(
         *run("(=== (rc (q . 1) (partial (q . 34))))")))
case("examine/eq-single-arg-buried-func",
     lambda: (lambda r, b: (str(r) == "nil" and not b.exhausted,
                            f"result {r}"))(
         *run("(= (rc (q . 1) (partial (q . 34))))")))

# operators that already rejected every non-value stay errors
errs("examine/add", "(+ (q . 1) (partial (q . 34)))",
     "add requires atoms")
errs("examine/head", "(h (partial (q . 34)))", "not a list")
errs("examine/tail", "(t (partial (q . 34)))", "not a list")
errs("examine/strlen", "(strlen (partial (q . 34)))",
     "strlen: not an atom")
errs("examine/substr", "(substr (partial (q . 34)))",
     "substr: cannot take substr of non-atom")
errs("examine/shift", "(shift (partial (q . 34)) (q . 1))",
     "shift: expects atomic arguments")
errs("examine/and-bytes", "(& (q . 3) (partial (q . 34)))",
     "and_bytes: argument must be atom")
errs("examine/sha256", "(sha256 (partial (q . 34)))",
     "cannot hash list")
errs("examine/rd", "(rd (partial (q . 34)))",
     "rd: argument must be atom")
errs("examine/wr", "(wr (partial (q . 34)))",
     "can only serialize atom/cons")
errs("examine/wr-nested", "(wr (rc (q . 0) (partial (q . 34))))",
     "can only serialize atom/cons")
# x renders its arguments into the exception message, so the result
# is that error whatever the argument kinds
errs("examine/x-renders-function-object", "(x (partial (q . 34)))",
     "Exception")


# ---- unknown operators and softfork positions ----

# the flat shape ignores arguments of any kind, the charging shapes
# examine them
case("unknown/flat-shape-ignores-function-object",
     lambda: (lambda r, b: (str(r) == "nil" and not b.exhausted,
                            f"result {r}"))(
         *run("(43 (partial (q . 34)))")))
errs("unknown/charging-shape-rejects-function-object",
     "(64 (partial (q . 34)))", "unknown op requires an atom")

# softfork's lenient positions treat a function object like any
# other unrecognized shape, the forward-compatibility hook wins
errs("sf/cost-position-function-object",
     "(sf (partial (q . 34)))", "softfork requires positive cost")
total("sf/extension-position-function-object",
      "(sf (q . 100) (partial (q . 34)) (q . 7) (q . 0))",
      costs.STEP * 14 + PARG + 100, want="nil")
# every wrong-arity shape discards its evaluated values, function
# objects included, and charges exactly the declared cost
total("sf/arity-2-discards-function-object",
      "(sf (q . 100) (partial (q . 34)))",
      costs.STEP * 6 + PARG + 100, want="nil")
total("sf/arity-3-discards-function-object",
      "(sf (q . 100) (q . 0) (partial (q . 34)))",
      costs.STEP * 10 + PARG + 100, want="nil")
total("sf/arity-5-discards-function-object",
      "(sf (q . 100) (q . 0) (q . 1) (q . 2) (partial (q . 34)))",
      costs.STEP * 18 + PARG + 100, want="nil")

# a function object finishing a softfork guard is discarded by the
# guard's exit frame, never reaching the top-level gate: the atom
# program is the whole-env reference resolving to the guard's
# function-object environment
D_ENV = standalone("1") + 2 * costs.STEP + costs.GUARD
total("sf/guard-discards-function-object",
      f"(sf (q . {D_ENV}) (q . 0) (q . 1) (partial (q . 34)))",
      costs.STEP * 14 + PARG + D_ENV, want="nil")

# a function object as the guarded program fails inside the guard,
# and the error escapes when its delivery pop fits the allowance
D_EVALF = costs.GUARD + 2 * costs.STEP
total("sf/guard-program-function-object",
      f"(sf (q . {D_EVALF}) (q . 0) (partial (q . 34)) (q . 0))",
      costs.STEP * 14 + PARG + D_EVALF,
      want="cannot evaluate a function object")


# ---- boundary replay ----

replay("replay/result-gate", "(partial (q . 34))")
replay("replay/wide-opcode-atom-scan",
       "(partial (q . 0x2200000000000000000000))")
replay("replay/finalise",
       "(partial (partial (q . 34) (q . 0x616263)))")
replay("replay/bind-pass-apply",
       "(a (q 3 1) (partial (q . 23) (q . 1) (q . 2)))")
replay("replay/i-condition", "(i (partial (q . 34)) (q . 1) (q . 2))")
replay("replay/bigeq-nested",
       "(=== (rc (q . 1) (partial (q . 34))) (rc (q . 1) (partial (q . 34))))")
replay("replay/guard-discard",
       f"(sf (q . {D_ENV}) (q . 0) (q . 1) (partial (q . 34)))")
replay("replay/guard-program-function-object",
       f"(sf (q . {D_EVALF}) (q . 0) (partial (q . 34)) (q . 0))")


# ---- allocator balance across every partial path ----

def no_leak_across_budgets():
    from element import ALLOCATOR
    srcs = ["(partial (q . 34))",
            "(partial (partial (q . 34) (q . 0x616263)))",
            "(a (q 3 1) (partial (q . 23) (q . 1) (q . 2)))",
            "(a (q rc (q . 0)"
            " (partial (partial 1 (q . 98)))"
            " (partial (partial 1 (q . 99))))"
            " (partial (q . 34) (q . 97)))",
            "(sf (q . 100) (partial (q . 34)))",
            "(rc (q . 0) (partial (q . 34)))",
            "(a (partial (q . 34)) (q . 0))",
            "(i (partial (q . 34)) (q . 1) (q . 2))",
            "(= (q . 1) (partial (q . 34)))",
            "(=== (rc (q . 1) (partial (q . 34)))"
            " (rc (q . 1) (partial (q . 34))))",
            "(=== (rc (q . 1) (partial (q . 34))))",
            "(partial (q . 0x2200000000000000000000))",
            "(partial (q . 3))",
            f"(sf (q . {D_ENV}) (q . 0) (q . 1) (partial (q . 34)))",
            f"(sf (q . {D_EVALF}) (q . 0) (partial (q . 34)) (q . 0))"]
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
