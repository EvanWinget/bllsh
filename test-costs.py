#!/usr/bin/env python3
"""Charge tests for the cost accounting.

Each total is written out as explicit costs.py arithmetic so a wrong
constant or a missing charge site fails the assertion, and the
boundary replay cases pin the exhaustion contract from both sides:
an evaluation that completed with charged total C completes
identically when replayed with budget C and reports exhaustion with
used C-1 when replayed with budget C-1.

Run from anywhere: ./test-costs.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import costs
from costs import Budget, atom_scan
from element import SerDeser, Atom, Error, Element, SExpr
from testutil import case, mach, replay, report, run, total


# the budget latch: a failed charge pins used to the full limit and
# every later charge fails, including free ones
def latch():
    b = Budget(10)
    steps = [b.charge(4), b.used == 4, not b.exhausted,
             not b.charge(7), b.used == 10, b.exhausted,
             not b.charge(0), b.used == 10]
    return all(steps), f"used {b.used} exhausted {b.exhausted}"
case("budget-latch", latch)

def zero_fits():
    b = Budget(0)
    return b.charge(0) and b.used == 0 and not b.exhausted, f"used {b.used}"
case("budget-zero-charge-fits", zero_fits)

case("atom-scan-exemption",
     lambda: (atom_scan(8) == 0 and atom_scan(9) == 9 and atom_scan(0) == 0,
              f"{atom_scan(8)}, {atom_scan(9)}"))

# machine charges: the env walk pays per edge including the edge that
# discovers an invalid reference, and wide program atoms pay the scan
total("machine/env-error-pays-edge", "2",
      costs.STEP + costs.ENV_EDGE, want="invalid env reference")
total("machine/wide-program-atom-scan", "0x010203040506070809",
      costs.STEP + atom_scan(9) + costs.ENV_EDGE,
      want="invalid env reference")
total("machine/wide-operator-atom-scan",
      "(0x0e000000000000000000 (q . 2) (q . 2))",
      mach(2) + atom_scan(10) + 2 * costs.COMPARE_ARG + costs.COMPARE_PER_BYTE)

# control and fixed-arity collection
total("control/i", "(i (q . 1) (q . 2) (q . 3))",
      mach(3) + 3 * costs.FIX_COLLECT + costs.CONTROL_BASE)
total("control/x-error-charged", "(x)",
      2 * costs.STEP + costs.CONTROL_BASE, want="Exception")
total("control/rc", "(rc (q . 1) (q . 2))", mach(2) + 2 * costs.RC_ARG)
# b's finish conses one pending subtree per set bit of the count
# beyond the first (none for two arguments, one for three, the
# newest subtree rides the merged slot), each charged at finish
# since a shared binding re-runs the finish per finalise
total("control/b", "(b (q . 1) (q . 2))", mach(2) + 2 * costs.B_ARG)
total("control/b-finish-cons", "(b (q . 1) (q . 2) (q . 3))",
      mach(3) + 3 * costs.B_ARG + costs.ELEMENT_ALLOC)
total("logic/all", "(all (q . 1) (q . 1))", mach(2) + 2 * costs.LOGIC_ARG)

# compare: the sticky chains pay the per-argument base even after
# failing, and only atom comparisons pay the byte scan
total("compare/eq", "(= (q . 0x0102) (q . 0x0102) (q . 0x0102))",
      mach(3) + 3 * costs.COMPARE_ARG + 2 * 2 * costs.COMPARE_PER_BYTE)
total("compare/eq-sticky", "(= (q . 5) (q 1 . 2) (q . 4))",
      mach(3) + 3 * costs.COMPARE_ARG)
total("compare/lt-num", "(< (q . 3) (q . 0x0405))",
      mach(2) + 2 * costs.COMPARE_ARG + costs.LT_NUM_PER_BYTE * (1 + 2))
total("compare/lt-str", '(<s (q . "a") (q . "ab"))',
      mach(2) + 2 * costs.COMPARE_ARG + 2 * costs.COMPARE_PER_BYTE)
total("compare/bigeq-shared-walk", "(=== (q 1 2) (q 1 2))",
      mach(2) + 2 * costs.COMPARE_ARG + 5 * costs.BIGEQ_PER_NODE
      + 2 * costs.COMPARE_PER_BYTE)
total("compare/strlen", "(strlen (q . 0x010203))",
      mach(1) + costs.STRLEN_ARG + costs.ELEMENT_ALLOC)

# bytes: cat recopies its state every fold, which is the quadratic
# self-append pricing, the delivered accumulator's element object is
# charged flat at finish (the and_bytes nil passthrough overpays it,
# the safe direction), and the passthrough stays free of the size
# charge
BYTE = costs.COPY_PER_BYTE + costs.MALLOC_PER_BYTE
total("bytes/cat-quadratic", "(cat (q . 0x0102) (q . 0x03) (q . 0x04))",
      mach(3) + 3 * costs.CAT_ARG + BYTE * ((0 + 2) + (2 + 1) + (3 + 1))
      + costs.ELEMENT_ALLOC)
total("bytes/and-nil-passthrough", "(& (q . 0x0102))",
      mach(1) + costs.BITWISE_ARG + costs.ELEMENT_ALLOC)
total("bytes/and-second-fold", "(& (q . 0x0102) (q . 0x03))",
      mach(2) + 2 * costs.BITWISE_ARG + BYTE * 2 + costs.ELEMENT_ALLOC)
total("bytes/xor", "(^ (q . 0x0102) (q . 0x030405))",
      mach(2) + 2 * costs.BITWISE_ARG + BYTE * 2 + BYTE * 3
      + costs.ELEMENT_ALLOC)
total("bytes/substr-range", "(substr (q . 0x0102030405) (q . 1) (q . 3))",
      mach(3) + 3 * costs.FIX_COLLECT + costs.SUBSTR_BASE + BYTE * 2)
total("bytes/substr-identity", "(substr (q . 0x010203) (q . 0))",
      mach(2) + 2 * costs.FIX_COLLECT + costs.SUBSTR_BASE)
total("bytes/substr-past-end-nil", "(substr (q . 0x01) (q . 5))",
      mach(2) + 2 * costs.FIX_COLLECT + costs.SUBSTR_BASE)

# arithmetic: scans over both operands, allocation on the minimal
# encoding, the delivered total's element object charged flat at
# finish, the sub marker fold base-only with the charged finish
# negation, mul's divided product term and mod's by-zero error
# paying the full division charge
total("arith/add", "(+ (q . 5) (q . 3))",
      mach(2) + 2 * costs.ARITH_ARG
      + costs.ARITH_PER_BYTE * (0 + 1) + costs.MALLOC_PER_BYTE
      + costs.ARITH_PER_BYTE * (1 + 1) + costs.MALLOC_PER_BYTE
      + costs.ELEMENT_ALLOC)
total("arith/sub-negate-finish", "(- (q . 5))",
      mach(1) + costs.ARITH_ARG
      + costs.ARITH_ARG + costs.ELEMENT_ALLOC
      + costs.ARITH_PER_BYTE * 1 + costs.MALLOC_PER_BYTE)
total("arith/mul", "(* (q . 0x0102) (q . 0x0304))",
      mach(2) + 2 * costs.ARITH_ARG
      + costs.ARITH_PER_BYTE * (1 + 2) + costs.MULDIV_LIMB_PER_BYTE * 2
      + (1 * 2) // costs.MUL_PRODUCT_DIV + costs.MALLOC_PER_BYTE * 2
      + costs.ARITH_PER_BYTE * (2 + 2) + costs.MULDIV_LIMB_PER_BYTE * 2
      + (2 * 2) // costs.MUL_PRODUCT_DIV + costs.MALLOC_PER_BYTE * 3
      + costs.ELEMENT_ALLOC)
total("arith/mod-by-zero-pays-work", "(% (q . 5) (q . 0))",
      mach(2) + 2 * costs.FIX_COLLECT + costs.MOD_BASE
      + costs.MOD_PER_BYTE * (1 + 0) + costs.MULDIV_LIMB_PER_BYTE * 1
      + (1 * 0) // costs.MUL_PRODUCT_DIV,
      want="mod: attempted div by 0")
total("arith/shift-zero-free", "(shift (q . 0x0102) (q . 0))",
      mach(2) + 2 * costs.FIX_COLLECT + costs.SHIFT_BASE)
total("arith/shift-right-bound", "(shift (q . 0x0102) (q . -8))",
      mach(2) + 2 * costs.FIX_COLLECT + costs.SHIFT_BASE + BYTE * (2 + 1))
total("arith/shift-left-bound", "(shift (q . 0x01) (q . 9))",
      mach(2) + 2 * costs.FIX_COLLECT + costs.SHIFT_BASE
      + BYTE * (9 // 8 + 1 + 1))

# hashes: per argument before the shape check, per hashed byte, and
# one finish charge with the digest allocation, 20 bytes for the
# ripemd160 family
total("hash/sha256", "(sha256 (q . 0x616263))",
      mach(1) + costs.HASH_ARG + costs.HASH_PER_BYTE * 3
      + costs.HASH_BASE + costs.MALLOC_PER_BYTE * 32)
total("hash/hash160", "(hash160 (q . 0x61))",
      mach(1) + costs.HASH_ARG + costs.HASH_PER_BYTE * 1
      + costs.HASH_BASE + costs.MALLOC_PER_BYTE * 20)
# a fold error finalizes evaluation without a finish step, so its
# machine cost is one pop short of a completed application
total("hash/list-error-charged", "(sha256 (q 1 . 2))",
      mach(1) - costs.STEP + costs.HASH_ARG, want="cannot hash list")

# signatures: the nil path rides the collection charge for bip340,
# a bad ecdsa prefix pays the parse it skipped, a garbage signature
# pays the verification it asked for
PK32 = "0x" + "11" * 32
MSG32 = "0x" + "22" * 32
BADPK33 = "0x05" + "11" * 32
SIG64 = "0x" + "33" * 64
total("sig/bip340-nil-flat", f"(bip340_verify (q . {PK32}) (q . {MSG32}) (q . 0))",
      mach(3) + 3 * costs.FIX_COLLECT)
total("sig/bip340-verify-charged",
      f"(bip340_verify (q . {PK32}) (q . {MSG32}) (q . {SIG64}))",
      mach(3) + 3 * costs.FIX_COLLECT + costs.SIG_VERIFY,
      want="invalid, non-empty signature")
total("sig/ecdsa-bad-prefix-pays-parse",
      f"(ecdsa_verify (q . {BADPK33}) (q . {MSG32}) (q . 0))",
      mach(3) + 3 * costs.FIX_COLLECT + costs.ECDSA_PARSE,
      want="invalid pubkey")

# muladd: per argument at the fold, base at finish, and one charge
# per term inside the walk, newest term first, so a decode error
# leaves older terms unpaid
total("muladd/empty", "(secp256k1_muladd)",
      2 * costs.STEP + costs.MULADD_BASE)
total("muladd/per-term", "(secp256k1_muladd (q . 1) (q . 2))",
      mach(2) + 2 * costs.MULADD_ARG + costs.MULADD_BASE
      + 2 * costs.MULADD_PER_TERM,
      want="did not sum to inf")
total("muladd/newest-term-error-first", "(secp256k1_muladd (q . 1) (q 1 . 5))",
      mach(2) + 2 * costs.MULADD_ARG + costs.MULADD_BASE
      + costs.MULADD_PER_TERM,
      want="unparseable point")

# codec: rd charges per decoded element with the allocation share on
# payload bytes only, insufficient data is never charged, trailing
# data pays twice the per-byte rate for its hex rendering, and wr
# charges per element and per emitted byte, headers included
RD_BYTE = costs.RD_PER_BYTE + costs.MALLOC_PER_BYTE
WR_BYTE = costs.WR_PER_BYTE + costs.MALLOC_PER_BYTE
total("codec/rd", "(rd (q . 0xff0102))",
      mach(1) + costs.FIX_COLLECT + costs.RD_BASE + 3 * costs.RD_PER_ELEMENT)
total("codec/rd-payload", "(rd (q . 0x820304))",
      mach(1) + costs.FIX_COLLECT + costs.RD_BASE
      + costs.RD_PER_ELEMENT + RD_BYTE * 2)
total("codec/rd-insufficient-uncharged", "(rd (q . 0x81))",
      mach(1) + costs.FIX_COLLECT + costs.RD_BASE,
      want="insuffient")
total("codec/rd-trailing-charged", "(rd (q . 0x8080))",
      mach(1) + costs.FIX_COLLECT + costs.RD_BASE + costs.RD_PER_ELEMENT
      + 2 * RD_BYTE * 1,
      want="incomplete deserialization")
total("codec/wr", "(wr (q . (1 . 2)))",
      mach(1) + costs.FIX_COLLECT + costs.WR_BASE
      + 3 * costs.WR_PER_ELEMENT + WR_BYTE * 3)
total("codec/wr-prefixed-atom", "(wr (q . 0x030405))",
      mach(1) + costs.FIX_COLLECT + costs.WR_BASE
      + costs.WR_PER_ELEMENT + WR_BYTE * 4)

# boundary replay from both sides over one program per family
REPLAY_PROGRAMS = [
    "2",
    "(i (q . 1) (q . 2) (q . 3))",
    "(= (q . 0x0102) (q . 0x0102) (q . 0x0103))",
    "(=== (q 1 2) (q 1 2))",
    "(cat (q . 0x0102) (q . 0x03) (q . 0x04))",
    "(substr (q . 0x0102030405) (q . 1) (q . 3))",
    "(+ (q . 5) (q . 3))",
    "(- (q . 5))",
    "(* (q . 0x0102) (q . 0x0304))",
    "(% (q . 5) (q . 3))",
    "(% (q . 5) (q . 0))",
    "(shift (q . 0x0102) (q . -8))",
    "(sha256 (q . 0x616263))",
    f"(bip340_verify (q . {PK32}) (q . {MSG32}) (q . 0))",
    "(secp256k1_muladd (q . 1) (q 1 . 5))",
    "(rd (q . 0xff0102))",
    "(rd (q . 0x8080))",
    "(wr (q . (1 . 2)))",
    "(x (q . 1))",
]
for i, src in enumerate(REPLAY_PROGRAMS):
    replay(f"replay/{i}-{src[:24]}", src)


# the charge precedes every unit of work, so a program whose error
# fires within one charge of the budget reports exhaustion rather
# than the error
def error_vs_exhaustion():
    r0, b0 = run("(h (q . 1) (q . 2))")
    c = b0.used
    ok = isinstance(r0, Error) and "too many arguments" in str(r0)
    r1, b1 = run("(h (q . 1) (q . 2))", c - 1)
    ok = ok and b1.exhausted and b1.used == c - 1
    shown = f"C={c}, at C-1 exhausted {b1.exhausted} result {str(r1)[:30]}"
    Element.deref_all(r0, r1)
    return ok, shown
case("charge-precedes-work", error_vs_exhaustion)


# a single pathological demand can latch even the default budget (a
# shift output size bound prices past it before any allocation), and
# the symbolic evaluator must abort cleanly rather than stepping an
# emptied stack
def symbll_exhaustion_aborts():
    import symbll
    r = symbll.symbolic_eval(SExpr.parse("(shift 1 36893488147419103232)"),
                             symbll.SymbolTable())
    ok = isinstance(r, Error) and "budget exhausted" in str(r)
    shown = str(r)[:60]
    r.deref()
    return ok, shown
case("symbll-exhaustion-aborts", symbll_exhaustion_aborts)


# charged runs leave the allocator balanced even when exhaustion
# unwinds mid-evaluation
def no_leak_on_exhaustion():
    from element import ALLOCATOR
    src = "(cat (q . 0x0102) (q . 0x0304) (q . 0x0506))"
    _, b_full = run(src)
    before = ALLOCATOR.x
    for limit in range(0, b_full.used + 1, 7):
        r, _ = run(src, limit)
        r.deref()
    leaked = ALLOCATOR.x - before
    return leaked == 0, f"leaked {leaked} bytes"
case("no-leak-on-exhaustion", no_leak_on_exhaustion)

report()
