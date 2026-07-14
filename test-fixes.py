#!/usr/bin/env python3
"""Regression tests for interpreter error paths.

Each case exercises an input that previously crashed the process with an
uncaught exception or assertion, or returned the wrong result, and checks
the bll-level outcome now pinned by the fixes:

- element: SerDeser.read bounds check and multi-byte size prefixes
- workitem: argument fold errors finalize evaluation
- opcodes: mod, rd and wr return bll errors instead of crashing
- opcodes: comparison chain failures are sticky

Run from anywhere: ./test-fixes.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from element import SerDeser, Atom, Error, Element, SExpr
import bll

results = []


def case(name, fn, check):
    try:
        r = fn()
        ok, shown = check(r)
        if isinstance(r, Element):
            r.deref()
        results.append((name, ok, shown))
    except Exception as e:
        results.append((name, False, f"raised {type(e).__name__}: {e}"))


def bll_eval(src):
    se = SExpr.parse(src)
    prog = bll.ToBLL(se)
    se.deref()
    return bll.eval(prog, Atom(0))


def is_err(substr):
    def check(r):
        ok = isinstance(r, Error) and substr in str(r)
        return ok, str(r)
    return check


def is_atom_len(n):
    def check(r):
        ok = isinstance(r, Atom) and not isinstance(r, Error) and len(r.val2) == n
        return ok, f"atom len {len(r.val2)}" if isinstance(r, Atom) else str(r)
    return check


def is_nil_result(r):
    return (r.is_nil() and not isinstance(r, Error)), str(r)


# SerDeser.read bounds check: truncated input fails cleanly at every
# truncation point instead of escaping as IndexError or short-reading
case("read-bounds/empty", lambda: SerDeser.Deserialize(b""), is_err("insuffient"))
case("read-bounds/trunc-header", lambda: SerDeser.Deserialize(b"\xff\x01"),
     is_err("insuffient"))
case("read-bounds/trunc-payload", lambda: SerDeser.Deserialize(b"\x81"),
     is_err("insuffient"))

# multi-byte size prefixes: two- and three-byte length forms decode
# (previously TypeError on the bytes arithmetic, including round trips
# of the serializer's own output)
case("two-byte-prefix", lambda: SerDeser.Deserialize(bytes([0xC0, 0x40]) + b"x" * 64),
     is_atom_len(64))
case("two-byte-roundtrip",
     lambda: SerDeser.Deserialize(SerDeser.Serialize(Atom(b"y" * 64))),
     is_atom_len(64))
case("three-byte-prefix",
     lambda: SerDeser.Deserialize(bytes([0xE0, 0x20, 0x00]) + b"x" * 0x2000),
     is_atom_len(0x2000))
case("zero-length-two-byte-prefix",
     lambda: SerDeser.Deserialize(bytes([0xC0, 0x00])), is_nil_result)
case("zero-length-three-byte-prefix",
     lambda: SerDeser.Deserialize(bytes([0xE0, 0x00, 0x00])), is_nil_result)


def truncated_cons_no_leak():
    """A truncation unwinding out of the cons branch must release the
    completed left subtree, or every failed decode leaks it."""
    from element import ALLOCATOR
    before = ALLOCATOR.x
    r = SerDeser.Deserialize(b"\xff\xff\x01\x02\xff\x03")
    ok = isinstance(r, Error) and "insuffient" in str(r)
    r.deref()
    leaked = ALLOCATOR.x - before
    return ok and leaked == 0, f"leaked {leaked} bytes"


case("read-bounds/trunc-cons-no-leak", truncated_cons_no_leak,
     lambda got: got)

# argument fold errors finalize evaluation: fixed-arity overflow and
# every BinOpcode error path surface as bll errors instead of crashing
# the continuation machinery
case("fix-arity/h", lambda: bll_eval("(h (q . 1) (q . 2))"), is_err("too many arguments"))
case("fix-arity/i", lambda: bll_eval("(i (q . 1) (q . 2) (q . 3) (q . 4))"),
     is_err("too many arguments"))
case("fix-arity/x", lambda: bll_eval("(x " + " ".join("(q . 1)" for _ in range(11)) + ")"),
     is_err("too many arguments"))
case("fix-arity/too-few-still-ok", lambda: bll_eval("(h)"), is_err("too few arguments"))
case("fold-error/strlen", lambda: bll_eval("(strlen (q 1 . 2))"), is_err("strlen: not an atom"))
case("fold-error/cat", lambda: bll_eval("(cat (q . 5) (q 1 . 2))"), is_err("cat: not an atom"))

# mod, rd and wr return bll errors instead of raising or asserting
case("mod-by-zero", lambda: bll_eval("(% (q . 5) (q . 0))"), is_err("mod: attempted div by 0"))
case("rd-pair", lambda: bll_eval("(rd (q 1 . 2))"), is_err("rd: argument must be atom"))
case("wr-oversize", lambda: bll_eval("(wr (shift (q . 1) (q . 8388600)))"),
     is_err("atom too large to serialize"))

# comparison chain failures are sticky: a failed < or <s chain stays
# failed instead of restarting on the next argument, matching =
case("sticky-lt-num", lambda: bll_eval("(< (q . 5) (q . 3) (q . 4))"), is_nil_result)
case("sticky-lt-str", lambda: bll_eval('(<s (q . "b") (q . "a") (q . "c"))'), is_nil_result)
case("sticky-lt-pair-reset", lambda: bll_eval("(< (q 1 . 2) (q . 1) (q . 2))"), is_nil_result)
case("lt-num-still-works", lambda: bll_eval("(< (q . 3) (q . 4) (q . 5))"),
     lambda r: (not r.is_nil() and not isinstance(r, Error), str(r)))
case("lt-eq-unchanged", lambda: bll_eval("(= (q . 5) (q . 3) (q . 4))"), is_nil_result)

fails = [x for x in results if not x[1]]
for name, ok, out in results:
    print(f"{'PASS' if ok else 'FAIL'} {name}: {out[:90]}")
print(f"\n{len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
