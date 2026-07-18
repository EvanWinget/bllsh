#!/usr/bin/env python3
"""Tests for the bll taproot spend validation in spend.py.

The canonical decoder cases pin the unique-encoding rule from both
sides: every canonical form round-trips and every redundant form is
refused by name. The spend cases drive verify_spend end to end over
a real transaction, one case per refusal reason, so the fixed stack
layout, the commitment check, the budget derivation and the
acceptance predicate each have a vector that fails if the rule
moves.

Run from anywhere: ./test-spend.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bll
import costs
import spend
from costs import Budget, budget_for_witness_size
from element import ALLOCATOR, Atom, Element, Error, SExpr, SerDeser
from testutil import case, report
from verystable.core.key import TaggedHash, compute_xonly_pubkey, tweak_add_pubkey
from verystable.core.messages import (MAX_BLOCK_WEIGHT, COutPoint, CTransaction,
                                      CTxIn, CTxInWitness, CTxOut, ser_string)

# deterministic fixture key, obviously not for real use
KEY_IPK = (7).to_bytes(32, "big")
IPK = compute_xonly_pubkey(KEY_IPK)[0]
FUNDING_TXID = int.from_bytes(bytes(range(32)), "little")
FUNDING_VALUE = 100000

BIG = Budget(2**62)


def prog(src):
    """Serialized bll program for a named-opcode source string."""
    se = SExpr.parse(src)
    p = bll.ToBLL(se)
    se.deref()
    b = SerDeser.Serialize(p)
    p.deref()
    return b


def leaf_hash(script):
    return TaggedHash("TapLeaf", bytes([spend.LEAF_VERSION_BLL]) + ser_string(script))


def ser_atom(b):
    a = Atom(b)
    s = SerDeser.Serialize(a)
    a.deref()
    return s


def make_spend(program, env, leafver=spend.LEAF_VERSION_BLL, path=(),
               reveal=None, annex=None, extra=None, spk=None, cb=None):
    """A transaction spending one output that commits program under
    leafver, with the witness revealing it (or `reveal` in its place)
    alongside env. The keyword overrides each break one link of the
    chain for the negative cases."""
    node = TaggedHash("TapLeaf", bytes([leafver]) + ser_string(program))
    for sibling in path:
        if sibling < node:
            node = TaggedHash("TapBranch", sibling + node)
        else:
            node = TaggedHash("TapBranch", node + sibling)
    outkey, parity = tweak_add_pubkey(IPK, TaggedHash("TapTweak", IPK + node))
    if spk is None:
        spk = bytes([0x51, 0x20]) + outkey
    if cb is None:
        cb = bytes([leafver | parity]) + IPK + b"".join(path)

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(COutPoint(FUNDING_TXID, 0), b"", 0xffffffff)]
    tx.vout = [CTxOut(FUNDING_VALUE - 1000, bytes([0x51, 0x20]) + IPK)]
    wit = CTxInWitness()
    stack = [env, program if reveal is None else reveal, cb]
    if extra is not None:
        stack.append(extra)
    if annex is not None:
        stack.append(annex)
    wit.scriptWitness.stack = stack
    tx.wit.vtxinwit = [wit]
    return tx, [CTxOut(FUNDING_VALUE, spk)]


def spendcase(name, program, env, want, idx=0, utxos=None, **kw):
    def fn():
        tx, spent = make_spend(program, env, **kw)
        r = spend.verify_spend(tx, idx, spent if utxos is None else utxos)
        return str(r) == want, str(r)
    case(name, fn)


# ---- the canonical decoder ----

def decodes_to(data, shown):
    """The input decodes and its element renders as shown."""
    def fn():
        el = spend.deserialize_canonical(data, BIG)
        ok = not isinstance(el, Error) and str(el) == shown
        got = str(el)
        el.deref()
        return ok, got
    return fn

def refused_with(data, msg):
    """The input is refused and the error names msg."""
    def fn():
        el = spend.deserialize_canonical(data, BIG)
        ok = isinstance(el, Error) and msg in el.val2
        got = str(el)
        el.deref()
        return ok, got
    return fn

case("decode/nil", decodes_to(b"\x80", "nil"))
case("decode/one-byte", decodes_to(b"\x7f", "127"))
case("decode/one-byte-high", decodes_to(b"\x81\x80", "0x80"))
case("decode/two-atoms-cons", decodes_to(b"\xff\x01\x02", "(1 . 2)"))
case("decode/list", decodes_to(b"\xff\x01\xff\x02\x80", "(1 2)"))
case("decode/long-atom", decodes_to(b"\xa0" + bytes(31) + b"\x01",
                                    "0x" + bytes(31).hex() + "01"))
case("decode/empty", refused_with(b"", "truncated"))
case("decode/truncated-atom", refused_with(b"\xa0" + bytes(31), "truncated"))
case("decode/truncated-cons", refused_with(b"\xff\x01", "truncated"))
case("decode/trailing", refused_with(b"\x01\x01", "trailing bytes"))
case("decode/redundant-one-byte", refused_with(b"\x81\x05", "one byte atom"))
case("decode/wide-two-byte-prefix", refused_with(b"\xc0\x05" + bytes(5),
                                                 "wide length prefix"))
case("decode/wide-three-byte-prefix", refused_with(b"\xe0\x00\x40" + bytes(0x40),
                                                   "wide length prefix"))
case("decode/oversize-prefix", refused_with(b"\xf0", "atom too large"))

def two_byte_floor():
    """0x40 is the first length the two byte prefix may carry."""
    el = spend.deserialize_canonical(b"\xc0\x40" + bytes(0x40), BIG)
    ok = not isinstance(el, Error) and el.val1 == 0x40
    el.deref()
    return ok, str(el)[:20]
case("decode/two-byte-floor", two_byte_floor)

def round_trip():
    """Serialize emits the canonical form, so it must round-trip."""
    checks = []
    for src in ["(q . 1)", "(= (tx (q . 6)) 1)", "(shift (q . 1) (q . 4000000))",
                "(sha256 (q . 0x0102030405060708091011121314151617181920212223242526272829303132))"]:
        b = prog(src)
        el = spend.deserialize_canonical(b, BIG)
        checks.append(not isinstance(el, Error) and SerDeser.Serialize(el) == b)
        el.deref()
    return all(checks), f"{checks}"
case("decode/round-trip", round_trip)

def charges_as_rd():
    """The canonical decoder of a canonical input charges exactly
    what the rd opcode charges for the same bytes."""
    data = prog("(= (tx (q . 6)) (q . 0x0102030405060708091011121314151617181920212223242526272829303132))")
    b1 = Budget(2**32)
    el1 = spend.deserialize_canonical(data, b1)
    b2 = Budget(2**32)
    b2.charge(costs.RD_BASE)
    el2 = SerDeser.DeserializeCharged(data, b2, costs.RD_PER_ELEMENT,
                                      costs.RD_PER_BYTE + costs.MALLOC_PER_BYTE)
    ok = b1.used == b2.used and str(el1) == str(el2)
    shown = f"canonical {b1.used}, rd {b2.used}"
    Element.deref_all(el1, el2)
    return ok, shown
case("decode/charges-as-rd", charges_as_rd)

def deep_nesting():
    """The decode walk is iterative, so nesting far beyond the
    Python recursion limit must decode and free cleanly."""
    depth = 50000
    el = spend.deserialize_canonical(b"\xff\x01" * depth + b"\x80", BIG)
    ok = not isinstance(el, Error)
    el.deref()
    return ok, f"depth {depth}"
case("decode/deep-nesting", deep_nesting)

def decode_latch():
    """A budget too small for the decode latches instead of building
    the element, and the partial structure is freed."""
    before = ALLOCATOR.x
    b = Budget(costs.RD_BASE + 3 * costs.RD_PER_ELEMENT)
    el = spend.deserialize_canonical(b"\xff\x01\xff\x02\xff\x03\x80", b)
    ok = el is None and b.exhausted and ALLOCATOR.x == before
    return ok, f"leaked {ALLOCATOR.x - before} bytes"
case("decode/budget-latch", decode_latch)

# ---- the spend verifier ----

spendcase("spend/valid", prog("(q . 1)"), b"\x01", "valid")
spendcase("spend/env-decides-truthy", prog("1"), b"\x01", "valid")
spendcase("spend/env-decides-nil", prog("1"), b"\x80",
          "invalid: program result is nil")
spendcase("spend/nil-result", prog("(q . 0)"), b"\x01",
          "invalid: program result is nil")
spendcase("spend/error-result", prog("(x)"), b"\x01",
          "invalid: ERR(Exception: )")
spendcase("spend/function-result", prog("(partial (q . 34))"), b"\x01",
          "invalid: ERR(program result contains a function object)")
spendcase("spend/budget-exhausted", prog("(shift (q . 1) (q . 4000000))"),
          b"\x01", "invalid: ERR(budget exhausted)")
spendcase("spend/with-merkle-path", prog("(q . 1)"), b"\x01", "valid",
          path=(bytes(32),))
spendcase("spend/with-annex", prog("(q . 1)"), b"\x01", "valid",
          annex=b"\x50annex")
spendcase("spend/extra-stack-item", prog("(q . 1)"), b"\x01",
          "invalid: witness stack must be environment, leaf script, control block",
          extra=b"\x01")
spendcase("spend/wrong-leaf-version", prog("(q . 1)"), b"\x01",
          "invalid: leaf version is not bll", leafver=0xc0)
spendcase("spend/tampered-program", prog("(q . 1)"), b"\x01",
          "invalid: control block does not match spent output",
          reveal=prog("(q . 2)"))
spendcase("spend/non-p2tr-output", prog("(q . 1)"), b"\x01",
          "invalid: spent output is not pay-to-taproot",
          spk=bytes([0x00, 0x20]) + bytes(32))
spendcase("spend/bad-control-block-size", prog("(q . 1)"), b"\x01",
          "invalid: control block size invalid",
          cb=bytes([spend.LEAF_VERSION_BLL]) + IPK + b"\x00")
spendcase("spend/control-path-too-long", prog("(q . 1)"), b"\x01",
          "invalid: control block path too long",
          cb=bytes([spend.LEAF_VERSION_BLL]) + IPK + bytes(32 * 129))
spendcase("spend/index-out-of-range", prog("(q . 1)"), b"\x01",
          "invalid: input index out of range", idx=1)
spendcase("spend/utxo-count-mismatch", prog("(q . 1)"), b"\x01",
          "invalid: one spent output per input required", utxos=[])
spendcase("spend/redundant-env-encoding", prog("(q . 1)"), b"\x81\x05",
          "invalid: environment: witness element not canonical: one byte atom with length prefix")
spendcase("spend/env-trailing-bytes", prog("(q . 1)"), b"\x01\x01",
          "invalid: environment: witness element has trailing bytes")
spendcase("spend/redundant-program-encoding", b"\x81\x05", b"\x01",
          "invalid: leaf script: witness element not canonical: one byte atom with length prefix")
spendcase("spend/empty-program", b"", b"\x01",
          "invalid: leaf script: witness element truncated")

def missing_witness():
    tx, spent = make_spend(prog("(q . 1)"), b"\x01")
    tx.wit.vtxinwit = []
    r = spend.verify_spend(tx, 0, spent)
    return str(r) == "invalid: witness missing", str(r)
case("spend/missing-witness", missing_witness)

def two_item_stack():
    """A key-path-shaped witness is not a bll spend."""
    tx, spent = make_spend(prog("(q . 1)"), b"\x01")
    tx.wit.vtxinwit[0].scriptWitness.stack = tx.wit.vtxinwit[0].scriptWitness.stack[1:]
    r = spend.verify_spend(tx, 0, spent)
    want = "invalid: witness stack must be environment, leaf script, control block"
    return str(r) == want, str(r)
case("spend/two-item-stack", two_item_stack)

def wrong_parity():
    tx, spent = make_spend(prog("(q . 1)"), b"\x01")
    stack = tx.wit.vtxinwit[0].scriptWitness.stack
    stack[2] = bytes([stack[2][0] ^ 1]) + stack[2][1:]
    r = spend.verify_spend(tx, 0, spent)
    want = "invalid: control block does not match spent output"
    return str(r) == want, str(r)
case("spend/wrong-parity-bit", wrong_parity)

# ---- introspection wiring ----

def leaf_hash_binding():
    """The executing program's (tx 6) is the hash of the committed
    leaf script: the program compares it against the environment,
    which the spender must fill with the exact leaf hash."""
    program = prog("(= (tx (q . 6)) 1)")
    good = ser_atom(leaf_hash(program))
    tx, spent = make_spend(program, good)
    r_good = spend.verify_spend(tx, 0, spent)
    bad = ser_atom(bytes(32))
    tx, spent = make_spend(program, bad)
    r_bad = spend.verify_spend(tx, 0, spent)
    ok = str(r_good) == "valid" and str(r_bad) == "invalid: program result is nil"
    return ok, f"good {r_good}, bad {r_bad}"
case("wiring/leaf-hash-binding", leaf_hash_binding)

# ---- the budget ----

def budget_from_witness():
    """The limit is bought by the input's full serialized witness."""
    tx, spent = make_spend(prog("(q . 1)"), b"\x01")
    r = spend.verify_spend(tx, 0, spent)
    expect = budget_for_witness_size(len(tx.wit.vtxinwit[0].serialize()))
    ok = r.valid and r.limit == expect and 0 < r.used < r.limit
    return ok, f"limit {r.limit}, expected {expect}, used {r.used}"
case("budget/from-witness-size", budget_from_witness)

def budget_counts_annex():
    """Annex bytes buy budget like any other witness bytes."""
    tx0, spent0 = make_spend(prog("(q . 1)"), b"\x01")
    r0 = spend.verify_spend(tx0, 0, spent0)
    annex = b"\x50" + bytes(99)
    tx1, spent1 = make_spend(prog("(q . 1)"), b"\x01", annex=annex)
    r1 = spend.verify_spend(tx1, 0, spent1)
    delta = (len(tx1.wit.vtxinwit[0].serialize())
             - len(tx0.wit.vtxinwit[0].serialize()))
    ok = (r0.valid and r1.valid
          and r1.limit - r0.limit == costs.BUDGET_PER_WITNESS_BYTE * delta)
    return ok, f"delta {delta} bytes, {r1.limit - r0.limit} budget"
case("budget/annex-buys-budget", budget_counts_annex)

case("budget/block-weight-clamp",
     lambda: (spend.BUDGET_MAX == budget_for_witness_size(MAX_BLOCK_WEIGHT)
              and min(budget_for_witness_size(MAX_BLOCK_WEIGHT + 1000),
                      spend.BUDGET_MAX) == spend.BUDGET_MAX,
              f"BUDGET_MAX {spend.BUDGET_MAX}"))

# ---- allocator hygiene ----

def no_leaks():
    """Every verdict path frees what it built."""
    tx, spent = make_spend(prog("(q . 1)"), b"\x01")
    spend.verify_spend(tx, 0, spent)  # warm the interned atoms
    before = ALLOCATOR.x
    for program, env, kw in [
            (prog("(q . 1)"), b"\x01", {}),
            (prog("1"), b"\x80", {}),
            (prog("(x)"), b"\x01", {}),
            (prog("(partial (q . 34))"), b"\x01", {}),
            (prog("(shift (q . 1) (q . 4000000))"), b"\x01", {}),
            (prog("(q . 1)"), b"\x81\x05", {}),
            (b"\x81\x05", b"\x01", {}),
            (prog("(q . 1)"), b"\x01", {"reveal": prog("(q . 2)")}),
            (prog("(= (tx (q . 6)) 1)"),
             ser_atom(leaf_hash(prog("(= (tx (q . 6)) 1)"))), {}),
    ]:
        tx, spent = make_spend(program, env, **kw)
        spend.verify_spend(tx, 0, spent)
    leaked = ALLOCATOR.x - before
    return leaked == 0, f"leaked {leaked} bytes"
case("hygiene/no-leaks", no_leaks)

report()
