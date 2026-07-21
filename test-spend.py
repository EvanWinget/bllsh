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
from verystable.core.key import (TaggedHash, compute_xonly_pubkey, sign_schnorr,
                                 tweak_add_pubkey)
from verystable.core.messages import (MAX_BLOCK_WEIGHT, COutPoint, CTransaction,
                                      CTxIn, CTxInWitness, CTxOut, ser_string)
from verystable.core.script import LEAF_VERSION_TAPSCRIPT, TaprootSignatureHash

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


P_TRUE = prog("(q . 1)")
STACK_ERR = "invalid: witness stack must be environment, leaf script, control block"


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
    shown = str(el)[:20]
    el.deref()
    return ok, shown
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

spendcase("spend/valid", P_TRUE, b"\x01", "valid")
spendcase("spend/env-decides-truthy", prog("1"), b"\x01", "valid")
spendcase("spend/env-decides-nil", prog("1"), b"\x80",
          "invalid: program result is nil")
spendcase("spend/nil-result", prog("(q . 0)"), b"\x01",
          "invalid: program result is nil")
spendcase("spend/error-result", prog("(x)"), b"\x01",
          "invalid: Exception: ")
spendcase("spend/function-result", prog("(partial (q . 34))"), b"\x01",
          "invalid: program result contains a function object")
spendcase("spend/budget-exhausted", prog("(shift (q . 1) (q . 4000000))"),
          b"\x01", "invalid: budget exhausted")
spendcase("spend/with-merkle-path", P_TRUE, b"\x01", "valid",
          path=(bytes(32),))
spendcase("spend/with-annex", P_TRUE, b"\x01", "valid",
          annex=b"\x50annex")
spendcase("spend/extra-stack-item", P_TRUE, b"\x01",
          STACK_ERR, extra=b"\x01")
spendcase("spend/wrong-leaf-version", P_TRUE, b"\x01",
          "invalid: leaf version is not bll", leafver=0xc0)
spendcase("spend/tampered-program", P_TRUE, b"\x01",
          "invalid: control block does not match spent output",
          reveal=prog("(q . 2)"))
spendcase("spend/non-p2tr-output", P_TRUE, b"\x01",
          "invalid: spent output is not pay-to-taproot",
          spk=bytes([0x00, 0x20]) + bytes(32))
spendcase("spend/bad-control-block-size", P_TRUE, b"\x01",
          "invalid: control block size invalid",
          cb=bytes([spend.LEAF_VERSION_BLL]) + IPK + b"\x00")
spendcase("spend/control-path-too-long", P_TRUE, b"\x01",
          "invalid: control block path too long",
          cb=bytes([spend.LEAF_VERSION_BLL]) + IPK + bytes(32 * 129))
spendcase("spend/index-out-of-range", P_TRUE, b"\x01",
          "invalid: input index out of range", idx=1)
spendcase("spend/utxo-count-mismatch", P_TRUE, b"\x01",
          "invalid: one spent output per input required", utxos=[])
spendcase("spend/redundant-env-encoding", P_TRUE, b"\x81\x05",
          "invalid: environment: witness element not canonical: one byte atom with length prefix")
spendcase("spend/env-trailing-bytes", P_TRUE, b"\x01\x01",
          "invalid: environment: witness element has trailing bytes")
spendcase("spend/redundant-program-encoding", b"\x81\x05", b"\x01",
          "invalid: leaf script: witness element not canonical: one byte atom with length prefix")
spendcase("spend/empty-program", b"", b"\x01",
          "invalid: leaf script: witness element truncated")

def missing_witness():
    tx, spent = make_spend(P_TRUE, b"\x01")
    tx.wit.vtxinwit = []
    r = spend.verify_spend(tx, 0, spent)
    return str(r) == "invalid: witness missing", str(r)
case("spend/missing-witness", missing_witness)

def two_item_stack():
    """A key-path-shaped witness is not a bll spend."""
    tx, spent = make_spend(P_TRUE, b"\x01")
    tx.wit.vtxinwit[0].scriptWitness.stack = tx.wit.vtxinwit[0].scriptWitness.stack[1:]
    r = spend.verify_spend(tx, 0, spent)
    return str(r) == STACK_ERR, str(r)
case("spend/two-item-stack", two_item_stack)

def wrong_parity():
    tx, spent = make_spend(P_TRUE, b"\x01")
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

def sighash_names_executing_leaf():
    """bip342_txmsg takes the leaf version from the control block,
    so only a signature over the bll-versioned message validates and
    a signature over the tapscript-versioned message of the same
    script is refused."""
    priv = (8).to_bytes(32, "big")
    pub = compute_xonly_pubkey(priv)[0]
    program = prog(f"(bip340_verify (q . 0x{pub.hex()}) (bip342_txmsg) 1)")
    results = []
    for leafver in (spend.LEAF_VERSION_BLL, LEAF_VERSION_TAPSCRIPT):
        tx, spent = make_spend(program, b"\x80")
        msg = TaprootSignatureHash(txTo=tx, spent_utxos=spent, hash_type=0,
                                   input_index=0, scriptpath=True,
                                   script=program, leaf_ver=leafver)
        tx, spent = make_spend(program, ser_atom(sign_schnorr(priv, msg)))
        results.append(str(spend.verify_spend(tx, 0, spent)))
    ok = (results[0] == "valid"
          and results[1] == "invalid: bip340_verify: invalid, non-empty signature")
    return ok, f"{results}"
case("wiring/sighash-names-executing-leaf", sighash_names_executing_leaf)

# ---- the budget ----

def budget_from_witness():
    """The limit is bought by the input's full serialized witness."""
    tx, spent = make_spend(P_TRUE, b"\x01")
    r = spend.verify_spend(tx, 0, spent)
    expect = budget_for_witness_size(len(tx.wit.vtxinwit[0].serialize()))
    ok = r.valid and r.limit == expect and 0 < r.used < r.limit
    return ok, f"limit {r.limit}, expected {expect}, used {r.used}"
case("budget/from-witness-size", budget_from_witness)

def budget_counts_annex():
    """Annex bytes buy budget like any other witness bytes."""
    tx0, spent0 = make_spend(P_TRUE, b"\x01")
    r0 = spend.verify_spend(tx0, 0, spent0)
    annex = b"\x50" + bytes(99)
    tx1, spent1 = make_spend(P_TRUE, b"\x01", annex=annex)
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

# ---- the element allocation cap ----

# A self-application loop: the program applies its own environment to
# itself, so every step is machine work that allocates continuation
# conses until a limit stops it. Decode builds 11 elements, the loop
# then allocates without bound, which separates the two phases under
# a small injected cap.
P_LOOP = prog("(a (q . (a 1 1)) (q . (a 1 1)))")


def with_cap(limit, fn):
    """Run fn with the spend cap patched to limit, restoring the
    consensus constant afterwards."""
    saved = spend.ELEMENT_ALLOCATION_LIMIT
    spend.ELEMENT_ALLOCATION_LIMIT = limit
    try:
        return fn()
    finally:
        spend.ELEMENT_ALLOCATION_LIMIT = saved


def cap_exact_boundary():
    """The counted span admits exactly the cap and latches on the
    next construction, without touching the charge latches."""
    b = Budget(2**62)
    ALLOCATOR.arm_element_cap(3, b)
    els = [Atom(bytes([i + 2])) for i in range(3)]
    at_cap = not b.alloc_breach and b.charge(0)
    els.append(Atom(b"\x05"))
    over = (b.alloc_breach and not b.charge(0) and b.latched
            and not b.exhausted and not b.guard_breach)
    ALLOCATOR.disarm_element_cap()
    Element.deref_all(*els)
    return at_cap and over, f"breach {b.alloc_breach}"
case("cap/exact-boundary", cap_exact_boundary)


def cap_interned_exempt():
    """The interned nil and one are constructed once at import, so
    reusing them costs nothing against the cap."""
    b = Budget(2**62)
    warm = [Atom(b""), Atom(b"\x01")]
    ALLOCATOR.arm_element_cap(0, b)
    reused = [Atom(b""), Atom(b"\x01"), Atom(b""), Atom(b"\x01")]
    ok = not b.alloc_breach
    ALLOCATOR.disarm_element_cap()
    Element.deref_all(*warm, *reused)
    return ok, f"breach {b.alloc_breach}"
case("cap/interned-exempt", cap_interned_exempt)


def cap_disarm_restores():
    """After disarm construction is uncounted again."""
    b = Budget(2**62)
    ALLOCATOR.arm_element_cap(0, b)
    ALLOCATOR.disarm_element_cap()
    el = Atom(b"\x02")
    ok = not b.alloc_breach and b.charge(0)
    el.deref()
    return ok, f"breach {b.alloc_breach}"
case("cap/disarm-restores", cap_disarm_restores)


def cap_breach_survives_unwind():
    """clear_allowances drops guard state but not the breach latch,
    so an unwind cannot launder the cap into a program outcome."""
    b = Budget(1000)
    b.push_allowance(100)
    b.latch_alloc_breach()
    b.clear_allowances()
    return (b.alloc_breach and not b.charge(0) and b.latched
            and not b.guard_breach and not b.exhausted), \
        f"breach {b.alloc_breach} guard {b.guard_breach}"
case("cap/breach-survives-unwind", cap_breach_survives_unwind)


def cap_decode_breach():
    """A cap below the leaf script's own element count refuses the
    spend during decode, named apart from exhaustion."""
    tx, spent = make_spend(P_LOOP, b"\x01")
    r = with_cap(4, lambda: spend.verify_spend(tx, 0, spent))
    return (str(r) == "invalid: element allocation limit exceeded",
            str(r))
case("cap/decode-breach", cap_decode_breach)


def cap_eval_breach():
    """A cap the decode fits but the loop crosses refuses the spend
    during evaluation."""
    tx, spent = make_spend(P_LOOP, b"\x01")
    r = with_cap(200, lambda: spend.verify_spend(tx, 0, spent))
    return (str(r) == "invalid: element allocation limit exceeded",
            str(r))
case("cap/eval-breach", cap_eval_breach)


def cap_guard_breach_fatal():
    """A breach inside a softfork guard allowance fails the whole
    spend: the cap is a resource invariant, not a guarded program
    outcome the mismatch rule could absorb."""
    guarded = prog("(sf (q . 50000) (q . 0) (q a 1 1) (q a 1 1))")
    tx, spent = make_spend(guarded, b"\x01")
    r = with_cap(300, lambda: spend.verify_spend(tx, 0, spent))
    return (str(r) == "invalid: element allocation limit exceeded",
            str(r))
case("cap/guard-breach-fatal", cap_guard_breach_fatal)


def cap_exhaustion_first_at_consensus_constant():
    """Under the real constant the loop exhausts its budget long
    before the cap: the backstop is unreachable from an admissible
    spend, which is the relationship the module level assert pins."""
    tx, spent = make_spend(P_LOOP, b"\x01")
    r = spend.verify_spend(tx, 0, spent)
    return str(r) == "invalid: budget exhausted", str(r)
case("cap/exhaustion-first-at-consensus-constant",
     cap_exhaustion_first_at_consensus_constant)


def cap_breach_no_leak():
    """Both breach phases free everything they built."""
    tx, spent = make_spend(P_LOOP, b"\x01")
    spend.verify_spend(tx, 0, spent)  # warm the interned atoms
    before = ALLOCATOR.x
    with_cap(4, lambda: spend.verify_spend(tx, 0, spent))
    with_cap(200, lambda: spend.verify_spend(tx, 0, spent))
    leaked = ALLOCATOR.x - before
    return leaked == 0, f"leaked {leaked} bytes"
case("cap/breach-no-leak", cap_breach_no_leak)


# ---- allocator hygiene ----

def no_leaks():
    """Every verdict path frees what it built."""
    leafcheck = prog("(= (tx (q . 6)) 1)")
    tx, spent = make_spend(P_TRUE, b"\x01")
    spend.verify_spend(tx, 0, spent)  # warm the interned atoms
    before = ALLOCATOR.x
    for program, env, kw in [
            (P_TRUE, b"\x01", {}),
            (prog("1"), b"\x80", {}),
            (prog("(x)"), b"\x01", {}),
            (prog("(partial (q . 34))"), b"\x01", {}),
            (prog("(shift (q . 1) (q . 4000000))"), b"\x01", {}),
            (P_TRUE, b"\x81\x05", {}),
            (b"\x81\x05", b"\x01", {}),
            (P_TRUE, b"\x01", {"reveal": prog("(q . 2)")}),
            (leafcheck, ser_atom(leaf_hash(leafcheck)), {}),
    ]:
        tx, spent = make_spend(program, env, **kw)
        spend.verify_spend(tx, 0, spent)
    leaked = ALLOCATOR.x - before
    return leaked == 0, f"leaked {leaked} bytes"
case("hygiene/no-leaks", no_leaks)

report()
