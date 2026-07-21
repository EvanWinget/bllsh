#!/usr/bin/env python3
"""Validation of a bll taproot script path spend.

A bll program is committed as the body of a taproot leaf with leaf
version LEAF_VERSION_BLL: the leaf script bytes are the serialized
program, so the taproot commitment binds the program and every
constant quoted inside it with no further rule. A spend supplies,
after the optional annex is removed, a witness stack of exactly three
items:

    environment element, leaf script, control block

Any other stack size is invalid, so no third party can append items
to someone else's witness. The environment item is one serialized
element carrying all spender-supplied data. Both the leaf script and
the environment item must be canonically encoded: every atom uses the
shortest form the serialization grammar offers, and the whole input
must be consumed. The evaluator's own decoders (the rd opcode) stay
total and accept any well-formed encoding, since evaluation must be
able to process whatever bytes a program constructs at runtime. The
strictness lives only here, at the boundary where witness bytes
become consensus input, so a spend has exactly one valid encoding.

The spend's budget is bought by its own witness bytes, the tapscript
sigops budget analog: BUDGET_BASE plus BUDGET_PER_WITNESS_BYTE per
serialized witness byte, saturating at the budget a whole block's
weight could buy. Decoding the leaf script and the environment item
is charged against that budget at the same rates the rd opcode pays,
so witness-supplied structure is priced identically to structure a
program builds at runtime, and the element-count analysis that rides
on allocation charges covers decoded witness data too.

The spend is valid if and only if evaluation of the committed program
against the environment completes within budget with a result that is
neither an error nor nil. Nil is a refusal: the corpus convention is
that a failed check returns nil, so accepting a nil result would turn
every contract's refusal path into consent.

This module models the validation a consensus deployment performs
after dispatching on the leaf version. Spends carrying another leaf
version are reported invalid here, where a deployment would instead
route them to that version's rules (0xc0 is tapscript, anything else
is unencumbered).
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple

import bll
import costs
from costs import Budget, ELEMENT_ALLOCATION_LIMIT, STEP, budget_for_witness_size
from element import ALLOCATOR, Atom, Cons, Element, Error
from verystable.core.key import TaggedHash, tweak_add_pubkey
from verystable.core.messages import MAX_BLOCK_WEIGHT, CTransaction, CTxOut, ser_string
from opcodes import Set_GLOBAL_TX, Set_GLOBAL_TX_INPUT_IDX, Set_GLOBAL_TX_SCRIPT, Set_GLOBAL_UTXOS

# The bll taproot leaf version. Chain-local and cheap to renumber:
# nothing else derives from the byte. It is even, as every leaf
# version must be (the low control byte bit carries the output key
# parity), avoids 0xc0 (tapscript) and 0x50 (the annex prefix, which
# BIP341 excludes), and avoids 0xbe (Simplicity on Liquid) so the two
# deployments are never confused in conversation.
LEAF_VERSION_BLL = 0xc2

ANNEX_TAG = 0x50

# One spend can never be granted more budget than a witness filling
# the whole block would buy. The saturation makes that a stated
# invariant rather than a consequence of the block weight limit.
BUDGET_MAX = budget_for_witness_size(MAX_BLOCK_WEIGHT)

# The element allocation cap is a backstop of the charge coverage:
# at least STEP / 2 units precede every construction, so the largest
# budget the clamp grants cannot afford the cap and exhaustion fires
# first on every admissible spend.
assert ELEMENT_ALLOCATION_LIMIT * (STEP // 2) >= BUDGET_MAX

# A serialized atom's payload is capped at 0xFFFFF bytes by the
# grammar itself: the widest size prefix carries 20 bits.
SERIALIZED_ATOM_MAX = 0xFFFFF


def deserialize_canonical(data: bytes, budget: Budget) -> Optional[Element]:
    """Decodes one canonically encoded element, consuming the whole
    input. Returns an Error for any deviation from the unique
    canonical form, and None if the budget latched mid-decode.

    Canonical means every atom uses the shortest encoding the grammar
    offers: nil is 0x80, a one byte atom below 0x80 is that byte, and
    each length prefix width is used only above the range of the
    narrower widths. The decode is charged like an rd application,
    per element before it is built and per payload byte with the
    allocation share riding along, so a budget latch mid-decode
    refuses the spend the same way it refuses an oversized
    evaluation. The walk is iterative: witness bytes must not choose
    the decoder's stack depth."""
    if not budget.charge(costs.RD_BASE):
        return None
    per_element = costs.RD_PER_ELEMENT
    per_byte = costs.RD_PER_BYTE + costs.MALLOC_PER_BYTE

    # Pending cons frames: None is a cons awaiting its left child, an
    # Element is that left child awaiting its right.
    frames: List[Optional[Element]] = []
    pos = 0

    def drop_frames() -> None:
        for left in frames:
            if left is not None:
                left.deref()

    def fail(msg: str) -> Error:
        drop_frames()
        return Error(msg)

    while True:
        if pos >= len(data):
            return fail("witness element truncated")
        b = data[pos]
        pos += 1
        el = None
        if b == 0xff:
            # The cons charge is spent at marker read time, before
            # either child is decoded.
            if not budget.charge(per_element):
                drop_frames()
                return None
            frames.append(None)
            continue
        elif b == 0x80:
            if not budget.charge(per_element):
                drop_frames()
                return None
            el = Atom(0)
        elif b < 0x80:
            if not budget.charge(per_element):
                drop_frames()
                return None
            el = Atom(bytes([b]))
        elif b < 0xc0:
            n = b & 0x3f
            # n is at least 1: length zero in this width is 0x80,
            # nil, handled above.
            if pos + n > len(data):
                return fail("witness element truncated")
            if n == 1 and data[pos] < 0x80:
                return fail("witness element not canonical: one byte atom with length prefix")
            if not budget.charge(per_element + per_byte * n):
                drop_frames()
                return None
            el = Atom(data[pos:pos + n])
            pos += n
        elif b < 0xe0:
            if pos + 1 > len(data):
                return fail("witness element truncated")
            n = ((b & 0x1f) << 8) | data[pos]
            pos += 1
            if n <= 0x3f:
                return fail("witness element not canonical: wide length prefix")
            if pos + n > len(data):
                return fail("witness element truncated")
            if not budget.charge(per_element + per_byte * n):
                drop_frames()
                return None
            el = Atom(data[pos:pos + n])
            pos += n
        elif b < 0xf0:
            if pos + 2 > len(data):
                return fail("witness element truncated")
            n = ((b & 0x1f) << 16) | (data[pos] << 8) | data[pos + 1]
            pos += 2
            if n <= 0x1fff:
                return fail("witness element not canonical: wide length prefix")
            if pos + n > len(data):
                return fail("witness element truncated")
            if not budget.charge(per_element + per_byte * n):
                drop_frames()
                return None
            el = Atom(data[pos:pos + n])
            pos += n
        else:
            # 0xf0 through 0xfe would prefix atoms beyond
            # SERIALIZED_ATOM_MAX, which the grammar does not encode.
            return fail("witness element atom too large")

        # Deliver the completed element into the innermost pending
        # cons, folding up every cons this delivery completes.
        while True:
            if not frames:
                if pos != len(data):
                    el.deref()
                    return fail("witness element has trailing bytes")
                return el
            if frames[-1] is None:
                frames[-1] = el
                break
            el = Cons(frames.pop(), el)


def strip_annex(stack: List[bytes]) -> Tuple[List[bytes], Optional[bytes]]:
    """Splits off the optional annex: the last witness item, when
    there are at least two and it is nonempty and starts with the
    annex tag byte."""
    if len(stack) >= 2 and len(stack[-1]) > 0 and stack[-1][0] == ANNEX_TAG:
        return stack[:-1], stack[-1]
    return stack, None


def verify_commitment(spk: bytes, leaf_script: bytes, control_block: bytes) -> Optional[str]:
    """Checks that the control block links the leaf script to the
    spent output's taproot commitment under the bll leaf version.
    Returns None on success, else the reason the check failed."""
    if len(spk) != 34 or spk[0] != 0x51 or spk[1] != 0x20:
        return "spent output is not pay-to-taproot"
    if len(control_block) < 33 or (len(control_block) - 33) % 32 != 0:
        return "control block size invalid"
    if (len(control_block) - 33) // 32 > 128:
        return "control block path too long"
    leafver = control_block[0] & 0xfe
    if leafver != LEAF_VERSION_BLL:
        return "leaf version is not bll"
    ipk = control_block[1:33]
    node = TaggedHash("TapLeaf", bytes([LEAF_VERSION_BLL]) + ser_string(leaf_script))
    for i in range(33, len(control_block), 32):
        sibling = control_block[i:i + 32]
        if sibling < node:
            node = TaggedHash("TapBranch", sibling + node)
        else:
            node = TaggedHash("TapBranch", node + sibling)
    tweaked = tweak_add_pubkey(ipk, TaggedHash("TapTweak", ipk + node))
    if tweaked is None:
        return "control block internal pubkey invalid"
    outkey, parity = tweaked
    if outkey != spk[2:34] or parity != (control_block[0] & 1):
        return "control block does not match spent output"
    return None


@dataclass
class SpendResult:
    """The verdict of one spend validation: valid exactly when reason
    is empty. used and limit report the budget when one was derived,
    and stay zero for spends refused before the budget exists."""
    reason: str
    used: int = 0
    limit: int = 0

    @property
    def valid(self) -> bool:
        return not self.reason

    def __str__(self):
        if self.valid:
            return "valid"
        return f"invalid: {self.reason}"


def verify_spend(tx: CTransaction, input_index: int, spent_outputs: List[CTxOut]) -> SpendResult:
    """Validates one bll script path spend, deriving everything the
    evaluation needs from the transaction itself: the program from
    the committed leaf script, the environment from the witness, the
    budget from the witness size, and the introspection context from
    the spend. The four opcode globals are set as one unit here, so
    a driver never assembles a context by hand."""
    if input_index < 0 or input_index >= len(tx.vin):
        return SpendResult("input index out of range")
    if len(spent_outputs) != len(tx.vin):
        return SpendResult("one spent output per input required")
    if input_index >= len(tx.wit.vtxinwit):
        return SpendResult("witness missing")

    witness = tx.wit.vtxinwit[input_index]
    stack, annex = strip_annex(list(witness.scriptWitness.stack))
    if len(stack) != 3:
        return SpendResult("witness stack must be environment, leaf script, control block")
    env_bytes, leaf_script, control_block = stack

    reason = verify_commitment(spent_outputs[input_index].scriptPubKey,
                               leaf_script, control_block)
    if reason is not None:
        return SpendResult(reason)

    # The full serialized witness of this input buys the budget:
    # every item including the annex, each length prefixed, plus the
    # item count.
    witness_size = len(witness.serialize())
    limit = min(budget_for_witness_size(witness_size), BUDGET_MAX)
    budget = Budget(limit)

    def refused(reason: str) -> SpendResult:
        return SpendResult(reason, used=budget.used, limit=limit)

    def budget_refused() -> SpendResult:
        """A latched budget with no result. The allocation breach is
        named apart from exhaustion: the two latches are exclusive
        and the breach is a resource refusal, not a spent budget."""
        if budget.alloc_breach:
            return refused("element allocation limit exceeded")
        return refused("budget exhausted")

    # The counted span of the cap is decode plus evaluation: every
    # element the spend constructs is counted, and the span is
    # disarmed before the verdict returns so the repl outside spends
    # runs uncapped.
    ALLOCATOR.arm_element_cap(ELEMENT_ALLOCATION_LIMIT, budget)
    try:
        program = deserialize_canonical(leaf_script, budget)
        if program is None:
            return budget_refused()
        if isinstance(program, Error):
            # A breach latched mid-decode wins over the decode error
            # in hand, so the verdict is derived from the latch in
            # every phase and never from a message race.
            if budget.alloc_breach:
                program.deref()
                return budget_refused()
            reason = f"leaf script: {program.val2}"
            program.deref()
            return refused(reason)

        env = deserialize_canonical(env_bytes, budget)
        if env is None:
            program.deref()
            return budget_refused()
        if isinstance(env, Error):
            if budget.alloc_breach:
                Element.deref_all(program, env)
                return budget_refused()
            reason = f"environment: {env.val2}"
            Element.deref_all(program, env)
            return refused(reason)

        Set_GLOBAL_TX(tx)
        Set_GLOBAL_TX_INPUT_IDX(input_index)
        Set_GLOBAL_TX_SCRIPT(leaf_script)
        Set_GLOBAL_UTXOS(spent_outputs)

        result = bll.eval(program, env, budget)
        if isinstance(result, Error):
            # The bare message keeps one verdict vocabulary across the
            # phases: a budget latched during decode and one exhausted
            # during evaluation read identically. A breach verdict is
            # derived from the latch here too, not from the error
            # text, so the vocabulary has one structural source.
            if budget.alloc_breach:
                result.deref()
                return budget_refused()
            reason = result.val2
            result.deref()
            return refused(reason)
        if result.is_nil():
            result.deref()
            return refused("program result is nil")
        result.deref()
        return SpendResult("", used=budget.used, limit=limit)
    finally:
        ALLOCATOR.disarm_element_cap()
