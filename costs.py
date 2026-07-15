"""Evaluation cost accounting.

The constants and charging semantics mirror libbll's cost model
(libbll/src/cost.h in the bll-consensus repository, adopted at its
commit 34573a0). The values are calibrated there, one cost unit per
nanosecond of measured evaluation time on libbll's pinned calibration
machine, and adopted here verbatim so differential vectors can pin
exact charged totals across both implementations. They are proposals
for review, not settled consensus values.

libbll's cost arithmetic saturates at the uint64 maximum so an
overflowing charge reads as unpayably large. Python integers are
unbounded, so no saturation mirror is needed within the consensus
domain: for atoms within the serialization cap every saturating
add or multiply chain reaches the uint64 maximum before any
divided term can truncate below its exact value, so a charge fails
on one side exactly when it fails on the other for every limit
below 2**64. Outside that domain the guarantee narrows: an
API-constructed atom wider than the serialization cap can saturate
the divided product term of the mul-shaped charges (op_mul and the
unknown-operator mul shape) before the linear terms saturate the
total, and libbll then charges less than the exact value here, up
to the product divisor's factor, observable only under budgets
near 2**63 that no witness can buy.
"""

# Machine costs: the evaluator's own bookkeeping, independent of any
# opcode's work. STEP is charged per continuation frame pop at both
# pop sites (step and feedback delivery), ENV_EDGE per environment
# tree edge walked by an environment reference.
STEP = 24
ENV_EDGE = 3

# Machine-level collection cost of a fixed-arity opcode's argument
# accumulator, charged per argument folded. It covers the
# accumulator's two conses and count atom plus the finish-time walk
# that unpacks them.
FIX_COLLECT = 152

# Control and list: the flat per-application cost of x, i, h, t and
# l, charged at finish, the per-argument costs of the rc and b folds,
# and the per-argument cost of the all, any and notall flag folds.
CONTROL_BASE = 64
RC_ARG = 64
B_ARG = 192
LOGIC_ARG = 10

# Compare: the per-argument fold base shared by =, <s, < and ===, the
# per-byte scan rate of the raw byte comparisons, the per-byte rate
# of <'s numeric decode (charged on both decoded operands), the
# per-node rate of ==='s tree walk (charged incrementally with early
# exit, since a small shared structure can walk exponentially many
# node pairs), and strlen's flat per-argument cost.
COMPARE_ARG = 64
COMPARE_PER_BYTE = 1
LT_NUM_PER_BYTE = 3
BIGEQ_PER_NODE = 10
STRLEN_ARG = 128

# Allocation cost per byte of atom payload an opcode allocates,
# charged before the allocation. It prices memory pressure, not
# time, at CLVM's deployed rate.
MALLOC_PER_BYTE = 10

# Interpreting an atom as a machine integer scans every byte, since
# non-minimal encodings carry meaning in their zero tails. Atoms at
# machine-integer width or below ride their operation's base charge
# instead.
ATOM_SCAN_PER_BYTE = 1


def atom_scan(width):
    """The scan charge for interpreting an atom of the given width as
    a machine integer: nothing at machine-integer width, every byte
    at the scan rate beyond it."""
    return 0 if width <= 8 else ATOM_SCAN_PER_BYTE * width


# Bytes: per-argument fold bases for cat and the bitwise folds, the
# shared per-byte rate of the copying loops, and substr's finish
# base.
CAT_ARG = 96
COPY_PER_BYTE = 1
BITWISE_ARG = 160
SUBSTR_BASE = 64

# Arithmetic: the per-argument base of the bignum folds, the per-byte
# carry-loop rate charged over both operands, the per-limb term
# shared by * and % (per byte of the wider operand), the
# divided-product term shared by * and %, %'s finish base and
# per-byte rate, and shift's finish base.
ARITH_ARG = 160
ARITH_PER_BYTE = 4
MULDIV_LIMB_PER_BYTE = 6
MUL_PRODUCT_DIV = 8
MOD_BASE = 512
MOD_PER_BYTE = 3
SHIFT_BASE = 384


def mul_fold_work(left_width, right_width):
    """The work charge of one multiplication fold over operand
    widths: the carry-loop rate over both operands, the per-limb
    pass over the wider one, and the divided byte product. Shared
    by op_mul and the unknown-operator mul shape so the shape's
    weight-class promise cannot drift from the real fold."""
    return (ARITH_PER_BYTE * (left_width + right_width)
            + MULDIV_LIMB_PER_BYTE * max(left_width, right_width)
            + (left_width * right_width) // MUL_PRODUCT_DIV)

# Hashes: the per-argument cost of the midstate folds, the per-byte
# compression rate, and the finish cost covering finalization
# including the double-hash opcodes' second compression pass. One
# constant set covers all four hash opcodes.
HASH_ARG = 200
HASH_PER_BYTE = 4
HASH_BASE = 448

# Signatures: one flat verification charge shared by bip340_verify
# and ecdsa_verify. ECDSA_PARSE prices the pubkey decompression
# ecdsa_verify performs before its nil-signature shortcut, charged
# ahead of the parse so the early return cannot hand out curve work
# uncharged.
SIG_VERIFY = 28000
ECDSA_PARSE = 4096

# secp256k1_muladd: the fold's shape checks and collection cons per
# argument, the finish-time setup and combine, and one charge per
# term decoded in the finish walk, spent inside the walk before each
# decode. One term is one verification-scale scalar multiplication,
# priced identically to SIG_VERIFY to keep the sigop parity argument
# uniform across both curve opcodes.
MULADD_ARG = 96
MULADD_BASE = 3072
MULADD_PER_TERM = 28000

# Transaction introspection: the tx fold's per-argument cost. The
# field's byte contribution charges like cat's fold, copy and
# allocation rates on the joint width of accumulator and field. Wide
# selector and index atoms charge the scan rate ahead of their
# decodes.
TX_ARG = 176

# bip342_txmsg: priced as if every call recomputed the BIP341
# whole-transaction digests from the serialized bytes, base plus a
# per-byte rate over transaction plus spent outputs.
TXMSG_BASE = 3584
TXMSG_PER_BYTE = 8

# Serialize: the codec opcodes charge through their codec loops with
# early exit once the budget latches, because serialized size follows
# structure rather than memory. rd charges per element decoded plus a
# per-payload-byte rate that rides with the allocation charge. wr
# charges per element walked plus copy and allocation per emitted
# byte, headers included.
RD_BASE = 192
RD_PER_ELEMENT = 16
RD_PER_BYTE = 4
WR_BASE = 224
WR_PER_ELEMENT = 4
WR_PER_BYTE = 1

# Softfork guard machinery: the flat cost of entering and leaving a
# recognized softfork guard (allowance push, exit frame, exactness
# check, pop and nil delivery), charged against the guard's declared
# allowance at entry so both validator classes charge exactly the
# declared cost.
GUARD = 56

# The budget bought by one evaluation's witness bytes, the BIP342
# tapscript analog in nanosecond units: one signature check per 50
# witness bytes priced at the measured verification time.
BUDGET_BASE = 28000
BUDGET_PER_WITNESS_BYTE = 560
assert BUDGET_PER_WITNESS_BYTE * 50 == SIG_VERIFY
assert BUDGET_BASE == SIG_VERIFY

# The default allowance when an evaluation is started without an
# explicit budget. Large enough that only a pathological single
# demand exhausts it (a shift whose output size bound alone prices
# past it, for example), so drivers must still handle exhaustion:
# eval returns an error, the symbolic evaluator aborts, and the
# debugger reports it.
DEFAULT_BUDGET = 2**62


class Budget:
    """The spendable cost allowance of one evaluation. Charges
    accumulate until one does not fit, which latches the budget
    exhausted: that charge and every later one fail, including free
    ones. The failed charge sets used to the full limit, so an
    exhausted evaluation reports exactly the budget it was given,
    which is what makes the boundary replay contract exact.

    A softfork guard prepays its declared cost as one lump and then
    routes every charge inside the guard to an allowance of exactly
    that amount, so the outer counter never moves while a guard is
    active. A charge that does not fit the innermost allowance sets
    the sticky guard_breach flag instead of the exhausted latch: the
    outer budget may have room, so breach is a program outcome (the
    guarded program overran its declaration), not exhaustion. The
    two latches are mutually exclusive because no charge can reach
    the outer counter while an allowance is active, and no allowance
    can exist unless its lump already fit."""

    def __init__(self, limit):
        self.limit = limit
        self.used = 0
        self.exhausted = False
        self.allowances = []
        self.guard_breach = False

    def charge(self, amount):
        """Spends amount, against the innermost guard allowance if
        one is active, else against the budget itself. Charged before
        the work it covers. False once either latch is set. A zero
        charge always fits until then."""
        if self.exhausted or self.guard_breach:
            return False
        if self.allowances:
            allowed, used = self.allowances[-1]
            if amount > allowed - used:
                self.guard_breach = True
                return False
            self.allowances[-1] = (allowed, used + amount)
            return True
        if amount > self.limit - self.used:
            self.exhausted = True
            self.used = self.limit
            return False
        self.used += amount
        return True

    def push_allowance(self, allowed):
        """Opens a guard allowance. Every charge until the matching
        pop spends this allowance, whose lump the enclosing context
        already paid."""
        self.allowances.append((allowed, 0))

    def pop_allowance(self):
        """Closes the innermost guard allowance and reports whether
        it was consumed exactly."""
        allowed, used = self.allowances.pop()
        return used == allowed

    def clear_allowances(self):
        """Discards all guard allowances and the breach latch, used
        when an unwind abandons the guarded evaluation."""
        self.allowances = []
        self.guard_breach = False

    @property
    def latched(self):
        """True once any charge has failed, whichever latch it set.
        The one predicate call sites need to tell a failed charge
        from a missing result."""
        return self.exhausted or self.guard_breach


def budget_for_witness_size(witness_size):
    """The evaluation budget a witness of the given serialized size
    buys: BUDGET_BASE plus BUDGET_PER_WITNESS_BYTE per byte."""
    return BUDGET_BASE + BUDGET_PER_WITNESS_BYTE * witness_size
