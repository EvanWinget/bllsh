#!/usr/bin/env python3
"""Generate deterministic test contexts for the corpus examples.

Every hex constant in examples/test-vault, examples/test-flexmarks,
examples/test-flexmarks-htlc and examples/test-p2-delegated is produced
by this script, so the examples can be regenerated and audited. Run from
the repository root:

    python3 examples/gen-test-context.py vault
    python3 examples/gen-test-context.py flexmarks
    python3 examples/gen-test-context.py htlc
    python3 examples/gen-test-context.py p2d

The output is a block of REPL commands (tx, tx_in_idx, tx_script, utxos)
followed by def lines for the signatures and other witness data, ready to
paste into the example files.

The leaf script bytes are placeholders. The REPL evaluates the symbll
program directly and never checks that it matches the committed script,
so any bytes work as long as the control block, the utxo scriptPubKey
and tx_script agree with each other.
"""

import struct
import sys

sys.path.insert(0, ".")

from element import Atom, Cons, SExpr, SerDeser
from verystable.core import messages
from verystable.core.key import TaggedHash, compute_xonly_pubkey, sign_schnorr, tweak_add_pubkey
from verystable.core.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, ser_string
from verystable.core.script import LEAF_VERSION_TAPSCRIPT, TaprootSignatureHash

# deterministic keys, obviously not for real use
KEY_VAULT_COLD = (1).to_bytes(32, "big")
KEY_VAULT_HOT = (2).to_bytes(32, "big")
KEY_VAULT_IPK = (3).to_bytes(32, "big")
KEY_POOL_IPK = (11).to_bytes(32, "big")
KEY_MEMBER_1 = (21).to_bytes(32, "big")
KEY_MEMBER_2 = (22).to_bytes(32, "big")
KEY_HTLC_IPK = (31).to_bytes(32, "big")
KEY_HTLC_RECV = (32).to_bytes(32, "big")
KEY_HTLC_SEND = (33).to_bytes(32, "big")
KEY_P2D_SYNTH = (41).to_bytes(32, "big")
KEY_P2D_IPK = (42).to_bytes(32, "big")
KEY_P2D_DEST1 = (43).to_bytes(32, "big")
KEY_P2D_DEST2 = (44).to_bytes(32, "big")

FUNDING_TXID = int.from_bytes(bytes(range(32)), "little")
FUNDING_TXID_ALT = int.from_bytes(bytes(range(32, 64)), "little")
FUNDING_VALUE = 100000


def xonly(priv):
    pub, _ = compute_xonly_pubkey(priv)
    return pub


def tapleaf_hash(script):
    return TaggedHash("TapLeaf", bytes([LEAF_VERSION_TAPSCRIPT]) + ser_string(script))


def tapbranch(a, b):
    if b < a:
        a, b = b, a
    return TaggedHash("TapBranch", a + b)


def taproot_spk(ipk, leafhash, path):
    """Output key for a script tree walked from leafhash along path."""
    node = leafhash
    for sibling in path:
        node = tapbranch(node, sibling)
    tweak = TaggedHash("TapTweak", ipk + node)
    outkey, odd = tweak_add_pubkey(ipk, tweak)
    return bytes([0x51, 0x20]) + outkey, int(odd)


def p2tr_raw(pub):
    """A plain destination output, key used untweaked for simplicity."""
    return bytes([0x51, 0x20]) + pub


def make_tx(spk, outputs, nsequence, nlocktime, script, control_block,
            nversion=2, prev_txid=FUNDING_TXID, prev_value=FUNDING_VALUE):
    utxo = CTxOut(prev_value, spk)
    tx = CTransaction()
    tx.nVersion = nversion
    tx.nLockTime = nlocktime
    tx.vin = [CTxIn(COutPoint(prev_txid, 0), b"", nsequence)]
    tx.vout = [CTxOut(value, out_spk) for value, out_spk in outputs]
    wit = CTxInWitness()
    wit.scriptWitness.stack = [script, control_block]
    tx.wit.vtxinwit = [wit]
    return tx, utxo


def emit_context(label, tx, utxo, script):
    print(f"; {label}")
    print(f"tx {tx.serialize_with_witness().hex()}")
    print("tx_in_idx 0")
    print(f"tx_script {script.hex()}")
    print(f"utxos {utxo.serialize().hex()}")
    print()


def sig_for(priv, tx, utxo, script):
    msg = TaprootSignatureHash(txTo=tx, spent_utxos=[utxo], hash_type=0,
                               input_index=0, scriptpath=True, script=script)
    return sign_schnorr(priv, msg)


def wr(element):
    return SerDeser.Serialize(element)


def emleaf(em):
    return TaggedHash("EMLeaf", wr(em))


def embranch(a, b):
    if b < a:
        a, b = b, a
    return TaggedHash("EMBranch", a + b)


def emroot(ov, em, empath):
    node = emleaf(em)
    for sibling in empath:
        node = embranch(node, sibling)
    return TaggedHash("EM", wr(Cons(ov, Atom(node))))


def gen_vault():
    script = b"bll: vault demo"
    ipk = xonly(KEY_VAULT_IPK)
    spk, parity = taproot_spk(ipk, tapleaf_hash(script), [])
    cb = bytes([LEAF_VERSION_TAPSCRIPT | parity]) + ipk

    print(f"; cold pubkey {xonly(KEY_VAULT_COLD).hex()}")
    print(f"; hot pubkey {xonly(KEY_VAULT_HOT).hex()}")
    print()

    outputs = [(99000, p2tr_raw(xonly(KEY_VAULT_HOT)))]
    mature, utxo = make_tx(spk, outputs, 144, 0, script, cb)
    emit_context("hot spend after the 144 block delay", mature, utxo, script)
    print(f"def SIGHOTA 0x{sig_for(KEY_VAULT_HOT, mature, utxo, script).hex()}")
    print(f"def SIGCOLDA 0x{sig_for(KEY_VAULT_COLD, mature, utxo, script).hex()}")
    print()

    immature, utxo = make_tx(spk, outputs, 10, 0, script, cb)
    emit_context("premature hot spend, only 10 blocks of delay", immature, utxo, script)
    print(f"def SIGHOTB 0x{sig_for(KEY_VAULT_HOT, immature, utxo, script).hex()}")
    print(f"def SIGCOLDB 0x{sig_for(KEY_VAULT_COLD, immature, utxo, script).hex()}")


def gen_flexmarks():
    script = b"bll: flexmark withdraw demo"
    ipk = xonly(KEY_POOL_IPK)
    ov = Atom(0)
    em1 = Cons(Atom(xonly(KEY_MEMBER_1)), Atom(30000))
    em2 = Cons(Atom(xonly(KEY_MEMBER_2)), Atom(20000))
    sibling = emleaf(em2)

    root_old = emroot(ov, em1, [sibling])
    spk, parity_old = taproot_spk(ipk, tapleaf_hash(script), [root_old])
    cb = bytes([LEAF_VERSION_TAPSCRIPT | parity_old]) + ipk + root_old

    root_new = emroot(ov, Atom(0), [sibling])
    new_spk, parity_new = taproot_spk(ipk, tapleaf_hash(script), [root_new])

    print(f"; member 1 pubkey {xonly(KEY_MEMBER_1).hex()} earmark amount 30000")
    print(f"; member 2 pubkey {xonly(KEY_MEMBER_2).hex()} earmark amount 20000")
    print(f"; new pool output key parity {parity_new}")
    print()

    outputs = [(70000, new_spk), (29000, p2tr_raw(xonly(KEY_MEMBER_1)))]
    tx, utxo = make_tx(spk, outputs, 0xffffffff, 0, script, cb)
    emit_context("member 1 withdraws their 30000 sat earmark", tx, utxo, script)
    print(f"def EM1 (q 0x{xonly(KEY_MEMBER_1).hex()} . 30000)")
    print(f"def EM2 (q 0x{xonly(KEY_MEMBER_2).hex()} . 20000)")
    print(f"def SIBLING 0x{sibling.hex()}")
    print(f"def SIG1 0x{sig_for(KEY_MEMBER_1, tx, utxo, script).hex()}")
    print(f"def SIG2 0x{sig_for(KEY_MEMBER_2, tx, utxo, script).hex()}")
    print()

    # generation two: member 2 withdraws from the recreated pool coin,
    # whose earmark tree holds the nil left by member 1's withdrawal
    tx.rehash()
    sibling2 = emleaf(Atom(0))
    root_gen3 = emroot(ov, Atom(0), [sibling2])
    gen3_spk, parity_gen3 = taproot_spk(ipk, tapleaf_hash(script), [root_gen3])
    cb2 = bytes([LEAF_VERSION_TAPSCRIPT | parity_new]) + ipk + root_new
    outputs2 = [(50000, gen3_spk), (19000, p2tr_raw(xonly(KEY_MEMBER_2)))]
    tx2, utxo2 = make_tx(new_spk, outputs2, 0xffffffff, 0, script, cb2,
                         prev_txid=tx.sha256, prev_value=70000)
    print(f"; generation three output key parity {parity_gen3}")
    print()
    emit_context("member 2 withdraws from the recreated pool coin", tx2, utxo2, script)
    print(f"def SIBLING2 0x{sibling2.hex()}")
    print(f"def SIG2B 0x{sig_for(KEY_MEMBER_2, tx2, utxo2, script).hex()}")


def gen_htlc():
    script = b"bll: flexmark htlc demo"
    ipk = xonly(KEY_HTLC_IPK)
    ov = Atom(0)
    preimage = b"htlc demo preimage, 32 bytes ok!"
    assert len(preimage) == 32
    payment_hash = messages.sha256(preimage)
    timeout = 500
    em = Atom(0)
    for part in reversed([payment_hash, 5000, xonly(KEY_HTLC_RECV), xonly(KEY_HTLC_SEND), timeout]):
        em = Cons(Atom(part), em)

    root_old = emroot(ov, em, [])
    spk, parity_old = taproot_spk(ipk, tapleaf_hash(script), [root_old])
    cb = bytes([LEAF_VERSION_TAPSCRIPT | parity_old]) + ipk + root_old

    root_new = emroot(ov, Atom(0), [])
    new_spk, parity_new = taproot_spk(ipk, tapleaf_hash(script), [root_new])

    print(f"; recipient pubkey {xonly(KEY_HTLC_RECV).hex()}")
    print(f"; sender pubkey {xonly(KEY_HTLC_SEND).hex()}")
    print(f"; payment hash {payment_hash.hex()}")
    print(f"; preimage {preimage.hex()}")
    print(f"; new output key parity {parity_new}")
    print()

    claim_outputs = [(95000, new_spk), (4000, p2tr_raw(xonly(KEY_HTLC_RECV)))]
    claim, utxo = make_tx(spk, claim_outputs, 0xfffffffe, 0, script, cb)
    emit_context("recipient claims with the preimage", claim, utxo, script)
    print(f"def SIGCLAIM 0x{sig_for(KEY_HTLC_RECV, claim, utxo, script).hex()}")
    print()

    refund_outputs = [(95000, new_spk), (4000, p2tr_raw(xonly(KEY_HTLC_SEND)))]
    refund, utxo = make_tx(spk, refund_outputs, 0xfffffffe, 505, script, cb)
    emit_context("sender refunds after the timeout", refund, utxo, script)
    print(f"def SIGREFUND 0x{sig_for(KEY_HTLC_SEND, refund, utxo, script).hex()}")
    print()

    early_outputs = [(95000, new_spk), (4000, p2tr_raw(xonly(KEY_HTLC_SEND)))]
    early, utxo = make_tx(spk, early_outputs, 0xfffffffe, 490, script, cb)
    emit_context("sender tries to refund before the timeout", early, utxo, script)
    print(f"def SIGEARLY 0x{sig_for(KEY_HTLC_SEND, early, utxo, script).hex()}")
    print()

    late_claim, utxo = make_tx(spk, claim_outputs, 0xfffffffe, 505, script, cb)
    emit_context("recipient claims after the timeout has passed", late_claim, utxo, script)
    print(f"def SIGCLAIMLATE 0x{sig_for(KEY_HTLC_RECV, late_claim, utxo, script).hex()}")
    print()

    timetyped, utxo = make_tx(spk, refund_outputs, 0xfffffffe, 1700000000, script, cb)
    emit_context("sender tries a time typed nLockTime against the height timeout", timetyped, utxo, script)
    print(f"def SIGTIMETYPED 0x{sig_for(KEY_HTLC_SEND, timetyped, utxo, script).hex()}")


DELEG_ANY = "(0 . 1)"
DELEG_COV = "(14 (41 (0 . 3)) (0 . 2))"
DELEG_SOL = "(14 1 (0 . 5))"


def sha256tree(el):
    """The p2d example's SHA256TREE def, computed in Python: leaves
    are hashed under a 1 prefix and pairs under a 2 prefix."""
    if el.is_cons():
        return messages.sha256(b"\x02" + sha256tree(el.val1) + sha256tree(el.val2))
    return messages.sha256(b"\x01" + el.val2)


def deleg_hash(text):
    el = SExpr.parse(text)
    r = sha256tree(el)
    el.deref()
    return r


def p2d_sig_for(priv, deleg_text, tx):
    """The AGG_SIG_ME analogue: a signature over the delegate's tree
    hash bound to the spent outpoint, matching the example's
    (sha256 (SHA256TREE DELEG) (tx 11) (tx 12)). The transaction's
    outputs are deliberately not covered, only the delegate is."""
    prevout = tx.vin[0].prevout
    msg = messages.sha256(deleg_hash(deleg_text)
                          + messages.ser_uint256(prevout.hash)
                          + struct.pack("<I", prevout.n))
    return sign_schnorr(priv, msg)


def gen_p2d():
    script = b"bll: p2d demo"
    ipk = xonly(KEY_P2D_IPK)
    spk, parity = taproot_spk(ipk, tapleaf_hash(script), [])
    cb = bytes([LEAF_VERSION_TAPSCRIPT | parity]) + ipk

    print(f"; synthetic pubkey {xonly(KEY_P2D_SYNTH).hex()}")
    print(f"; sha256tree DELEGANY {deleg_hash(DELEG_ANY).hex()}")
    print(f"; sha256tree DELEGCOV {deleg_hash(DELEG_COV).hex()}")
    print(f"; sha256tree DELEGSOL {deleg_hash(DELEG_SOL).hex()}")
    print()
    print(f"def SYNPK 0x{xonly(KEY_P2D_SYNTH).hex()}")
    print("def DELEGANY (q 0 . 1)")
    print("def DELEGCOV (q 14 (41 (0 . 3)) (0 . 2))")
    print("def DELEGSOL (q 14 1 (0 . 5))")
    print()

    outputs_a = [(60000, p2tr_raw(xonly(KEY_P2D_DEST1))),
                 (39000, p2tr_raw(xonly(KEY_P2D_DEST2)))]
    tx_a, utxo_a = make_tx(spk, outputs_a, 0xffffffff, 0, script, cb)
    emit_context("context A: two outputs, first funding outpoint", tx_a, utxo_a, script)
    print(f"def SIGANYA 0x{p2d_sig_for(KEY_P2D_SYNTH, DELEG_ANY, tx_a).hex()}")
    print(f"def SIGCOVA 0x{p2d_sig_for(KEY_P2D_SYNTH, DELEG_COV, tx_a).hex()}")
    print(f"def SIGSOLA 0x{p2d_sig_for(KEY_P2D_SYNTH, DELEG_SOL, tx_a).hex()}")
    print()

    outputs_b = [(99000, p2tr_raw(xonly(KEY_P2D_DEST1)))]
    tx_b, utxo_b = make_tx(spk, outputs_b, 0xffffffff, 0, script, cb,
                           prev_txid=FUNDING_TXID_ALT)
    emit_context("context B: one output, different funding outpoint", tx_b, utxo_b, script)
    print(f"def SIGCOVB 0x{p2d_sig_for(KEY_P2D_SYNTH, DELEG_COV, tx_b).hex()}")


def main():
    targets = {"vault": gen_vault, "flexmarks": gen_flexmarks, "htlc": gen_htlc,
               "p2d": gen_p2d}
    if len(sys.argv) != 2 or sys.argv[1] not in targets:
        print(f"usage: {sys.argv[0]} {{vault|flexmarks|htlc|p2d}}", file=sys.stderr)
        return 1
    targets[sys.argv[1]]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
