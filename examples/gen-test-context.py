#!/usr/bin/env python3
"""Generate deterministic test contexts for the corpus examples.

Every hex constant in examples/test-vault, examples/test-flexmarks,
examples/test-flexmarks-htlc, examples/test-p2-delegated,
examples/test-singleton and examples/test-cat is produced by this
script, so the examples can be regenerated and audited. Run from the
repository root:

    python3 examples/gen-test-context.py vault
    python3 examples/gen-test-context.py flexmarks
    python3 examples/gen-test-context.py htlc
    python3 examples/gen-test-context.py p2d
    python3 examples/gen-test-context.py singleton
    python3 examples/gen-test-context.py cat
    python3 examples/gen-test-context.py commitment

The output is a block of REPL commands (tx, tx_in_idx, tx_script, utxos)
followed by def lines for the signatures and other witness data, ready to
paste into the example files.

For the vault, flexmarks, htlc and p2d targets the leaf script bytes
are placeholders. The REPL evaluates the symbll program directly and
never checks that it matches the committed script, so any bytes work
as long as the control block, the utxo scriptPubKey and tx_script
agree with each other. The commitment and singleton targets instead
drive the spend command, which validates the committed leaf script as
the program, so there the leaf script bytes are the real serialized
bll program. The singleton's committed bytes are compiled from the
sentinel delimited def region of examples/test-singleton, so the
example's defs are the single source of truth, and every emitted
spend line is validated by verify_spend before it is printed.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import struct
import sys
import tempfile

sys.path.insert(0, ".")

import bll
import symbll
from element import Atom, Cons, SExpr, SerDeser, int_to_bytes
from spend import LEAF_VERSION_BLL, verify_spend
from verystable.core import messages
from verystable.core.key import H_POINT, TaggedHash, compute_xonly_pubkey, sign_schnorr, tweak_add_pubkey
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
KEY_SGL_INNER = (51).to_bytes(32, "big")
KEY_SGL_IPK = (52).to_bytes(32, "big")
KEY_SGL_DEST = (53).to_bytes(32, "big")
KEY_CMT_SIG = (61).to_bytes(32, "big")
KEY_CMT_IPK = (62).to_bytes(32, "big")
KEY_CAT_H1 = (71).to_bytes(32, "big")
KEY_CAT_H2 = (72).to_bytes(32, "big")
KEY_CAT_H3 = (73).to_bytes(32, "big")
KEY_CAT_DEST = (74).to_bytes(32, "big")
KEY_CAT_B1 = (75).to_bytes(32, "big")
KEY_CAT_B2 = (76).to_bytes(32, "big")

FUNDING_TXID = int.from_bytes(bytes(range(32)), "little")
FUNDING_TXID_ALT = int.from_bytes(bytes(range(32, 64)), "little")
FUNDING_VALUE = 100000


def xonly(priv):
    pub, _ = compute_xonly_pubkey(priv)
    return pub


def tapleaf_hash(script, leaf_ver=LEAF_VERSION_TAPSCRIPT):
    return TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))


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


def make_tx2(prevs, outputs, script, control_block,
             nsequence=0xffffffff, nlocktime=0, nversion=2):
    """A transaction spending each (prev_txid, prev_vout, prev_value,
    prev_spk) through the same script path. The single input make_tx
    delegates here."""
    tx = CTransaction()
    tx.nVersion = nversion
    tx.nLockTime = nlocktime
    utxos = []
    for prev_txid, prev_vout, prev_value, prev_spk in prevs:
        tx.vin.append(CTxIn(COutPoint(prev_txid, prev_vout), b"", nsequence))
        wit = CTxInWitness()
        wit.scriptWitness.stack = [script, control_block]
        tx.wit.vtxinwit.append(wit)
        utxos.append(CTxOut(prev_value, prev_spk))
    tx.vout = [CTxOut(value, out_spk) for value, out_spk in outputs]
    return tx, utxos


def make_tx(spk, outputs, nsequence, nlocktime, script, control_block,
            nversion=2, prev_txid=FUNDING_TXID, prev_value=FUNDING_VALUE,
            prev_vout=0):
    tx, utxos = make_tx2([(prev_txid, prev_vout, prev_value, spk)], outputs,
                         script, control_block, nsequence, nlocktime, nversion)
    return tx, utxos[0]


def emit_context2(label, tx, utxos, script):
    print(f"; {label}")
    print(f"tx {tx.serialize_with_witness().hex()}")
    print("tx_in_idx 0")
    print(f"tx_script {script.hex()}")
    print("utxos " + " ".join(u.serialize().hex() for u in utxos))
    print()


def emit_context(label, tx, utxo, script):
    emit_context2(label, tx, [utxo], script)


# A target spending a non tapscript leaf must pass leaf_ver: the
# default preserves the tapscript message of the earlier targets,
# and a commitment style spend signed under it fails validation
# with a bare signature error.
def sig_for_at(priv, tx, utxos, script, idx, leaf_ver=LEAF_VERSION_TAPSCRIPT):
    msg = TaprootSignatureHash(txTo=tx, spent_utxos=utxos, hash_type=0,
                               input_index=idx, scriptpath=True, script=script,
                               leaf_ver=leaf_ver)
    return sign_schnorr(priv, msg)


def sig_for(priv, tx, utxo, script, leaf_ver=LEAF_VERSION_TAPSCRIPT):
    return sig_for_at(priv, tx, [utxo], script, 0, leaf_ver)


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


# the delegate program trees, spelled once as the numeric bll text
# that both the emitted def lines and the tree hashes derive from
P2D_DELEGATES = {
    "DELEGANY": "0 . 1",
    "DELEGCOV": "14 (41 (0 . 3)) (0 . 2)",
    "DELEGARG": "14 1 (0 . 5)",
}


def sha256tree(el):
    """The p2d example's SHA256TREE def, computed in Python: leaves
    are hashed under a 1 prefix and pairs under a 2 prefix."""
    if el.is_cons():
        return messages.sha256(b"\x02" + sha256tree(el.val1) + sha256tree(el.val2))
    return messages.sha256(b"\x01" + el.val2)


def deleg_hash(text):
    el = SExpr.parse(f"({text})")
    r = sha256tree(el)
    el.deref()
    return r


def p2d_sig_for(priv, treehash, tx):
    """The AGG_SIG_ME analogue: a signature over the delegate's tree
    hash bound to the spent outpoint under the bll/delegate tagged
    hash, matching the example's
    (SIGNMSG "bll/delegate" (SHA256TREE DELEG)) built on
    lib-taproot's signing convention. The transaction's outputs are
    deliberately not covered, only the delegate is."""
    prevout = tx.vin[0].prevout
    msg = TaggedHash("bll/delegate",
                     treehash
                     + messages.ser_uint256(prevout.hash)
                     + struct.pack("<I", prevout.n))
    return sign_schnorr(priv, msg)


def gen_p2d():
    script = b"bll: p2d demo"
    ipk = xonly(KEY_P2D_IPK)
    spk, parity = taproot_spk(ipk, tapleaf_hash(script), [])
    cb = bytes([LEAF_VERSION_TAPSCRIPT | parity]) + ipk
    synpk = xonly(KEY_P2D_SYNTH)
    hashes = {name: deleg_hash(text) for name, text in P2D_DELEGATES.items()}

    def blleval_env(deleg, sig):
        """The compiled argument tree for a delegation spend:
        (((SYNPK . ORIGPK) . (DELEG . ARGS)) . SIG)."""
        return (f"(((0x{synpk.hex()} . 0) . "
                f"(({P2D_DELEGATES[deleg]}) . 0)) . 0x{sig.hex()})")

    print(f"; synthetic pubkey {synpk.hex()}")
    for name, treehash in hashes.items():
        print(f"; sha256tree {name} {treehash.hex()}")
    print()
    print(f"def SYNPK 0x{synpk.hex()}")
    for name, text in P2D_DELEGATES.items():
        print(f"def {name} (q {text})")
    print()

    outputs_a = [(60000, p2tr_raw(xonly(KEY_P2D_DEST1))),
                 (39000, p2tr_raw(xonly(KEY_P2D_DEST2)))]
    tx_a, utxo_a = make_tx(spk, outputs_a, 0xffffffff, 0, script, cb)
    emit_context("context A: two outputs, first funding outpoint", tx_a, utxo_a, script)
    sig_any_a = p2d_sig_for(KEY_P2D_SYNTH, hashes["DELEGANY"], tx_a)
    sig_cov_a = p2d_sig_for(KEY_P2D_SYNTH, hashes["DELEGCOV"], tx_a)
    print(f"def SIGANYA 0x{sig_any_a.hex()}")
    print(f"def SIGCOVA 0x{sig_cov_a.hex()}")
    print(f"def SIGARGA 0x{p2d_sig_for(KEY_P2D_SYNTH, hashes['DELEGARG'], tx_a).hex()}")
    print()
    print("; compiled path spends for context A")
    print(f"blleval @P2D {blleval_env('DELEGANY', sig_any_a)}")
    print(f"blleval @P2D {blleval_env('DELEGCOV', sig_cov_a)}")
    print()

    outputs_b = [(99000, p2tr_raw(xonly(KEY_P2D_DEST1)))]
    tx_b, utxo_b = make_tx(spk, outputs_b, 0xffffffff, 0, script, cb,
                           prev_txid=FUNDING_TXID_ALT)
    emit_context("context B: one output, different funding outpoint", tx_b, utxo_b, script)
    print(f"def SIGCOVB 0x{p2d_sig_for(KEY_P2D_SYNTH, hashes['DELEGCOV'], tx_b).hex()}")


# sentinels delimiting the committed program region of an example
# file, re-read by the generator so the example's defs are the single
# source of truth for the committed bytes
REGION_BEGIN = "; --- committed program ---"
REGION_END = "; --- end committed program ---"

# the BIP341 unspendable internal key, the x coordinate of a point
# with no known discrete logarithm. UNSPENDABLEIPK in
# examples/lib-exclusivity carries the same bytes on the bll side.
UNSPENDABLE_IPK = bytes.fromhex(H_POINT)


def compile_committed_region(path, symname):
    """Compile SYMNAME from the sentinel delimited def region of an
    example file, returning the serialized program bytes, the printed
    compiled form for the example's program marker, and the region's
    command lines."""
    loader = importlib.machinery.SourceFileLoader("bllsh_repl", "bllsh")
    spec = importlib.util.spec_from_loader("bllsh_repl", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    repl = module.BTCLispRepl(prompt="")

    with open(path) as f:
        lines = [ln.strip() for ln in f]
    if REGION_BEGIN not in lines or REGION_END not in lines:
        raise SystemExit(f"{path}: missing the committed program sentinels")
    region = [line for line in
              lines[lines.index(REGION_BEGIN) + 1:lines.index(REGION_END)]
              if line != "" and not line.startswith(";")]
    for line in region:
        with contextlib.redirect_stdout(io.StringIO()):
            repl.onecmd(line)
    r = symbll.compile_program(symname, repl.symbols)
    b = SerDeser.Serialize(r)
    s = str(r)
    r.deref()
    return b, s, region


def gen_singleton():
    """Real spends of the singleton committed under the bll leaf
    version, driven through the spend command. Emits the complete
    example file content following the program marker line, prose
    included, so regeneration is a byte comparison against the
    committed file's bottom half."""
    div = "; " + "-" * 67
    program, prog_str, region = compile_committed_region(
        "examples/test-singleton", "SINGLETON")
    leaf = tapleaf_hash(program, LEAF_VERSION_BLL)

    def commit(ipk, path):
        """scriptPubKey and control block committing the program
        under IPK with PATH sibling hashes beside the leaf."""
        spk_, parity_ = taproot_spk(ipk, leaf, path)
        cb_ = bytes([LEAF_VERSION_BLL | parity_]) + ipk + b"".join(path)
        return spk_, cb_

    spk, cb = commit(UNSPENDABLE_IPK, [])
    dest = p2tr_raw(xonly(KEY_SGL_DEST))
    genesis = messages.ser_uint256(FUNDING_TXID) + struct.pack("<I", 0)
    genesis_alt = messages.ser_uint256(FUNDING_TXID_ALT) + struct.pack("<I", 0)

    # the contrast def is the committed SINGLETON with GENESIS moved
    # back to a witness argument, derived from the region so it
    # cannot drift from the def it claims to mirror
    singleton_defs = [line for line in region
                      if line.startswith("def (SINGLETON ")]
    if len(singleton_defs) != 1:
        raise SystemExit("committed region: expected exactly one SINGLETON def")
    arg_def = singleton_defs[0].replace(
        "def (SINGLETON ", "def (SINGLETONARG GENESIS ").replace(
        "(LINEAGE (GENESIS)", "(LINEAGE GENESIS")
    if "def (SINGLETONARG GENESIS " not in arg_def or "(LINEAGE GENESIS " not in arg_def:
        raise SystemExit("committed region: the SINGLETON def changed shape,"
                         " update the SINGLETONARG rewrite")

    err_invalid = "invalid: Exception: 0x" + b"singleton: invalid spend".hex()
    err_second = "invalid: Exception: 0x" + b"singleton: second odd output".hex()
    err_sig = "invalid: bip340_verify: invalid, non-empty signature"
    err_eval_invalid = ("ERR(Exception: 0x"
                        + b"singleton: invalid spend".hex() + ")")

    def proof(tx):
        return tx.serialize_without_witness()

    def envb(sig, p1, p2, pidx):
        """The witness environment element for a singleton spend, the
        compiled argument tree ((IARGS . PROOF) . (PROOF2 . PIDX))."""
        e = Cons(Cons(Atom(sig), Atom(p1)), Cons(Atom(p2), Atom(pidx)))
        b = SerDeser.Serialize(e)
        e.deref()
        return b

    def sgl_sig(tx, utxos):
        return sig_for_at(KEY_SGL_INNER, tx, utxos, program, 0,
                          leaf_ver=LEAF_VERSION_BLL)

    def sgl_spend(tx, utxos, p1, p2, pidx, expect, sig=None, cb_=cb):
        """Set the spend witness, self check the verdict against the
        real validator, and emit the spend line with its marker. The
        inner signature is computed for the spend itself unless a
        deliberately foreign one is passed."""
        if sig is None:
            sig = sgl_sig(tx, utxos)
        tx.wit.vtxinwit[0].scriptWitness.stack = [envb(sig, p1, p2, pidx),
                                                  program, cb_]
        got = str(verify_spend(tx, 0, utxos))
        if got != expect:
            raise SystemExit(f"self check: expected {expect!r}, got {got!r}")
        print(f"spend 0 {tx.serialize_with_witness().hex()} "
              + " ".join(u.serialize().hex() for u in utxos))
        print(f"; expect: {expect}")

    print(f"; expect: {prog_str}")
    print()
    print(div)
    print("; context free pins")
    print()
    print("; parity semantics on raw little endian amounts, the empty atom is")
    print("; refused rather than misread")
    print("eval (ODD8 0x0100000000000000)")
    print("; expect: 1")
    print("eval (ODD8 0x6200000000000000)")
    print("; expect: nil")
    print("eval (ODD8 0)")
    print("; expect: nil")
    print()
    print("; the canonical form guard, an out of range read raises rather than")
    print("; parsing as zero")
    print("eval (RD1 0x7f 0)")
    print("; expect: 127")
    print("eval (RD1 0x80 0)")
    print("; expect: ERR(Exception: 0x73696e676c65746f6e3a20766172696e74)")
    print("eval (RD1 0x7f 5)")
    print("; expect: ERR(Exception: 0x73696e676c65746f6e3a20766172696e74)")
    print()

    # the launch transaction spends the genesis outpoint and creates
    # the first singleton output at index 0, its witness is irrelevant
    fund, _ = make_tx(dest, [(90001, spk), (8998, dest)], 0xffffffff, 0,
                      program, cb)
    fund.rehash()
    print("; the launch transaction, revealed by the genesis spend")
    print(f"def PROOFGEN 0x{proof(fund).hex()}")
    print()
    print("; the proof serialization is the txid preimage")
    print("eval (hash256 (PROOFGEN))")
    print(f"; expect: 0x{messages.ser_uint256(fund.sha256).hex()}")
    print("; and its input 0 outpoint is the genesis outpoint")
    print("eval (PREVOUTAT (PROOFGEN) 5)")
    print(f"; expect: 0x{genesis.hex()}")
    print()

    txa, utxoa = make_tx2([(fund.sha256, 0, 90001, spk)],
                          [(88001, spk), (1000, dest)], program, cb)
    txa.rehash()
    siga = sgl_sig(txa, utxoa)
    print(div)
    print("; context A: the genesis spend continues the chain, the launch")
    print("; transaction consumed the genesis outpoint and this UTXO is its")
    print("; output 0")
    sgl_spend(txa, utxoa, proof(fund), b"", b"", "valid")
    print()
    print("; a proof that does not hash to the actual parent txid is refused,")
    print("; here the proof is this very transaction instead of the parent")
    sgl_spend(txa, utxoa, proof(txa), b"", b"", err_invalid)
    print()
    print("; the spend derived the introspection context, the executing")
    print("; program is the committed leaf, its control block carries the")
    print("; exclusivity SOLELEAF requires, and the leaf version and parity")
    print("; bit ride the control block's first byte")
    print(f"blleval (= (tx (q . 6)) (q . 0x{leaf.hex()}))")
    print("; expect: 1")
    print("eval (SOLELEAF)")
    print("; expect: 1")
    print(f"eval (all (= (h (tx 9)) {LEAF_VERSION_BLL}) (= (t (tx 9)) {cb[0] & 1}))")
    print("; expect: 1")
    print()

    txb, utxob = make_tx2([(txa.sha256, 0, 88001, spk)],
                          [(86001, spk), (1000, dest)], program, cb)
    txb.rehash()
    sigb = sgl_sig(txb, utxob)
    print(div)
    print("; context B: an ancestry spend continues the chain, the parent")
    print("; transaction spent an odd output at my scriptPubKey, shown by the")
    print("; grandparent reveal")
    sgl_spend(txb, utxob, proof(txa), proof(fund), b"", "valid")
    print()
    print("; a non-genesis UTXO cannot claim the genesis branch, the parent")
    print("; did not consume the genesis outpoint")
    sgl_spend(txb, utxob, proof(txa), b"", b"", err_invalid)
    print()
    print("; the inner program refuses a signature for a different transaction")
    sgl_spend(txb, utxob, proof(txa), proof(fund), b"", err_sig, sig=siga)
    print()
    print("; an input index past the parent's input count is refused before")
    print("; it can drive any parsing")
    sgl_spend(txb, utxob, proof(txa), proof(fund), b"\x01", err_invalid)
    print()
    print("; a non-minimally encoded index is re-encoded before the")
    print("; countdown, 0x00 is index zero, not an atom that never counts")
    print("; down")
    sgl_spend(txb, utxob, proof(txa), proof(fund), b"\x00", "valid")
    print()
    print("; a grandparent reveal that does not hash to the parent's prevout")
    print("; txid is never parsed")
    sgl_spend(txb, utxob, proof(txa), proof(txb), b"", err_invalid)
    print()

    txc, utxoc = make_tx2([(txb.sha256, 0, 86001, spk)], [(85000, dest)],
                          program, cb)
    print(div)
    print("; context C: a retire spend. The inner signature covers the")
    print("; outputs, so zero odd outputs is a consented retirement of the")
    print("; chain")
    sgl_spend(txc, utxoc, proof(txb), proof(txa), b"", "valid")
    print()

    txd, utxod = make_tx2([(txb.sha256, 0, 86001, spk)],
                          [(43001, spk), (41001, dest)], program, cb)
    print(div)
    print("; context D: a second odd output would fork the chain")
    sgl_spend(txd, utxod, proof(txb), proof(txa), b"", err_second)
    print()

    txe, utxoe = make_tx2([(txb.sha256, 0, 86001, spk)], [(85001, dest)],
                          program, cb)
    print(div)
    print("; context E: the successor must recreate my scriptPubKey")
    sgl_spend(txe, utxoe, proof(txb), proof(txa), b"", err_invalid)
    print()

    txf, utxof = make_tx2([(txb.sha256, 0, 86000, spk)],
                          [(84001, spk), (1000, dest)], program, cb)
    print(div)
    print("; context F: an even spent amount is not a singleton")
    sgl_spend(txf, utxof, proof(txb), proof(txa), b"", err_invalid)
    print()

    # a look-alike chain funded from a different outpoint, spending
    # the true singleton scriptPubKey
    fund_alt, _ = make_tx(dest, [(70001, spk), (28998, dest)], 0xffffffff, 0,
                          program, cb, prev_txid=FUNDING_TXID_ALT)
    fund_alt.rehash()
    txg, utxog = make_tx2([(fund_alt.sha256, 0, 70001, spk)],
                          [(68001, spk), (1000, dest)], program, cb)
    sigg = sgl_sig(txg, utxog)
    print(div)
    print("; context G: a look-alike output funded outside the chain. Anyone")
    print("; can fund an output at the singleton scriptPubKey, but GENESIS is")
    print("; quoted in the committed program, so the genesis claim names an")
    print("; outpoint the look-alike's parent never consumed. The exclusion")
    print("; is unconditional, the contrast section at the end shows the")
    print("; uncommitted variant accepting this same transaction")
    sgl_spend(txg, utxog, proof(fund_alt), b"", b"", err_invalid)
    print()
    print("; and its ancestry claim fails because the revealed grandparent")
    print("; does not hash to the parent's prevout txid")
    sgl_spend(txg, utxog, proof(fund_alt), proof(fund), b"", err_invalid)
    print()

    txh, utxosh = make_tx2([(txb.sha256, 0, 86001, spk),
                            (fund_alt.sha256, 0, 70001, spk)],
                           [(155001, spk)], program, cb)
    print(div)
    print("; context H: two singleton outputs spent in one transaction, two")
    print("; chains cannot merge through one successor")
    sgl_spend(txh, utxosh, proof(txb), proof(txa), b"", err_invalid)
    print()

    txi, utxoi = make_tx2([(txb.sha256, 0, 86001, spk)],
                          [(1000, dest), (84001, spk)], program, cb)
    print(div)
    print("; context I: the successor sits at a nonzero output index, found")
    print("; by the scan rather than assumed, pinning ODDSCAN's index plus")
    print("; one encoding at an index above zero")
    sgl_spend(txi, utxoi, proof(txb), proof(txa), b"", "valid")
    print()

    # a launch variant with two odd outputs at the singleton
    # scriptPubKey, output 1 may not claim the genesis branch
    fund2, _ = make_tx(dest, [(45001, spk), (43999, spk)], 0xffffffff, 0,
                       program, cb)
    fund2.rehash()
    print(div)
    print("; the two odd output launch variant for context J")
    print(f"def PROOFGEN2 0x{proof(fund2).hex()}")
    print()
    txj, utxoj = make_tx2([(fund2.sha256, 1, 43999, spk)], [(42999, spk)],
                          program, cb)
    print("; context J: the launch variant consumed the genesis outpoint and")
    print("; this output is odd at the singleton scriptPubKey, but only")
    print("; output 0 may claim the genesis branch, so the (tx 12) index rule")
    print("; is the check that refuses")
    sgl_spend(txj, utxoj, proof(fund2), b"", b"", err_invalid)
    print()

    # the same committed leaf without the exclusivity the induction
    # needs: an ordinary internal key for context K, a second leaf in
    # the tree for context L. Both launches consume the genesis
    # outpoint, mutually exclusive hypotheticals like C through I.
    ipk_ord = xonly(KEY_SGL_IPK)
    spk_k, cb_k = commit(ipk_ord, [])
    fund_k, _ = make_tx(dest, [(60001, spk_k), (38998, dest)], 0xffffffff, 0,
                        program, cb_k)
    fund_k.rehash()
    txk, utxok = make_tx2([(fund_k.sha256, 0, 60001, spk_k)],
                          [(58001, spk_k), (1000, dest)], program, cb_k)
    print(div)
    print("; context K: the same leaf committed under an ordinary internal")
    print("; key. The genesis claim holds, so the internal key half of")
    print("; SOLELEAF is the check that refuses: a key path could spend this")
    print("; output around the covenant")
    sgl_spend(txk, utxok, proof(fund_k), b"", b"", err_invalid, cb_=cb_k)
    print("eval (SOLELEAF)")
    print("; expect: nil")
    print()

    sibling = tapleaf_hash(b"bll: sibling leaf")
    spk_l, cb_l = commit(UNSPENDABLE_IPK, [sibling])
    fund_l, _ = make_tx(dest, [(50001, spk_l), (48998, dest)], 0xffffffff, 0,
                        program, cb_l)
    fund_l.rehash()
    txl, utxol = make_tx2([(fund_l.sha256, 0, 50001, spk_l)],
                          [(48001, spk_l), (1000, dest)], program, cb_l)
    print(div)
    print("; context L: the same leaf beside a second leaf in the tree. The")
    print("; genesis claim holds, so the merkle path half of SOLELEAF is the")
    print("; check that refuses: a sibling leaf could spend this output")
    print("; around the covenant")
    sgl_spend(txl, utxol, proof(fund_l), b"", b"", err_invalid, cb_=cb_l)
    print("eval (SOLELEAF)")
    print("; expect: nil")
    print()

    # the differential section: the same defs the committed bytes
    # compile from, evaluated through the symbolic evaluator
    print(div)
    print("; the symbolic evaluator on the committed defs: context B again,")
    print("; evaluated through symbll under the legacy setter harness, the")
    print("; differential against the compiled spend lines above")
    print()
    print(f"def PROOFA 0x{proof(txa).hex()}")
    print(f"def SIGB 0x{sigb.hex()}")
    print()
    txb.wit.vtxinwit[0].scriptWitness.stack = [envb(sigb, proof(txa),
                                                    proof(fund), b""),
                                               program, cb]
    emit_context2("context B under the legacy setter harness", txb, utxob,
                  program)
    print("; the ancestry spend accepts symbolically as it did compiled")
    print("eval (SINGLETON (SIGB) (PROOFA) (PROOFGEN) 0)")
    print("; expect: 1")
    print()

    # the contrast section: the look-alike under the legacy setter
    # harness, where the spender names the genesis
    print(div)
    print("; the contrast: context G under the earlier port's shape.")
    print("; SINGLETONARG is the committed program with GENESIS moved back to")
    print("; a witness argument, derived from the committed region by the")
    print("; generator, so the spender names a genesis of their own choosing")
    print("; and the look-alike transaction validates. The spend command")
    print("; line at the end re-refuses the same transaction under the")
    print("; committed layout, the binding that quoting constants into the")
    print("; committed program body exists to provide.")
    print()
    print(arg_def)
    print()
    print("; the genesis outpoint the look-alike chain descends from")
    print(f"def GENESISALT 0x{genesis_alt.hex()}")
    print(f"def PROOFALT 0x{proof(fund_alt).hex()}")
    print(f"def SIGLOOK 0x{sigg.hex()}")
    print()
    txg.wit.vtxinwit[0].scriptWitness.stack = [envb(sigg, proof(fund_alt),
                                                    b"", b""), program, cb]
    emit_context2("the look-alike transaction under the legacy setter harness",
                  txg, utxog, program)
    print("; this setter context is self consistent: the committed leaf, the")
    print("; control block and the spent scriptPubKey satisfy the BIP341")
    print("; equation, which the spend command verifies itself and this")
    print("; harness does not, and the muladd raises on a mismatch. The")
    print("; reconstruction defs are imported here, outside the committed")
    print("; region, so the pin runs without riding into the committed leaf")
    print("import examples/lib-taproot")
    print("eval (TAPROOT (t (tx 9)) (tx 6) (tx 8) (tx 7) (CHECKTAPSPK (tx 16)))")
    print("; expect: 1")
    print()
    print("; the spender-named genesis validates under the setter harness")
    print("eval (SINGLETONARG (GENESISALT) (SIGLOOK) (PROOFALT) 0 0)")
    print("; expect: 1")
    print()
    print("; while the committed program refuses the same context, GENESIS")
    print("; is not the spender's to name")
    print("eval (SINGLETON (SIGLOOK) (PROOFALT) 0 0)")
    print(f"; expect: {err_eval_invalid}")
    print()
    print("; and the same transaction under the spend command is refused by")
    print("; the committed GENESIS")
    sgl_spend(txg, utxog, proof(fund_alt), b"", b"", err_invalid, sig=sigg)


# the constant wrapper bytes of a member leaf
#   (a (q . BODY) (rc (q . INNER) 1))
# serialized as WRAP_HEAD || BODY || WRAP_MID || SINNER || WRAP_TAIL,
# so PREFIX = WRAP_HEAD || BODY || WRAP_MID is the shared committed
# half and SINNER is the holder's serialized quoted inner program
WRAP_HEAD = bytes.fromhex("ff01ffff80")
WRAP_MID = bytes.fromhex("ffff06ffff80")
WRAP_TAIL = bytes.fromhex("ff018080")


def region_constant(region, name):
    """The value token of a committed region constant def line."""
    defs = [line for line in region if line.startswith(f"def {name} ")]
    if len(defs) != 1:
        raise SystemExit(f"committed region: expected exactly one {name} def")
    return defs[0].split()[2]


def cat_tail_text(genesis):
    """The issuance program, genesis_by_coin_id's port, as a numeric
    bll tree over the argument tree (DELTA PROOF . TS), DELTA at 2
    and PROOF at 5:
      (all (notall DELTA)
           (<s (substr PROOF (q . 4) (q . 5)) (q . 0x80))
           (= (substr PROOF (q . 5) (q . 41)) (q . GENESIS)))
    a truthy verdict needs a zero delta and a parent that consumed
    GENESIS at input 0, with a canonical input count byte."""
    return ("(12 (11 2) (15 (17 5 (0 . 4) (0 . 5)) (0 . 0x80))"
            f" (14 (17 5 (0 . 5) (0 . 41)) (0 . 0x{genesis.hex()})))")


def gen_cat():
    """Real spends of the CAT committed under the bll leaf version,
    driven through the spend command. Emits the complete example file
    content following the program marker line, prose included, so
    regeneration is a byte comparison against the committed file's
    bottom half."""
    div = "; " + "-" * 67
    body, body_str, region = compile_committed_region(
        "examples/test-cat", "CAT")
    prefix = WRAP_HEAD + body + WRAP_MID

    # the committed region pins two values the region itself cannot
    # compute: the shared prefix length and the issuance program's
    # tree hash. Assert both fixed points on every run.
    committed_len = int(region_constant(region, "PREFIXLEN"))
    if committed_len != len(prefix):
        raise SystemExit("committed region: PREFIXLEN is"
                         f" {committed_len}, the compiled prefix is"
                         f" {len(prefix)} bytes, update the def")
    genesis = messages.ser_uint256(FUNDING_TXID) + struct.pack("<I", 0)
    genesis_b = messages.ser_uint256(FUNDING_TXID_ALT) + struct.pack("<I", 0)
    if region_constant(region, "GENESIS") != f"0x{genesis.hex()}":
        raise SystemExit("committed region: GENESIS does not match the"
                         " generator's funding outpoint")
    tail_el = SExpr.parse(cat_tail_text(genesis))
    tailhash = sha256tree(tail_el)
    tail_el.deref()
    if region_constant(region, "TAILHASH") != f"0x{tailhash.hex()}":
        raise SystemExit("committed region: TAILHASH is not"
                         f" 0x{tailhash.hex()}, update the def")

    # the wrong-asset contrast compiles the same region under asset
    # B's constants, derived by line surgery so it cannot drift
    region_b = []
    for line in region:
        if line.startswith("def GENESIS "):
            line = f"def GENESIS 0x{genesis_b.hex()}"
        elif line.startswith("def TAILHASH "):
            tail_el_b = SExpr.parse(cat_tail_text(genesis_b))
            line = f"def TAILHASH 0x{sha256tree(tail_el_b).hex()}"
            tail_el_b.deref()
        region_b.append(line)
    with tempfile.NamedTemporaryFile("w", suffix="-test-cat-b",
                                     delete=False) as f:
        f.write(REGION_BEGIN + "\n")
        f.write("\n".join(region_b) + "\n")
        f.write(REGION_END + "\n")
        path_b = f.name
    try:
        body_b, _, _ = compile_committed_region(path_b, "CAT")
    finally:
        os.unlink(path_b)
    prefix_b = WRAP_HEAD + body_b + WRAP_MID
    if len(prefix_b) != len(prefix):
        raise SystemExit("asset B: the rewritten region compiled to a"
                         " different prefix length")

    def holder(key, pfx=prefix):
        """A holder's member leaf under an asset prefix: the inner
        program is (bip340_verify (q . PUB) (bip342_txmsg) 1) with
        the signature as the whole inner argument tree."""
        pub = xonly(key)
        inner = SExpr.parse(f"(38 (0 . 0x{pub.hex()}) (42) 1)")
        sinner = SerDeser.Serialize(inner)
        inner.deref()
        leaf = pfx + sinner + WRAP_TAIL
        if not 253 <= len(leaf) <= 0x7fff:
            raise SystemExit("member leaf outside the 0xfd compact"
                             " size form HASHLEAF assumes")
        leafhash = tapleaf_hash(leaf, LEAF_VERSION_BLL)
        spk, parity = taproot_spk(UNSPENDABLE_IPK, leafhash, [])
        cb = bytes([LEAF_VERSION_BLL | parity]) + UNSPENDABLE_IPK
        return {"key": key, "sinner": sinner, "leaf": leaf,
                "leafhash": leafhash, "spk": spk, "cb": cb,
                "par": int_to_bytes(parity)}

    h1 = holder(KEY_CAT_H1)
    h2 = holder(KEY_CAT_H2)
    h3 = holder(KEY_CAT_H3)
    bh1 = holder(KEY_CAT_B1, prefix_b)
    bh2 = holder(KEY_CAT_B2, prefix_b)
    dest = p2tr_raw(xonly(KEY_CAT_DEST))

    def claims(*items):
        """A claim list as a Cons list, each item a tuple of atoms
        whose leading members cons onto its final member, so a
        triple (a, b, c) becomes the improper list (a b . c)."""
        e = Atom(0)
        for item in reversed(items):
            c = Atom(item[-1])
            for payload in reversed(item[:-1]):
                c = Cons(Atom(payload), c)
            e = Cons(c, e)
        return e

    def iclaim(idx, hol):
        return (int_to_bytes(idx), hol["sinner"], hol["par"])

    def oclaim(hol):
        return (b"", hol["sinner"], hol["par"])

    def odisclaim(hol):
        """A disclaimer entry revealing a foreign output's taproot
        preimage: leaf version, leaf bytes, internal key, empty
        merkle path and output key parity."""
        return (b"\x01", b"\xc2", hol["leaf"], UNSPENDABLE_IPK, b"",
                hol["par"])

    def lclaim(pidx, hol):
        return (int_to_bytes(pidx), hol["sinner"], hol["par"])

    def cat_env(sinnerme, ic, oc, proof, proof2=b"", lc=None,
                tail=None, iargs=b"", pfx=prefix):
        """The witness environment element, the compiled argument tree
        (((PREFIX . SINNERME) . (ICLAIMS . OCLAIMS)) .
         ((PROOF . PROOF2) . ((LC . TAILR) . (TAILS . IARGS)))),
        with LC a (pidx, sinner, parity) tuple and TAIL the issuance
        program's numeric text when the spend reveals one."""
        lc_e = (Cons(Atom(lc[0]), Cons(Atom(lc[1]), Atom(lc[2])))
                if lc else Atom(0))
        tail_e = SExpr.parse(tail) if tail else Atom(0)
        e = Cons(Cons(Cons(Atom(pfx), Atom(sinnerme)), Cons(ic, oc)),
                 Cons(Cons(Atom(proof), Atom(proof2)),
                      Cons(Cons(lc_e, tail_e),
                           Cons(Atom(b""), Atom(iargs)))))
        b = SerDeser.Serialize(e)
        e.deref()
        return b

    def proof(tx):
        return tx.serialize_without_witness()

    def cat_sig(hol, tx, utxos, idx):
        return sig_for_at(hol["key"], tx, utxos, hol["leaf"], idx,
                          leaf_ver=LEAF_VERSION_BLL)

    def cat_spend(tx, utxos, idx, hol, env, expect, prefix_only=False):
        """Set input IDX's spend witness, self check the verdict
        against the real validator, and emit the spend line with its
        marker. A muladd refusal appends the mismatching point, so
        those sites assert the message prefix and record the full
        verdict."""
        tx.wit.vtxinwit[idx].scriptWitness.stack = [env, hol["leaf"],
                                                    hol["cb"]]
        got = str(verify_spend(tx, idx, utxos))
        ok = got.startswith(expect) if prefix_only else got == expect
        if not ok:
            raise SystemExit(f"self check: expected {expect!r}, got {got!r}")
        print(f"spend {idx} {tx.serialize_with_witness().hex()} "
              + " ".join(u.serialize().hex() for u in utxos))
        print(f"; expect: {got}")

    err_invalid = "invalid: Exception: 0x" + b"cat: invalid spend".hex()
    err_inclaim = "invalid: Exception: 0x" + b"cat: input claim".hex()
    err_unclaimed = ("invalid: Exception: 0x"
                     + b"cat: unclaimed odd output".hex())
    err_tailhash = "invalid: Exception: 0x" + b"cat: tail hash".hex()
    err_notclaimed = ("invalid: Exception: 0x"
                      + b"cat: own input not claimed".hex())

    print(f"; expect: {body_str}")
    print()
    print(div)
    print("; context free pins")
    print()
    print("; the shared prefix, its committed length, and each holder's")
    print("; leaf rebuilt from it, the member reconstruction every claim")
    print("; runs")
    print(f"def PREFIXBYTES 0x{prefix.hex()}")
    print(f"def SINNERH1 0x{h1['sinner'].hex()}")
    print(f"def SINNERH2 0x{h2['sinner'].hex()}")
    print(f"def SINNERH3 0x{h3['sinner'].hex()}")
    print("eval (strlen (PREFIXBYTES))")
    print(f"; expect: {len(prefix)}")
    print("eval (= (strlen (PREFIXBYTES)) (PREFIXLEN))")
    print("; expect: 1")
    print("eval (HASHLEAF (PREFIXBYTES) (SINNERH1))")
    print(f"; expect: 0x{h1['leafhash'].hex()}")
    print()
    print("; the issuance program and its committed tree hash")
    print(f"def TAILGEN (q {cat_tail_text(genesis)[1:-1]})")
    print("eval (= (SHA256TREE (TAILGEN)) (TAILHASH))")
    print("; expect: 1")
    print()
    print("; parity semantics on raw little endian amounts, the empty atom")
    print("; is refused rather than misread")
    print("eval (ODD8 0x0100000000000000)")
    print("; expect: 1")
    print("eval (ODD8 0x6200000000000000)")
    print("; expect: nil")
    print("eval (ODD8 0)")
    print("; expect: nil")
    print()
    print("; the canonical form guard and the fixed width size prefix")
    print("eval (RD1 0x80 0)")
    print("; expect: ERR(Exception: 0x" + b"cat: varint".hex() + ")")
    print("eval (= (LE16 300) 0x2c01)")
    print("; expect: 1")
    print("eval (= (CSIZE 100) 0x64)")
    print("; expect: 1")
    print("eval (= (CSIZE 300) 0xfd2c01)")
    print("; expect: 1")
    print()

    # the genesis transaction consumes the GENESIS outpoint and mints
    # the asset's whole supply as its odd member outputs
    gentx, _ = make_tx2([(FUNDING_TXID, 0, FUNDING_VALUE, dest)],
                        [(90001, h1["spk"]), (8999, h2["spk"]),
                         (500, dest), (500, dest)], h1["leaf"], h1["cb"])
    gentx.rehash()
    print("; the genesis transaction, revealed by every first generation")
    print("; spend: it consumes the GENESIS outpoint at input 0 and its odd")
    print("; member outputs, 90001 to holder 1 and 8999 to holder 2, are")
    print("; the asset's fixed supply. The even outputs pass outside the")
    print("; asset.")
    print(f"def PROOFG 0x{proof(gentx).hex()}")
    print("eval (hash256 (PROOFG))")
    print(f"; expect: 0x{messages.ser_uint256(gentx.sha256).hex()}")
    print("eval (PREVOUTAT (PROOFG) 5)")
    print(f"; expect: 0x{genesis.hex()}")
    print()

    # context A: holder 1's first generation output moves to holder 3
    # through the issuance path, since the genesis transaction has no
    # member input to exhibit
    txa, utxoa = make_tx2([(gentx.sha256, 0, 90001, h1["spk"]),
                           (gentx.sha256, 2, 500, dest)],
                          [(90001, h3["spk"])], h1["leaf"], h1["cb"])
    txa.rehash()
    siga = cat_sig(h1, txa, utxoa, 0)
    tail_a = cat_tail_text(genesis)
    enva = cat_env(h1["sinner"], claims(iclaim(0, h1)),
                   claims(oclaim(h3)), proof(gentx), tail=tail_a,
                   iargs=siga)
    print(div)
    print("; context A: the genesis spend. Holder 1 moves the 90001 unit")
    print("; output to holder 3. Lineage has nothing to exhibit, the parent")
    print("; is the genesis transaction itself, so the spend reveals the")
    print("; issuance program, which approves the zero delta because the")
    print("; revealed parent consumed GENESIS at input 0. The even change")
    print("; input pays the fee, members cannot.")
    cat_spend(txa, utxoa, 0, h1, enva, "valid")
    print()
    print("; a proof that does not hash to the actual parent txid is")
    print("; refused before either branch reads it, here the proof is this")
    print("; very transaction instead of the parent")
    cat_spend(txa, utxoa, 0, h1,
              cat_env(h1["sinner"], claims(iclaim(0, h1)),
                      claims(oclaim(h3)), proof(txa), tail=tail_a,
                      iargs=siga), err_invalid)
    print()
    print("; a revealed issuance program that does not tree hash to the")
    print("; committed TAILHASH is refused, here asset B's program")
    cat_spend(txa, utxoa, 0, h1,
              cat_env(h1["sinner"], claims(iclaim(0, h1)),
                      claims(oclaim(h3)), proof(gentx),
                      tail=cat_tail_text(genesis_b), iargs=siga),
              err_tailhash)
    print()
    print("; the spend derived the introspection context: the executing")
    print("; leaf is holder 1's rebuilt leaf")
    print(f"blleval (= (tx (q . 6)) (q . 0x{h1['leafhash'].hex()}))")
    print("; expect: 1")
    print()

    # context B: holder 3 moves the output to holder 1 through the
    # lineage path, exhibiting context A's member input
    txb, utxob = make_tx2([(txa.sha256, 0, 90001, h3["spk"])],
                          [(90001, h1["spk"])], h3["leaf"], h3["cb"])
    txb.rehash()
    sigb = cat_sig(h3, txb, utxob, 0)
    envb_ = cat_env(h3["sinner"], claims(iclaim(0, h3)),
                    claims(oclaim(h1)), proof(txa), proof(gentx),
                    lclaim(0, h1), iargs=sigb)
    print(div)
    print("; context B: the ancestry spend. Holder 3 moves the output to")
    print("; holder 1. The parent reveal is context A's transaction, whose")
    print("; input 0 spent holder 1's odd member output in the genesis")
    print("; transaction, proven by the grandparent reveal, so no issuance")
    print("; program is needed for the zero delta.")
    cat_spend(txb, utxob, 0, h3, envb_, "valid")
    print()
    print("; a lineage claim naming the parent's even change input is not")
    print("; a member exhibit")
    cat_spend(txb, utxob, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1)), proof(txa), proof(gentx),
                      lclaim(1, h1), iargs=sigb), err_invalid)
    print()
    print("; a lineage claim past the parent's input count is refused by")
    print("; the bound")
    cat_spend(txb, utxob, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1)), proof(txa), proof(gentx),
                      lclaim(5, h1), iargs=sigb), err_invalid)
    print()
    print("; a grandparent reveal that does not hash to the named txid is")
    print("; refused before it is parsed")
    cat_spend(txb, utxob, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1)), proof(txa), proof(txb),
                      lclaim(0, h1), iargs=sigb), err_invalid)
    print()
    print("; a wrong output key parity bit on the lineage claim refuses")
    print("; through the muladd")
    flipped = b"" if h1["par"] else b"\x01"
    cat_spend(txb, utxob, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1)), proof(txa), proof(gentx),
                      (int_to_bytes(0), h1["sinner"], flipped),
                      iargs=sigb),
              "invalid: secp256k1_muladd: did not sum to inf",
              prefix_only=True)
    print()
    print("; an empty claim list never claims the executing input")
    cat_spend(txb, utxob, 0, h3,
              cat_env(h3["sinner"], claims(), claims(oclaim(h1)),
                      proof(txa), proof(gentx), lclaim(0, h1),
                      iargs=sigb), err_notclaimed)
    print()

    print("; holder 3's inner program refuses a foreign signature, the")
    print("; authorization layer under the asset layer")
    cat_spend(txb, utxob, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1)), proof(txa), proof(gentx),
                      lclaim(0, h1), iargs=cat_sig(h1, txb, utxob, 0)),
              "invalid: bip340_verify: invalid, non-empty signature")
    print()

    # context C: a split into three odd member outputs
    txc, utxoc = make_tx2([(txa.sha256, 0, 90001, h3["spk"])],
                          [(30001, h1["spk"]), (30001, h2["spk"]),
                           (29999, h3["spk"])], h3["leaf"], h3["cb"])
    txc.rehash()
    sigc = cat_sig(h3, txc, utxoc, 0)
    print(div)
    print("; context C: a split. One member input funds three odd member")
    print("; outputs whose amounts sum to the input, an odd count, since")
    print("; two odd amounts cannot sum to an odd amount.")
    cat_spend(txc, utxoc, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1), oclaim(h2), oclaim(h3)),
                      proof(txa), proof(gentx), lclaim(0, h1),
                      iargs=sigc), "valid")
    print()

    # context D: a merge of both live coins, one input on each branch
    txd, utxod = make_tx2([(txa.sha256, 0, 90001, h3["spk"]),
                           (gentx.sha256, 1, 8999, h2["spk"])],
                          [(49001, h1["spk"]), (49999, h2["spk"])],
                          h3["leaf"], h3["cb"])
    txd.rehash()
    sigd0 = cat_sig(h3, txd, utxod, 0)
    sigd1 = cat_sig(h2, txd, utxod, 1)
    envd0 = cat_env(h3["sinner"], claims(iclaim(0, h3), iclaim(1, h2)),
                    claims(oclaim(h1), oclaim(h2)), proof(txa),
                    proof(gentx), lclaim(0, h1), iargs=sigd0)
    envd1 = cat_env(h2["sinner"], claims(iclaim(0, h3), iclaim(1, h2)),
                    claims(oclaim(h1), oclaim(h2)), proof(gentx),
                    tail=tail_a, iargs=sigd1)
    print(div)
    print("; context D: a merge. Both member inputs claim the same input")
    print("; set and compute the same objective sums. Input 0 proves")
    print("; ancestry through context A, input 1 is first generation and")
    print("; reveals the issuance program, both runs validate the one")
    print("; transaction.")
    txd.wit.vtxinwit[1].scriptWitness.stack = [envd1, h2["leaf"], h2["cb"]]
    cat_spend(txd, utxod, 0, h3, envd0, "valid")
    txd.wit.vtxinwit[0].scriptWitness.stack = [envd0, h3["leaf"], h3["cb"]]
    cat_spend(txd, utxod, 1, h2, envd1, "valid")
    print()
    print("; input 0 under-claiming its inputs fails its own equation, the")
    print("; objective odd output sum does not move")
    cat_spend(txd, utxod, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1), oclaim(h2)), proof(txa),
                      proof(gentx), lclaim(0, h1), iargs=sigd0),
              err_invalid)
    print()
    print("; claim indices must strictly increase, no input counts twice")
    cat_spend(txd, utxod, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3), iclaim(0, h3)),
                      claims(oclaim(h1), oclaim(h2)), proof(txa),
                      proof(gentx), lclaim(0, h1), iargs=sigd0),
              err_inclaim)
    print()

    # context E: the diamond followup, a child of the merge exhibits
    # the merge's second input
    txe, utxoe = make_tx2([(txd.sha256, 0, 49001, h1["spk"])],
                          [(49001, h2["spk"])], h1["leaf"], h1["cb"])
    txe.rehash()
    sige = cat_sig(h1, txe, utxoe, 0)
    print(div)
    print("; context E: the merge's child proves ancestry by exhibiting")
    print("; the merge's input 1, a nonzero claim index walking the parent")
    print("; reveal")
    cat_spend(txe, utxoe, 0, h1,
              cat_env(h1["sinner"], claims(iclaim(0, h1)),
                      claims(oclaim(h2)), proof(txd), proof(gentx),
                      lclaim(1, h2), iargs=sige), "valid")
    print()

    # context F: the boundary shift the committed PREFIXLEN refuses
    shift_prefix = prefix[:-1]
    shift = prefix[-1:]
    print(div)
    print("; context F: the boundary shift. The witness moves the last")
    print("; prefix byte into every revealed inner serialization: the")
    print("; rebuilt leaves and the executing leaf hash still match, only")
    print("; the committed PREFIXLEN refuses the split. The contrast")
    print("; section below shows the mint this check closes.")
    cat_spend(txb, utxob, 0, h3,
              cat_env(shift + h3["sinner"],
                      claims((b"", shift + h3["sinner"], h3["par"])),
                      claims((b"", shift + h1["sinner"], h1["par"])),
                      proof(txa), proof(gentx),
                      (b"", shift + h1["sinner"], h1["par"]),
                      iargs=sigb, pfx=shift_prefix), err_invalid)
    print()

    # context G: an odd output nobody claims, and one no claim can cover
    txg, utxog = make_tx2([(txa.sha256, 0, 90001, h3["spk"]),
                           (gentx.sha256, 3, 500, dest)],
                          [(90001, h1["spk"]), (499, dest)],
                          h3["leaf"], h3["cb"])
    txg.rehash()
    sigg = cat_sig(h3, txg, utxog, 0)
    print(div)
    print("; context G: an odd output outside the asset. The claim list")
    print("; ends before the stray odd output, so the scan refuses it")
    cat_spend(txg, utxog, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1)), proof(txa), proof(gentx),
                      lclaim(0, h1), iargs=sigg), err_unclaimed)
    print()
    print("; and no claim can cover it, the muladd refuses the rebuilt")
    print("; leaf against a scriptPubKey that is not a member")
    cat_spend(txg, utxog, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1), oclaim(h1)), proof(txa),
                      proof(gentx), lclaim(0, h1), iargs=sigg),
              "invalid: secp256k1_muladd: did not sum to inf",
              prefix_only=True)
    print()

    # context H: the two-asset swap, each run claiming its own
    # members and disclaiming the other asset's
    gentxb, _ = make_tx2([(FUNDING_TXID_ALT, 0, FUNDING_VALUE, dest)],
                         [(999, bh1["spk"]), (99000, dest)],
                         bh1["leaf"], bh1["cb"])
    gentxb.rehash()
    txh, utxoh = make_tx2([(txa.sha256, 0, 90001, h3["spk"]),
                           (gentxb.sha256, 0, 999, bh1["spk"])],
                          [(90001, h1["spk"]), (999, bh2["spk"])],
                          h3["leaf"], h3["cb"])
    txh.rehash()
    sigh0 = cat_sig(h3, txh, utxoh, 0)
    sigh1 = cat_sig(bh1, txh, utxoh, 1)
    envh0 = cat_env(h3["sinner"], claims(iclaim(0, h3)),
                    claims(oclaim(h1), odisclaim(bh2)), proof(txa),
                    proof(gentx), lclaim(0, h1), iargs=sigh0)
    envh1 = cat_env(bh1["sinner"], claims(iclaim(1, bh1)),
                    claims(odisclaim(h1), oclaim(bh2)), proof(gentxb),
                    tail=cat_tail_text(genesis_b), iargs=sigh1,
                    pfx=prefix_b)
    print(div)
    print("; context H: the two-asset swap. Asset A's units move to holder")
    print("; 1 while asset B's unit moves between B holders, one")
    print("; transaction. Each asset's run claims its own odd outputs and")
    print("; disclaims the other's by revealing the foreign leaf and")
    print("; showing its first committed-length bytes differ from its own")
    print("; prefix, the partition that makes cross-asset offers")
    print("; composable.")
    txh.wit.vtxinwit[1].scriptWitness.stack = [envh1, bh1["leaf"],
                                               bh1["cb"]]
    cat_spend(txh, utxoh, 0, h3, envh0, "valid")
    txh.wit.vtxinwit[0].scriptWitness.stack = [envh0, h3["leaf"],
                                               h3["cb"]]
    cat_spend(txh, utxoh, 1, bh1, envh1, "valid")
    print()
    print("; without the disclaimer the foreign odd output is refused, no")
    print("; entry covers it")
    cat_spend(txh, utxoh, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1)), proof(txa), proof(gentx),
                      lclaim(0, h1), iargs=sigh0), err_unclaimed)
    print()
    print("; and disclaiming one's own genuine member is refused, the")
    print("; revealed leaf carries the asset's own prefix")
    cat_spend(txh, utxoh, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(odisclaim(h1), odisclaim(bh2)), proof(txa),
                      proof(gentx), lclaim(0, h1), iargs=sigh0),
              "invalid: Exception: 0x" + b"cat: disclaimed member".hex())
    print()

    # context I: an even payment to a member script leaves the asset
    txi, utxoi = make_tx2([(txa.sha256, 0, 90001, h3["spk"]),
                           (gentx.sha256, 3, 500, dest)],
                          [(90001, h1["spk"]), (500, h2["spk"])],
                          h3["leaf"], h3["cb"])
    txi.rehash()
    sigi = cat_sig(h3, txi, utxoi, 0)
    print(div)
    print("; context I: an even payment to a member script. The scan")
    print("; ignores even outputs, so the spend validates, and the even")
    print("; output holds no units: spending it fails its own parity")
    print("; checks, a freeze its payer chose.")
    cat_spend(txi, utxoi, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1)), proof(txa), proof(gentx),
                      lclaim(0, h1), iargs=sigi), "valid")
    print()
    txi2, utxoi2 = make_tx2([(txi.sha256, 1, 500, h2["spk"])],
                            [(498, dest)], h2["leaf"], h2["cb"])
    txi2.rehash()
    sigi2 = cat_sig(h2, txi2, utxoi2, 0)
    cat_spend(txi2, utxoi2, 0, h2,
              cat_env(h2["sinner"], claims(iclaim(0, h2)), claims(),
                      proof(txi), proof(txa), lclaim(0, h3),
                      iargs=sigi2), err_inclaim)
    print()

    # context J: nonzero deltas
    txj, utxoj = make_tx2([(txa.sha256, 0, 90001, h3["spk"])],
                          [(89001, h1["spk"]), (1000, dest)],
                          h3["leaf"], h3["cb"])
    txj.rehash()
    sigj = cat_sig(h3, txj, utxoj, 0)
    print(div)
    print("; context J: a nonzero delta. Underpaying the odd output sum")
    print("; without an issuance reveal is refused, units cannot leak")
    print("; into fees or change")
    cat_spend(txj, utxoj, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1)), proof(txa), proof(gentx),
                      lclaim(0, h1), iargs=sigj), err_invalid)
    print()
    txj2, utxoj2 = make_tx2([(gentx.sha256, 1, 8999, h2["spk"]),
                             (FUNDING_TXID, 1, FUNDING_VALUE, dest)],
                            [(10999, h1["spk"]), (98000, dest)],
                            h2["leaf"], h2["cb"])
    txj2.rehash()
    sigj2 = cat_sig(h2, txj2, utxoj2, 0)
    print("; and the issuance program itself refuses a nonzero delta even")
    print("; with genesis parentage, following the pinned source: no")
    print("; issuance after the genesis transaction, supply is fixed")
    cat_spend(txj2, utxoj2, 0, h2,
              cat_env(h2["sinner"], claims(iclaim(0, h2)),
                      claims(oclaim(h1)), proof(gentx), tail=tail_a,
                      iargs=sigj2), err_invalid)
    print()

    # context K: an unbacked donation is frozen on both branches
    dontx, _ = make_tx2([(FUNDING_TXID, 1, FUNDING_VALUE, dest)],
                        [(999, h1["spk"]), (99000, dest)],
                        h1["leaf"], h1["cb"])
    dontx.rehash()
    txk, utxok = make_tx2([(dontx.sha256, 0, 999, h1["spk"])],
                          [(999, h2["spk"])], h1["leaf"], h1["cb"])
    txk.rehash()
    sigk = cat_sig(h1, txk, utxok, 0)
    print(div)
    print("; context K: an unbacked donation, an odd payment to a member")
    print("; script from outside the asset. Lineage fails, the donating")
    print("; transaction has no member input to exhibit, and the issuance")
    print("; program fails, it never consumed GENESIS: the units are")
    print("; frozen at their donor's expense, never minted.")
    cat_spend(txk, utxok, 0, h1,
              cat_env(h1["sinner"], claims(iclaim(0, h1)),
                      claims(oclaim(h2)), proof(dontx), proof(gentx),
                      lclaim(0, h1), iargs=sigk), err_invalid)
    print()
    cat_spend(txk, utxok, 0, h1,
              cat_env(h1["sinner"], claims(iclaim(0, h1)),
                      claims(oclaim(h2)), proof(dontx), tail=tail_a,
                      iargs=sigk), err_invalid)
    print()

    # context L: a member whose SINNER region is not a serialized
    # element, payable but never spendable
    frozen_leaf = prefix + b"\xa0" + WRAP_TAIL
    frozen_lh = tapleaf_hash(frozen_leaf, LEAF_VERSION_BLL)
    frozen_spk, frozen_par = taproot_spk(UNSPENDABLE_IPK, frozen_lh, [])
    frozen = {"sinner": b"\xa0", "leaf": frozen_leaf,
              "leafhash": frozen_lh, "spk": frozen_spk,
              "cb": bytes([LEAF_VERSION_BLL | frozen_par])
              + UNSPENDABLE_IPK,
              "par": int_to_bytes(frozen_par)}
    txl, utxol = make_tx2([(txa.sha256, 0, 90001, h3["spk"])],
                          [(89001, h1["spk"]), (999, frozen["spk"]),
                           (1, h2["spk"])], h3["leaf"], h3["cb"])
    txl.rehash()
    sigl = cat_sig(h3, txl, utxol, 0)
    print(div)
    print("; context L: a frozen SINNER. The claimed member's inner region")
    print("; is a single truncated size prefix, not a serialized element.")
    print("; Membership only rehashes bytes, so paying it validates, and")
    print("; the units are frozen: the leaf can never deserialize, the")
    print("; freeze deviation demonstrated at its payer's expense.")
    cat_spend(txl, utxol, 0, h3,
              cat_env(h3["sinner"], claims(iclaim(0, h3)),
                      claims(oclaim(h1), oclaim(frozen), oclaim(h2)),
                      proof(txa), proof(gentx), lclaim(0, h1),
                      iargs=sigl), "valid")
    print()
    txl2, utxol2 = make_tx2([(txl.sha256, 1, 999, frozen["spk"])],
                            [(998, dest)], frozen["leaf"], frozen["cb"])
    txl2.rehash()
    cat_spend(txl2, utxol2, 0, frozen,
              cat_env(frozen["sinner"], claims(iclaim(0, frozen)),
                      claims(), proof(txl), proof(txa),
                      lclaim(0, h3)),
              "invalid: leaf script: witness element truncated")
    print()

    # the differential section: the same defs the committed bytes
    # compile from, evaluated through the symbolic evaluator
    print(div)
    print("; the symbolic evaluator on the committed defs: context B again,")
    print("; evaluated through symbll under the legacy setter harness, the")
    print("; differential against the compiled spend lines above")
    print()
    print(f"def PROOFA 0x{proof(txa).hex()}")
    print(f"def SIGB 0x{sigb.hex()}")
    par1 = 1 if h1["par"] else 0
    par3 = 1 if h3["par"] else 0
    print(f"def INNERH3 (q 38 (0 . 0x{xonly(KEY_CAT_H3).hex()}) (42) 1)")
    print(f"def ICB (q (0 0x{h3['sinner'].hex()} . {par3}))")
    print(f"def OCB (q (0 0x{h1['sinner'].hex()} . {par1}))")
    print(f"def LCB (q 0 0x{h1['sinner'].hex()} . {par1})")
    print()
    txb.wit.vtxinwit[0].scriptWitness.stack = [envb_, h3["leaf"], h3["cb"]]
    emit_context2("context B under the legacy setter harness", txb, utxob,
                  h3["leaf"])
    print("; the ancestry spend accepts symbolically as it did compiled")
    print("eval (CAT2 (PREFIXBYTES) (SINNERH3) (ICB) (OCB) (PROOFA)"
          " (PROOFG) (LCB) 0 0 (SIGB) (INNERH3))")
    print("; expect: 1")
    print()

    # the contrast section: the committed program with the PREFIXLEN
    # clause dropped accepts the boundary shift
    cat2_defs = [line for line in region if line.startswith("def (CAT2 ")]
    if len(cat2_defs) != 1:
        raise SystemExit("committed region: expected exactly one CAT2 def")
    nolen_def = cat2_defs[0].replace("def (CAT2 ", "def (CAT2NOLEN ").replace(
        "(all (= (strlen PREFIX) (PREFIXLEN)) ", "(all ")
    if "def (CAT2NOLEN " not in nolen_def or "PREFIXLEN" in nolen_def:
        raise SystemExit("committed region: the CAT2 def changed shape,"
                         " update the CAT2NOLEN rewrite")
    print(div)
    print("; the contrast: context F under a body without the PREFIXLEN")
    print("; clause, derived from the committed region by the generator.")
    print("; The shifted split rebuilds every genuine member and the")
    print("; executing leaf hash still matches, so the check-free body")
    print("; accepts the spender's boundary, and with it any program that")
    print("; shares only the shortened prefix: an attacker mints by")
    print("; vetting leaves this body never saw. The committed PREFIXLEN")
    print("; is what pins the split, the spend line at the end re-refuses")
    print("; the same transaction under the committed layout.")
    print()
    print(nolen_def)
    print()
    print(f"def PREFIXSHIFT 0x{shift_prefix.hex()}")
    print(f"def SINNERSHIFTME 0x{(shift + h3['sinner']).hex()}")
    print(f"def ICSHIFT (q (0 0x{(shift + h3['sinner']).hex()} . {par3}))")
    print(f"def OCSHIFT (q (0 0x{(shift + h1['sinner']).hex()} . {par1}))")
    print(f"def LCSHIFT (q 0 0x{(shift + h1['sinner']).hex()} . {par1})")
    print()
    print("; the shifted boundary accepts without the committed length")
    print("eval (CAT2NOLEN (PREFIXSHIFT) (SINNERSHIFTME) (ICSHIFT)"
          " (OCSHIFT) (PROOFA) (PROOFG) (LCSHIFT) 0 0 (SIGB) (INNERH3))")
    print("; expect: 1")
    print()
    print("; while the committed program refuses the same split, the")
    print("; boundary is not the spender's to name")
    print("eval (CAT2 (PREFIXSHIFT) (SINNERSHIFTME) (ICSHIFT) (OCSHIFT)"
          " (PROOFA) (PROOFG) (LCSHIFT) 0 0 (SIGB) (INNERH3))")
    print("; expect: ERR(Exception: 0x" + b"cat: invalid spend".hex() + ")")


def serialize_bll(src):
    """Serialized bll program bytes for a named-opcode source string."""
    se = SExpr.parse(src)
    p = bll.ToBLL(se)
    se.deref()
    b = SerDeser.Serialize(p)
    p.deref()
    return b


def serialize_atom(payload):
    """Serialized single-atom element, for witness environment items."""
    a = Atom(payload)
    b = SerDeser.Serialize(a)
    a.deref()
    return b


def gen_commitment():
    """Spends of an output committing a bll program under the bll leaf
    version, driven through the spend command. The program is the
    simplest real contract, a signature check over the transaction:

        (bip340_verify (q . PUB) (bip342_txmsg) 1)

    with the pubkey quoted inside the committed program and the
    signature as the whole witness environment. The signature message
    commits to the leaf script under the executing leaf version taken
    from the control block, so the 0xc2 contexts sign a message no
    tapscript path could share."""
    pub = xonly(KEY_CMT_SIG)
    ipk = xonly(KEY_CMT_IPK)
    src = f"(bip340_verify (q . 0x{pub.hex()}) (bip342_txmsg) 1)"
    program = serialize_bll(src)
    leaf = tapleaf_hash(program, LEAF_VERSION_BLL)
    spk, parity = taproot_spk(ipk, leaf, [])
    cb = bytes([LEAF_VERSION_BLL | parity]) + ipk

    def spend_tx(env):
        tx, utxo = make_tx(spk, [(FUNDING_VALUE - 1000, p2tr_raw(pub))],
                           0xffffffff, 0, program, cb)
        tx.wit.vtxinwit[0].scriptWitness.stack = [env, program, cb]
        return tx, utxo

    tx, utxo = spend_tx(b"")
    sig = sig_for(KEY_CMT_SIG, tx, utxo, program, leaf_ver=LEAF_VERSION_BLL)
    tx, utxo = spend_tx(serialize_atom(sig))

    print(f"; program: {src}")
    print(f"; leaf script: {program.hex()}")
    print(f"; leaf hash: {leaf.hex()}")
    print()
    print("; context A: the valid spend")
    print(f"spend 0 {tx.serialize_with_witness().hex()} {utxo.serialize().hex()}")
    print()

    bad = sig[:-1] + bytes([sig[-1] ^ 1])
    txb, utxo = spend_tx(serialize_atom(bad))
    print("; context B: one signature bit flipped")
    print(f"spend 0 {txb.serialize_with_witness().hex()} {utxo.serialize().hex()}")
    print()

    # A fixed redundant encoding (a length prefixed one byte atom
    # below 0x80), constant so regeneration cannot land on signature
    # bytes whose 0x81 prefixed form happens to be canonical.
    txc, utxo = spend_tx(b"\x81\x05")
    print("; context C: redundantly encoded environment")
    print(f"spend 0 {txc.serialize_with_witness().hex()} {utxo.serialize().hex()}")
    print()

    txd, utxo = spend_tx(serialize_atom(sig))
    txd.wit.vtxinwit[0].scriptWitness.stack.insert(0, b"\x01")
    print("; context D: a fourth witness stack item")
    print(f"spend 0 {txd.serialize_with_witness().hex()} {utxo.serialize().hex()}")
    print()

    leaf_ts = tapleaf_hash(program)
    spk_ts, parity_ts = taproot_spk(ipk, leaf_ts, [])
    cb_ts = bytes([LEAF_VERSION_TAPSCRIPT | parity_ts]) + ipk
    txe, utxoe = make_tx(spk_ts, [(FUNDING_VALUE - 1000, p2tr_raw(pub))],
                         0xffffffff, 0, program, cb_ts)
    sig_ts = sig_for(KEY_CMT_SIG, txe, utxoe, program)
    txe.wit.vtxinwit[0].scriptWitness.stack = [serialize_atom(sig_ts), program, cb_ts]
    print("; context E: the same program committed under leaf version 0xc0")
    print(f"spend 0 {txe.serialize_with_witness().hex()} {utxoe.serialize().hex()}")


# the targets whose output is a whole generated file half, compared
# by --check against everything after the file's program marker line
CHECKED_FILES = {"singleton": ("examples/test-singleton",
                               "program SINGLETON\n"),
                 "cat": ("examples/test-cat", "program CAT\n")}


def check_generated(target, gen):
    """Compare a generator's output against the example file's
    generated half, everything after the program marker line, which
    the file header records as verbatim generator output."""
    path, marker = CHECKED_FILES[target]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        gen()
    with open(path) as f:
        content = f.read()
    committed = content[content.index(marker) + len(marker):]
    if committed != out.getvalue():
        print(f"{path}: the generated half differs from the"
              " committed file, regenerate and paste", file=sys.stderr)
        return 1
    print(f"{path}: generated half matches")
    return 0


def main():
    targets = {"vault": gen_vault, "flexmarks": gen_flexmarks, "htlc": gen_htlc,
               "p2d": gen_p2d, "singleton": gen_singleton, "cat": gen_cat,
               "commitment": gen_commitment}
    args = sys.argv[1:]
    check = args and args[-1] == "--check"
    if check:
        args = args[:-1]
    if len(args) != 1 or args[0] not in targets:
        print(f"usage: {sys.argv[0]} {{vault|flexmarks|htlc|p2d|singleton|cat|commitment}} [--check]", file=sys.stderr)
        return 1
    if check:
        if args[0] not in CHECKED_FILES:
            print("--check compares a whole generated file half, which only"
                  " the singleton and cat targets emit", file=sys.stderr)
            return 1
        return check_generated(args[0], targets[args[0]])
    targets[args[0]]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
