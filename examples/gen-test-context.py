#!/usr/bin/env python3
"""Generate deterministic test contexts for the corpus examples.

Every hex constant in examples/test-vault, examples/test-flexmarks,
examples/test-flexmarks-htlc, examples/test-p2-delegated and
examples/test-singleton is produced by this script, so the examples can
be regenerated and audited. Run from the repository root:

    python3 examples/gen-test-context.py vault
    python3 examples/gen-test-context.py flexmarks
    python3 examples/gen-test-context.py htlc
    python3 examples/gen-test-context.py p2d
    python3 examples/gen-test-context.py singleton
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
import struct
import sys

sys.path.insert(0, ".")

import bll
import symbll
from element import Atom, Cons, SExpr, SerDeser
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


def check_singleton():
    """Compare the generator's singleton output against the example
    file's generated half, everything after the program marker line,
    which the file header records as verbatim generator output."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        gen_singleton()
    with open("examples/test-singleton") as f:
        content = f.read()
    marker = "program SINGLETON\n"
    committed = content[content.index(marker) + len(marker):]
    if committed != out.getvalue():
        print("examples/test-singleton: the generated half differs from the"
              " committed file, regenerate and paste", file=sys.stderr)
        return 1
    print("examples/test-singleton: generated half matches")
    return 0


def main():
    targets = {"vault": gen_vault, "flexmarks": gen_flexmarks, "htlc": gen_htlc,
               "p2d": gen_p2d, "singleton": gen_singleton,
               "commitment": gen_commitment}
    args = sys.argv[1:]
    check = args and args[-1] == "--check"
    if check:
        args = args[:-1]
    if len(args) != 1 or args[0] not in targets:
        print(f"usage: {sys.argv[0]} {{vault|flexmarks|htlc|p2d|singleton|commitment}} [--check]", file=sys.stderr)
        return 1
    if check:
        if args[0] != "singleton":
            print("--check compares a whole generated file half, which only"
                  " the singleton target emits", file=sys.stderr)
            return 1
        return check_singleton()
    targets[args[0]]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
