# B3 gaps log: design input from the witness model glue

Findings from implementing the commitment and witness layout glue
(spend.py, the repl's spend command, and the test-commitment
example), recorded as the work surfaces them and routed at B3
close-out the same way as the earlier logs. Unit 1 recorded
2026-07-18, unit 2 (the singleton under the real layout) recorded
2026-07-20, unit 3 (sizing and the element cap) recorded
2026-07-20.

## The signature message

1. **bip342_txmsg hashes the leaf under tapscript's version.** The
   BIP341 signature message helper takes the leaf version as a
   parameter defaulting to 0xc0 and the opcode does not pass it, so
   the message commits to the leaf script hashed under tapscript's
   leaf version whatever version the executing leaf carries. Spends
   validate, since signer and validator compute the same message,
   but the sighash names a tapleaf hash that is not the executing
   leaf's, the hash `(tx 6)` returns. Full transaction replay across
   the two leaf versions is still excluded, because every sighash
   mode commits to the spent output's scriptPubKey and committing
   the same script under a different leaf version changes the output
   key. The fix is one line, passing the control block's leaf
   version through, but it changes interpreter semantics, so it was
   held for Evan's decision rather than fixed in the glue unit.
   Decided 2026-07-18 (Evan): fixed. The opcode now takes the leaf
   version from the control block, with tapscript's version standing
   in when no script path witness is present, and the rule is pinned
   by the sighash case in test-spend.py. Every earlier corpus
   context commits its leaf under tapscript's version, where the old
   and new messages coincide, so no existing signature changed. The
   libbll port hashes the leaf under a hardcoded tapscript version
   in txcontext.cpp and must adopt the same rule in the pin bump
   that carries this change, with differential vectors expected to
   change for contexts whose control blocks carry other versions.

## The budget

2. **Witness decode cannot exhaust the budget under the A3
   constants.** The boundary decoder charges the rd rates plus the
   allocation share, at most 30 per payload byte and 16 per element,
   and an element's encoding is at least one byte, while every
   witness byte buys 560. A witness therefore always affords its own
   decode, and the exhausted-mid-decode refusal is unreachable from
   a real spend. The path stays implemented and tested, since the
   boundary contract must not depend on the constants staying in
   this ratio. Two inputs for the element cap sizing: decoded
   witness structure contributes at most one element per witness
   byte to the live count before evaluation starts, and those
   elements are already priced through the decode charges, so the
   cap analysis that rides on allocation charges covers them.
   Consumed at unit 3: the cap landed as ELEMENT_ALLOCATION_LIMIT
   in costs.py, a backstop just above the constructions the clamped
   maximum budget affords, enforced by verify_spend over decode
   plus evaluation.

## The singleton under the real layout

3. **Commitment exclusivity is expressible from inside evaluation
   with no new rule.** The singleton's induction needs the spent
   scriptPubKey spendable only through the executing leaf. BIP341
   validation already verified the control block against the spent
   output, so the program only has to inspect what that control
   block revealed: `(tx 8)` empty means a single leaf tree and
   `(tx 7)` equal to the BIP341 unspendable internal key means no
   key path. The vetted copy is SOLELEAF beside UNSPENDABLEIPK in
   examples/lib-taproot, the recommitted singleton enforces it, and
   its contexts pin each half refusing alone (an ordinary internal
   key, a second leaf). Design consequence for the layout: the
   introspection surface pinned in A2, fields 7 and 8, turned out to
   be exactly sufficient for covenant exclusivity, and no chain
   level "this output is exclusive" flag is needed. One scope note:
   the inference is sound only where BIP341 validation checked the
   control block, so SOLELEAF is meaningful under the spend command
   and reads unchecked witness bytes under the legacy setter
   harness. A setter context without a script path control block
   also lands on the oracle's known crash shape in the shared
   bip341 classifier, the recorded tx introspection divergence,
   which the spend command's stack validation makes unreachable
   from a real spend.

4. **The compiler embeds the whole symbol table, so committed bytes
   are a function of every def in scope and their insertion order.**
   compile_program folds the full table into the emitted program,
   used or not, which makes the committed leaf's bytes depend on the
   def region as a whole rather than on the entry symbol's call
   graph. The corpus pins reproducibility structurally: the example
   file's sentinel delimited def region is the single input, the
   generator recompiles it and validates every spend before
   emitting, and the program marker fails the example runner on any
   drift. Two findings for later tooling: unused library defs ride
   into committed programs and cost witness weight (the recommitted
   singleton pays roughly 300 bytes of its roughly 2000 byte leaf
   for the taproot reconstruction defs it never calls), and any
   future dead-def elimination is a committed-bytes-changing
   compiler choice that must be bit-for-bit deterministic across
   implementations before a corpus adopts it. Resolved at unit 3
   (2026-07-20, Evan): the exclusivity pair moved to its own vetted
   copy in examples/lib-exclusivity and the committed region imports
   only that pair, so the committed singleton fell from 2031 to
   1678 bytes and now embeds no def its entry point cannot reach.
   The determinism finding stands for any future compiler-level
   dead-def elimination, which this restructuring deliberately is
   not: the region is still embedded whole, it just contains
   nothing unreachable. One bundling residue is left deliberately:
   lib-taproot still carries the reconstruction defs beside the
   signing convention, so a future real layout port needing only
   SIGNMSG would embed four dead defs. Deferred at no cost because
   the delegation port commits a demo tapscript leaf today, not its
   compiled program, so no committed bytes pin exists to churn: the
   signing convention gets its own vetted copy when that migration
   lands.

5. **Explicit-message signatures adopt a tagged hash discipline, and
   the model exposes no chain identity** (decided 2026-07-20, Evan).
   The corpus convention, carried by lib-taproot's SIGNMSG: a
   message that is not a bip342_txmsg transaction hash is hashed
   with TAGHASH under a per-application tag with the spent outpoint
   appended, bll/delegate for the delegation port. The tag
   separates protocols, and the outpoint binds the network only as
   far as funding ancestries differ, since an outpoint recurs on
   another chain exactly when its entire funding ancestry recurs
   there. That is a real bound between mainnet-class chains and a
   weak one between twin test networks: coinbase txids do not
   commit to a signet's challenge, the block signature rides the
   coinbase witness, so two custom signets mined to the same script
   at the same heights can share early ancestries. A deployment on
   such chains commits a network identifier of its own, as does any
   application needing unconditional separation. Goes into the SPEC
   section 7 draft at unit 3 as a convention of the corpus, not a
   consensus rule, with the twin network caveat stated.

## Sizing and the element cap

6. **The cap's counted span is a driver decision, and the two
   implementations cap different surfaces outside real spends.**
   verify_spend arms the allocator around decode plus evaluation
   and disarms before returning, so the repl's eval command, the
   symbolic evaluator and the debugger run uncapped, which is what
   keeps interactive work and the differential harness unconstrained
   by a consensus limit they never approach. The libbll evaluator
   arms at evaluation entry instead, its spend dispatch layer
   arriving with the inquisition glue, so between the two
   implementations the uncapped surfaces differ everywhere except
   the one place it matters, a validated spend, where both count
   decode plus evaluation under the same constant. Whether that
   asymmetry earns a recorded divergence entry is routed to Evan at
   close-out with the SPEC section 7 draft. One measured point for
   the repo side sizing analysis: the self application loop, pure
   machine work, allocates one element per 18.4 charged units, above
   the provable floor of one per 12 and far below the worst measured
   retention shape's one per 877.
