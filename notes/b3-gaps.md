# B3 gaps log: design input from the witness model glue

Findings from implementing the commitment and witness layout glue
(spend.py, the repl's spend command, and the test-commitment
example), recorded as the work surfaces them and routed at B3
close-out the same way as the earlier logs. Unit 1 recorded
2026-07-18.

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
   version through, but it changes interpreter semantics and
   invalidates every corpus signature generated before it, so it is
   held for Evan's decision rather than fixed in the glue unit.

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
