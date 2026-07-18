# B4 gaps log: design input from the symbll corpus, part 2

Findings from porting the deployed Chia puzzle stack to symbll, unit
by unit, against the pinned sources in Chia-Network/chia_puzzles
release 0.20.3. Each item is input either for Track B design work,
for SPEC.md, or for upstream discussion, and the log is routed at B4
close-out in the same way as part 1. Unit 1 (the delegation half of
p2_delegated_puzzle_or_hidden_puzzle) recorded 2026-07-18.

## Language and opcode surface

1. **symbll had no apply surface.** The delegation half is literally
   `(a delegated_puzzle solution)`, and neither the symbolic
   evaluator nor the compiler accepted `a` in source, even though the
   compiler emits the opcode internally for user calls and `if`. The
   surface was added in this unit, restricted to exactly two
   operands: bll's one argument apply defaults the environment to the
   current one, and the symbolic evaluator's environment is a symbol
   table with no bll value form, so the short form cannot be
   mirrored. bll semantics are unchanged. The repl's own TODO wanted
   this surface, so it is an upstream candidate.

2. **Quoted program literals must be spelled in opcode numbers.** A
   quoted tree containing symbols is symbolic, not bll, so it cannot
   be applied as a program or embedded in a compiled body. The
   example writes its delegates as numeric trees with the symbolic
   spelling in comments. An assembler form that turns a symbolic
   spelling into a bll tree (the repl TODO's `@SYM` generalization
   points the same way) would remove the noise. Upstream candidate.

3. **A nested apply is one debugger step.** The symbolic apply runs
   its program through a nested bll evaluation, so the repl's step
   and trace facilities see the whole delegate execute as one atomic
   step. Acceptable for now, worth a note if delegates grow.

## Signatures and replay

4. **No AGG_SIG_ME analogue, the port signs the delegate hash bound
   to the outpoint.** The message is
   `(sha256 (SHA256TREE DELEG) (tx 11) (tx 12))`. Chia appends the
   coin id and a genesis challenge to the delegate hash. The outpoint
   stands in for the coin id and is unique on one chain, but the
   genesis challenge has no counterpart here, so the same key signing
   over the same outpoint on another network would validate there
   too. Design input for the witness model work: whether corpus
   signing messages should carry a network tag, or adopt a tagged
   hash discipline like BIP340's challenge derivation.

## The source puzzle itself

5. **The hidden puzzle half is taproot by construction.** Chia's
   `is_hidden_puzzle_correct` checks that the committed key equals
   the original key plus a point derived from hashing the key with
   the hidden program's tree hash, which is the BIP341 tweak equation
   rebuilt inside a puzzle. On Bitcoin the construction is native:
   committing a hidden program behind a key that can also sign is
   what a taproot output is. The port therefore keeps only the
   delegation half and refuses a nonzero original key, recording the
   equivalence instead of re-implementing it. Consensus finding for
   the commitment layout design: the standard payment puzzle's
   hidden half costs nothing in bll.

## The framework itself

6. **SymbolTable.deref could not release function entries.** Value
   entries are Elements but function entries are (params, body)
   tuples, and deref only handled the former, where set and unset
   handle both. Unreachable from the repl, whose table lives for the
   whole session, and first exercised by the apply test suite
   building and dropping tables. Fixed in this unit.
