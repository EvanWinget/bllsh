# B4 gaps log: design input from the symbll corpus, part 2

Findings from porting the deployed Chia puzzle stack to symbll, unit
by unit, against the pinned sources in Chia-Network/chia_puzzles
release 0.20.3. Each item is input either for Track B design work,
for SPEC.md, or for upstream discussion, and the log is routed at B4
close-out in the same way as part 1. Unit 1 (the delegation half of
p2_delegated_puzzle_or_hidden_puzzle) recorded 2026-07-18. Unit 2
(singleton_top_layer_v1_1, items 7 through 17) recorded 2026-07-18.
Unit 3 (cat_v2 with genesis_by_coin_id, items 18 through 22)
recorded 2026-07-23.

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
   this surface, so it is an upstream candidate. Like the existing
   special names (`if`, `q`, `report`, `partial`), `a` now resolves
   before user symbols, so a def or parameter named `a` is silently
   captured on the symbolic path while a bare parameter still
   resolves on the compiled path, a divergence the other special
   names share. A def-time diagnostic for reserved names would close
   it, an upstream question.

2. **Quoted program literals must be spelled in opcode numbers.** A
   quoted tree containing symbols is symbolic, not bll, so it cannot
   be applied as a program or embedded in a compiled body. The
   example writes its delegates as numeric trees with the symbolic
   spelling in comments. An assembler form that turns a symbolic
   spelling into a bll tree (the repl TODO's `@SYM` generalization
   points the same way) would remove the noise. Upstream candidate.

3. **A nested apply is one debugger step.** The symbolic apply
   drives its program through nested bll evaluation inside a single
   symbolic step, so the repl's step and trace facilities see the
   whole delegate execute atomically. The evaluator's step allowance
   and allocation cap do interpose between the nested steps, so
   termination is preserved, only the visibility is coarse.
   Acceptable for now, worth a note if delegates grow.

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
   hash discipline like BIP340's challenge derivation. Resolved at
   B3 unit 2 (2026-07-20, Evan): the tagged hash discipline, no
   chain identity in the model. The delegation message is now
   TAGHASH under the bll/delegate tag, the outpoint carries the
   practical network binding, and an application needing
   unconditional separation commits a network identifier of its own.
   The convention is b3-gaps item 5.

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

## Transaction introspection surface

7. **A UTXO one-hop lineage proof needs the grandparent reveal.** An
   outpoint names a txid and an index but not the scriptPubKey it
   pays, so proving the parent transaction spent a singleton coin
   means revealing the grandparent transaction whose output carries
   that scriptPubKey. Chia's proof is three hashed fields because
   coin ids structurally embed the parent puzzle hash. A tx
   introspection surface that resolved a revealed outpoint to its
   scriptPubKey and amount would collapse the singleton's proof to
   one revealed transaction, but it would need consensus access to
   spent output data, which BIP341 sighashes already require nodes
   to have. Design input for the tx opcode surface.

8. **The control block sign bit is already introspectable.** The
   singleton reconstructs its own scriptPubKey with the parity bit
   from the cdr of `(tx 9)`, where the flexmarks recommitment takes
   the parity as witness data. A self recommitment never needs a
   witness supplied parity. Cleanup candidate for the flexmarks
   examples and a note for any future recommitment helper.

## Proof parsing in bll

9. **Witness supplied counters must be bounded before they recurse,
   and re-encoded minimally before they count down.** The first draft
   let the parent input index drive the input skipping recursion
   directly, and an out of range index burned the evaluator's cost
   ceiling instead of refusing cleanly. The second draft bounded the
   value but not the encoding: a non-minimal zero like 0x00 passes a
   numeric bound, yet a countdown that terminates on atom truthiness
   never reaches the empty atom and spins past every negative value.
   The port now bounds every witness supplied index by the count byte
   it walks under, re-encodes it with `(+ X 0)` before any countdown,
   and parses revealed bytes only after they hash to a pinned txid,
   so every cursor walk runs over verified data with a ceiling below
   128 steps. The consensus result of an overrun is the same refusal,
   but a bounded refusal is free where an overrun spends the whole
   budget, a cost griefing surface once budgets are real. SPEC input:
   the no unbounded recursion rule extends to programs the spec's
   examples teach people to write, and numeric bounds are not
   encoding bounds.

10. **Transaction parsing wants canonical form guards.** The port
    accepts only single byte counts and lengths below 0x80, raising
    on anything larger, because bll integers are signed little endian
    and a multi byte varint read as an integer misparses silently.
    Descendants of transactions with 128 or more inputs or outputs
    are therefore unspendable through this program, a recorded
    restriction. A bounded varint opcode or a vetted parsing library
    would remove the restriction and the hand rolled cursor
    arithmetic with it. Upstream and Track B design input.

11. **Non-empty zero atoms are truthy, so bitwise parity tests fail
    open.** `(& amount 1)` over a raw 8 byte little endian amount
    yields an 8 byte atom that is truthy even when the value is zero,
    because only the empty atom is falsy. The port masks the low byte
    and compares byte exactly. The empty atom needs its own guard on
    top: the bitwise fold passes the other operand through when one
    side is empty, so `(& nil 1)` is 1 and an unguarded parity test
    calls a nonexistent amount odd. The `(+ X 0)` normalization idiom
    covers the integer cases. A signextend style opcode, already on
    the upstream TODO list, or a minimal integer coercion would make
    the natural spelling safe. Upstream discussion input.

## The commitment layout

12. **The singleton's induction assumes the scriptPubKey is
    spendable only through its own leaf.** The ancestry proof shows
    the parent spent an odd coin at the same scriptPubKey, and that
    spend enforced the covenant only if no key path and no other
    leaf could have authorized it. That means a provably unusable
    internal key and a single leaf tree, which the program cannot
    verify from inside, and the test contexts use an ordinary
    internal key. Consensus finding for the commitment layout design:
    a recommitment covenant is only as strong as the commitment's
    exclusivity, the layout should give programs a way to know or
    force it. Resolved at B3 unit 2: the pattern is expressible with
    no new rule, an empty `(tx 8)` and `(tx 7)` equal to the BIP341
    unspendable internal key, since BIP341 validation already
    verified the control block against the spent scriptPubKey.
    SOLELEAF in examples/lib-taproot is the vetted copy, the
    recommitted singleton enforces it, and its contexts pin each
    half refusing alone. The finding is b3-gaps item 3.

13. **Nothing commits the argument tree, and for the singleton that
    means neither INNER nor GENESIS.** The singleton takes its own
    leaf hash as an explicit argument and binds it to `(tx 6)`, but
    INNER and GENESIS ride the unbound argument tree. For INNER this
    means inner transitions in Chia's morph sense have no meaning
    yet, and the port pins successor identity to the whole
    scriptPubKey instead. For GENESIS the consequence is sharper:
    every spend picks its own genesis outpoint, so a look-alike
    output at the singleton scriptPubKey validates against a genesis
    of its own choosing, and the exclusion of look-alike chains that
    the parent and grandparent reveal earns is conditional on the
    commitment layout binding GENESIS. Chia gets the unconditional
    version by currying LAUNCHER_ID into the puzzle hash. A committed
    program in the leaf with its constants quoted inside restores the
    same property by construction. This is the strongest single input
    the corpus has produced for the commitment layout design.
    Resolved at B3 unit 2: the singleton is committed as a 0xc2 leaf
    with GENESIS and INNER quoted in the program body, and look-alike
    exclusion is unconditional. The contrast section of
    examples/test-singleton shows the same look-alike transaction
    validating under the argument tree variant and refusing under
    the committed layout. Inner transitions in the morph sense are
    deliberately not adopted, the inner program is fixed for the
    life of the chain and successor identity stays
    whole-scriptPubKey.

## The source puzzle itself

14. **Retire fails open where Chia's melt fails closed.** Chia
    requires an explicit odd CREATE_COIN of -113 even to end the
    lineage, so a spend that creates no odd child without the
    sentinel is invalid. The port treats zero odd outputs as the
    retire mode, so absence is consent, and the guarantee rests on
    the inner program covering the outputs with its signature, which
    the example's does through bip342_txmsg. An inner program that
    signs less would allow third party retirement where Chia would
    refuse the spend. Recorded structural deviation and a note for
    corpus inner program conventions.

15. **The launcher and its announcement have no analogue and need
    none.** Chia's launcher breaks a hash circularity, the singleton
    struct cannot contain its own coin id, and announces the created
    singleton to the funding spend. Here the genesis outpoint plays
    the launcher id, the genesis spend proves the launch transaction
    consumed it at input 0, and no-double-spend makes the genesis
    output unique for a given genesis outpoint, subject to item 13's
    caveat that GENESIS itself is uncommitted before the commitment
    layout. The funder verifies the launch transaction they sign,
    which is the announcement's job done by the signer. Recorded
    structural deviation.

17. **The transaction wide odd scan is a composition constraint.**
    Chia scopes the exactly-one-odd rule to one coin's emitted
    conditions, so several singletons and odd-amount bystanders
    coexist in one spend bundle. The port's scan sees the whole
    transaction: every non-successor output must be even, two
    singletons with different scriptPubKeys cannot share a
    transaction, and any co-resident protocol needing an odd output
    is shut out. Input for the offer flow unit, which composes
    multiple parties' outputs in one transaction and must either
    live inside the even-amount constraint or motivate a scoping
    mechanism.

## The framework, unit 2

16. **The corpus library layout decision executed.** The taproot
    reconstruction block reached its fourth prospective copy, and the
    corpus now keeps one vetted copy in examples/lib-taproot pulled
    in through the repl's import command, the closest analogue of a
    Chialisp .clib include. Compiled programs are unchanged, defs
    still compile into each program that uses them. The upstream
    test-taproot demo keeps its own copy, the fork leaves upstream
    files untouched, and the lib carries only defs with corpus users,
    the leaf hashing chain stayed upstream since every corpus
    reconstruction starts from the introspected leaf hash. The
    boundary drawn: corpus generic blocks get the lib, family
    internal duplication like the earmark defs shared by the two
    flexmarks files stays inline until a third family member exists.
    The timelock helpers follow at the first B4 program that needs
    one.

## The commitment layout, unit 3

18. **A shared byte prefix restores currying under a flat leaf
    hash.** Chia rebuilds a wrapped puzzle hash from an inner hash
    because tree hashing is compositional. The bll leaf hash is a
    flat sha256 over serialized bytes, so nothing can be rebuilt
    from an inner hash alone. The port's substitute: every holder's
    leaf is the shared body applied to a quoted trailing inner
    program, so the serialization splits as PREFIX, SINNER, constant
    suffix, the witness reveals PREFIX once, and members rebuild by
    hashing PREFIX with a revealed SINNER. Two facts carry the
    soundness. The committed PREFIXLEN pins the split, since a
    spender-chosen boundary self-verifies against the executing leaf
    hash at any split point and a shortened prefix vets programs the
    body never saw, the mint the contrast section demonstrates. And
    serialization is a prefix code, so no leaf can begin with two
    different assets' complete prefixes, which makes membership
    exclusive. PREFIXLEN is a fixed point of the body that quotes
    it, width stable across two byte values, and the generator
    asserts it on every run. Input for the commitment layout memo:
    this is the general recipe for per-instance constants under a
    committed program.

19. **Non-membership is provable, and that is what makes assets
    compose.** The odd amount marking makes membership objective
    only if every odd output resolves, and demanding they all be
    members would shut two assets out of one transaction, which
    forecloses the offer flow. The resolution: an odd output is
    either claimed as a member or disclaimed by revealing its actual
    taproot preimage, leaf version, leaf bytes, internal key and
    path, rebuilding the output key from it, and showing the leaf is
    not a member, a different version or different first PREFIXLEN
    bytes. Disclaiming a genuine member always fails, so the
    partition is sound and each asset's conservation equation runs
    over its own members. The cost is the foreign leaf bytes riding
    the witness per disclaimer. The residue: an odd key path or
    untweaked output has no preimage to reveal under this rule, so
    plain payments beside a CAT use even amounts by convention, and
    a keypath disclaimer form is future work if the offer flow needs
    odd plain payouts.

20. **The genesis issuance program fixes supply at one transaction
    and locks it.** The ported genesis_by_coin_id refuses every
    nonzero delta, so supply is exactly the odd member outputs of
    the transaction that consumed the GENESIS outpoint, no melt and
    no later issuance. Consequences worth recording: member spends
    can contribute nothing to fees, which ride co-spent unmarked
    inputs, and value freezes are always payer-borne, whether an
    even payment to a member script, a SINNER region that never
    deserializes, or an unbacked odd donation, all three
    demonstrated in contexts. A first generation output spends
    through the issuance path because the genesis transaction has no
    member input for lineage to exhibit, and the program checks the
    revealed parent consumed GENESIS at input 0, count byte
    canonical, the same one restriction the singleton's genesis
    branch carries.

## The framework, unit 3

21. **Foreign output key parity is witness data.** Rebuilding
    another output's key needs its parity bit, which no opcode
    exposes, so every membership claim, disclaimer and lineage claim
    carries one. A wrong bit only refuses the spend through the
    muladd. The executing input needs none, its leaf hash pins to
    the introspected leaf hash directly and its control block
    carries the bit the reconstruction defs read.

22. **muladd refusals carry the mismatching point in the verdict.**
    A false membership claim surfaces as the muladd's raise, whose
    message appends a context dependent point, so the generator
    asserts those verdicts by prefix and records the full message in
    the expect marker. A corpus program wanting stable refusal
    messages would need a non-raising point equality check, which
    bll deliberately does not offer, the raise is the refusal.
