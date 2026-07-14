# B1 gaps log: design input from the symbll corpus, part 1

Findings from completing the flexmarks example (signature withdrawal
and HTLC instantiations) and writing the vault example against
`ajtowns/bllsh` at `04f924f`. Each item is input either for Track B
design work, for SPEC.md, or for upstream discussion. Recorded
2026-07-10.

## Language and opcode surface

1. **No `and`, `or` or `not` in symbll.** The builtins are `all`,
   `any` and `notall`. The shipped flexmarks framework used `(and ...)`
   and `(not ...)` and therefore could not run. The examples now use
   the builtins, but the ergonomic gap is real and the framework's
   author reached for the missing names instinctively.

2. **Eager conjunctions mask refusal reasons.** `all` evaluates every
   argument, and an error in a later check aborts evaluation before an
   earlier check's nil can produce the contract's own failure path. In
   the withdraw example, a spend refused by the value check surfaces as
   a `secp256k1_muladd` error from the new output check instead of the
   contract's `(x)`. Contract authors would want a lazy `and`, or the
   discipline of ordering error-raising checks first. Worth a SPEC.md
   note on evaluation order.

3. **Failure checks error rather than return nil.**
   `secp256k1_muladd` errors when the sum is not infinity and
   `bip340_verify` errors on an invalid non-empty signature. Both are
   reasonable alone, but combined with eager `all` they decide which
   failure a contract reports. Whether consensus should distinguish
   error from nil in these opcodes is a design decision to record.

4. **No `let`, lambda, destructuring, defconst or quasiquote** (already
   listed as TODO in the repl banner). Deep accessor chains like
   `(h (t (t (t (t EM)))))` are unavoidable when an earmark carries
   five fields. Destructuring in `def` argument lists would remove most
   of the noise.

5. **`bip342_txmsg` cannot be called as `(bip342_txmsg 0)`.** The bll
   integer 0 is the empty atom, and the opcode requires a single
   sighash byte, so SIGHASH_DEFAULT must be requested by calling with
   no argument at all (or `0x00`). A minimal-int footgun that will
   recur anywhere a field code or flag byte can be zero.

## Transaction introspection

6. **Value fields are raw 8 byte little endian.** `(tx 15)` and
   `(tx (rc IDX 20))` return `struct.pack("<Q", value)`. bll integers
   are little endian sign magnitude, so arithmetic on them is correct
   for any realistic amount (below 2^55 sats), but the atom is not
   minimally encoded and equality against a computed amount fails
   unless the contract re-encodes. The withdraw example's value check
   works through `+` and `<`, which decode both encodings. SPEC.md
   should pin whether introspected integers are normalized.

7. **Timelocks are readable but not modeled.** nSequence `(tx 10)`,
   nLockTime `(tx 1)` and nVersion `(tx 0)` make delay and timeout
   assertions expressible (the vault and HTLC examples do), but the
   repl does not model BIP68 or nLockTime consensus enforcement, so
   an example can only assert what the transaction claims about
   itself. The differential harness in libbll will need real consensus
   context for these paths eventually.

8. **Reserved `tx` sub-codes return empty.** Codes 17 to 19 and 22 to
   29 return `b''` rather than erroring. Already relevant to libbll's
   SPEC.md section on field codes, and worth an upstream question since
   silent empties are easy to misuse in contracts.

9. **Nothing binds the evaluated program to the committed script.**
   `tx_script` and the witness script element are set independently of
   the symbll program being evaluated, and `(tx 6)` derives the leaf
   hash from the witness, not from the program. Fine for a repl, but it
   is the visible edge of the open witness and commitment model design
   (Track B3).

## The flexmarks framework itself

10. **The shipped framework had five defects that only execution could
    reveal**: `TAPLEAF` referenced but defined in another example,
    `and`/`not` undefined, `CHECKVALUE` reading the output scriptPubKey
    field instead of the output value and ignoring its output index,
    `NEWEM` defined but never wired into the new merkle path, and
    `CHECKTAPSPK` matching taproot scripts on `0x0120` instead of
    `0x5120`. All are fixed in small separate commits, each a candidate
    upstream PR. The meta-lesson for libbll is that examples need a
    harness that runs them (see 12).

11. **Payment pool key subtraction is unexplored.** The withdraw
    example leaves `NEWIPK` as the identity. A real pool removes the
    exiting member's key from the musig internal key, which needs the
    negation tracking discussed in the delving post. Expressible with
    `secp256k1_muladd` in principle, a good candidate for corpus part 2
    (B4) and a likely source of further introspection needs.

## Tooling

12. **No example harness or expected-output convention.** Success is
    eyeballing that evals print 1 and errors where comments say so. The
    new examples embed expected results in comments and a deterministic
    context generator (`examples/gen-test-context.py`) so every hex
    constant is reproducible, but a marker convention a runner could
    check (and that libbll's differential harness could consume) is the
    obvious next step. Addressed at B1 close-out: `; expect:` markers
    on every eval and blleval in the corpus examples, checked by
    `examples/run-examples.py`.

13. **Piping an example into the repl double-runs commands.**
    `cmd.Cmd` repeats the last command on every blank input line, so
    `./bllsh < examples/test-x` re-executes each eval once per blank
    line. `import examples/test-x` skips blank lines and is the
    reliable runner. Worth a one-line upstream fix (override
    `emptyline`).

14. **Timelock assertions are easy to get subtly wrong, a helper
    library is warranted.** Self review of the first drafts of the
    corpus examples caught two classic bugs that bll makes easy to
    write: a raw nSequence comparison that ignored BIP68's low 16 bit
    mask (a value like `0x01000A` passes `>= 144` while carrying an
    effective delay of 10 blocks) and a height timeout compared
    against nLockTime without the height versus time type check that
    OP_CLTV enforces (any past unix time satisfies a bare numeric
    comparison against a height). The fixed patterns are in
    `test-vault` (`CHECKDELAY`, bound below 2^16) and
    `test-flexmarks-htlc` (`CLTVOK`, type check plus comparison). A
    consensus deployment of bll wants these as vetted library
    functions or opcodes, not as per-contract hand rolled arithmetic,
    exactly the argument OP_CSV and OP_CLTV settled for Script.
