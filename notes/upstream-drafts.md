# Upstream candidates: draft texts

Drafts for issues and pull requests against `ajtowns/bllsh`, prepared
at B1 close-out. Nothing here has been filed. Filing waits for Evan's
go-ahead, likely batched with the Phase 0 outreach. Body text is
written to be pasted as-is.

## PR: fix the flexmarks example framework so it runs

Branch material: the five framework-fix commits at the base of
`b1-corpus` (`c4a7186`, `76d13c1`, `0e8fec3`, `cc0be5b`, `322a19a`),
one defect per commit.

Title: `examples: fix the flexmarks framework so it runs`

Body draft:

> Completing the flexmarks example turned up five defects in the
> shipped framework, each of which keeps `examples/test-flexmarks`
> from running once the policy hooks are implemented. One commit per
> defect:
>
> 1. `TAPLEAF` is used by `TAPROOTMAN` but only defined in
>    `test-taproot`, so the file does not evaluate on its own.
> 2. The framework calls `(and ...)` and `(not ...)`, which are not
>    defined. The builtins are `all` and `notall`.
> 3. `CHECKVALUE` read the scriptPubKey of the current input rather
>    than the value of output `OUTIDX`.
> 4. The recreated output's merkle path never committed to the updated
>    earmark from `NEWEM`, so any earmark mutation passed the new
>    output check.
> 5. `CHECKTAPSPK` matched a leading `0x0120` rather than `0x5120`
>    (`OP_1` then a 32 byte push) for a v1 taproot scriptPubKey.
>
> Each fix is minimal and the completed example in the follow-up
> branch runs green with them. Happy to split or squash as preferred.

## PR or issue: repl re-runs the last command on blank input lines

Gaps log item 13. The fix is a one-liner, so a PR is natural, but it
touches repl behavior rather than an example, so an issue first may be
the polite opening. Not implemented on `b1-corpus`, which deliberately
leaves everything outside `examples/` and `notes/` untouched.

Title: `repl: do not repeat the last command on a blank line`

Body draft:

> `cmd.Cmd`'s default `emptyline` re-runs the last command, so piping
> a file into the repl (`./bllsh < examples/test-sig`) re-executes
> each command once per blank line that follows it. `import` avoids
> this by skipping blank lines, but the piped form looks natural and
> silently double-evaluates. Overriding `emptyline` to do nothing
> makes both forms agree:
>
>     def emptyline(self):
>         pass

## Issue: symbll has no and, or or not

Gaps log item 1.

Title: `symbll: no and/or/not, and the flexmarks framework reached for them`

Body draft:

> The symbll builtins are `all`, `any` and `notall`. The names `and`,
> `or` and `not` do not exist, and the shipped flexmarks framework
> itself called `(and ...)` and `(not ...)`, so the instinct to reach
> for them is strong even for the language's author. Aliases would be
> the small fix. A lazy `and`/`or` would be the larger one, and would
> also address refusal-reason masking: `all` evaluates every argument,
> so an error raised by a later check (for example `bip340_verify` on
> an invalid non-empty signature) aborts evaluation before an earlier
> check's nil can reach the contract's own failure path.

## Issue: bip342_txmsg cannot be called with an explicit 0

Gaps log item 5.

Title: `bip342_txmsg: SIGHASH_DEFAULT is not spellable as 0`

Body draft:

> `(bip342_txmsg 0)` fails because the integer 0 is the empty atom,
> while the opcode wants a single sighash byte. SIGHASH_DEFAULT has to
> be requested by calling with no argument, or as `0x00`. That is
> workable once known, but the same minimal-int footgun will recur
> anywhere a field code or flag byte can be zero. Worth either
> accepting the empty atom as 0x00 here, or a documented convention
> for zero-valued flag bytes.

## Issue: field access ergonomics in symbll (supporting data for the TODO list)

Gaps log item 4. The repl banner already lists destructuring, defconst
and quasiquote as TODOs, so this is corpus evidence rather than a new
idea. Lowest priority of the four, possibly fold into a comment on
another thread instead of its own issue.

Title: `symbll: corpus experience with deep field access`

Body draft:

> Data point from porting a vault, a payment-pool withdrawal and an
> HTLC earmark to symbll: with a five-field earmark, accessor chains
> like `(h (t (t (t (t EM)))))` dominate the policy code and were the
> single largest source of first-draft bugs. Destructuring in `def`
> argument lists (already on the repl's TODO list) would remove most
> of the noise. `let` or lambda would help the remainder.
