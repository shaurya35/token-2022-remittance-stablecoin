# Written finding: sanctioned funds moved into the confidential system before seizure

**Question:** What happens if a sanctioned user moves their balance into the
confidential system before the permanent delegate acts?

## Short answer

The permanent delegate loses. Once a balance sits in the confidential
`pending_balance` or `available_balance` of a Token-2022 account (both are
twisted-ElGamal ciphertexts, not plaintext `u64` amounts), the
`PermanentDelegate` extension has no instruction that can read, move, or
seize it. `PermanentDelegate` authorizes the delegate to sign as if it were
the account owner for the public token instructions (`Transfer`,
`TransferChecked`, `Burn`, `TransferCheckedWithFee`), all of which operate on
the plaintext `amount` field. None of those instructions can touch
`ConfidentialTransferAccount.pending_balance_lo/hi` or `available_balance`.
There is no confidential seize instruction in the Token-2022 program, by
design: every confidential-balance mutation (`ApplyPendingBalance`,
confidential `Transfer`, `Withdraw`) requires a proof generated from the
account owner's own ElGamal and AES keys, and the program verifies that
proof against the ciphertext already stored in the account. The permanent
delegate holds no ElGamal secret key for the sanctioned user's account, so
it cannot construct a valid proof, and there is no delegate override path
that would let it skip proof verification. `PermanentDelegate` is a
public-balance-only capability. It is functionally blind and powerless
against ciphertext balances.

## The race condition

This produces a genuine race between two authorities that act on the same
account at different layers:

1. **Freeze authority** (mint-level, via `FreezeAccount`/`ThawAccount`): can
   freeze an account instantly. A frozen account cannot submit any token
   instruction, public or confidential, so freezing always wins if it lands
   first.
2. **Permanent delegate** (seizure, via public `Transfer`/`Burn`): can only
   claw back funds still sitting in the plaintext `amount` field.

If a sanctioned user calls `Deposit` (public `amount` into confidential
`pending_balance`) before either of these lands, the deposited amount is
gone from the delegate's reach the instant the deposit transaction confirms.
The public `amount` field only holds what has not yet been deposited, or
what has since been withdrawn back out. Everything inside the confidential
system is opaque ciphertext the delegate cannot act on. `Deposit` itself is
a fully public instruction (the amount appears in instruction data and
transaction logs), so it is observable in real time, even though its effect
is to move value out of the delegate's reach.

## Freezing still works, but it does not undo the deposit

Even after funds are confidential, the freeze authority retains full power
to freeze the account (`FreezeAccount` checks only the mint's freeze
authority, not the extensions present on the account, and a frozen account's
`state` field blocks every instruction handler in the Token-2022 processor,
confidential ones included). So the issuer can still stop the sanctioned
user from moving the funds *further*: no more confidential transfers, no
`ApplyPendingBalance`, no `Withdraw` back to plaintext. But freezing does not
claw the balance back to the issuer, and it does not decrypt it. The funds
are frozen *in place*, in ciphertext, under the sanctioned user's own keys,
indefinitely, unless the user's own key material is later obtained (e.g. by
compelling the user, which is outside the protocol layer entirely).

## What the auditor key does and does not give you

If `ConfidentialTransferMint.auditor_elgamal_pubkey` is configured (as it is
in `confidential_mint_plan`/the reissued mint in this repo), every
confidential transfer additionally encrypts the transferred amount under the
auditor's public key, so a party holding the auditor's *secret* key can
decrypt transfer amounts after the fact for investigation. This is
**visibility, not control**: decrypting an auditor ciphertext lets a
compliance team see what moved and how much, but it grants no instruction
path to move, freeze, or seize the underlying balance. It is a forensic tool,
not an enforcement one, and it only covers `Transfer`, not `Deposit` or
`Withdraw` amounts (those aren't confidential-transfer-with-fee instructions
carrying auditor ciphertexts).

## Mitigations that actually close the gap

1. **Manual confidential-transfer approval as a chokepoint.** This repo's
   reissued mint sets `auto_approve_new_accounts: false`, so every new
   confidential account needs an explicit `ApproveAccount` from the
   confidential-transfer authority before it can hold confidential balances.
   Screening happens before an account can be used, not after.
2. **Freeze-before-any-fund-movement policy.** Treat sanctions screening as
   a precondition to unfreezing at all (this repo's KYC flow already does
   this: accounts default to `Frozen` and only thaw after KYC clears). If a
   wallet is later flagged, freeze first and investigate second, never the
   reverse, since freezing is the only lever that works identically on both
   public and confidential balances.
3. **Atomic thaw-seize-freeze transactions.** When funds must move through
   the public seizure path, do the seizure and any re-freeze in the same
   atomic transaction as any authority action that could otherwise let the
   user front-run it, so there is no intervening slot where the user can
   submit a `Deposit`.
4. **Off-chain monitoring of `Deposit` instructions.** `Deposit` is fully
   public (source, amount, and discriminant are visible pre-confirmation),
   so an issuer can monitor for large or sanctioned-wallet deposits and
   trigger an immediate freeze, shrinking, though never fully eliminating,
   the race window before the balance becomes opaque.

## Bottom line

`PermanentDelegate` seizure and confidential transfers are not equivalent
powers layered on the same balance. They operate on disjoint
representations of balance (plaintext `amount` vs. ElGamal ciphertext), and
only one of the two authorities in this system, freeze, has power over both.
Any compliance design built on this extension set must treat "deposit into
confidential" as the terminal event after which seizure is no longer
possible, and must front-load all screening and freeze decisions to before
that point.
