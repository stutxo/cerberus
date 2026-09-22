# BTC-to-Ark adaptor swap protocol

This document describes version 3 of `bark swap btc-ark`. Alice pays Ark VTXOs
and receives on-chain BTC; Bob pays BTC and receives Ark VTXOs. The protocol
uses exactly three one-way peer messages, followed by chain observation. See the
[CLI walkthrough](../bark-btc-ark-swap/btc-ark-swap.md) for commands and setup.

The adaptor signatures link the two payments: a valid signature for the pinned
BTC claim lets Bob recover the secret needed to finalize the Ark transfer.
**Publishing that signature is not the same as confirming the BTC claim.**
Safety also depends on deadlines, transaction inclusion, ordinary Ark recovery,
and continuous monitoring. This is not a production-security guarantee, an
offline-safe protocol, or a grief-free exchange.

## Roles and assumptions

- **Alice (`ark-payer`)** chooses the adaptor secret `t`, publishes `T = t*G`,
  and prepares the Ark transfer before Bob funds.
- **Bob (`btc-payer`)** supplies the BTC funding template, pays into a Taproot
  lock, and retains its independent refund key.
- **The Ark server** performs ordinary arkoor co-signing and transaction-chain
  registration. There is no swap-specific server policy or RPC.

The security argument assumes correct signature/adaptor verification, fresh
secret nonces, uncompromised keys and durable local state, honest normal Ark
policy issuance, and a trusted, live chain backend. It also assumes bounded
transaction-inclusion delays and reorgs, sufficient on-chain fee reserves, and
monitoring with timely fee bumps and emergency-exit execution until settlement
or recovery is stable. The configured margins are budgets for these assumptions,
not guarantees that miners or the server will respond in time.

Full VTXO-genesis validation does not establish an unconditional guarantee
against a malicious Ark operator: historical policies committed through tweaks
do not expose their complete script trees. This protocol does not remove the
underlying Ark issuance and recovery assumptions.

Bitcoin Core backends must be version 29.0 or newer for P2A package relay and
must have `-txindex=1` with a fully synchronized transaction index. Commands
reject an unavailable index rather than treating confirmed
transactions as absent; monitoring repeats this check. They must also retain
block data for the recovery scan window; a node pruned inside that window fails
closed. Esplora supplies indexed transaction lookup. Losing the backend still
requires restoring reliable chain access before the recovery deadlines.

Keep Bob's funding wallet idle between M1 and M3. Requests reject funding-input
overlap with other open local swaps, but ordinary wallet sends, boards, exits,
or external spends do not participate in that reservation. A spent template
input fails closed; after M2, that failure still forces Alice's emergency exit.

## The three messages

Each message is a snapshot of a public JSON relay file, copied in the indicated
direction. Relay status is coordination data, not authority to sign, abort, or
consider a payment settled. Each side verifies the message against its private
state and live chain data.

| Message | Direction | Command | New public material |
| --- | --- | --- | --- |
| M1 | Bob → Alice | `btc-request` | Terms, unsigned funding template and prevouts, lock-output slot, fixed refund height, Bob's keys and one-use public nonce |
| M2 | Alice → Bob | `ark-offer` | Alice's payout and claim key, `T`, final unsigned funding transaction, exact claim, Alice's adapted BTC nonce and partial signature, server-co-signed Ark adaptor package |
| M3 | Bob → Alice | `btc-fund` | Signed funding transaction with the same txid and the verified aggregate BTC claim adaptor signature |

There is no fourth peer handoff. Once Alice has imported M3 into her local state,
both sides can continue without either relay file, using
`progress --role btc-payer|ark-payer --watch` and their chain backends.
Blockchain publication and ordinary server requests are still required; “three
messages” counts peer handoffs, not all network traffic.

### M1: Bob fixes funding and a one-use nonce

Bob chooses the amount, Ark receive policy, claim/refund keys, feerate,
confirmation depth, and refund window. At request height `h0`, he fixes the
absolute refund height `R = h0 + refund_delay`.

Bob prepares an unsigned PSBT with a P2TR placeholder for the lock output. Its
inputs must be confirmed, unspent native-SegWit outputs with empty `scriptSig`
and no funding witnesses. The public message contains the unsigned transaction,
input prevouts, and the designated output index—not the private PSBT or wallet
signing metadata. Bob persists the PSBT and an ordinary MuSig2 secret nonce
locally before publishing its public nonce in M1.

### M2: Alice fixes both claims before funding

Alice checks the request, BTC prevouts, and Bob's Ark destination. She selects
fresh eligible Ark inputs, validates their live ancestry and timing, and freezes
their exact IDs in durable private state together with `t` before contacting the
server. She locks those inputs locally; retries use those same inputs rather
than selecting new ones.

Alice replaces only the agreed placeholder output with the final BTC lock.
Every other funding field remains fixed. Because native-SegWit funding
signatures only add witnesses, she can compute the final funding txid and the
exact BTC claim before Bob signs the funding transaction. The claim pays her
pinned payout script and commits to a fee anchor.

Alice generates a fresh BTC claim nonce adapted to `T` and signs her MuSig2
partial for the exact claim, Bob's M1 nonce, both keys, and the Taproot tweak.
Bob's nonce can therefore be published before Alice's key, `T`, or the claim
sighash is known; only Alice's BTC nonce share needs the adaptor offset.

For the Ark transfer, Alice similarly adapts each user public nonce before
ordinary server co-signing. The first nonce point is offset by `T`, while the
corresponding unadapted secret nonce remains local. Combining the server's
ordinary partial signatures with Alice's shares produces adaptor pre-signatures
that verify against `T`, not final transaction signatures. The transferable
package pays Bob's receive policy and includes any Alice change. It contains
public transaction/signing data, not private keys, secret nonces, or `t`.

Alice persists the complete M2 artifacts and their transcript commitment before
publishing them. **Server co-signing is already an irreversible Ark-side action,
even though Bob has not funded.** A crash or an abandoned offer must be handled
using the frozen recovery inputs; discarding the relay does not undo that action.

### M3: Bob verifies, consumes his nonce, and funds

Before funding, Bob verifies:

- The original request is unchanged, and only the designated funding output was
  replaced; input prevouts, change, amounts, and fees match the template.
- The BTC lock, claim transaction, payout, sighash, Taproot tweak, and nonce
  shares agree with the offered terms.
- The Ark package's adaptor signatures, server key, exact input set, payment to
  his receive policy, amount, ancestry, and expiries pass public and live checks.
- The complete accepted transcript matches any previously pinned commitment.

The commitment includes protocol/version/swap identity, both keys and nonce
shares, `T`, the partial signature, funding and claim data, and the Ark package.
It excludes mutable progress status and strips funding witnesses so that M3 can
add signatures without changing the accepted transaction.

Bob durably pins that transcript before using his secret nonce. He aggregates
Alice's partial with his own and verifies the resulting BTC adaptor signature
against the tweaked lock key, exact sighash, and `T` **before funding**. He then
signs his own persisted PSBT, never a peer-supplied PSBT, and checks that its txid
matches the claim outpoint. He also signs his independent refund transaction.

The complete result, signed funding and refund, and deletion of the secret
nonce and private PSBT are persisted together before broadcast or publication.
A retry uses the persisted result; it cannot sign a changed transcript with the
same nonce. Fresh chain checks precede the initial funding broadcast. M3 gives
Alice the aggregate adaptor and the signed funding transaction.

## BTC lock and fee handling

The Taproot lock has a MuSig2 key path controlled by Alice and Bob, and a script
path allowing Bob's refund key to spend after absolute-height CLTV lock `R`.
Neither party alone can produce the agreed key-path claim without the other's
signing contribution. With the verified adaptor signature, Alice can finalize
that claim using `t`; a verifier holding the same adaptor can recover `t` from
the valid final signature, including the required nonce-parity handling.

The claim is a version-3 transaction with a 330-sat pay-to-anchor (P2A) output.
Alice's payout is the locked amount minus the fixed claim fee and anchor value.
The signed parent is fixed; fee increases use a child-pays-for-parent (CPFP)
transaction rather than another peer signing round. Alice needs confirmed
on-chain fee funds. `progress --fee-rate` can override the automatic target.

Bob's refund supports replace-by-fee (RBF). If funding is still unconfirmed,
recovery can broadcast the pinned funding and refund as a package, paying for
both. A signed funding transaction must not be forgotten merely because it was
not seen in the mempool: Alice could publish it later. Repricing or delayed
funding never moves `R`.
When funding is already in the mempool, a refund replacement is submitted as
a single transaction, not unsupported non-TRUC package RBF. Previously signed
refund IDs remain durable: an older refund can still be mined after replacement.
Evicted claim children and Ark-reclaim drains can be repriced, and recovery
tracks older drain candidates as well.

## Fixed-height safety conditions

Let `c` be the required confirmation depth, `m` the safety margin, `h` the current
validated tip, and `d_i` the emergency-exit delay of Ark input `i`.

- `--refund-delay` is the request-height-to-fixed-refund-height window, default
  24 blocks; it is not a delay starting when funding confirms.
- `--confirmations` defaults to 6 and `--safety-margin` defaults to 6. Accepted
  requests require `c >= 1`, `m >= c`, and enough remaining time:
  `h + c + m < R`.
- `R` must be a block height, and height arithmetic must not overflow.

Before Alice co-signs and before Bob releases funding, each selected Ark input
must have a valid full genesis, a public-key policy, a confirmed live chain
anchor, and no published exit ancestor—not even in the mempool. Already-on-chain
inputs, duplicate inputs, conflicting or overlapping ancestry, and duplicate
output counting are rejected. Legitimate shared ancestry prefixes are allowed.
The backend must report the anchor output unspent and matching its confirmed
transaction. The timing conditions are:

```text
h + m < R
R + m < h + d_i                 for every Ark input i
expiry_i > R + m               for every input and offered output
```

The fresh-ancestry requirement matters: `h + d_i` is not a sound lower bound for
an old-state spend whose exit clock started earlier. The strict inequalities
reserve time to settle Bob's refund before a newly started old-state exit can
mature. They do not prevent new exits from appearing after validation, stop the
chain from advancing between calls, or guarantee inclusion within the margin.

Alice's first disclosure additionally requires the exact BTC funding output to
be confirmed in the current chain, unspent, and at depth at least `c`, with
`tip + m < R`. She prepares the signed CPFP child using a dummy parent witness,
then rechecks the claim window before creating a revealing signature. She
persists that first signed claim and child immediately before broadcast, without
further fee-estimation or network preparation between the recheck and signing.
A final timing race still exists; bounded inclusion and reorg assumptions remain.

## Disclosure, confirmation, and old-state protection

A valid claim signature can disclose `t` as soon as it leaves Alice's control,
including through a broadcast attempt that returns an error. Mempool admission,
confirmation, and durable payment are distinct events. A rejected, evicted, or
reorged claim does not make an already disclosed secret private again.

Bob observes the exact pinned claim, verifies its final signature against his
adaptor, and persists the observed transaction. He can recover `t` from an
unconfirmed claim and immediately finalize/import his Ark VTXOs; waiting for
BTC confirmation before learning the secret would waste response time.

Alice also finalizes the Ark package and registers its signed transaction chain
with the server during claim completion. Bob imports his fully signed VTXOs
before attempting registration; if registration fails, his completion path
starts local emergency-exit recovery. These are ordinary Ark recovery steps.

**Registration is not atomicity or an on-chain revocation of Alice's old state.**
It supplies signed transaction data to the server/watchman. Defeating an old-state
exit still requires the appropriate spend/checkpoint path to be published and
confirmed in time. Registration, local import, and an `ArkCompleted` status do
not prove that every conflicting exit or reorg has become impossible. Bob must
retain his recovery data and maintain ordinary Ark monitoring; fallback exits
may need continued progression and fees.

The BTC claim key path also remains valid after `R`: the refund lock enables a
competing spend, not an expiry of Alice's signature. If a claim is disclosed too
late or inclusion is delayed past the budget, Bob may learn `t` while the refund
wins the BTC spend. Conversely, late old-state handling can endanger Bob's Ark
receive. The fixed deadlines and refusal to first disclose late mitigate these
races under the stated assumptions; they do not make disclosure and both
settlements simultaneous.

## Recovery and terminal states

- **Bob abandons before M2 co-signing:** no BTC funding has been signed or
  published. If Alice has not reached the irreversible co-signing step, there
  is no server-co-signed Ark transfer to recover from.
- **Bob abandons after M2, even without ever funding:** Alice may already need
  emergency exits of her frozen Ark inputs. Bob can force delay, fees, and
  monitoring without first locking BTC. This pre-funding grief is the explicit
  trade-off that makes the three-message sequence possible.
- **No secret has escaped:** Alice can use `ark-abort` to start exits of the exact
  frozen inputs. Her `progress` also chooses this path when the first-disclosure
  window closes. `Cancelled` is not completed recovery: progress drives the
  exits, persists and broadcasts a signed drain, and reaches `ArkReclaimed`
  only after the configured confirmation depth.
- **No claim is observed by the refund height:** Bob uses `btc-refund` or
  `progress` to publish/reprice the refund, including a funding/refund package
  when needed. He stays online until it is sufficiently confirmed and before
  the relevant Ark old-state deadline.
- **Ark registration fails after Bob learns the secret:** Bob retains his fully
  signed receive outputs and enters `ArkRecovering`. Progress drives their
  unilateral exits and drain to `ArkReclaimed`; it does not refund the BTC leg.
- **A claim signature may have escaped:** Alice must not abort. The persisted
  signed-claim marker prevents abort even if the chain backend no longer sees
  the claim. She continues rebroadcast/CPFP and Ark registration. Bob completes
  from valid claim evidence, not from a relay cancellation label.

Alice's `BtcClaimed` and Bob's `Refunded` require depth `c`; broadcasting alone
is not terminal. `ArkCompleted` records Bob's local receive and successful chain
registration, not BTC confirmation or final resolution of every Ark exit race.
The manual commands `ark-finalize-btc-claim`, `btc-complete-ark`, `btc-refund`, and
`ark-abort` remain available; they do not introduce additional peer messages.

## Local durability and privacy boundaries

Private state and relay snapshots use strict version-3 formats; legacy formats
are rejected. Writes use private mode-0600 files, file synchronization, atomic
rename, and parent-directory synchronization. Each wallet holds an exclusive
swap-command lock, including for the lifetime of `--watch`; the watch loop
reloads durable state on every iteration, including after failed writes. Use
separate wallets for the two roles rather than running both against one wallet
under a long-held watch lock.

Do not copy private state to the peer, restore a backup containing a spent
nonce, or fork a signing session from old state. Durable nonce deletion protects
retries in the current state history; it does not make stale secret backups
safe. Preserve local transcripts, refund transactions, and exit data through
stable settlement or recovery.

The server receives ordinary arkoor requests containing adapted, otherwise
ordinary public nonces, and later ordinary signed transaction-chain
registration. The client sends no explicit `T`, `t`, swap ID, BTC transcript, or
transferable adaptor package to the server. With fresh random nonce material,
the offset does not itself label the co-signing request as a swap.

This is a protocol-metadata privacy boundary, not operator blindness or network
anonymity. The server still sees ordinary Ark inputs, outputs, amounts, timing,
registrations, and emergency exits. Peer relay artifacts expose swap terms and
BTC linkage to their holders; public chain activity and network observations can
also permit correlation. The protocol does not protect against a peer sharing
that information with the operator.
