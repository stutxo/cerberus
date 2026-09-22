# BTC-Ark swap walkthrough

This experimental `bark swap btc-ark` flow exchanges BTC for Ark VTXOs with
**exactly three one-way peer messages**. Bob pays BTC; Alice pays Ark and knows
the adaptor secret `t`. Each participant has a separate wallet and a separate
local relay JSON file. Copy only that public relay file between participants.
There is no network coordinator service or fourth signing handoff.

See [the protocol review](../docs/adaptor-swap-protocol.md) for the transcript,
proof boundaries, timing assumptions, and counterexamples. This is not a
production-security claim, a grief-free protocol, or a protocol that is safe
while participants are offline.

## Read before committing Ark funds

The order is:

```text
Bob: btc-request  -- M1 -->  Alice: ark-offer
Bob: btc-fund     <-- M2 --  Alice
Bob              -- M3 -->  Alice
Both: progress --watch; completion and recovery use local state and the chain
```

**`ark-offer` is already irreversible.** It obtains ordinary Ark server
co-signatures and freezes the exact Ark inputs before Bob funds BTC. Bob may
abandon the exchange at this point, forcing Alice to pay for emergency exits.
Even a failed command may have reached the server; keep its private state and
use its pinned inputs for recovery. There is no instant off-chain rollback.

Alice's BTC claim reveals `t`, allowing Bob to complete his Ark receive. She
must not disclose it for unconfirmed, spent, insufficiently confirmed, or late
BTC funding. Once a signed claim has been durably prepared for broadcast, treat
`t` as potentially public. A rejected broadcast, mempool eviction, reorg, or
missing transaction is **not** permission to abort Alice's Ark transfer.

Both sides need continuous monitoring, a trusted live chain backend, sufficient
on-chain fee reserves, and bounded transaction inclusion/reorg assumptions.
Normal honest Ark issuance is also assumed; historical policies committed in
VTXO tweaks prevent an unconditional guarantee against a malicious operator.
Registering the completed Ark chain is useful, but it does not create atomicity
or eliminate old-state timing races.

## Wallet and fee prerequisites

Use a local regtest deployment for experiments, with a working Ark server and
chain backend. The commands below are network-neutral: they assume you already
created **two distinct funded wallets**, configured for the same network and
Ark server. They do not depend on a public signet service.

For Bitcoin Core, use version 29.0 or newer for P2A package relay, enable
`-txindex=1`, and wait for its transaction index to
synchronize. The swap commands and monitor reject an unavailable index; mempool
visibility alone is not sufficient for recovery. Keep block data available for
the recovery scan window; a node pruned inside that window fails closed. An
indexed Esplora backend is also supported.

Between M1 and M3, do not use Bob's funding wallet for other sends, boards,
exits, or external spends. New swap requests reject overlapping inputs from
open local swaps, but this is not a wallet-wide coin lock. A conflicting spend
can strand Alice after her irreversible M2 commitment; prefer a dedicated wallet.

Point `BARK` at a binary built from this checkout. Set the wallet paths to your
existing wallets, not two aliases for the same directory:

```sh
export BARK="$PWD/target/debug/bark"
export BTC_PAYER_DATADIR=/tmp/bark-swap-bob
export ARK_PAYER_DATADIR=/tmp/bark-swap-alice
export BOB_RELAY=/tmp/btc-ark-bob.json
export ALICE_RELAY=/tmp/btc-ark-alice.json
export SWAP_AMOUNT="10000 sats"
export FEE_RATE=1
export REFUND_WINDOW=24
export CONFIRMATIONS=6
export SAFETY_MARGIN=6
```

Use fresh relay filenames for a new swap. These two relay paths must not be
symlinks to the same file. For participants on separate machines, each variable
refers to a local path; replace the three `cp` commands below with three
corresponding authenticated file deliveries.

Check each wallet before beginning:

```sh
$BARK --datadir "$BTC_PAYER_DATADIR" onchain balance
$BARK --datadir "$ARK_PAYER_DATADIR" onchain balance
$BARK --datadir "$ARK_PAYER_DATADIR" balance
$BARK --datadir "$ARK_PAYER_DATADIR" vtxos
$BARK --datadir "$ARK_PAYER_DATADIR" ark-info
```

- Bob needs confirmed, unspent native-SegWit on-chain inputs covering the BTC
  lock amount and its funding fee. Do not spend the selected inputs elsewhere
  while the request is outstanding.
- Alice needs spendable Ark VTXOs covering the swap amount, with valid, fresh
  off-chain ancestry and enough lifetime for the fixed refund window. A
  `pending_board_sat` balance is not spendable.
- Alice also needs **separate confirmed on-chain funds** for the BTC claim's
  child-pays-for-parent (CPFP) transaction and possible emergency exits. Do not
  board her entire on-chain balance. Bob should retain on-chain reserves for
  emergency recovery too.
- The claim pays Alice less than the lock amount: its fee and 330-sat P2A anchor
  are deducted. Refund fee increases reduce Bob's refund output.
- `FEE_RATE=1` is an example for a controlled local experiment, not a promise of
  timely inclusion. Select a feerate suitable for your chain and deadlines.

If Alice needs Ark funds, board from her own on-chain wallet, leaving a fee
reserve, or receive an ordinary Ark payment. For boarding:

```sh
$BARK --datadir "$ARK_PAYER_DATADIR" board "$SWAP_AMOUNT"
$BARK --datadir "$ARK_PAYER_DATADIR" balance
$BARK --datadir "$ARK_PAYER_DATADIR" vtxos
```

Wait for the board and its chain anchor to confirm and for the Ark balance to
become spendable before M1. On regtest, mine these prerequisite confirmations
before starting the refund clock.

Collect each destination from its actual owner:

```sh
export BTC_PAYOUT="$($BARK --quiet --datadir "$ARK_PAYER_DATADIR" onchain address | jq -r '.address')"
export ARK_RECEIVE="$($BARK --quiet --datadir "$BTC_PAYER_DATADIR" address)"
```

## Choose the fixed refund window

`--refund-delay` is the number of blocks from **request creation** to an absolute
height-locked BTC refund, not a delay counted from funding confirmation. Its
default is 24. M1 fixes:

```text
R = request.created_height + refund_delay
```

Delayed funding, retries, and fee bumps never move `R`. `--confirmations`
defaults to 6; `--safety-margin` defaults to 6. Both must be positive, the margin
must cover the confirmation depth, and the refund window must exceed their
sum. M2 and M3 also require enough remaining time to confirm funding and claim.

For every selected Ark input, at validation height `h`, the client requires:

```text
h + safety_margin < R
R + safety_margin < h + input.exit_delta
input.expiry_height > R + safety_margin
```

The input must have a confirmed, live chain anchor and no already-published
exit ancestor, even in the mempool. An already-running exit cannot be treated
as if its clock starts afresh at `h`. Increasing the refund window blindly can
therefore make the request unsafe or unacceptable; choose it against Alice's
actual VTXO exit delays and expiry heights. If no window satisfies these bounds,
do not proceed with those inputs.

Alice's first disclosure additionally requires the exact BTC lock to be
confirmed, unspent, at least `CONFIRMATIONS` deep, and still satisfy
`tip + SAFETY_MARGIN < R`. The client prepares the fee child without revealing
the signature, then rechecks the window immediately before persisting the
revealing signature for broadcast. Do not bypass a late-claim rejection.

On regtest, advance blocks deliberately: after M3, mine enough funding
confirmations while preserving the claim window, let Alice's watcher publish
the claim, and then mine settlement confirmations. A large blind block jump
can correctly select recovery instead of settlement.

## Exactly three peer handoffs

### M1: Bob requests the swap

```sh
$BARK --datadir "$BTC_PAYER_DATADIR" swap btc-ark btc-request \
  --coordinator "$BOB_RELAY" \
  --amount "$SWAP_AMOUNT" \
  --ark-receive "$ARK_RECEIVE" \
  --fee-rate "$FEE_RATE" \
  --refund-delay "$REFUND_WINDOW" \
  --confirmations "$CONFIRMATIONS" \
  --safety-margin "$SAFETY_MARGIN"

export SWAP_ID="$(jq -r '.swap_id' "$BOB_RELAY")"

# Handoff 1: Bob -> Alice
cp "$BOB_RELAY" "$ALICE_RELAY"
```

The command reports `Requested` and `next: ark-offer`. M1 contains the unsigned
native-SegWit funding transaction template, prevouts, fixed refund height, terms,
and Bob's one-use public nonce. Bob retains the actual PSBT and secret nonce in
his private wallet state; neither is a peer message. No funding is broadcast yet.
On separate machines, Alice reads `SWAP_ID` from her received relay file.

### M2: Alice commits the Ark offer

Before running this command, accept the forced-emergency-exit risk described
above. Bob has **not** funded BTC.

```sh
$BARK --datadir "$ARK_PAYER_DATADIR" swap btc-ark ark-offer \
  --coordinator "$ALICE_RELAY" \
  --swap "$SWAP_ID" \
  --btc-payout "$BTC_PAYOUT"

# Handoff 2: Alice -> Bob
cp "$ALICE_RELAY" "$BOB_RELAY"
```

The command reports `Offered` and `next: btc-fund`. Alice fills only the agreed
lock-output slot in Bob's template, fixing the funding txid and BTC claim. M2
includes her adapted BTC public nonce and partial signature, plus the
server-co-signed adaptor Ark package. Alice durably pins and locks the exact
Ark inputs and keeps `t` locally. This is not merely publication of tentative
terms.

If Bob stalls, Alice must still monitor the deadline and recover her Ark inputs.
She can start her `progress --role ark-payer --watch` command below immediately
after sending M2; it waits for M3 or starts recovery when the safe claim window
closes. Deliver M3 to her relay path when it arrives.

### M3: Bob verifies and funds

```sh
$BARK --datadir "$BTC_PAYER_DATADIR" swap btc-ark btc-fund \
  --coordinator "$BOB_RELAY" \
  --swap "$SWAP_ID"

# Handoff 3: Bob -> Alice
cp "$BOB_RELAY" "$ALICE_RELAY"
```

The command reports `BtcClaimReady` and `next: progress`. Bob verifies the full
pinned transcript, live Ark package, economics, and aggregate BTC adaptor
signature before funding. He signs his own persisted PSBT, not a peer-supplied
PSBT. The final funding bytes, adaptor result, nonce deletion, and signed refund
are durably stored before funding broadcast and M3 publication.

M3 supplies the signed funding transaction and aggregate adaptor signature.
There are **no further peer file copies**. A funding broadcast alone is not a
substitute for delivering M3 to Alice.

## Monitor settlement without further relay writes

Run Bob's watcher in one terminal:

```sh
$BARK --datadir "$BTC_PAYER_DATADIR" swap btc-ark progress \
  --coordinator "$BOB_RELAY" \
  --swap "$SWAP_ID" \
  --role btc-payer \
  --watch
```

Run Alice's watcher in another terminal, unless it is already running from M2:

```sh
$BARK --datadir "$ARK_PAYER_DATADIR" swap btc-ark progress \
  --coordinator "$ALICE_RELAY" \
  --swap "$SWAP_ID" \
  --role ark-payer \
  --watch
```

Keep these running and attend to errors; stopping a watcher does not stop any
chain deadline. Each watch iteration reloads durable state. The two data
directories are essential: a watcher holds its wallet's swap lock, so a
one-wallet loopback would prevent the other role from progressing. Stop a
wallet's watcher before issuing another swap command against that same wallet,
then promptly resume monitoring.

Alice imports M3 into private state, waits for sufficient funding confirmations,
and claims BTC only inside the safe window. Bob observes the claim signature
on-chain, including in the mempool, extracts `t`, and completes his Ark receive
without a fourth message. Once Alice has durably accepted M3, neither relay file
is needed for settlement or recovery; the CLI still takes `--coordinator`, but
uses the stored transcript. Do not delete Alice's M3 file before acceptance.

`progress` accepts optional `--fee-rate SAT/VB` to override the automatic fee
estimate. Otherwise it uses the backend's fast estimate, with the request
feerate as a floor. The v3 BTC claim has a 330-sat P2A anchor for CPFP; the watcher
can reprice its fee child. Refunds support RBF, including a funding-plus-refund
package if the pinned funding remains unconfirmed. Fee bumps never extend `R`.
When funding is already in the mempool, refund RBF uses a single-transaction
submission. Persisted history recognizes an older refund or reclaim transaction
if miners confirm it after a replacement. Evicted claim children and reclaim
drains can also be repriced.

To inspect current progress once, use the same command without `--watch`.
This is **not read-only status**: it can broadcast, claim, complete, or recover.
Its JSON includes `status`, `next`, `refund_height`, and transaction IDs. Alice's
`BtcClaimed` and Bob's `Refunded` require the configured confirmation depth;
`ArkCompleted` means Bob has imported and registered his receive, not that the
BTC claim has that depth. Bob's watcher stops at `ArkCompleted`; Alice must keep
her claim watcher running until `BtcClaimed`. Continue monitoring recovery until
the relevant outcome is stable.
If Bob cannot register the finalized receive, `ArkRecovering` means his locally
stored, fully signed VTXOs are being exited. Keep his watcher running through
`ArkReclaimed`; this fallback does not request a BTC refund.
Use `balance`, `onchain balance`, and `vtxos` after releasing the relevant wallet
lock to inspect the resulting balances.

## Manual settlement and recovery

These commands are alternatives to automatic progress, not additional peer
handoffs. Stop the same wallet's watcher before invoking them.

Alice can explicitly claim BTC after accepting M3 and satisfying the funding
and timing checks:

```sh
$BARK --datadir "$ARK_PAYER_DATADIR" swap btc-ark ark-finalize-btc-claim \
  --coordinator "$ALICE_RELAY" --swap "$SWAP_ID"
```

Bob can explicitly extract the visible claim signature and complete Ark:

```sh
$BARK --datadir "$BTC_PAYER_DATADIR" swap btc-ark btc-complete-ark \
  --coordinator "$BOB_RELAY" --swap "$SWAP_ID"
```

If Alice has not revealed a claim signature, Bob can refund once the absolute
height `R` arrives. Continue monitoring until the refund has the configured
depth, not merely until its broadcast succeeds:

```sh
$BARK --datadir "$BTC_PAYER_DATADIR" swap btc-ark btc-refund \
  --coordinator "$BOB_RELAY" --swap "$SWAP_ID" --fee-rate "$FEE_RATE"
```

If funding is still unconfirmed, Bob must not simply forget the signed funding
transaction: it remains publishable. Recovery can broadcast the pinned funding
and refund together. If the claim signature is already visible, complete Ark
instead of trying to refund.

Before any signed BTC claim may have escaped, Alice can register her exact
frozen Ark inputs for emergency exit:

```sh
$BARK --datadir "$ARK_PAYER_DATADIR" swap btc-ark ark-abort \
  --coordinator "$ALICE_RELAY" --swap "$SWAP_ID"
```

Then resume Alice's `progress --role ark-payer --watch`. `Cancelled` is only the
start of her recovery, not a recovered balance. Progress drives the emergency
exits, signs and broadcasts their drain, and waits for its configured
confirmation depth before reporting `ArkReclaimed`. It does not select new Ark
inputs. Bob independently refunds at `R` if no claim was revealed.

Never use `ark-abort` after a signed claim was persisted for broadcast, even if
the broadcast returned an error or the transaction later disappeared. Disclosure
is irreversible; use the claim/completion path and maintain fee support instead.

## Public relay versus secret durable state

The version-3 relay contains public coordination data: amount and destinations,
refund height and safety parameters, public keys and nonces, funding template
and prevouts, final funding bytes, claim template, adaptor signatures, and Ark
package. "Public" means safe to give the peer, **not** anonymous or suitable for
unnecessary publication. The relay links the swap's amounts, addresses, and
transactions. Transport and authenticate it as appropriate for your peer.

Private state lives under each wallet's `swap/` directory, in
`btc-ark-<swap-id>-btc-payer.json` or `btc-ark-<swap-id>-ark-payer.json`. It contains
secret material and the authoritative frozen transcript and recovery artifacts.
Writes use atomic replacement, file and directory synchronization, and mode
`0600` on Unix. Never send these files, wallet seeds, secret nonces, private
PSBTs, or Alice's `t` to the peer or Ark server.

- Retry the same command with the same wallet, swap ID, relay path, and terms.
  Completed artifacts are republished from durable state; changed transcripts
  are rejected rather than signed with an old nonce.
- Do not edit JSON to bypass a rejection, reuse a secret nonce, restore a spent
  nonce from backup, or run cloned copies of live swap state. Wallet seed
  recovery alone is not a substitute for the current swap recovery artifacts.
- Keep private state even when a command or broadcast fails. A failed response
  does not prove that no irreversible action happened. Resume from durable
  state; do not start over with the same inputs and stale nonce files.
- A new swap needs fresh state, fresh nonces, and fresh relay filenames. Version-2
  relay/state files are rejected, not silently migrated. Never relabel an old
  file as version 3.

The Ark server sees ordinary arkoor co-signing public nonces and eventual signed
chain registration. It is not sent a swap ID, explicit `T` or `t`, the BTC
transcript, or the adaptor package. This limits swap-specific protocol metadata;
it does **not** hide ordinary amounts, timing, connections, or wallet activity,
and does not provide network anonymity. The server's eventual registration is
not an atomicity guarantee. Keep the timing, issuance, fee, and monitoring
assumptions in the [protocol review](../docs/adaptor-swap-protocol.md) in view.
