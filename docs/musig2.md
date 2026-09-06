# MuSig2 on the device

Key-path MuSig2 (BIP-327) signing from a psbt, with the BIP-373 fields and BIP-328
derivation, plus the extra round a BIP-352 silent payment send needs. Code:
`helpers/musig2.py` (the BIP's algorithms, checked against its vectors) and
`helpers/musig2_psbt.py` (everything psbt).

## What the device reads, and checks

| From the psbt | Checked against |
|---|---|
| `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` (0x1a): participant list, in aggregation order | must aggregate to the key it is filed under |
| taproot derivation filed under `hash160(aggregate)[:4]` (BIP-328 fingerprint) | walked with the BIP-328 chaincode; unhardened only |
| `PSBT_IN_TAP_MERKLE_ROOT`, `PSBT_IN_TAP_INTERNAL_KEY`, leaf scripts | key-path aggregate after the taptweak must equal the coin's scriptPubKey; the policy shown is rebuilt from the tree and only shown when it proves out |
| our participant key | matched x-only against our taproot derivations, then the seed must reproduce it |

Anything malformed is refused on screen; nothing is inferred from a wallet file.

## Rounds

Plain spend: `nonce` (publish a nonce, keep the secret half in RAM), then `signed` (verify
every nonce is present, write the partial signature, destroy the secret nonce). A re-scan of
the first-round psbt republishes the same nonce. A psbt that already carries our partial
signature is verified, never re-signed.

Silent payment send: one round before those. Each signer writes `d_i * B_scan` and a
BIP-374 proof, keyed `<scan key><participant key>`. Both ride in BIP-174 proprietary fields
(0xFC, identifier `DOOMSIGNER`, subtypes 0x02 and 0x03) rather than on per-input numbers just
past the end of the registry, which are unallocated rather than reserved and which a later BIP
could claim and mean something else by. The coordinator combines the shares with the public
KeyAgg coefficients, parity and tweaks and writes the output script.
Every later round verifies every proof and the script before a nonce or a signature leaves
the device. Inputs that are not MuSig2 must carry the BIP-375 per-input share and proof.

Refused: a seed that also owns non-MuSig2 inputs in the same psbt, a missing share, a bad
proof, a script that does not match, a partial signature that does not verify, and
hardened derivation of an aggregate.

## The session

By default secret nonces live on the Controller in RAM, keyed by input, aggregate,
participant key and sighash. They survive the trip to the main menu between scans and die
on wipe or power loss. A nonce must never be written to a file: a copy of that file
replays it, and two signatures under one nonce leak the key. Nothing in software can tell
the copy from the original.

## The card

A card can, which is what `helpers/musig2_card.py` is for. `CardSession` subclasses
`Session` and overrides the two seams `advance()` calls, so the round logic is untouched.

The card generates the secret nonce, returns it sealed under keys that never leave the
applet, and opens each sealed nonce exactly once. So a copy of a sealed nonce is worth
nothing, the sealed form is safe to put in the transaction, and the device may be switched
off between the two rounds.

Offered once per signing by `PSBTMusig2CardOfferView`, before the first round, to anyone
with smartcard support enabled. Choosing it opens the reader, which asks for the PIN; that
prompt is deliberately the answer to a question just asked rather than a surprise. A card
that works but is not carrying this seed cannot make the nonce and says so on its own
screen. Declining signs in RAM exactly as before.

Silent selection was tried and withdrawn: the Controller clears `Satochip_Connector` on
every return to the main menu unless `CACHE_SCARD_PIN` is enabled, and it is off by
default, so the feature was inert on a default device and invisible where it worked.

### Pooled nonces, and why a spend costs one visit

MuSig2 forces two rounds because a nonce must be fixed before its owner sees anyone
else's. Made in advance, that wait disappears: the coordinator has every public nonce
before it builds anything, so each signer visits once.

Every card-backed signing takes one unused nonce and leaves four fresh ones behind, in the
transaction that was going back anyway. No stocking ceremony, no state on the device. A
card that will not restock is not an error; the spend completes and the next one costs the
old two visits. `BIP327_MAX_NB_ID` in the applet is 16, shared across all keys, so four
per key means four keys per card before the oldest start being evicted.

A pooled nonce is bound to a sighash the moment it is taken, which is what stops a
coordinator that alters the transaction after round one from spending it on something the
user never approved.

### On the wire

All four fields are BIP-174 proprietary, identifier `DOOMSIGNER`, built by
`musig2_psbt.proprietary_key`:

| subtype | meaning | keydata |
| --- | --- | --- |
| `0x00` | sealed nonce, bound | participant pubkey, aggregate, sighash |
| `0x01` | pooled nonce, unbound | participant pubkey, index |
| `0x02` | partial ECDH share (silent payments) | scan key, participant pubkey |
| `0x03` | BIP-374 proof of that share | scan key, participant pubkey |

`0x02` and `0x03` were per-input types `0x21` and `0x22` until 2026-09-06. The registry in
`bip-0174/type-registry.mediawiki` allocates `0x00` to `0x20` and then jumps to `0xFC`, so
those numbers were unallocated rather than ours, and a later BIP taking one would have
made two producers disagree about the same key. Proprietary space is where a field nobody
has standardised belongs.

### The applet

`bitsagarob/Seedkeeper-Applet`, branch `musig2-nonce-vault`, a fork of Toporin's. INS
`0x7E` generates, `0x7F` opens once. `test/run.sh` runs the real applet Java under jCardSim
and checks the published public nonce really is `k1*G` and `k2*G` for the secret nonce
released, that a second opening is refused, and that a batch spent out of order behaves.
It needs a JDK 8 and a jcardsim built from source; the header of that script says how.

## Test fixture

`tests/data/musig2_psbts.json` was captured from Bitcoin Core v31.1.0 on regtest:
`importdescriptors` of `tr(musig(A,B)/0/*,{pk(musig(A,C)/0/*),pk(musig(B,C)/0/*)})` with the
three published BIP-39 test mnemonics in the file, `createpsbt`, `utxoupdatepsbt`, then
`walletprocesspsbt` on a watch-only wallet (all fields) and on a wallet holding A's key
(Core's nonce, and later its partial signature).
