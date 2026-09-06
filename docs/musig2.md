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

Secret nonces live on the Controller in RAM, keyed by input, aggregate, participant key and
sighash. They survive the trip to the main menu between scans and die on wipe or power
loss. They are never written to the card: a copied card that replays a nonce gives two
signatures under one nonce, which leaks the key.

## Test fixture

`tests/data/musig2_psbts.json` was captured from Bitcoin Core v31.1.0 on regtest:
`importdescriptors` of `tr(musig(A,B)/0/*,{pk(musig(A,C)/0/*),pk(musig(B,C)/0/*)})` with the
three published BIP-39 test mnemonics in the file, `createpsbt`, `utxoupdatepsbt`, then
`walletprocesspsbt` on a watch-only wallet (all fields) and on a wallet holding A's key
(Core's nonce, and later its partial signature).
