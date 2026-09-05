"""MuSig2 secret nonces kept on a SeedKeeper, which releases each one exactly once.

MuSig2 signing takes two rounds. The secret nonce made in the first is spent in the
second, and two partial signatures under one secret nonce hand anybody the private key.
`musig2_psbt.Session` therefore keeps the secret nonce in RAM and loses it at power-off,
so the device has to stay on between the rounds and a spend costs two visits.

Writing it to a file instead would be worse, not better: a copy of the file replays the
nonce, and nothing in software can tell the copy from the original. A card can. This
subclass asks the card for the nonce, stores it in the PSBT sealed, and asks the card to
open it in round two. The card refuses the second opening, so a copy of the sealed nonce
is worth nothing, and the device may be switched off in between.

The card does not sign. It has no need to: the seed is already on the device, and what is
missing there is not the key but somewhere to keep a nonce that cannot be replayed.

The sealed nonce travels in a proprietary PSBT field, which Bitcoin Core preserves
unchanged through combining. It is bound to the sighash as well as to the participant and
the aggregate, so a transaction that changed after round one simply misses and asks the
card for a fresh nonce, which is what the base class would have done anyway.

Only usable when the seed being signed with is the seed on the card, because the card
makes the nonce from the key it derives itself. `for_seed` says whether that holds; when
it does not, the caller uses the base class and nothing changes.
"""

from typing import List, Optional

from seedsigner.helpers import musig2 as m
from seedsigner.helpers import musig2_psbt as mp

# BIP-174 proprietary field: 0xFC, then the identifier, then the subtype, then the key
# data. The identifier keeps this out of the way of every other producer's fields.
PROPRIETARY = 0xFC
IDENTIFIER = b"DOOMSIGNER"
SUBTYPE_SEALED_NONCE = 0x00

# What the card answers, and so what a stored field holds: the public nonce it published,
# then the secret nonce sealed under keys that never leave the applet.
SIZE_PUBNONCE = 66
SIZE_SEALED = 144
SIZE_SECNONCE = 97

INS_MUSIG2_GENERATE_NONCE = 0x7E
INS_MUSIG2_UNSEAL_NONCE = 0x7F
INS_BIP32_GET_EXTENDED_KEY = 0x6D
OP_INIT = 0x01
OP_FINALIZE = 0x03
CARD_EDGE_CLA = 0xB0

# The card has no nonce for a key it was never given, and no nonce left to give.
SW_OK = (0x90, 0x00)
SW_BIP327_WRONG_SECNONCE = (0x9C, 0x44)
SW_BIP327_COUNTER_OVERFLOW = (0x9C, 0x46)
SW_BIP327_INVALID_ID = (0x9C, 0x47)


class CardNonceError(mp.Musig2Error):
    """The card refused, or is not the card this nonce was made on."""


def sealed_nonce_key(role: mp.Role, msg: bytes) -> bytes:
    """Where one sealed nonce lives on its input.

    The participant key and the aggregate identify whose nonce it is, in the same order
    the BIP-373 fields use. The sighash is what makes resuming safe: a coordinator that
    changes the transaction after round one produces a different sighash, so the lookup
    misses and the card is asked for a fresh nonce, rather than the old one being spent
    on a transaction the user never approved.
    """
    return (bytes([PROPRIETARY, len(IDENTIFIER)]) + IDENTIFIER
            + bytes([SUBTYPE_SEALED_NONCE]) + role.pubkey + role.aggregate.key + msg)


def _transmit(connector, ins, p1, p2, data=b"") -> bytes:
    """One card-edge APDU. The secure channel and PIN re-entry are the connector's."""
    apdu = [CARD_EDGE_CLA, ins, p1, p2, len(data)] + list(data)
    response, sw1, sw2 = connector.card_transmit(apdu)
    if (sw1, sw2) == SW_BIP327_INVALID_ID:
        raise CardNonceError("This card has already released that nonce once.")
    if (sw1, sw2) == SW_BIP327_WRONG_SECNONCE:
        raise CardNonceError("This nonce was not made on this card.")
    if (sw1, sw2) == SW_BIP327_COUNTER_OVERFLOW:
        raise CardNonceError("This card has run out of nonces and needs resetting.")
    if (sw1, sw2) != SW_OK:
        raise CardNonceError("The card refused: %02X%02X." % (sw1, sw2))
    return bytes(response)


def _path_bytes(derivation: List[int]) -> bytes:
    return b"".join(index.to_bytes(4, "big") for index in derivation)


class CardSession(mp.Session):
    """`musig2_psbt.Session` with the secret nonce on a card instead of in RAM."""

    def __init__(self, connector, sid: int):
        super().__init__()
        self._connector = connector
        self._sid = sid

    # --- the seam ----------------------------------------------------------------------

    def new_nonce(self, psbt, role: mp.Role, msg: bytes, secret: bytearray):
        """A sealed nonce and the public nonce that goes with it.

        A sealed nonce already in the PSBT is returned as it is, which is how a device
        that was switched off between the rounds picks up where it left off rather than
        burning a second one.
        """
        field = sealed_nonce_key(role, msg)
        stored = psbt.inputs[role.input_index].unknown.get(field)
        if stored is not None and len(stored) == SIZE_PUBNONCE + SIZE_SEALED:
            return bytes(stored[SIZE_PUBNONCE:]), bytes(stored[:SIZE_PUBNONCE])

        self._derive(role)
        answer = _transmit(self._connector, INS_MUSIG2_GENERATE_NONCE, 0x00, OP_INIT,
                           # no aggregate key, no message, no extra input: the card
                           # appends its own never-repeating id to the last of these.
                           bytes([0x00, 0xFF, 0x00]))
        pubnonce = answer[:SIZE_PUBNONCE]
        sealed = _transmit(self._connector, INS_MUSIG2_GENERATE_NONCE, 0x00, OP_FINALIZE)
        if len(pubnonce) != SIZE_PUBNONCE or len(sealed) != SIZE_SEALED:
            raise CardNonceError("The card answered a nonce of the wrong size.")

        psbt.inputs[role.input_index].unknown[field] = pubnonce + sealed
        return sealed, pubnonce

    def sign(self, psbt, secnonce, role: mp.Role, secret: bytearray,
             context: "m.SessionContext") -> bytes:
        """Open the sealed nonce, once, and sign with it here."""
        if not isinstance(secnonce, bytes) or len(secnonce) != SIZE_SEALED:
            # Not one of ours: a nonce made before the card was in play.
            return super().sign(psbt, secnonce, role, secret, context)

        opened = bytearray(_transmit(self._connector, INS_MUSIG2_UNSEAL_NONCE,
                                     0x00, 0x00, secnonce))
        if len(opened) != SIZE_SECNONCE:
            mp._wipe(opened)
            raise CardNonceError("The card answered a secret nonce of the wrong size.")
        try:
            # m.sign zeroes the secret nonce it is handed and refuses one already zeroed.
            return m.sign(opened, bytes(secret), context)
        finally:
            mp._wipe(opened)
            # Spent, and the card will not open it again, so leaving it in the PSBT would
            # only mislead the next reader.
            psbt.inputs[role.input_index].unknown.pop(
                sealed_nonce_key(role, context.msg), None)

    # --- the card ----------------------------------------------------------------------

    def _derive(self, role: mp.Role) -> None:
        """Point the card at the key this nonce is for. It makes the nonce from that key,
        so it has to derive it before generating, and it keeps only the last one."""
        path = _path_bytes(role.derivation)
        _transmit(self._connector, INS_BIP32_GET_EXTENDED_KEY,
                  len(role.derivation), 0x40,
                  path + self._sid.to_bytes(2, "big"))


def for_seed(connector, root) -> Optional[CardSession]:
    """A card-backed session for this seed, or None if this card is not holding it.

    The card can only make nonces for a key it derives itself, so a seed that arrived by
    any other route than this card has no counterpart here. Rather than track which
    secret a seed came from, ask the card what it is holding and compare fingerprints,
    which needs no state and is right even if the seed was loaded in an earlier session.
    """
    try:
        headers = connector.seedkeeper_list_secret_headers()
    except Exception:
        return None

    wanted = root.my_fingerprint
    for header in headers:
        if header.get("type") != "Masterseed":
            continue
        sid = header["id"]
        try:
            pubkey, _ = connector.card_bip32_get_extendedkey("m", sid=sid)
        except Exception:
            continue
        if _fingerprint(pubkey) == wanted:
            return CardSession(connector, sid)
    return None


def _fingerprint(pubkey) -> bytes:
    from embit.hashes import hash160
    return hash160(pubkey.get_public_key_bytes(True))[:4]
