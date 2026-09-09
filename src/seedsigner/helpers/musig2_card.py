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

import logging
from typing import List, Optional

from seedsigner.helpers import musig2 as m
from seedsigner.helpers import musig2_psbt as mp

logger = logging.getLogger(__name__)

# BIP-174 proprietary field: 0xFC, then the identifier, then the subtype, then the key
# data. The identifier keeps this out of the way of every other producer's fields, and
# `musig2_psbt.proprietary_key` builds the key; the whole subtype list lives beside it.
SUBTYPE_SEALED_NONCE = 0x00
SUBTYPE_POOLED_NONCE = 0x01

# How many unused nonces to leave behind in the transaction on the way out.
#
# This is what removes the extra trip. A nonce made in advance lets the coordinator put
# both halves of the arrangement together before anyone visits a device, so a spend costs
# one visit per signer instead of two. Four rather than one because a spend that is
# abandoned takes its nonce with it, and two transactions in flight at once need two.
#
# They ride in the transaction that was going back anyway, so there is no separate
# ceremony to stock a card: every signing tops the supply back up as it leaves. The card
# tracks sixteen unspent nonces at a time, so four plus whatever is in flight fits.
POOLED_NONCES = 4

# What the card answers, and so what a stored field holds: the public nonce it published,
# then the secret nonce sealed under keys that never leave the applet.
SIZE_PUBNONCE = 66
SIZE_SEALED = 144
SIZE_SECNONCE = 97

# The type byte a SeedKeeper files a master seed under: SECRET_TYPE_MASTER_SEED in the
# applet, 'Masterseed' in pysatochip's SEEDKEEPER_DIC_TYPE. Written out rather than read
# from pysatochip because the test suite replaces that package with a mock, and because
# it is a wire value that cannot move without breaking every card already in the field.
SECRET_TYPE_MASTERSEED = 0x10
# A seed saved from this device lands as a BIP39 mnemonic, not a masterseed, so
# looking only for the latter found nothing on a card this device had written
# itself: signing fell back to memory without a word and left no spare nonces,
# which is the whole of the pool. Both mnemonic types are here because the
# applet has two, and which one a card holds depends on when it was written.
SECRET_TYPE_BIP39 = 0x30
SECRET_TYPE_BIP39_V2 = 0x31
SEED_BEARING_TYPES = (SECRET_TYPE_MASTERSEED, SECRET_TYPE_BIP39, SECRET_TYPE_BIP39_V2)

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
    return mp.proprietary_key(SUBTYPE_SEALED_NONCE,
                              role.pubkey + role.aggregate.key + msg)


def pooled_nonce_key(pubkey: bytes, index: int) -> bytes:
    """Where one unused nonce waits, before it has a transaction to belong to.

    Keyed by the signer and nothing else. A nonce generated with no message and no
    aggregate is not bound to either, so it can serve whichever spend arrives first;
    the index only keeps several of them apart on the same input.
    """
    return mp.proprietary_key(SUBTYPE_POOLED_NONCE, pubkey + index.to_bytes(2, "big"))


def _pooled(psbt, role: mp.Role) -> List[bytes]:
    """The keys of this signer's unused nonces on its input, in index order."""
    prefix = mp.proprietary_key(SUBTYPE_POOLED_NONCE, role.pubkey)
    return sorted(k for k in psbt.inputs[role.input_index].unknown
                  if bytes(k).startswith(prefix))


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

    nonce_on_card = True

    def __init__(self, connector, sid: int):
        super().__init__()
        self._connector = connector
        self._sid = sid

    def __bool__(self) -> bool:
        """A session exists whether or not it is holding a nonce yet.

        Session defines __len__, so without this a freshly built one is falsy and
        `card_session or Session()` quietly discards the card. That is not a
        hypothetical: it shipped in the first version of the selection above.
        """
        return True

    # --- the seam ----------------------------------------------------------------------

    def new_nonce(self, psbt, role: mp.Role, msg: bytes, secret: bytearray):
        """A sealed nonce and the public nonce that goes with it.

        A sealed nonce already in the PSBT is returned as it is, which is how a device
        that was switched off between the rounds picks up where it left off rather than
        burning a second one.
        """
        scope = psbt.inputs[role.input_index]
        field = sealed_nonce_key(role, msg)
        stored = scope.unknown.get(field)
        if stored is not None and len(stored) == SIZE_PUBNONCE + SIZE_SEALED:
            return bytes(stored[SIZE_PUBNONCE:]), bytes(stored[:SIZE_PUBNONCE])

        # An unused nonce, if the coordinator brought one. Taking it is what makes this
        # a one-visit signing: its public half was published before the transaction was
        # built, so every nonce is already present and there is nothing to wait for.
        pooled = _pooled(psbt, role)
        if pooled:
            entry = bytes(scope.unknown.pop(pooled[0]))
            # Bound to this sighash from here on, so it cannot be resumed for a
            # transaction that changed underneath it.
            scope.unknown[field] = entry
            self._restock(psbt, role)
            return entry[SIZE_PUBNONCE:], entry[:SIZE_PUBNONCE]

        pubnonce, sealed = self._mint(role)
        scope.unknown[field] = pubnonce + sealed
        self._restock(psbt, role)
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

    def _mint(self, role: mp.Role):
        """One fresh nonce from the card, made without a message so it can serve any
        transaction: BIP-327 allows that, and the card mixes its own counter in so a
        batch made this way cannot repeat itself."""
        self._derive(role)
        answer = _transmit(self._connector, INS_MUSIG2_GENERATE_NONCE, 0x00, OP_INIT,
                           # no aggregate key, no message, no extra input
                           bytes([0x00, 0xFF, 0x00]))
        pubnonce = answer[:SIZE_PUBNONCE]
        sealed = _transmit(self._connector, INS_MUSIG2_GENERATE_NONCE, 0x00, OP_FINALIZE)
        if len(pubnonce) != SIZE_PUBNONCE or len(sealed) != SIZE_SEALED:
            raise CardNonceError("The card answered a nonce of the wrong size.")
        return pubnonce, sealed

    def _restock(self, psbt, role: mp.Role) -> None:
        """Leave the supply of unused nonces full on the way out.

        Every signing tops it back up in the transaction that was going back anyway, so
        there is no separate visit to stock the card and no state kept on the device. A
        card that cannot supply them is not an error: the spend still completes, the next
        one just costs the extra trip again.
        """
        try:
            for index in range(POOLED_NONCES):
                if len(_pooled(psbt, role)) >= POOLED_NONCES:
                    return
                key = pooled_nonce_key(role.pubkey, index)
                if key in psbt.inputs[role.input_index].unknown:
                    continue
                pubnonce, sealed = self._mint(role)
                psbt.inputs[role.input_index].unknown[key] = pubnonce + sealed
        except Exception:
            logger.info("musig2: could not restock pooled nonces", exc_info=True)

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

    Every kind of secret a seed can be stored as is considered, not masterseeds
    alone: this device saves a seed as a BIP39 mnemonic, so a card it had
    written itself was being passed over. A secret the card cannot derive from
    raises and is skipped, which is what the fingerprint comparison would have
    done with it anyway.
    """
    try:
        headers = connector.seedkeeper_list_secret_headers()
    except Exception:
        logger.info("musig2: the card would not list what it holds", exc_info=True)
        return None

    wanted = root.my_fingerprint
    logger.info("musig2: card holds %d secrets, want fingerprint %s",
                len(headers), wanted.hex())
    for header in headers:
        logger.info("musig2: secret id=%s type=%s", header.get("id"), header.get("type"))
        if header.get("type") not in SEED_BEARING_TYPES:
            continue
        sid = header["id"]
        try:
            pubkey, _ = connector.card_bip32_get_extendedkey("m", sid=sid)
        except Exception as why:
            logger.info("musig2: secret %s would not derive: %s", sid, why)
            continue
        logger.info("musig2: secret %s derives fingerprint %s",
                    sid, _fingerprint(pubkey).hex())
        if _fingerprint(pubkey) == wanted:
            return CardSession(connector, sid)
    logger.info("musig2: no secret on this card matches the seed")
    return None


def select(controller, root) -> Optional[CardSession]:
    """A card-backed session, if one can be had without interrupting the user.

    Only a card that is already open is used: the connector the controller is holding
    from whatever unlocked it earlier, which for the flow this is built for is loading
    the seed off that same card. Nothing here opens a reader, and nothing here asks for
    a PIN, because a PIN prompt appearing in the middle of signing is exactly the sort
    of surprise that makes a signer untrustworthy. No card, no open connector, a locked
    card or a card holding a different seed all mean the caller gets None and signs the
    way it always has.
    """
    connector = getattr(controller, "Satochip_Connector", None)
    if connector is None:
        return None
    try:
        session = for_seed(connector, root)
    except Exception:
        logger.info("musig2: no card-backed nonce store, signing in memory", exc_info=True)
        return None
    if session is not None:
        logger.info("musig2: secret nonces will be held on the card")
    return session


def _fingerprint(pubkey) -> bytes:
    from embit.hashes import hash160
    return hash160(pubkey.get_public_key_bytes(True))[:4]
