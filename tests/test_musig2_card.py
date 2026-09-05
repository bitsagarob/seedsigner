"""
    MuSig2 nonces held on a card. The card here is a stand-in that answers the same
    APDUs as the applet, so these check the wallet's half: that a sealed nonce goes into
    the psbt, that a device which lost power picks the same one up again, that a changed
    transaction does not, and that the signature produced is the same one the software
    path produces.

    The applet's own half, that a sealed nonce opens exactly once, is checked against
    the real Java in the applet repository under jCardSim.
"""
import json
import os

import pytest
from embit import bip32, bip39
from embit.psbt import PSBT

from seedsigner.helpers import musig2 as m
from seedsigner.helpers import musig2_card as mc
from seedsigner.helpers import musig2_psbt as mp

FIXTURE = os.path.join(os.path.dirname(__file__), "data", "musig2_psbts.json")


@pytest.fixture(scope="module")
def data():
    with open(FIXTURE) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def roots(data):
    return {n: bip32.HDKey.from_seed(bip39.mnemonic_to_seed(data["mnemonics"][n])) for n in "ABC"}


def without_other_nonces(psbt_b64):
    psbt = PSBT.from_string(psbt_b64)
    for scope in psbt.inputs:
        for key in [k for k in scope.unknown if k[0] == mp.PSBT_IN_MUSIG2_PUB_NONCE]:
            del scope.unknown[key]
    return psbt


@pytest.fixture
def psbt(data):
    return without_other_nonces(data["psbt_round_one"])


def role_of(psbt, root):
    keypath, _ = mp.roles(psbt, root)
    return keypath[0]


def core_nonce(data, role):
    both = PSBT.from_string(data["psbt_both_nonces"])
    other = next(pk for pk in role.aggregate.participants if pk != role.pubkey)
    return other, both.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, other)]


class FakeCard:
    """A stand-in for the applet: it derives, it makes nonces, and it opens each once.

    Deliberately not a re-implementation of the sealing. What the wallet depends on is
    that a sealed nonce is opaque, that it opens once, and that the secret nonce inside
    matches the public nonce that was published. Those hold here, so a wallet bug shows
    up as a failure rather than being hidden by a clever fake.
    """

    def __init__(self, root):
        self.root = root
        self.derived = None
        self.sealed = {}     # sealed bytes -> secret nonce
        self.spent = set()
        self.generated = 0

    def card_transmit(self, apdu):
        ins, p1, p2 = apdu[1], apdu[2], apdu[3]
        data = bytes(apdu[5:])
        if ins == mc.INS_BIP32_GET_EXTENDED_KEY:
            path = [int.from_bytes(data[i:i + 4], "big") for i in range(0, 4 * p1, 4)]
            self.derived = self.root.derive(path).key
            return [], 0x90, 0x00
        if ins == mc.INS_MUSIG2_GENERATE_NONCE and p2 == mc.OP_INIT:
            if self.derived is None:
                return [], 0x9C, 0x13
            self.generated += 1
            secnonce, pubnonce = m.nonce_gen(
                self.derived.secret, self.derived.sec(), None, None,
                self.generated.to_bytes(2, "big"))
            self._pending = (bytes(secnonce),
                             bytes(pubnonce) + bytes(self.generated.to_bytes(2, "big")))
            return list(self._pending[1]), 0x90, 0x00
        if ins == mc.INS_MUSIG2_GENERATE_NONCE and p2 == mc.OP_FINALIZE:
            secnonce, published = self._pending
            sealed = (b"sealed" + self.generated.to_bytes(2, "big")).ljust(mc.SIZE_SEALED, b"\x00")
            self.sealed[sealed] = secnonce
            return list(sealed), 0x90, 0x00
        if ins == mc.INS_MUSIG2_UNSEAL_NONCE:
            if data not in self.sealed:
                return [], 0x9C, 0x44
            if data in self.spent:
                return [], 0x9C, 0x47
            self.spent.add(data)
            return list(self.sealed[data]), 0x90, 0x00
        return [], 0x6D, 0x00


@pytest.fixture
def card(roots):
    return FakeCard(roots["B"])


@pytest.fixture
def session(card):
    return mc.CardSession(card, sid=1)


def sighash_of(psbt, root):
    return mp.sighash(psbt, role_of(psbt, root))


# --- round one -----------------------------------------------------------------------

def test_the_sealed_nonce_is_written_into_the_psbt(psbt, roots, session):
    session.advance(psbt, roots["B"])
    role = role_of(psbt, roots["B"])
    field = mc.sealed_nonce_key(role, sighash_of(psbt, roots["B"]))
    stored = psbt.inputs[0].unknown[field]
    assert len(stored) == mc.SIZE_PUBNONCE + mc.SIZE_SEALED


def test_the_published_nonce_is_the_one_the_card_made(psbt, roots, session):
    session.advance(psbt, roots["B"])
    role = role_of(psbt, roots["B"])
    field = mc.sealed_nonce_key(role, sighash_of(psbt, roots["B"]))
    published = psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, role.pubkey)]
    assert bytes(published) == bytes(psbt.inputs[0].unknown[field][:mc.SIZE_PUBNONCE])


def test_a_device_that_lost_power_resumes_the_same_nonce(psbt, roots, card):
    """Round one, then a completely new session, as a reboot would give."""
    mc.CardSession(card, sid=1).advance(psbt, roots["B"])
    role = role_of(psbt, roots["B"])
    published = bytes(psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, role.pubkey)])

    mc.CardSession(card, sid=1).advance(psbt, roots["B"])
    again = bytes(psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, role.pubkey)])
    assert again == published
    assert card.generated == 1, "a second nonce was burned for the same signing"


def test_a_transaction_that_changed_does_not_resume(psbt, roots, card, data):
    """The field is bound to the sighash, so an altered transaction misses it."""
    mc.CardSession(card, sid=1).advance(psbt, roots["B"])
    role = role_of(psbt, roots["B"])
    field = mc.sealed_nonce_key(role, sighash_of(psbt, roots["B"]))
    stored = psbt.inputs[0].unknown.pop(field)

    # The same sealed nonce, filed under a sighash that is not this transaction's.
    psbt.inputs[0].unknown[mc.sealed_nonce_key(role, b"\x11" * 32)] = stored
    del psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, role.pubkey)]

    mc.CardSession(card, sid=1).advance(psbt, roots["B"])
    assert card.generated == 2, "the stale nonce was resumed for a different message"


# --- round two -----------------------------------------------------------------------

def test_it_signs_what_the_software_path_signs(psbt, roots, data, card):
    """Same nonce in, same partial signature out, so the card changes where the nonce
    lives and nothing else."""
    session = mc.CardSession(card, sid=1)
    session.advance(psbt, roots["B"])
    role = role_of(psbt, roots["B"])
    other, nonce = core_nonce(data, role)
    psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, other)] = nonce
    session.advance(psbt, roots["B"])

    partial = psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PARTIAL_SIG, role, role.pubkey)]
    secnonce = bytearray(list(card.sealed.values())[0])
    msg = sighash_of(psbt, roots["B"])
    context = m.SessionContext(
        m.nonce_agg(mp.pubnonces(psbt, role)), role.aggregate.participants,
        role.aggregate.tweaks, role.aggregate.is_xonly, msg)
    secret = roots["B"].derive(role.derivation).key.secret
    assert bytes(partial) == m.sign(secnonce, secret, context)


def test_the_sealed_nonce_is_removed_once_it_is_spent(psbt, roots, data, card):
    session = mc.CardSession(card, sid=1)
    session.advance(psbt, roots["B"])
    role = role_of(psbt, roots["B"])
    field = mc.sealed_nonce_key(role, sighash_of(psbt, roots["B"]))
    other, nonce = core_nonce(data, role)
    psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, other)] = nonce
    session.advance(psbt, roots["B"])
    assert field not in psbt.inputs[0].unknown


def test_a_card_that_refuses_to_open_twice_is_reported(psbt, roots, data, card):
    session = mc.CardSession(card, sid=1)
    session.advance(psbt, roots["B"])
    role = role_of(psbt, roots["B"])
    field = mc.sealed_nonce_key(role, sighash_of(psbt, roots["B"]))
    stored = bytes(psbt.inputs[0].unknown[field])
    other, nonce = core_nonce(data, role)
    psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, other)] = nonce
    session.advance(psbt, roots["B"])

    # Put the spent nonce back and ask again, as a coordinator replaying an old psbt would.
    psbt.inputs[0].unknown[field] = stored
    del psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PARTIAL_SIG, role, role.pubkey)]
    with pytest.raises(mc.CardNonceError, match="already released"):
        mc.CardSession(card, sid=1).advance(psbt, roots["B"])
