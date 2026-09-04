"""The two rounds, and the rule that the secret nonce between them is not reusable.

Both rounds run here against the captured PSBT without a node. Bitcoin Core's
public nonce is already in the fixture, so once this seed adds its own the
session has everything it needs to produce a partial signature, and that
signature can be checked with the same code Core's is checked with.

What is deliberately not asserted is the final aggregated signature. Producing
one needs Core's secret nonce, which is exactly the thing nobody should ever
have, and the end-to-end run against a live node covers it instead.
"""

import json
import os

import pytest
from embit import bip32, bip39
from embit.psbt import PSBT

from seedsigner.helpers import musig2 as m
from seedsigner.helpers import musig2_psbt as mp
from seedsigner.helpers import musig2_session as ms

FIXTURE = os.path.join(os.path.dirname(__file__), "data", "musig2_psbts.json")


@pytest.fixture(scope="module")
def data():
    with open(FIXTURE) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def root(data):
    return bip32.HDKey.from_seed(bip39.mnemonic_to_seed(data["mnemonics"]["B"]))


@pytest.fixture
def psbt(data):
    return PSBT.from_string(data["psbt_round_one"])


def keypath(psbt, root):
    return next(r for r in mp.roles_for_root(psbt, root) if r.is_keypath)


def test_first_pass_publishes_a_nonce_and_signs_nothing(psbt, root):
    session = ms.Musig2Session()
    progress = ms.advance(psbt, root, session)

    assert progress.stage == ms.ROUND_ONE
    assert (progress.signed_inputs, progress.waiting_inputs) == (0, 1)
    assert progress.skipped_leaves == 1, "the leaf this seed is also in must be counted"
    assert len(session) == 1

    role = keypath(psbt, root)
    nonces = mp.scope_fields(psbt.inputs[role.input_index], mp.FIELD_PUBNONCE)
    assert nonces[role.my_pubkey + role.agg_id]


def test_second_pass_signs_and_spends_the_nonce(psbt, root):
    session = ms.Musig2Session()
    ms.advance(psbt, root, session)
    progress = ms.advance(psbt, root, session)

    assert progress.stage == ms.SIGNED
    assert (progress.signed_inputs, progress.waiting_inputs) == (1, 0)
    assert len(session) == 0, "the secret nonce must not outlive the signature"

    role = keypath(psbt, root)
    msg = mp.sighash_for(psbt, role)
    sigs = mp.scope_fields(psbt.inputs[role.input_index], mp.FIELD_PARTIAL_SIG)
    ours = sigs[role.my_pubkey + role.agg_id]
    assert m.partial_sig_verify(ours, mp.pubnonces(psbt, role), role.participants,
                                role.tweaks, role.is_xonly, msg, role.my_index)


def test_a_third_pass_has_nothing_left_to_do(psbt, root):
    """Rescanning a finished PSBT must not start a new round and must not sign
    again, since a second signature would need a second nonce."""
    session = ms.Musig2Session()
    ms.advance(psbt, root, session)
    ms.advance(psbt, root, session)
    role = keypath(psbt, root)
    before = dict(psbt.inputs[role.input_index].unknown)

    progress = ms.advance(psbt, root, session)
    assert dict(psbt.inputs[role.input_index].unknown) == before
    assert progress.stage == ms.SIGNED
    assert len(session) == 0


def test_a_different_transaction_gets_a_different_nonce(data, root):
    """Entries are keyed by the message, so a secret nonce made for one spend
    can never be picked up for another. This is the property that stops a
    replayed round two from being a key disclosure."""
    session = ms.Musig2Session()
    first = PSBT.from_string(data["psbt_round_one"])
    ms.advance(first, root, session)

    second = PSBT.from_string(data["psbt_round_one"])
    second.tx_version = 1                      # any change the sighash commits to
    assert mp.sighash_for(second, keypath(second, root)) != \
        mp.sighash_for(first, keypath(first, root))

    ms.advance(second, root, session)
    assert len(session) == 2, "the second spend reused the first spend's nonce"

    role_a, role_b = keypath(first, root), keypath(second, root)
    nonce_a = mp.scope_fields(first.inputs[0], mp.FIELD_PUBNONCE)[role_a.my_pubkey + role_a.agg_id]
    nonce_b = mp.scope_fields(second.inputs[0], mp.FIELD_PUBNONCE)[role_b.my_pubkey + role_b.agg_id]
    assert nonce_a != nonce_b


def test_clearing_the_session_wipes_the_secret(psbt, root):
    session = ms.Musig2Session()
    ms.advance(psbt, root, session)
    held = list(session._secnonces.values())[0]

    session.clear()
    assert len(session) == 0
    assert bytes(held[:64]) == b"\x00" * 64, "the buffer was dropped but not wiped"


def test_a_seed_that_is_not_a_participant_is_told_so(data):
    stranger = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(
        "letter advice cage absurd amount doctor acoustic avoid letter "
        "advice cage above"))
    with pytest.raises(mp.Musig2Error, match="not a participant"):
        ms.advance(PSBT.from_string(data["psbt_round_one"]), stranger, ms.Musig2Session())
