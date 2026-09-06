"""
    MuSig2 from a psbt: reading the arrangement, checking it against the coin, and the two
    rounds. The fixture is a 2-of-3 captured from Bitcoin Core; see docs/musig2.md.
"""
import json
import os

import pytest
from embit import bip32, bip39
from embit.psbt import PSBT, InputScope, DerivationPath
from embit.ec import PublicKey

from seedsigner.helpers import musig2 as m
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
    """The captured psbt carries Core's nonce already; drop it to exercise the waiting round."""
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
    """Core's (signer A's) public nonce, taken from the fixture that carries both nonces."""
    both = PSBT.from_string(data["psbt_both_nonces"])
    other = next(pk for pk in role.aggregate.participants if pk != role.pubkey)
    return other, both.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, other)]


# --- reading -------------------------------------------------------------------------

def test_the_arrangement_is_read_from_the_psbt(psbt, roots, data):
    keypath, leaves = mp.roles(psbt, roots["B"])
    assert len(keypath) == 1 and leaves == 1
    role = keypath[0]
    e = data["expected"]
    assert role.aggregate.key.hex() == e["keypath_agg_id"]
    assert [pk.hex() for pk in role.aggregate.participants] == e["participants"]
    assert role.aggregate.participants.index(role.pubkey) == e["my_index"]
    assert role.derivation == e["my_derivation"]
    assert [t.hex() for t in role.aggregate.tweaks] == e["tweaks"]
    assert role.aggregate.is_xonly == e["is_xonly"]
    assert mp.sighash(psbt, role).hex() == e["sighash"]


def test_a_seed_outside_the_arrangement_has_no_role(psbt):
    stranger = bip32.HDKey.from_seed(os.urandom(64))
    assert mp.roles(psbt, stranger) == ([], 0)


def test_the_third_seed_is_only_in_leaves(psbt, roots):
    keypath, leaves = mp.roles(psbt, roots["C"])
    assert keypath == [] and leaves == 2


def _participants_field(psbt):
    scope = psbt.inputs[0]
    return next(k for k in scope.unknown if k[0] == mp.PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS)


@pytest.mark.parametrize("tamper", ["truncate", "empty", "swap_key", "not_a_point", "no_derivation"])
def test_malformed_fields_are_refused_not_crashed(psbt, roots, tamper):
    scope = psbt.inputs[0]
    key = _participants_field(psbt)
    if tamper == "truncate":
        scope.unknown[key] = scope.unknown[key][:65]
    elif tamper == "empty":
        scope.unknown[key] = b""
    elif tamper == "swap_key":
        blob = scope.unknown[key]
        scope.unknown[key] = m.individual_pk(os.urandom(32)) + blob[33:]
    elif tamper == "not_a_point":
        scope.unknown[key] = b"\x02" + b"\xff" * 32 + scope.unknown[key][33:]
    elif tamper == "no_derivation":
        fingerprint = mp.hash160(key[1:])[:4]
        for pub in [p for p, (_, der) in scope.taproot_bip32_derivations.items()
                    if der.fingerprint == fingerprint]:
            del scope.taproot_bip32_derivations[pub]
    with pytest.raises(mp.Musig2Error):
        mp.roles(psbt, roots["B"])


def test_hardened_derivation_of_an_aggregate_is_refused():
    with pytest.raises(mp.Musig2Error):
        mp._derive(m.individual_pk(os.urandom(32)), [mp.HARDENED])


# --- the coin ------------------------------------------------------------------------

def test_the_aggregate_must_lock_the_coin(psbt, roots):
    role = role_of(psbt, roots["B"])
    mp.check_coin(psbt, role)
    spk = bytearray(psbt.inputs[0].utxo.script_pubkey.data)
    spk[-1] ^= 1
    psbt.inputs[0].utxo.script_pubkey.data = bytes(spk)
    with pytest.raises(mp.Musig2Error):
        mp.check_coin(psbt, role)


def test_a_changed_merkle_root_changes_the_key_and_fails_the_coin(psbt, roots):
    psbt.inputs[0].taproot_merkle_root = os.urandom(32)
    with pytest.raises(mp.Musig2Error):
        mp.check_coin(psbt, role_of(psbt, roots["B"]))


def test_the_policy_is_proven_from_the_tree(psbt, roots):
    assert str(mp.policy(psbt, role_of(psbt, roots["B"]))) == "2 of 3"


def test_a_tampered_leaf_gives_no_policy(psbt, roots):
    scope = psbt.inputs[0]
    control_block = next(iter(scope.taproot_scripts))
    value = bytearray(scope.taproot_scripts[control_block])
    value[5] ^= 1
    scope.taproot_scripts[control_block] = bytes(value)
    assert mp.policy(psbt, role_of(psbt, roots["B"])) is None


def test_no_internal_key_gives_no_policy(psbt, roots):
    psbt.inputs[0].taproot_internal_key = None
    assert mp.policy(psbt, role_of(psbt, roots["B"])) is None


# --- the rounds ----------------------------------------------------------------------

def test_the_first_pass_publishes_a_nonce_and_signs_nothing(psbt, roots):
    session = mp.Session()
    progress = session.advance(psbt, roots["B"])
    assert progress == mp.Progress(mp.NONCE, 0, 1, 1)
    role = role_of(psbt, roots["B"])
    assert mp.pubnonces(psbt, role).count(None) == 1
    assert mp.partial_sig(psbt, role) is None
    assert len(session) == 1


def test_the_last_signer_signs_in_one_pass(data, roots):
    """With every other nonce already present there is nothing to wait for."""
    psbt = PSBT.from_string(data["psbt_round_one"])
    session = mp.Session()
    assert session.advance(psbt, roots["B"]) == mp.Progress(mp.SIGNED, 1, 0, 1)
    assert mp.partial_sig(psbt, role_of(psbt, roots["B"])) is not None
    assert len(session) == 0


def test_a_rescan_republishes_the_same_nonce(data, roots):
    session = mp.Session()
    first = without_other_nonces(data["psbt_round_one"])
    session.advance(first, roots["B"])
    again = without_other_nonces(data["psbt_round_one"])
    session.advance(again, roots["B"])
    role = role_of(again, roots["B"])
    ours = role.aggregate.participants.index(role.pubkey)
    assert mp.pubnonces(again, role)[ours] == mp.pubnonces(first, role)[ours]
    assert len(session) == 1


def test_the_second_pass_signs_and_destroys_the_nonce(data, psbt, roots):
    session = mp.Session()
    session.advance(psbt, roots["B"])
    role = role_of(psbt, roots["B"])
    other, nonce = core_nonce(data, role)
    psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, other)] = nonce

    progress = session.advance(psbt, roots["B"])
    assert progress == mp.Progress(mp.SIGNED, 1, 0, 1)
    assert len(session) == 0
    agg = role.aggregate
    assert m.partial_sig_verify(mp.partial_sig(psbt, role), mp.pubnonces(psbt, role), agg.participants,
                                agg.tweaks, agg.is_xonly, mp.sighash(psbt, role),
                                agg.participants.index(role.pubkey))


def test_a_signed_psbt_is_verified_and_never_signed_again(data, psbt, roots):
    session = mp.Session()
    session.advance(psbt, roots["B"])
    role = role_of(psbt, roots["B"])
    other, nonce = core_nonce(data, role)
    psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, other)] = nonce
    session.advance(psbt, roots["B"])
    before = dict(psbt.inputs[0].unknown)

    assert session.advance(psbt, roots["B"]) == mp.Progress(mp.SIGNED, 1, 0, 1)
    assert dict(psbt.inputs[0].unknown) == before

    mp.write_partial_sig(psbt, role, bytes(32))
    with pytest.raises(mp.Musig2Error):
        session.advance(psbt, roots["B"])


def test_a_different_transaction_gets_a_different_nonce(data, roots):
    session = mp.Session()
    one = without_other_nonces(data["psbt_round_one"])
    two = without_other_nonces(data["psbt_round_one"])
    two.outputs[0].value -= 1
    session.advance(one, roots["B"])
    session.advance(two, roots["B"])
    role = role_of(one, roots["B"])
    ours = role.aggregate.participants.index(role.pubkey)
    assert mp.pubnonces(one, role)[ours] != mp.pubnonces(two, role_of(two, roots["B"]))[ours]
    assert len(session) == 2


def test_clear_wipes_every_secret_nonce(psbt, roots):
    session = mp.Session()
    session.advance(psbt, roots["B"])
    held = [secnonce for secnonce, _ in session._nonces.values()]
    session.clear()
    assert len(session) == 0
    assert all(bytes(n) == bytes(len(n)) for n in held)


def test_a_nonce_store_can_be_swapped_in(data, psbt, roots):
    """The seam a card-backed nonce store uses: it sees every nonce request and every signing."""
    calls = []

    class Store(mp.Session):
        def new_nonce(self, psbt, role, msg, secret):
            calls.append("nonce")
            return super().new_nonce(psbt, role, msg, secret)

        def sign(self, psbt, secnonce, role, secret, context):
            calls.append("sign")
            return super().sign(psbt, secnonce, role, secret, context)

    session = Store()
    session.advance(psbt, roots["B"])
    role = role_of(psbt, roots["B"])
    other, nonce = core_nonce(data, role)
    psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PUB_NONCE, role, other)] = nonce
    session.advance(psbt, roots["B"])
    assert calls == ["nonce", "sign"]


def test_a_seed_that_also_owns_an_ordinary_input_is_refused(psbt, roots):
    plain = InputScope()
    pub = PublicKey.parse(m.individual_pk(os.urandom(32)))
    plain.bip32_derivations[pub] = DerivationPath(roots["B"].my_fingerprint, [0])
    psbt.inputs.append(plain)
    with pytest.raises(mp.Musig2Error, match="Mixed"):
        mp.Session().advance(psbt, roots["B"])


def test_a_seed_with_no_role_is_refused(psbt):
    with pytest.raises(mp.Musig2Error):
        mp.Session().advance(psbt, bip32.HDKey.from_seed(os.urandom(64)))


def test_a_proprietary_key_is_laid_out_the_way_bip174_says():
    """0xFC, the identifier with its compact-size length, the subtype, then the key data.

    Pinned because the alternative these fields used to take, a per-input number just past
    the end of the registry, is unallocated rather than reserved: a later BIP may claim it
    and mean something else by it.
    """
    scan_key, pubkey = b"\x02" + b"\x11" * 32, b"\x03" + b"\x22" * 32
    key = mp._share_key(mp.SUBTYPE_MUSIG2_PARTIAL_ECDH_SHARE, scan_key, pubkey)
    assert key == bytes.fromhex("fc0a") + b"DOOMSIGNER" + b"\x02" + scan_key + pubkey
    assert len(key) == 1 + 1 + 10 + 1 + 33 + 33
    assert mp.proprietary_key(mp.SUBTYPE_MUSIG2_PARTIAL_DLEQ)[-1] == 0x03


def test_compact_size_is_correct_past_one_byte():
    assert mp.compact_size(0) == b"\x00"
    assert mp.compact_size(252) == b"\xfc"
    assert mp.compact_size(253) == b"\xfd\xfd\x00"
    assert mp.compact_size(0xFFFF) == b"\xfd\xff\xff"
    assert mp.compact_size(0x10000) == b"\xfe\x00\x00\x01\x00"
    assert mp.compact_size(0xFFFFFFFF) == b"\xfe\xff\xff\xff\xff"
    assert mp.compact_size(0x100000000) == b"\xff" + (0x100000000).to_bytes(8, "little")
