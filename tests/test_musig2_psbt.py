"""Reading a MuSig2 arrangement out of a PSBT, and signing it.

`tests/data/musig2_psbts.json` was captured from a live Bitcoin Core v31.1.0 on
regtest, which matters more than it sounds: the fields under test are ones we do
not generate, so a fixture we wrote ourselves would only prove that this module
agrees with itself. Core is a second implementation, and every check below is
really a check against it.

Two of these run in the opposite direction to the rest. Core's own partial
signature is verified by our code, and the final broadcast transaction's single
64-byte witness is verified as an ordinary BIP-340 signature for the taproot
output key. Between them they say that the two implementations agree about the
aggregate key, the tweak chain and the message, which is the whole of what could
silently go wrong.

The keys are throwaway and the network is regtest. Nothing here is a secret.
"""

import copy
import hashlib
import json
import os

import pytest
from embit import bip32, ec
from embit.psbt import PSBT
from embit.transaction import Transaction

from seedsigner.helpers import musig2 as m
from seedsigner.helpers import musig2_psbt as mp

FIXTURE = os.path.join(os.path.dirname(__file__), "data", "musig2_psbts.json")


@pytest.fixture(scope="module")
def data():
    with open(FIXTURE) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def root(data):
    seed = hashlib.sha256(data["seed_b_sha256_of"].encode()).digest()
    return bip32.HDKey.from_seed(seed)


def roles(data, root, which="psbt_round_one"):
    return mp.roles_for_root(PSBT.from_string(data[which]), root)


def keypath_role(data, root, which="psbt_round_one"):
    return next(r for r in roles(data, root, which) if r.is_keypath)


def test_finds_every_aggregate_this_seed_belongs_to(data, root):
    """In a 2-of-3 the same seed sits in the key path pair and in a leaf, so
    finding one role and stopping would look like success."""
    found = roles(data, root)
    assert len(found) == data["expected"]["roles"]
    assert sum(1 for r in found if r.is_keypath) == 1
    assert sum(1 for r in found if not r.is_keypath) == 1


def test_role_matches_what_core_encoded(data, root):
    role = keypath_role(data, root)
    expected = data["expected"]
    assert role.agg_id.hex() == expected["keypath_agg_id"]
    assert [p.hex() for p in role.participants] == expected["participants"]
    assert role.my_index == expected["my_index"]
    assert role.my_derivation == expected["my_derivation"]
    assert [t.hex() for t in role.tweaks] == expected["tweaks"]
    assert role.is_xonly == expected["is_xonly"]


def test_participant_order_is_not_the_order_a_human_would_write(data, root):
    """BIP-390 sorts, so this is a live example of the trap rather than a
    hypothetical one. If these ever come out sorted the same way by accident,
    the fixture has stopped testing what it was written to test."""
    role = keypath_role(data, root)
    assert role.participants != sorted(role.participants, reverse=True)
    assert role.participants == sorted(role.participants)


def test_our_key_derives_from_the_seed(data, root):
    role = keypath_role(data, root)
    sk = root.derive(role.my_derivation).key.secret
    assert m.individual_pk(sk) == role.my_pubkey


def test_the_aggregate_key_locks_the_coin(data, root):
    psbt = PSBT.from_string(data["psbt_round_one"])
    role = next(r for r in mp.roles_for_root(psbt, root) if r.is_keypath)
    mp.verify_against_utxo(psbt, role)


def test_a_swapped_utxo_is_caught(data, root):
    """The check that matters: MuSig2 fields describing a different arrangement
    from the one holding the money."""
    psbt = PSBT.from_string(data["psbt_round_one"])
    role = next(r for r in mp.roles_for_root(psbt, root) if r.is_keypath)
    tampered = copy.deepcopy(psbt)
    spk = tampered.inputs[role.input_index].witness_utxo.script_pubkey
    spk.data = spk.data[:2] + bytes(32)
    with pytest.raises(mp.Musig2Error, match="does not lock this coin"):
        mp.verify_against_utxo(tampered, role)


def test_sighash(data, root):
    psbt = PSBT.from_string(data["psbt_round_one"])
    role = next(r for r in mp.roles_for_root(psbt, root) if r.is_keypath)
    assert mp.sighash_for(psbt, role).hex() == data["expected"]["sighash"]


def test_leaf_signing_is_refused_rather_than_skipped(data, root):
    psbt = PSBT.from_string(data["psbt_round_one"])
    leaf = next(r for r in mp.roles_for_root(psbt, root) if not r.is_keypath)
    with pytest.raises(mp.Musig2Error, match="not supported yet"):
        mp.sighash_for(psbt, leaf)


def test_an_unfinished_first_round_reads_as_unfinished(data, root):
    """Not an error: it is the state the device shows a round-one screen for."""
    psbt = PSBT.from_string(data["psbt_round_one"])
    role = next(r for r in mp.roles_for_root(psbt, root) if r.is_keypath)
    assert mp.pubnonces(psbt, role) is None


def test_a_finished_first_round_yields_nonces_in_aggregation_order(data, root):
    psbt = PSBT.from_string(data["psbt_both_nonces"])
    role = next(r for r in mp.roles_for_root(psbt, root) if r.is_keypath)
    collected = mp.pubnonces(psbt, role)
    assert collected is not None and len(collected) == len(role.participants)
    assert all(len(n) == 66 for n in collected)


def test_written_fields_survive_a_serialize_round_trip(data, root):
    psbt = PSBT.from_string(data["psbt_round_one"])
    role = next(r for r in mp.roles_for_root(psbt, root) if r.is_keypath)
    mp.write_pubnonce(psbt, role, b"\x02" + bytes(32) + b"\x03" + bytes(32))
    mp.write_partial_sig(psbt, role, bytes(range(32)))

    again = PSBT.from_string(str(psbt))
    role2 = next(r for r in mp.roles_for_root(again, root) if r.is_keypath)
    fields = mp.scope_fields(again.inputs[role2.input_index], mp.FIELD_PARTIAL_SIG)
    assert fields[role2.my_pubkey + role2.agg_id] == bytes(range(32))


def test_we_accept_cores_partial_signature(data, root):
    """The cross-check, in the direction that is easy to forget: our code
    validating theirs."""
    psbt = PSBT.from_string(data["psbt_both_nonces"])
    role = next(r for r in mp.roles_for_root(psbt, root) if r.is_keypath)
    collected = mp.pubnonces(psbt, role)
    msg = mp.sighash_for(psbt, role)

    sigs = mp.scope_fields(psbt.inputs[role.input_index], mp.FIELD_PARTIAL_SIG)
    theirs = {pk: sigs[pk + role.agg_id] for pk in role.participants
              if pk + role.agg_id in sigs}
    assert theirs, "the fixture carries no partial signature from Core"

    for pubkey, psig in theirs.items():
        assert m.partial_sig_verify(psig, collected, role.participants, role.tweaks,
                                    role.is_xonly, msg,
                                    role.participants.index(pubkey))


def test_the_broadcast_transaction_carries_a_valid_signature(data, root):
    """End to end, with no node: one 64-byte witness item, and it verifies as an
    ordinary single-signer taproot signature for the aggregate key."""
    psbt = PSBT.from_string(data["psbt_both_nonces"])
    role = next(r for r in mp.roles_for_root(psbt, root) if r.is_keypath)
    msg = mp.sighash_for(psbt, role)
    output_key = psbt.inputs[role.input_index].utxo.script_pubkey.data[2:]

    tx = Transaction.from_string(data["final_tx_hex"])
    witness = tx.vin[role.input_index].witness.items
    assert len(witness) == 1, "not a key path spend"
    assert len(witness[0]) == 64, "not SIGHASH_DEFAULT"

    signature = ec.SchnorrSig.parse(witness[0])
    assert ec.PublicKey.from_xonly(output_key).schnorr_verify(signature, msg)
