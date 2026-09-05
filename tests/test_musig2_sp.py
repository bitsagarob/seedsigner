"""
    A silent payment send from a MuSig2 key path. The oracle is BIP-352's own sender holding
    the aggregate private key, which exists in a test because both seeds are known here and
    must never exist on a device.
"""
import json
import os

import pytest
from embit import bip32, bip39, ec
from embit.psbt import PSBT
from embit.script import Script
from embit.silent_payments.psbt import SilentPaymentsPSBT, SilentPaymentData
from embit.silent_payments.sp import derive_sp_outputs, group_sp_outputs_by_scan_key

from seedsigner.helpers import musig2 as m
from seedsigner.helpers import musig2_psbt as mp
from seedsigner.helpers import silent_payments
from seedsigner.models.settings_definition import SettingsConstants

FIXTURE = os.path.join(os.path.dirname(__file__), "data", "musig2_psbts.json")

pytestmark = pytest.mark.skipif(not silent_payments.is_available(),
                                reason="installed embit has no BIP-352 support")


@pytest.fixture(scope="module")
def data():
    with open(FIXTURE) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def roots(data):
    return {n: bip32.HDKey.from_seed(bip39.mnemonic_to_seed(data["mnemonics"][n])) for n in "ABC"}


@pytest.fixture(scope="module")
def recipient(data):
    return silent_payments.derive_keys(bip39.mnemonic_to_seed(data["mnemonics"]["C"]),
                                       SettingsConstants.REGTEST)


def silent_send(data, recipient):
    """The captured spend re-addressed to a silent payment, as PSBTv2 with no nonces."""
    v0 = PSBT.from_string(data["psbt_round_one"])
    psbt = SilentPaymentsPSBT.parse(v0.serialize())
    psbt.version = 2
    psbt.tx_version = v0.tx.version
    psbt.locktime = v0.tx.locktime
    for scope in psbt.inputs:
        for key in [k for k in scope.unknown if k[0] == mp.PSBT_IN_MUSIG2_PUB_NONCE]:
            del scope.unknown[key]
    out = psbt.outputs[0]
    out.script_pubkey = None
    scan, spend = recipient
    out.sp_data = SilentPaymentData(scan.get_public_key(), spend.get_public_key())
    return SilentPaymentsPSBT.parse(psbt.serialize())


def role_of(psbt, root):
    return mp.roles(psbt, root)[0][0]


def single_holder_scripts(psbt, roots):
    """What BIP-352's sender computes with the aggregate private key in hand."""
    role_a, role_b = role_of(psbt, roots["A"]), role_of(psbt, roots["B"])
    agg = role_a.aggregate
    Q, gacc, tacc = m.key_agg_and_tweak(agg.participants, agg.tweaks, agg.is_xonly)
    total = sum(m.key_agg_coeff(agg.participants, r.pubkey) * m.int_from_bytes(root.derive(r.derivation).key.secret)
                for r, root in ((role_a, roots["A"]), (role_b, roots["B"])))
    d_q = (gacc * total + tacc) % m.n
    a = d_q if m.has_even_y(Q) else m.n - d_q
    groups, indices = group_sp_outputs_by_scan_key(psbt.outputs)
    _, _, results = derive_sp_outputs([m.bytes_from_int(a)], [inp.vin for inp in psbt.inputs], groups)
    return {idx: Script(b"\x51\x20" + outs[pos]) for sk, (_, outs) in results.items()
            for pos, idx in enumerate(indices[sk])}


def contribute(psbt, roots, names="AB"):
    for name in names:
        role = role_of(psbt, roots[name])
        secret = roots[name].derive(role.derivation).key.secret
        for scan_key in mp.sp_scan_keys(psbt):
            mp.write_share(psbt, role, secret, scan_key)


def scripts_of(mapping):
    return {k: bytes(v.data) for k, v in mapping.items()}


def test_two_shares_rebuild_the_single_holder_output(data, roots, recipient):
    psbt = silent_send(data, recipient)
    assert mp.sp_scripts_missing(psbt)
    with pytest.raises(mp.SharesIncomplete):
        mp.expected_scripts(psbt)
    contribute(psbt, roots)
    assert scripts_of(mp.expected_scripts(psbt)) == scripts_of(single_holder_scripts(psbt, roots))


def test_the_shares_survive_the_wire(data, roots, recipient):
    psbt = silent_send(data, recipient)
    contribute(psbt, roots)
    again = SilentPaymentsPSBT.parse(psbt.serialize())
    assert scripts_of(mp.expected_scripts(again)) == scripts_of(single_holder_scripts(psbt, roots))


@pytest.mark.parametrize("attack", ["flip_proof", "drop_proof", "rogue_key"])
def test_a_share_that_does_not_prove_out_is_refused(data, roots, recipient, attack):
    psbt = silent_send(data, recipient)
    contribute(psbt, roots)
    role = role_of(psbt, roots["A"])
    scan_key = mp.sp_scan_keys(psbt)[0]
    scope = psbt.inputs[0]
    proof_key = mp._share_key(mp.PSBT_IN_MUSIG2_PARTIAL_DLEQ, scan_key, role.pubkey)
    if attack == "flip_proof":
        proof = bytearray(scope.unknown[proof_key])
        proof[40] ^= 1
        scope.unknown[proof_key] = bytes(proof)
    elif attack == "drop_proof":
        del scope.unknown[proof_key]
    else:
        # A share made with some other key, with a perfectly good proof for that other key
        from embit.silent_payments.dleq import generate_dleq_proof
        from embit.silent_payments.sp import _tweak_mul
        rogue = os.urandom(32)
        scope.unknown[mp._share_key(mp.PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE, scan_key, role.pubkey)] = \
            _tweak_mul(scan_key, rogue)
        scope.unknown[proof_key] = generate_dleq_proof(rogue, scan_key, r=os.urandom(32))
    with pytest.raises(mp.Musig2Error):
        mp.expected_scripts(psbt)


def partial_sig_agg(psigs, session_ctx):
    """BIP-327's coordinator step, which the device never runs."""
    Q, _, tacc, _, R, e = m.get_session_values(session_ctx)
    s = sum(m.int_from_bytes(p) for p in psigs) % m.n
    g = 1 if m.has_even_y(Q) else m.n - 1
    return m.xbytes(R) + m.bytes_from_int((s + e * g * tacc) % m.n)


def test_three_rounds_end_in_a_signature_the_coin_accepts(data, roots, recipient):
    psbt = silent_send(data, recipient)
    sessions = {n: mp.Session() for n in "AB"}
    for n in "AB":
        assert sessions[n].advance(psbt, roots[n]).stage == mp.SHARES
        assert len(sessions[n]) == 0
    for idx, script in mp.expected_scripts(psbt).items():
        psbt.outputs[idx].script_pubkey = script
    psbt = SilentPaymentsPSBT.parse(psbt.serialize())
    # A publishes and waits; B publishes, sees both nonces, signs at once; A signs last
    assert sessions["A"].advance(psbt, roots["A"]).stage == mp.NONCE
    assert sessions["B"].advance(psbt, roots["B"]).stage == mp.SIGNED
    assert sessions["A"].advance(psbt, roots["A"]).stage == mp.SIGNED
    assert len(sessions["A"]) == 0 and len(sessions["B"]) == 0

    role = role_of(psbt, roots["A"])
    agg = role.aggregate
    msg = mp.sighash(psbt, role)
    psigs = [psbt.inputs[0].unknown[mp._key(mp.PSBT_IN_MUSIG2_PARTIAL_SIG, role, pk)] for pk in agg.participants]
    ctx = m.SessionContext(m.nonce_agg(mp.pubnonces(psbt, role)), agg.participants, agg.tweaks, agg.is_xonly, msg)
    output_key = psbt.inputs[0].utxo.script_pubkey.data[2:]
    assert ec.PublicKey.parse(b"\x02" + output_key).schnorr_verify(
        ec.SchnorrSig.parse(partial_sig_agg(psigs, ctx)), msg)


def test_a_wrong_script_stops_the_signer_before_the_nonce(data, roots, recipient):
    psbt = silent_send(data, recipient)
    sessions = {n: mp.Session() for n in "AB"}
    for n in "AB":
        sessions[n].advance(psbt, roots[n])
    psbt.outputs[0].script_pubkey = Script(b"\x51\x20" + os.urandom(32))
    psbt = SilentPaymentsPSBT.parse(psbt.serialize())
    with pytest.raises(mp.Musig2Error):
        sessions["A"].advance(psbt, roots["A"])
    assert len(sessions["A"]) == 0
    assert mp.pubnonces(psbt, role_of(psbt, roots["A"])).count(None) == 2


def test_a_missing_share_stops_the_signer_before_the_nonce(data, roots, recipient):
    psbt = silent_send(data, recipient)
    contribute(psbt, roots, "A")
    psbt.outputs[0].script_pubkey = Script(b"\x51\x20" + os.urandom(32))
    with pytest.raises(mp.Musig2Error, match="still missing"):
        mp.Session().advance(psbt, roots["A"])


def test_an_ordinary_spend_has_no_shares_round(data, roots):
    psbt = PSBT.from_string(data["psbt_round_one"])
    assert mp.sp_scan_keys(psbt) == [] and not mp.sp_scripts_missing(psbt)
    assert mp.Session().advance(psbt, roots["B"]).stage == mp.SIGNED   # Core's nonce is in it


def test_the_review_shows_the_silent_payment_address_with_or_without_a_script(data, roots, recipient):
    from seedsigner.models.psbt_parser import PSBTParser
    from seedsigner.models.seed import Seed
    seed = Seed(mnemonic=data["mnemonics"]["B"].split())
    psbt = silent_send(data, recipient)
    parser = PSBTParser(psbt, seed=seed, network=SettingsConstants.REGTEST)
    assert parser.destination_addresses[0].startswith("tsp1")
    assert parser.change_amount == 0

    contribute(psbt, roots)
    for idx, script in mp.expected_scripts(psbt).items():
        psbt.outputs[idx].script_pubkey = script
    parser = PSBTParser(SilentPaymentsPSBT.parse(psbt.serialize()), seed=seed, network=SettingsConstants.REGTEST)
    assert parser.destination_addresses[0].startswith("tsp1")
