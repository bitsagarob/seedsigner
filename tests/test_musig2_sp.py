"""A silent payment from a MuSig2 key path, with nobody holding the input's key.

The captured 2-of-3 from tests/data/musig2_psbts.json is turned into a BIP-375
send: same coin, same arrangement, but the output is a silent payment address
whose script nobody can write down until every signer has contributed a share.

The oracle for the whole thing is the sender BIP-352 describes: one party holding
the aggregate private key outright. That key exists in a test because both seeds
are known here, and it must never exist on a device. If the shares from two
signers did not rebuild exactly the output that key produces, the recipient
would never find the money.
"""

import json
import os

import pytest
from embit import bip32, bip39
from embit.psbt import PSBT
from embit.script import Script
from embit.silent_payments.psbt import SilentPaymentsPSBT, SilentPaymentData
from embit.silent_payments.sp import derive_sp_outputs, group_sp_outputs_by_scan_key

from seedsigner.helpers import musig2 as m
from seedsigner.helpers import musig2_psbt as mp
from seedsigner.helpers import musig2_session as ms
from seedsigner.helpers import musig2_sp
from seedsigner.helpers import silent_payments
from seedsigner.models.settings_definition import SettingsConstants

FIXTURE = os.path.join(os.path.dirname(__file__), "data", "musig2_psbts.json")

pytestmark = pytest.mark.skipif(
    not silent_payments.is_available(),
    reason="installed embit has no BIP-352 support (needs embit#145)",
)


@pytest.fixture(scope="module")
def data():
    with open(FIXTURE) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def roots(data):
    return {name: bip32.HDKey.from_seed(bip39.mnemonic_to_seed(data["mnemonics"][name]))
            for name in "ABC"}


@pytest.fixture(scope="module")
def recipient(data):
    """Seed C's silent payment keys. C is the co-signer who does not take part."""
    scan, spend = silent_payments.derive_keys(
        bip39.mnemonic_to_seed(data["mnemonics"]["C"]), SettingsConstants.REGTEST)
    return scan, spend


def silent_send(data, recipient):
    """The captured spend, re-addressed to a silent payment, as PSBTv2.

    Core's nonce is dropped: both signers are driven here, and a nonce made for
    the old message would be meaningless for the new one anyway."""
    v0 = PSBT.from_string(data["psbt_round_one"])
    psbt = SilentPaymentsPSBT.parse(v0.serialize())
    psbt.version = 2
    psbt.tx_version = v0.tx.version
    psbt.locktime = v0.tx.locktime
    for scope in psbt.inputs:
        for key in [k for k in scope.unknown if k and k[0] == mp.FIELD_PUBNONCE]:
            del scope.unknown[key]
    assert len(psbt.outputs) == 1
    out = psbt.outputs[0]
    out.script_pubkey = None
    scan, spend = recipient
    out.sp_data = SilentPaymentData(scan.get_public_key(), spend.get_public_key())
    return SilentPaymentsPSBT.parse(psbt.serialize())


def keypath(psbt, root):
    return next(r for r in mp.roles_for_root(psbt, root) if r.is_keypath)


def single_holder_scripts(psbt, roots):
    """What BIP-352's sender computes with the aggregate private key in hand."""
    role_a, role_b = keypath(psbt, roots["A"]), keypath(psbt, roots["B"])
    assert role_a.participants == role_b.participants
    Q, gacc, tacc = m.key_agg_and_tweak(role_a.participants, role_a.tweaks, role_a.is_xonly)
    total = 0
    for role, root in ((role_a, roots["A"]), (role_b, roots["B"])):
        d = m.int_from_bytes(root.derive(role.my_derivation).key.secret)
        total += m.key_agg_coeff(role.participants, role.my_pubkey) * d
    d_q = (gacc * total + tacc) % m.n
    a = d_q if m.has_even_y(Q) else m.n - d_q
    assert m.point_mul_base(a) == m.lift_x(m.xbytes(Q))

    groups, indices = group_sp_outputs_by_scan_key(psbt.outputs)
    _, _, results = derive_sp_outputs([m.bytes_from_int(a)],
                                      [inp.vin for inp in psbt.inputs], groups)
    return {idx: Script(b"\x51\x20" + outs[pos])
            for sk, (_, outs) in results.items()
            for pos, idx in enumerate(indices[sk])}


def contribute_both(psbt, roots):
    for name in "AB":
        role = keypath(psbt, roots[name])
        secret = roots[name].derive(role.my_derivation).key.secret
        for scan_key in musig2_sp.scan_keys(psbt):
            musig2_sp.contribute(psbt, role, secret, scan_key)


def test_the_send_survives_the_wire(data, recipient):
    psbt = silent_send(data, recipient)
    assert psbt.version == 2
    assert musig2_sp.scripts_missing(psbt)
    assert len(musig2_sp.scan_keys(psbt)) == 1
    assert mp.has_musig2_fields(psbt)


def test_two_shares_rebuild_the_single_holder_output(data, roots, recipient):
    psbt = silent_send(data, recipient)
    with pytest.raises(musig2_sp.SharesIncomplete):
        musig2_sp.expected_output_scripts(psbt)

    contribute_both(psbt, roots)
    got = musig2_sp.expected_output_scripts(psbt)
    want = single_holder_scripts(psbt, roots)
    assert {k: bytes(v.data) for k, v in got.items()} == \
        {k: bytes(v.data) for k, v in want.items()}


def test_the_shares_survive_the_wire_too(data, roots, recipient):
    psbt = silent_send(data, recipient)
    contribute_both(psbt, roots)
    again = SilentPaymentsPSBT.parse(psbt.serialize())
    assert {k: bytes(v.data) for k, v in musig2_sp.expected_output_scripts(again).items()} == \
        {k: bytes(v.data) for k, v in single_holder_scripts(psbt, roots).items()}


def test_a_share_without_a_valid_proof_is_refused(data, roots, recipient):
    psbt = silent_send(data, recipient)
    contribute_both(psbt, roots)
    role = keypath(psbt, roots["A"])
    scan_key = musig2_sp.scan_keys(psbt)[0]
    scope = psbt.inputs[role.input_index]
    key = bytes([musig2_sp.FIELD_PARTIAL_PROOF]) + scan_key + role.my_pubkey

    proof = bytearray(scope.unknown[key])
    proof[40] ^= 0x01
    scope.unknown[key] = bytes(proof)
    with pytest.raises(mp.Musig2Error):
        musig2_sp.expected_output_scripts(psbt)

    del scope.unknown[key]
    with pytest.raises(mp.Musig2Error):
        musig2_sp.expected_output_scripts(psbt)


def test_a_share_from_the_wrong_key_is_refused_even_with_its_own_proof(data, roots, recipient):
    """The attack: a co-signer sends money to an output only they can find.

    Their share is made with some other key, and it comes with a perfectly
    good proof for that other key. It must fail against the key they are
    filed under, which is the one that actually locks the coin."""
    psbt = silent_send(data, recipient)
    contribute_both(psbt, roots)
    role = keypath(psbt, roots["A"])
    scan_key = musig2_sp.scan_keys(psbt)[0]
    scope = psbt.inputs[role.input_index]

    rogue = os.urandom(32)
    from embit.silent_payments.sp import _tweak_mul
    from embit.silent_payments.dleq import generate_dleq_proof
    scope.unknown[bytes([musig2_sp.FIELD_PARTIAL_SHARE]) + scan_key + role.my_pubkey] = \
        _tweak_mul(scan_key, rogue)
    scope.unknown[bytes([musig2_sp.FIELD_PARTIAL_PROOF]) + scan_key + role.my_pubkey] = \
        generate_dleq_proof(rogue, scan_key, r=os.urandom(32))
    with pytest.raises(mp.Musig2Error):
        musig2_sp.expected_output_scripts(psbt)


def partial_sig_agg(psigs, session_ctx):
    """BIP-327's coordinator step, which the device never runs."""
    (Q, _, tacc, _, R, e) = m.get_session_values(session_ctx)
    s = sum(m.int_from_bytes(p) for p in psigs) % m.n
    g = 1 if m.has_even_y(Q) else m.n - 1
    s = (s + e * g * tacc) % m.n
    return m.xbytes(R) + m.bytes_from_int(s)


def test_three_rounds_end_in_a_signature_the_coin_accepts(data, roots, recipient):
    """Shares, nonces, partial signatures, from two seeds with nothing shared
    but the PSBT. The aggregated signature is checked against the output key
    on the coin, with the sighash of the transaction whose output was built
    from the shares."""
    psbt = silent_send(data, recipient)
    sessions = {name: ms.Musig2Session() for name in "AB"}

    for name in "AB":
        progress = ms.advance(psbt, roots[name], sessions[name])
        assert progress.stage == ms.SHARES
        assert len(sessions[name]) == 0, "round zero holds no secret"

    # The coordinator's only job: write the script the shares give.
    for idx, script in musig2_sp.expected_output_scripts(psbt).items():
        psbt.outputs[idx].script_pubkey = script
    psbt = SilentPaymentsPSBT.parse(psbt.serialize())
    assert not musig2_sp.scripts_missing(psbt)

    for name in "AB":
        assert ms.advance(psbt, roots[name], sessions[name]).stage == ms.ROUND_ONE
    for name in "AB":
        assert ms.advance(psbt, roots[name], sessions[name]).stage == ms.SIGNED
        assert len(sessions[name]) == 0

    role = keypath(psbt, roots["A"])
    msg = mp.sighash_for(psbt, role)
    sigs = mp.scope_fields(psbt.inputs[role.input_index], mp.FIELD_PARTIAL_SIG)
    psigs = [sigs[pk + role.agg_id] for pk in role.participants]
    ctx = m.SessionContext(m.nonce_agg(mp.pubnonces(psbt, role)), role.participants,
                           role.tweaks, role.is_xonly, msg)
    signature = partial_sig_agg(psigs, ctx)

    from embit import ec
    output_key = psbt.inputs[role.input_index].utxo.script_pubkey.data[2:]
    assert ec.PublicKey.parse(b"\x02" + output_key).schnorr_verify(
        ec.SchnorrSig.parse(signature), msg)


def test_a_wrong_script_stops_the_signer_before_the_nonce(data, roots, recipient):
    """The coordinator wrote a different output. No nonce may leave the device."""
    psbt = silent_send(data, recipient)
    sessions = {name: ms.Musig2Session() for name in "AB"}
    for name in "AB":
        ms.advance(psbt, roots[name], sessions[name])
    psbt.outputs[0].script_pubkey = Script(b"\x51\x20" + os.urandom(32))
    psbt = SilentPaymentsPSBT.parse(psbt.serialize())

    with pytest.raises(mp.Musig2Error):
        ms.advance(psbt, roots["A"], sessions["A"])
    assert len(sessions["A"]) == 0
    assert not mp.scope_fields(psbt.inputs[0], mp.FIELD_PUBNONCE)


def test_an_ordinary_musig2_spend_is_untouched(data, roots):
    """No silent payment output, no extra round: the two-round flow as before."""
    psbt = PSBT.from_string(data["psbt_round_one"])
    assert musig2_sp.scan_keys(psbt) == []
    assert not musig2_sp.scripts_missing(psbt)
    assert ms.advance(psbt, roots["B"], ms.Musig2Session()).stage == ms.ROUND_ONE
