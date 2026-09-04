"""A silent payment (BIP-352) from a MuSig2 key path: the round before the nonces.

BIP-352 derives the recipient's output from the sum of the input private keys,
and a taproot input's private key is the one behind its output key. In a MuSig2
key path nobody holds that key. What each signer does hold is their own share of
it, and Diffie-Hellman is linear: if the aggregate is

    a_Q = g * (gacc * sum(mu_i * d_i) + tacc)           (BIP-327 notation)

then a_Q * B_scan is the same combination of the points d_i * B_scan, and every
coefficient in it is public. So each signer contributes d_i * B_scan, and anyone
can put the pieces together.

The piece that is not just arithmetic is trust. A share nobody can check lets one
co-signer steer the money to an output the recipient will never find, which is a
loss of funds and not a privacy leak. So every share travels with a BIP-374 proof
that it was made with the private key of the participant key it is filed under,
and a signer verifies every other share, and the output script built from them,
before it lets a nonce or a partial signature out.

The wire format is the one proposed for exactly this case (macgyver13, "Silent
Payments from a MuSig2 Treasury", 2026), so that a Coldcard on that branch and
this device can sit in the same arrangement:

    PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE  0x21  <scan key><participant key>  <33 byte share>
    PSBT_IN_MUSIG2_PARTIAL_DLEQ        0x22  <scan key><participant key>  <64 byte proof>

The standard BIP-375 per-input share (0x1d) and its proof (0x1e) are deliberately
not written: the proof there has to be made by whoever holds the input's private
key, and here nobody does. Inputs that are not MuSig2 may still carry them, and
they are verified against the input's key like any BIP-375 signer would.

The device never writes the output script itself. The coordinator does, once every
share is in, and every signer checks it. Fewer things that can disagree.
"""

import os
from typing import Dict, List, NamedTuple, Optional, Tuple

from embit import ec
from embit.hashes import hash160
from embit.script import Script
from embit.silent_payments.dleq import generate_dleq_proof, verify_dleq_proof
from embit.silent_payments.sp import (
    _tweak_mul,
    derive_recipient_outputs,
    get_eligible_inputs,
    get_input_hash,
    group_sp_outputs_by_scan_key,
)

from seedsigner.helpers import musig2 as m
from seedsigner.helpers import musig2_psbt as mp

FIELD_PARTIAL_SHARE = 0x21
FIELD_PARTIAL_PROOF = 0x22

# BIP-375's own per-input fields, for inputs that are not MuSig2.
FIELD_INPUT_SHARE = 0x1D
FIELD_INPUT_PROOF = 0x1E


class SharesIncomplete(Exception):
    """A share is still missing. Not an error: the round is not over yet."""


def scan_keys(psbt) -> List[bytes]:
    """Every distinct scan key this transaction pays, as 33 bytes each."""
    groups, _ = _groups(psbt)
    return list(groups)


def scripts_missing(psbt) -> bool:
    """Whether some silent payment output still has no script, i.e. round zero."""
    return any(
        getattr(out, "sp_data", None) is not None
        and (out.script_pubkey is None or len(out.script_pubkey.data) == 0)
        for out in psbt.outputs
    )


def _groups(psbt):
    if not any(getattr(out, "sp_data", None) is not None for out in psbt.outputs):
        return {}, {}
    return group_sp_outputs_by_scan_key(psbt.outputs)


def _key(field_type: int, scan_key: bytes, participant: bytes) -> bytes:
    return bytes([field_type]) + scan_key + participant


def has_share(psbt, role: mp.Musig2Role, scan_key: bytes) -> bool:
    return _key(FIELD_PARTIAL_SHARE, scan_key, role.my_pubkey) in \
        psbt.inputs[role.input_index].unknown


def contribute(psbt, role: mp.Musig2Role, secret_key: bytes, scan_key: bytes) -> None:
    """Round zero for one signer, one input, one scan key.

    The proof's auxiliary randomness is fresh each time, per BIP-374. A proof is
    not a nonce, so reuse would not leak the key, but the specification asks for
    fresh randomness and there is no reason to give it less.
    """
    share = _tweak_mul(scan_key, secret_key)
    proof = generate_dleq_proof(secret_key, scan_key, r=os.urandom(32))
    scope = psbt.inputs[role.input_index]
    scope.unknown[_key(FIELD_PARTIAL_SHARE, scan_key, role.my_pubkey)] = share
    scope.unknown[_key(FIELD_PARTIAL_PROOF, scan_key, role.my_pubkey)] = proof


class InputShare(NamedTuple):
    pubkey: bytes   # 33 bytes, the key BIP-352 sums for this input
    ecdh: bytes     # 33 bytes, that key's private scalar times the scan key


def _musig2_share(scope, agg: mp.Musig2Aggregate, scan_key: bytes) -> InputShare:
    """Put one MuSig2 key path's partial shares together, checking each."""
    Q, gacc, tacc = m.key_agg_and_tweak(agg.participants, agg.tweaks, agg.is_xonly)
    g = 1 if m.has_even_y(Q) else m.n - 1

    acc = None
    for pk in agg.participants:
        share = scope.unknown.get(_key(FIELD_PARTIAL_SHARE, scan_key, pk))
        proof = scope.unknown.get(_key(FIELD_PARTIAL_PROOF, scan_key, pk))
        if share is None:
            raise SharesIncomplete("participant %s has not contributed" % pk.hex()[:8])
        if proof is None or not verify_dleq_proof(pk, scan_key, share, proof):
            raise mp.Musig2Error(
                "the silent payment share from participant %s does not verify"
                % pk.hex()[:8])
        acc = m.point_add(acc, m.point_mul(m.cpoint(share), m.key_agg_coeff(agg.participants, pk)))

    ecdh = m.point_add(m.point_mul(acc, g * gacc % m.n),
                       m.point_mul(m.cpoint(scan_key), g * tacc % m.n))
    if ecdh is None:
        raise mp.Musig2Error("the silent payment shares sum to infinity")
    # BIP-352 sums the taproot output keys with even Y, which is exactly what the
    # g above negated the aggregate towards.
    return InputShare(pubkey=b"\x02" + m.xbytes(Q), ecdh=m.cbytes(ecdh))


def _plain_input_pubkey(scope) -> Optional[bytes]:
    """The key BIP-352 would sum for an ordinary input, or None if not derivable."""
    spk = scope.script_pubkey
    if spk is None:
        return None
    kind = spk.script_type()
    if kind == "p2tr":
        return b"\x02" + bytes(spk.data[2:34])
    for pub in scope.bip32_derivations:
        if hash160(pub.sec()) in bytes(spk.data):
            return pub.sec()
    return None


def _plain_share(scope, scan_key: bytes) -> InputShare:
    share = scope.unknown.get(bytes([FIELD_INPUT_SHARE]) + scan_key)
    proof = scope.unknown.get(bytes([FIELD_INPUT_PROOF]) + scan_key)
    if share is None:
        raise SharesIncomplete("an input without MuSig2 has no silent payment share")
    pubkey = _plain_input_pubkey(scope)
    if pubkey is None or proof is None or not verify_dleq_proof(pubkey, scan_key, share, proof):
        raise mp.Musig2Error("an input's silent payment share does not verify")
    return InputShare(pubkey=pubkey, ecdh=share)


def _input_share(scope, scan_key: bytes) -> InputShare:
    keypath = [a for a in mp.aggregates_on_input(scope) if a.leaf_hash is None]
    if keypath:
        if len(keypath) != 1:
            raise mp.Musig2Error("an input claims more than one key path aggregate")
        agg = keypath[0]
        spk = scope.script_pubkey.data
        tweaked = m.key_agg_and_tweak(agg.participants, agg.tweaks, agg.is_xonly).Q
        if bytes(spk[:2]) != b"\x51\x20" or bytes(spk[2:]) != m.xbytes(tweaked):
            raise mp.Musig2Error("an input's aggregate key does not lock the coin it spends")
        return _musig2_share(scope, agg, scan_key)
    return _plain_share(scope, scan_key)


def expected_output_scripts(psbt) -> Dict[int, Script]:
    """{output index: script} for every silent payment output, from the shares.

    Raises SharesIncomplete while a share is still missing, and Musig2Error for
    anything that fails to verify. Follows BIP-352's sender procedure with the
    private key sum replaced by the verified ECDH sum, as BIP-375 describes.
    """
    groups, output_indices = _groups(psbt)
    if not groups:
        return {}

    scripts = {}
    for sk_bytes, (scan_key, spend_keys) in groups.items():
        A_sum = None
        ecdh_sum = None
        for i in get_eligible_inputs(psbt.inputs):
            share = _input_share(psbt.inputs[i], sk_bytes)
            A_sum = m.point_add(A_sum, m.cpoint(share.pubkey))
            ecdh_sum = m.point_add(ecdh_sum, m.cpoint(share.ecdh))
        if A_sum is None or ecdh_sum is None:
            raise mp.Musig2Error("no input can contribute to the silent payment")

        input_hash = get_input_hash([inp.vin for inp in psbt.inputs], m.cbytes(A_sum))
        outputs = derive_recipient_outputs(_tweak_mul(m.cbytes(ecdh_sum), input_hash),
                                           spend_keys)
        for pos, out_idx in enumerate(output_indices[sk_bytes]):
            scripts[out_idx] = Script(b"\x51\x20" + outputs[pos])
    return scripts


def verify_output_scripts(psbt) -> None:
    """Every silent payment output must carry exactly the script the shares give.

    This is the check that stands between a bad share and a signature. Raises
    Musig2Error on any disagreement, including a script that is still missing.
    """
    try:
        expected = expected_output_scripts(psbt)
    except SharesIncomplete as e:
        raise mp.Musig2Error("silent payment shares are incomplete: %s" % e)
    for out_idx, script in expected.items():
        declared = psbt.outputs[out_idx].script_pubkey
        if declared is None or bytes(declared.data) != bytes(script.data):
            raise mp.Musig2Error(
                "output %d does not pay the silent payment address it claims to" % out_idx)
