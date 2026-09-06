"""
    The DLEQ proof this firmware ships is BIP-374's, and it has to stay BIP-374's.

    Silent payment shares are proved with embit's generate_dleq_proof and
    verify_dleq_proof. Checked against BIP-374's own 26 test vectors: 25 match byte for
    byte, and the 26th is a failure case whose input is the point at infinity, which
    embit's compressed-pubkey API cannot express and rejects anyway.

    This pins one generate vector and one verify vector so that result cannot rot
    silently. It is not a re-run of the BIP's suite; it is a tripwire on the two calls
    musig2_psbt.py actually makes.

    The tripwire has a specific hazard in mind. embit's signature is

        generate_dleq_proof(a_bytes, B_sec, r=None, m=None, G=None)

    where BIP-374's is dleq_generate_proof(a, B, r, G, m). G and m are swapped, so
    anyone writing a new call site by reading the BIP would pass the message where the
    base point goes.

    Measured rather than assumed: that swap does NOT go silent. A message must be 32
    bytes and a compressed point is 33, so embit raises DLEQError either way round. The
    length difference is doing real work here. It is asserted below so that a future
    embit which relaxes the check, or a curve encoding where the two lengths coincide,
    fails here rather than in the field.
"""
from embit.silent_payments.dleq import generate_dleq_proof, verify_dleq_proof

# BIP-374 test_vectors_generate_proof.csv, index 0, "Success case 1".
# This vector carries a non-standard base point, which is exactly why it catches a
# G/m swap: with the arguments crossed, the proof is computed over the wrong generator.
GEN_G = bytes.fromhex("02cef38f55e78b321a1f785cb1c6e33dfcef9784c18bdc4e279801c449ccdfb88e")
GEN_A = bytes.fromhex("07ff93d43f1012a5d4a44aba55240212ed39c87b3344e46757d99f24177fc576")
GEN_B = bytes.fromhex("02dad4b35c2379ba8334c9a5dda8f6e6d5cd575a7cc9d3ca4faaac51839daaa30f")
GEN_R = bytes.fromhex("cb979b0fc8ccc7f237751e719d992fcc324b6500af33999cd54a3e5c05fb1ea4")
GEN_M = bytes.fromhex("efb07d4b382d3da1079fbf24df623ba6c2e4c764993bbfa6dd7a4fe4aaf33859")
GEN_PROOF = bytes.fromhex(
    "7e7e934169e0bf4706e6b29e5a621c7fe199a524744a25af80071e111c0e2e94"
    "118e730d8add118dd2ee4f7d1cc183e1b87168362d1a6f85c16d8671a3fc7a8a")

# BIP-374 test_vectors_verify_proof.csv, index 0, "Success case 1".
VER_A = bytes.fromhex("02b540b22c2c5ef0dc886abdaad27498453d893265560bc08a187319af6f845f58")
VER_C = bytes.fromhex("03fefe00951dcd0ef10b12523393c2b8113119de4fdeeab320694e96bdccd2775b")


def test_the_proof_is_the_one_bip374_specifies():
    """Byte equality against the BIP's own expected output, not merely 'it returned'."""
    assert generate_dleq_proof(GEN_A, GEN_B, r=GEN_R, m=GEN_M, G=GEN_G) == GEN_PROOF


def test_verification_accepts_the_bips_own_proof():
    assert verify_dleq_proof(VER_A, GEN_B, VER_C, GEN_PROOF, m=GEN_M, G=GEN_G) is True


def test_a_tampered_proof_is_refused():
    tampered = bytearray(GEN_PROOF)
    tampered[0] ^= 0x01
    assert verify_dleq_proof(VER_A, GEN_B, VER_C, bytes(tampered), m=GEN_M, G=GEN_G) is False


def test_the_message_and_the_base_point_are_not_interchangeable():
    """The swap this file exists to catch, and it is refused rather than silent.

    A caller copying BIP-374's positional order passes the message where the base point
    goes. embit rejects it, because a message is 32 bytes and a compressed point is 33.
    If this ever stops raising, the two arguments have become interchangeable and every
    call site needs rereading.
    """
    import pytest
    from embit.silent_payments.dleq import DLEQError

    with pytest.raises(DLEQError):
        generate_dleq_proof(GEN_A, GEN_B, r=GEN_R, m=GEN_G, G=GEN_M)


def test_the_defaults_our_call_sites_rely_on_are_the_standard_ones():
    """musig2_psbt.py omits m and G. That is only correct if the default base point is
    secp256k1's own G, so the omission is checked rather than assumed."""
    from embit.ec import PublicKey

    standard_g = PublicKey.parse(bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
    proof_default = generate_dleq_proof(GEN_A, GEN_B, r=GEN_R)
    proof_explicit = generate_dleq_proof(GEN_A, GEN_B, r=GEN_R, G=standard_g.sec())
    assert proof_default == proof_explicit
