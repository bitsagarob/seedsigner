"""MuSig2, checked against BIP-327's own published test vectors.

`tests/data/musig2_vectors/` is copied unmodified from the BIP's `vectors/`
directory, and the cases below are the BIP's own test harness re-pointed at our
port. That is deliberate: the value of this file is that it is not our idea of
what correct looks like.

The error cases earn their place more than the valid ones. MuSig2 fails silently
when it fails at all -- a wrong aggregation coefficient, a mishandled point at
infinity or a nonce from the wrong signer all still produce 32 plausible bytes.
The vectors name which signer contributed the bad value and what was wrong with
it, so a port that merely refuses everything scores no better than one that
accepts everything.

`det_sign_vectors.json` and `sig_agg_vectors.json` are present but unused: they
cover `deterministic_sign` and `partial_sig_agg`, neither of which the device
carries. Delete neither, and add the cases when the functions arrive.
"""

import json
import os

import pytest

from seedsigner.helpers import musig2 as m

VECTORS = os.path.join(os.path.dirname(__file__), "data", "musig2_vectors")


def load(name):
    with open(os.path.join(VECTORS, name)) as f:
        return json.load(f)


def unhex(xs):
    return [bytes.fromhex(x) for x in xs]


def expect_error(test_case):
    """Turn a vector's `error` block into (exception type, predicate)."""
    error = test_case["error"]
    if error["type"] == "invalid_contribution":
        if "contrib" in error:
            return m.InvalidContributionError, (
                lambda e: e.signer == error["signer"] and e.contrib == error["contrib"])
        return m.InvalidContributionError, (lambda e: e.signer == error["signer"])
    if error["type"] == "value":
        return ValueError, (lambda e: str(e) == error["message"])
    raise RuntimeError("unknown error type: %s" % error["type"])


def assert_raises(test_case, fn):
    exception, matches = expect_error(test_case)
    with pytest.raises(exception) as excinfo:
        fn()
    assert matches(excinfo.value), "right exception, wrong detail: %r" % (excinfo.value,)


def test_key_agg_vectors():
    data = load("key_agg_vectors.json")
    X, T = unhex(data["pubkeys"]), unhex(data["tweaks"])

    for case in data["valid_test_cases"]:
        pubkeys = [X[i] for i in case["key_indices"]]
        assert m.get_xonly_pk(m.key_agg(pubkeys)) == bytes.fromhex(case["expected"])

    for case in data["error_test_cases"]:
        pubkeys = [X[i] for i in case["key_indices"]]
        tweaks = [T[i] for i in case["tweak_indices"]]
        assert_raises(case, lambda: m.key_agg_and_tweak(pubkeys, tweaks, case["is_xonly"]))


def test_nonce_gen_vectors():
    for case in load("nonce_gen_vectors.json")["test_cases"]:
        get = lambda k: bytes.fromhex(case[k])
        maybe = lambda k: get(k) if case[k] is not None else None
        assert m.nonce_gen_internal(
            get("rand_"), maybe("sk"), get("pk"), maybe("aggpk"),
            maybe("msg"), maybe("extra_in"),
        ) == (bytearray(get("expected_secnonce")), get("expected_pubnonce"))


def test_nonce_agg_vectors():
    data = load("nonce_agg_vectors.json")
    pnonce = unhex(data["pnonces"])

    for case in data["valid_test_cases"]:
        pubnonces = [pnonce[i] for i in case["pnonce_indices"]]
        assert m.nonce_agg(pubnonces) == bytes.fromhex(case["expected"])

    for case in data["error_test_cases"]:
        pubnonces = [pnonce[i] for i in case["pnonce_indices"]]
        assert_raises(case, lambda: m.nonce_agg(pubnonces))


def test_sign_verify_vectors():
    data = load("sign_verify_vectors.json")
    sk = bytes.fromhex(data["sk"])
    X = unhex(data["pubkeys"])
    assert X[0] == m.individual_pk(sk), "vector's key 0 is not the one sk makes"

    secnonces = unhex(data["secnonces"])
    pnonce = unhex(data["pnonces"])
    k_1 = m.int_from_bytes(secnonces[0][0:32])
    k_2 = m.int_from_bytes(secnonces[0][32:64])
    assert pnonce[0] == m.cbytes(m.point_mul_base(k_1)) + m.cbytes(m.point_mul_base(k_2))

    aggnonces = unhex(data["aggnonces"])
    assert aggnonces[0] == m.nonce_agg([pnonce[0], pnonce[1], pnonce[2]])
    # index 1 is the point at infinity, encoded as 33 zero bytes
    assert aggnonces[1] == m.nonce_agg([pnonce[0], pnonce[3]])

    msgs = unhex(data["msgs"])

    for case in data["valid_test_cases"]:
        pubkeys = [X[i] for i in case["key_indices"]]
        pubnonces = [pnonce[i] for i in case["nonce_indices"]]
        aggnonce = aggnonces[case["aggnonce_index"]]
        assert m.nonce_agg(pubnonces) == aggnonce
        msg = msgs[case["msg_index"]]
        expected = bytes.fromhex(case["expected"])

        ctx = m.SessionContext(aggnonce, pubkeys, [], [], msg)
        # Copying a secnonce is exactly what production code must never do.
        assert m.sign(bytearray(secnonces[0]), sk, ctx) == expected
        assert m.partial_sig_verify(expected, pubnonces, pubkeys, [], [], msg,
                                    case["signer_index"])

    for case in data["sign_error_test_cases"]:
        pubkeys = [X[i] for i in case["key_indices"]]
        ctx = m.SessionContext(aggnonces[case["aggnonce_index"]], pubkeys, [], [],
                               msgs[case["msg_index"]])
        secnonce = bytearray(secnonces[case["secnonce_index"]])
        assert_raises(case, lambda: m.sign(secnonce, sk, ctx))

    for case in data["verify_fail_test_cases"]:
        assert not m.partial_sig_verify(
            bytes.fromhex(case["sig"]),
            [pnonce[i] for i in case["nonce_indices"]],
            [X[i] for i in case["key_indices"]],
            [], [], msgs[case["msg_index"]], case["signer_index"])

    for case in data["verify_error_test_cases"]:
        assert_raises(case, lambda: m.partial_sig_verify(
            bytes.fromhex(case["sig"]),
            [pnonce[i] for i in case["nonce_indices"]],
            [X[i] for i in case["key_indices"]],
            [], [], msgs[case["msg_index"]], case["signer_index"]))


def test_tweak_vectors():
    """The taproot-shaped cases: x-only tweaks are what BIP-341 needs, and plain
    tweaks are what BIP-328 derivation of an aggregate key turns into."""
    data = load("tweak_vectors.json")
    sk = bytes.fromhex(data["sk"])
    X = unhex(data["pubkeys"])
    assert X[0] == m.individual_pk(sk)

    secnonce = bytearray(bytes.fromhex(data["secnonce"]))
    pnonce = unhex(data["pnonces"])
    k_1 = m.int_from_bytes(bytes(secnonce[0:32]))
    k_2 = m.int_from_bytes(bytes(secnonce[32:64]))
    assert pnonce[0] == m.cbytes(m.point_mul_base(k_1)) + m.cbytes(m.point_mul_base(k_2))

    aggnonce = bytes.fromhex(data["aggnonce"])
    assert aggnonce == m.nonce_agg([pnonce[0], pnonce[1], pnonce[2]])

    tweak = unhex(data["tweaks"])
    msg = bytes.fromhex(data["msg"])

    for case in data["valid_test_cases"]:
        pubkeys = [X[i] for i in case["key_indices"]]
        pubnonces = [pnonce[i] for i in case["nonce_indices"]]
        tweaks = [tweak[i] for i in case["tweak_indices"]]
        is_xonly = case["is_xonly"]
        expected = bytes.fromhex(case["expected"])

        ctx = m.SessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)
        assert m.sign(bytearray(secnonce), sk, ctx) == expected
        assert m.partial_sig_verify(expected, pubnonces, pubkeys, tweaks, is_xonly,
                                    msg, case["signer_index"])

    for case in data["error_test_cases"]:
        pubkeys = [X[i] for i in case["key_indices"]]
        tweaks = [tweak[i] for i in case["tweak_indices"]]
        ctx = m.SessionContext(aggnonce, pubkeys, tweaks, case["is_xonly"], msg)
        assert_raises(case, lambda: m.sign(bytearray(secnonce), sk, ctx))


def test_signing_destroys_the_secnonce():
    """The one safety property that is ours to keep rather than the BIP's to
    state: a secnonce that has been used must not be usable a second time."""
    data = load("sign_verify_vectors.json")
    sk = bytes.fromhex(data["sk"])
    X = unhex(data["pubkeys"])
    pnonce = unhex(data["pnonces"])
    secnonce = bytearray(unhex(data["secnonces"])[0])
    ctx = m.SessionContext(unhex(data["aggnonces"])[0], [X[0], X[1], X[2]], [], [],
                           unhex(data["msgs"])[0])

    m.sign(secnonce, sk, ctx)
    assert bytes(secnonce[0:64]) == b"\x00" * 64
    with pytest.raises(ValueError, match="out of range"):
        m.sign(secnonce, sk, ctx)
