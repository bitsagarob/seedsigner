"""BIP-353 proof validation, checked against the proofs BIP-353 itself publishes.

The corpus is the one at bitsaga/services/silentpayments/dnssec-verify/testdata: five example
proofs cut from the BIP, plus live captures from real zones, each carrying the answer the Rust
dnssec-prover gave for it. Two of the five examples are invalid on purpose and for two different
reasons, which is what makes them worth more than any fixture we could write ourselves:

  04-two-bitcoin-txt-INVALID       a cryptographically PERFECT chain that BIP-353 rejects, because
                                   the name carries two `bitcoin:` records instead of one
  05-missing-nsec3-wildcard-INVALID  case 03 with one NSEC3 removed, so a validator that checks
                                   every signature present, and forgets to notice a required
                                   denial-of-existence record is absent, accepts it

Every stored proof is a snapshot and the signatures have long expired, so the clock is pinned
inside each case's own recorded window rather than compared against now. That is the corpus
README's instruction and it is the difference between testing the validator and testing the date.
"""

import json
import os

import pytest

from seedsigner.helpers import bip353
from seedsigner.helpers.bip353 import Status
from seedsigner.models.settings_definition import SettingsConstants


CORPUS_DIR = os.environ.get(
    "PYDNSSEC_CORPUS",
    "/home/rob/apps/bitsaga/services/silentpayments/dnssec-verify/testdata")

def _corpus_present():
    try:
        import pydnssec_prover  # noqa: F401
    except ImportError:
        return False
    return os.path.exists(os.path.join(CORPUS_DIR, "INDEX.json"))


pytestmark = pytest.mark.skipif(
    not _corpus_present(), reason="pydnssec_prover or the proof corpus is unavailable")


def _index():
    with open(os.path.join(CORPUS_DIR, "INDEX.json")) as f:
        return json.load(f)


def _bip353_manifest():
    with open(os.path.join(CORPUS_DIR, "bip353", "manifest.json")) as f:
        return {c["slug"]: c for c in json.load(f)["cases"]}


def _window(case_name):
    """The recorded RRSIG window for one corpus case, so the clock can be pinned inside it"""
    for case in _index()["cases"]:
        if case["case"] == case_name:
            # Live captures record the window at the top level; the BIP's examples only carry it
            # under the oracle's answer, because they were never captured, only extracted.
            oracle = case.get("oracle_chain_result", {})
            valid_from = case.get("valid_from", oracle.get("valid_from"))
            expires = case.get("expires", oracle.get("expires"))
            if valid_from is None or expires is None:
                raise KeyError("%s records no signature window" % case_name)
            return valid_from, expires
    raise KeyError(case_name)


def _psbt_field(slug):
    """The whole PSBT_OUT_DNSSEC_PROOF value as the BIP prints it, name prefix and all"""
    with open(os.path.join(CORPUS_DIR, "bip353", slug + ".psbt.bin"), "rb") as f:
        return f.read()


class FakeOutput:
    """Only the attribute read_proof touches. embit puts key 0x35 in `unknown`."""

    def __init__(self, unknown):
        self.unknown = unknown


class FakeSPData:
    """Stands in for embit's SilentPaymentData, which is two public keys and nothing else"""

    def __init__(self, scan_key, spend_key):
        self.scan_key = scan_key
        self.spend_key = spend_key


# ------------------------------------------------------------------ name construction


@pytest.mark.parametrize("hrn,expected", [
    ("matt@mattcorallo.com", "matt.user._bitcoin-payment.mattcorallo.com."),
    ("rob@silentpayments.net", "rob.user._bitcoin-payment.silentpayments.net."),
    # BIP-353's own example: dots in the local part are legal and become extra labels
    ("a.x_domain_cname_wild@dnssec_proof_tests.bitcoin.ninja",
     "a.x_domain_cname_wild.user._bitcoin-payment.dnssec_proof_tests.bitcoin.ninja."),
    # A trailing dot on the domain is the same name
    ("rob@silentpayments.net.", "rob.user._bitcoin-payment.silentpayments.net."),
])
def test_dns_name_matches_the_bip(hrn, expected):
    assert bip353.dns_name_for(hrn) == expected


@pytest.mark.parametrize("hrn", [
    "nobody", "two@at@signs.com", "@nodomain.com", "nouser@", "",
    "rob@silentpayments..net",
    "rob@sil entpayments.net",
    # Non-ASCII must be refused rather than transliterated, or a homograph gets a verified badge
    "rоb@silentpayments.net",
])
def test_malformed_names_are_refused(hrn):
    assert bip353.dns_name_for(hrn) is None


def test_the_live_capture_names_agree_with_our_construction():
    """Cross-check against names captured from real DNS, not against our own reading of the BIP"""
    checked = 0
    for case in _index()["cases"]:
        query = case["query_name"]
        if ".user._bitcoin-payment." not in query:
            continue
        user, _, rest = query.partition(".user._bitcoin-payment.")
        assert bip353.dns_name_for("%s@%s" % (user, rest.rstrip("."))) == query
        checked += 1
    assert checked >= 5, "the corpus did not load"


# ------------------------------------------------------------------ reading the PSBT field


@pytest.mark.parametrize("slug,hrn", sorted((s, c["hrn"]) for s, c in _bip353_manifest().items()))
def test_read_proof_recovers_name_and_chain(slug, hrn):
    field = _psbt_field(slug)
    parsed = bip353.read_proof(FakeOutput({bip353.PSBT_OUT_DNSSEC_PROOF: field}))
    assert parsed is not None
    got_hrn, chain = parsed
    assert got_hrn == hrn
    with open(os.path.join(CORPUS_DIR, "bip353", slug + ".bin"), "rb") as f:
        assert chain == f.read()


@pytest.mark.parametrize("value", [
    b"",                     # absent
    b"\x00" + b"chain",      # zero-length name
    b"\x40" + b"short",      # name longer than the field
    bytes([4]) + b"abcd",    # a name and no chain at all
    bytes([2]) + b"\xff\xfe" + b"chain",  # a name that is not UTF-8
])
def test_unusable_proof_fields_read_as_no_proof(value):
    assert bip353.read_proof(FakeOutput({bip353.PSBT_OUT_DNSSEC_PROOF: value})) is None


def test_an_output_with_no_proof_reads_as_no_proof():
    assert bip353.read_proof(FakeOutput({})) is None
    assert bip353.read_proof(FakeOutput({b"\x99": b"something else"})) is None


# ------------------------------------------------------------------ the BIP's own five examples


@pytest.mark.parametrize("slug", ["01-simple-valid",
                                  "02-override-x-domain-cname-wild-valid",
                                  "03-a-x-domain-cname-wild-valid"])
def test_the_bips_valid_examples_verify(slug):
    hrn, chain = bip353.read_proof(FakeOutput({bip353.PSBT_OUT_DNSSEC_PROOF: _psbt_field(slug)}))
    valid_from, expires = _window("bip353/" + slug)
    result = bip353.verify(hrn, chain, now=(valid_from + expires) // 2)
    assert result.status == Status.VERIFIED, result.detail


def test_two_bitcoin_records_are_refused_even_though_the_chain_is_perfect():
    """BIP-353 case 04. The cryptography is fine; permitting this lets the zone pick your payee."""
    slug = "04-two-bitcoin-txt-INVALID"
    hrn, chain = bip353.read_proof(FakeOutput({bip353.PSBT_OUT_DNSSEC_PROOF: _psbt_field(slug)}))
    valid_from, expires = _window("bip353/" + slug)
    result = bip353.verify(hrn, chain, now=(valid_from + expires) // 2)
    assert result.status == Status.RECORD_INVALID
    assert "BIP-353 allows one" in result.detail


def test_a_missing_wildcard_denial_is_refused_by_the_chain_validator():
    """BIP-353 case 05, byte for byte case 03 with the required NSEC3 taken out"""
    slug = "05-missing-nsec3-wildcard-INVALID"
    hrn, chain = bip353.read_proof(FakeOutput({bip353.PSBT_OUT_DNSSEC_PROOF: _psbt_field(slug)}))
    result = bip353.verify(hrn, chain, now=1754400000)
    assert result.status == Status.CHAIN_INVALID


def test_a_tampered_chain_is_refused():
    """Flipping one byte of a real proof must not still validate"""
    hrn, chain = bip353.read_proof(
        FakeOutput({bip353.PSBT_OUT_DNSSEC_PROOF: _psbt_field("01-simple-valid")}))
    valid_from, expires = _window("bip353/01-simple-valid")
    tampered = chain[:-1] + bytes([chain[-1] ^ 0x01])
    result = bip353.verify(hrn, tampered, now=(valid_from + expires) // 2)
    assert result.status == Status.CHAIN_INVALID


# ------------------------------------------------------------------ the clock


def _live_sp_case():
    """The live silentpayments.net proof, which publishes a real sp= address"""
    name = "live/rob.user._bitcoin-payment.silentpayments.net"
    with open(os.path.join(CORPUS_DIR, name + ".bin"), "rb") as f:
        chain = f.read()
    valid_from, expires = _window(name)
    return "rob@silentpayments.net", chain, valid_from, expires


def test_no_date_is_its_own_answer_and_not_a_failure_or_a_pass():
    hrn, chain, _, _ = _live_sp_case()
    result = bip353.verify(hrn, chain, now=None)
    assert result.status == Status.NO_CLOCK
    # The name and the instructions are still known; only their age is not
    assert result.hrn == hrn
    assert result.status != Status.EXPIRED


def test_an_expired_proof_is_expired_and_not_merely_undated():
    hrn, chain, _, expires = _live_sp_case()
    result = bip353.verify(hrn, chain, now=expires + bip353.EXPIRY_GRACE_SECONDS + 1)
    assert result.status == Status.EXPIRED


def test_the_hour_of_grace_the_bip_allows_is_honoured():
    hrn, chain, _, expires = _live_sp_case()
    assert bip353.verify(hrn, chain, now=expires + 60).status == Status.VERIFIED
    assert bip353.verify(hrn, chain,
                         now=expires + bip353.EXPIRY_GRACE_SECONDS - 60).status == Status.VERIFIED


def test_a_proof_from_the_future_is_refused():
    hrn, chain, valid_from, _ = _live_sp_case()
    result = bip353.verify(hrn, chain, now=valid_from - 1)
    assert result.status == Status.NOT_YET_VALID


# ------------------------------------------------------------------ binding to the output


LIVE_SP_ADDRESS = ("sp1qqg94rylj0uklf6lkyc5n92jp3p392g0rpvh0f74qphufxcx9zya97"
                   "qh8w4z290qym8ve33a02ejfc3lanvw9aljfz6upuc2gfnulepd75ccrhdql")


def test_the_uri_gives_up_its_silent_payment_address():
    hrn, chain, valid_from, expires = _live_sp_case()
    result = bip353.verify(hrn, chain, now=(valid_from + expires) // 2)
    assert result.status == Status.VERIFIED
    assert result.sp_address == LIVE_SP_ADDRESS


def _sp_data_for(address):
    from embit.silent_payments.sp import decode_silent_payment_address
    return FakeSPData(*decode_silent_payment_address(address))


def test_a_proof_matching_the_output_verifies():
    hrn, chain, valid_from, expires = _live_sp_case()
    result = bip353.verify(hrn, chain, now=(valid_from + expires) // 2,
                           sp_data=_sp_data_for(LIVE_SP_ADDRESS),
                           network=SettingsConstants.MAINNET)
    assert result.status == Status.VERIFIED, result.detail


def test_a_proof_for_somebody_else_is_refused():
    """The attack this whole module exists to stop: a real, valid proof for the wrong recipient

    A silent payment output is derived, so it appears on no screen anywhere. Without this check the
    user reads a correctly verified name and pays a different person entirely.
    """
    from embit import ec
    from embit.silent_payments.sp import (decode_silent_payment_address,
                                          encode_silent_payment_address)

    scan_key, _ = decode_silent_payment_address(LIVE_SP_ADDRESS)
    other_spend = ec.PrivateKey(b"\x11" * 32).get_public_key()
    other = encode_silent_payment_address(scan_key, other_spend, network="main")

    hrn, chain, valid_from, expires = _live_sp_case()
    result = bip353.verify(hrn, chain, now=(valid_from + expires) // 2,
                           sp_data=_sp_data_for(other),
                           network=SettingsConstants.MAINNET)
    assert result.status == Status.OUTPUT_MISMATCH
    assert "different recipient" in result.detail


def test_a_mainnet_proof_does_not_vouch_for_a_testnet_payment():
    hrn, chain, valid_from, expires = _live_sp_case()
    result = bip353.verify(hrn, chain, now=(valid_from + expires) // 2,
                           sp_data=_sp_data_for(LIVE_SP_ADDRESS),
                           network=SettingsConstants.TESTNET)
    assert result.status == Status.OUTPUT_MISMATCH


def test_a_name_with_no_sp_address_cannot_vouch_for_a_silent_payment_output():
    """BIP-353 case 01 publishes an on-chain address only, so it says nothing about an SP output"""
    slug = "01-simple-valid"
    hrn, chain = bip353.read_proof(FakeOutput({bip353.PSBT_OUT_DNSSEC_PROOF: _psbt_field(slug)}))
    valid_from, expires = _window("bip353/" + slug)
    result = bip353.verify(hrn, chain, now=(valid_from + expires) // 2,
                           sp_data=_sp_data_for(LIVE_SP_ADDRESS),
                           network=SettingsConstants.MAINNET)
    assert result.status == Status.OUTPUT_MISMATCH
    assert "no sp= address" in result.detail


def test_a_mismatch_outranks_a_missing_clock():
    """An undated device must still refuse a proof for the wrong recipient, and say which it is"""
    hrn, chain, _, _ = _live_sp_case()
    from embit import ec
    from embit.silent_payments.sp import (decode_silent_payment_address,
                                          encode_silent_payment_address)
    scan_key, _unused = decode_silent_payment_address(LIVE_SP_ADDRESS)
    other = encode_silent_payment_address(
        scan_key, ec.PrivateKey(b"\x22" * 32).get_public_key(), network="main")

    result = bip353.verify(hrn, chain, now=None, sp_data=_sp_data_for(other),
                           network=SettingsConstants.MAINNET)
    assert result.status == Status.OUTPUT_MISMATCH


# ------------------------------------------------------------------ URI parsing


@pytest.mark.parametrize("uri,expected", [
    ("bitcoin:?sp=sp1qq", "sp1qq"),
    ("bitcoin:?lno=lno1abc&sp=sp1qq&creq=X", "sp1qq"),
    ("bitcoin:?SP=sp1qq", "sp1qq"),
    ("bitcoin:bc1qexample", None),
    ("bitcoin:?lno=lno1abc", None),
    ("bitcoin:?sp=", None),
])
def test_silent_payment_address_from_uri(uri, expected):
    assert bip353.silent_payment_address_from_uri(uri) == expected
