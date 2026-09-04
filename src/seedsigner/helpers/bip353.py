"""BIP-353 payment names, validated on the device rather than trusted from the coordinator.

A BIP-353 name looks like an email address, `rob@silentpayments.net`, and resolves through DNS
to the payment instructions behind it. The sending wallet does that lookup and puts both the name
and an RFC 9102 DNSSEC proof of the answer into the PSBT, as PSBT_OUT_DNSSEC_PROOF (key 0x35).

Every hardware signer shipping today throws that field away. Checking it here is the whole point
of this module, and it matters most for the silent payments case: a BIP-352 output is derived from
the recipient's keys and the sender's inputs, so the `sp1...` string the user typed appears nowhere
on chain and there is no address on the review screen for a human to compare against anything. A
validated name is the only check that exists at all.

What "validated" has to mean here, in order:

1. The DNSSEC chain verifies from the DNS root trust anchor down to the record, using only bytes
   carried in the PSBT. The coordinator is transport. It cannot make this succeed wrongly, because
   it holds no key that chains to the root, though it can certainly make it fail.
2. The record obeys BIP-353: exactly one TXT under `<user>._bitcoin-payment.<domain>` beginning,
   case-insensitively, with `bitcoin:`. Two of them is specified as invalid rather than as a
   preference, because otherwise an attacker who can add a record chooses which one you pay.
3. The instructions in that record are the instructions being paid. This is the step the proof
   itself does not give you: a perfectly valid proof for `alice@example.com` says nothing about
   the output in front of you unless somebody compares them. Skipping it is one of the four gaps
   written up in bitcoin/bips#2272.
4. The signatures are current, which needs a clock the device does not have. See below.

**The clock.** A SeedSigner has no RTC and the kernel has it compiled out, so every boot starts at
a hardcoded date. Real DNSSEC signature windows are short -- measured across eight zones, 1.2 to 13
days, with Cloudflare-hosted zones such as silentpayments.net at the bottom of that range -- so
"ignore freshness on a device with no clock" is not available to us. The device gets its date from
a timecode QR scanned off a second screen, and if it has not been given one then the honest answer
is that the name was NOT verified, said as loudly as a success would be said. Three outcomes stay
distinct and must never be collapsed into two: verified against a known time, proof expired, and no
date available.

The validator is `pydnssec_prover`, pinned by commit in the device image the same way embit is,
and imported late so that an image whose pin has drifted still boots and still signs.
"""

import re

from seedsigner.models.settings_definition import SettingsConstants


# BIP-353 puts the proof in a per-output PSBT field. embit does not model key 0x35, so it lands in
# the output's `unknown` dict, which is exactly where an unrecognised field belongs, and embit
# writes it back out untouched.
PSBT_OUT_DNSSEC_PROOF = b"\x35"

# BIP-353: the record lives at <user>.user._bitcoin-payment.<domain>. The literal `user` label in
# the middle is easy to drop when reading the BIP quickly, and dropping it produces a validator
# that resolves nothing while looking entirely correct.
BIP353_LABELS = "user._bitcoin-payment"

# The BIP allows treating a proof as current for up to an hour past its expiry, and only to absorb
# the delay between building a PSBT and signing it. That delay is precisely our case: the user
# scans a timecode, then walks the review screens. An hour is the ceiling the BIP names, so it is
# used as-is rather than invented.
EXPIRY_GRACE_SECONDS = 3600

BITCOIN_URI_PREFIX = "bitcoin:"


class Status:
    """What the review screen has to say. Ordered by how much the user needs to notice it."""

    VERIFIED = "verified"
    OUTPUT_MISMATCH = "output_mismatch"
    CHAIN_INVALID = "chain_invalid"
    RECORD_INVALID = "record_invalid"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    NO_CLOCK = "no_clock"
    UNAVAILABLE = "unavailable"


class Result:
    """The outcome of checking one output's proof.

    `status` is the only field a caller may branch on. Everything else is for display and may be
    None, including on success -- a verified proof still has no `expires` to show if the record
    somehow carried no signature window, and the screen must cope rather than crash.
    """

    def __init__(self, status, hrn=None, uri=None, sp_address=None,
                 valid_from=None, expires=None, detail=None, backend=None):
        self.status = status
        self.hrn = hrn
        self.uri = uri
        self.sp_address = sp_address
        self.valid_from = valid_from
        self.expires = expires
        self.detail = detail
        self.backend = backend

    @property
    def is_verified(self):
        return self.status == Status.VERIFIED

    def __repr__(self):
        return "<bip353.Result %s hrn=%r detail=%r>" % (self.status, self.hrn, self.detail)


def is_available():
    """Whether this image can validate a proof at all.

    Same contract as `silent_payments.is_available()`: a missing optional dependency must produce a
    device that boots and signs without the feature, never one that will not start. The device's
    pydnssec_prover comes from a Buildroot package and the desktop's from requirements.txt, and
    those two pins can drift apart.
    """
    try:
        _validator_imports()
    except ImportError:
        return False
    return True


def _validator_imports():
    """The pydnssec_prover pieces, imported late and never at module scope."""
    from pydnssec_prover.crypto import ECDSA_BACKEND
    from pydnssec_prover.rr import Name, Txt, parse_rr_stream
    from pydnssec_prover.validation import verify_rr_stream, ValidationError

    return ECDSA_BACKEND, Name, Txt, parse_rr_stream, verify_rr_stream, ValidationError


def read_proof(output):
    """Pull (human readable name, RFC 9102 chain) out of one PSBT output, or None.

    The field value is `<1-byte length><name without the leading bitcoin sign><chain>`. The name is
    returned as text because everything downstream, including the screen, wants it that way; a name
    that is not valid UTF-8 is treated as no proof at all rather than as a proof to argue with.
    """
    value = getattr(output, "unknown", {}).get(PSBT_OUT_DNSSEC_PROOF)
    if not value:
        return None

    name_len = value[0]
    if name_len == 0 or len(value) < 1 + name_len:
        return None

    try:
        hrn = value[1:1 + name_len].decode("utf-8")
    except UnicodeDecodeError:
        return None

    chain = value[1 + name_len:]
    if not chain:
        return None

    return hrn, chain


def dns_name_for(hrn):
    """`user@domain` becomes the fully qualified `user.user._bitcoin-payment.domain.`, or None.

    Deliberately strict about structure and permissive about content. A name with two at-signs or
    an empty half is not a BIP-353 name, and guessing what somebody meant is not a thing to do on
    the screen where money is authorised. Dots inside the user part are allowed, because they are
    allowed: BIP-353's own example `a.x_domain_cname_wild@dnssec_proof_tests.bitcoin.ninja` has
    one, and it simply becomes two DNS labels.

    Non-ASCII is refused rather than punycoded. BIP-353 requires such names to be encoded already,
    and a signing device that quietly transliterates a name is a homograph attack waiting to be
    displayed as verified.
    """
    if hrn.count("@") != 1:
        return None

    user, domain = hrn.split("@")
    if not user or not domain:
        return None

    label = r"^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)*$"
    if not re.match(label, user) or not re.match(label, domain.rstrip(".")):
        return None

    return "%s.%s.%s." % (user, BIP353_LABELS, domain.rstrip("."))


def _payment_uri(txt_records):
    """The one `bitcoin:` URI among the TXT records, or (None, reason).

    BIP-353 says a name resolving to more than one such record is invalid, full stop. That is not
    fussiness: if two are tolerated and a wallet picks one, then whoever can add a record to the
    zone gets to choose which instructions are paid, and the proof still validates perfectly.
    """
    candidates = []
    for data in txt_records:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            # Not a payment record. BIP-353 says to ignore records that are not ours.
            continue
        if text[:len(BITCOIN_URI_PREFIX)].lower() == BITCOIN_URI_PREFIX:
            candidates.append(text)

    if not candidates:
        return None, "no bitcoin: record under this name"
    if len(candidates) > 1:
        return None, "%d bitcoin: records under this name, BIP-353 requires exactly one" % len(candidates)
    return candidates[0], None


def silent_payment_address_from_uri(uri):
    """The `sp=` parameter of a BIP-321 URI, or None if it carries no silent payment address.

    A name may legitimately offer several rails at once -- an on-chain address, a BOLT 12 offer, a
    silent payment address -- and the sender's wallet chooses. Only the silent payment one can be
    checked against a BIP-352 output, so only that one is read here.
    """
    if "?" not in uri:
        return None

    for pair in uri.split("?", 1)[1].split("&"):
        if "=" not in pair:
            continue
        key, _, value = pair.partition("=")
        if key.lower() == "sp" and value:
            return value
    return None


def _matches_output(sp_address, sp_data, network):
    """Is the address the proof vouches for the one this output actually pays?

    Compared as keys rather than as strings. PSBT_OUT_SP_V0_INFO carries the scan and spend public
    keys directly (BIP-375), and the address is just those two keys in bech32m, so decoding and
    comparing the keys avoids caring how either side chose to spell them.

    The network is checked separately and on the string, because the keys are identical across
    chains: without this, a proof for a testnet name would vouch for a mainnet payment to the same
    recipient, which is a real difference in what the user is agreeing to.
    """
    from embit.silent_payments.sp import decode_silent_payment_address

    expected_hrp = "sp1" if network == SettingsConstants.MAINNET else "tsp1"
    if not sp_address.lower().startswith(expected_hrp):
        return False, "the proof is for a %s address, this is a %s transaction" % (
            "mainnet" if expected_hrp == "sp1" else "test network",
            "mainnet" if network == SettingsConstants.MAINNET else "test network")

    try:
        scan_key, spend_key = decode_silent_payment_address(sp_address)
    except Exception as e:
        return False, "the address in the proof could not be read: %s" % e

    if scan_key.sec() != sp_data.scan_key.sec() or spend_key.sec() != sp_data.spend_key.sec():
        return False, "the proof vouches for a different recipient than this output pays"

    return True, None


def verify(hrn, chain, now, sp_data=None, network=None):
    """Check one proof end to end and say what the screen should say.

    `now` is unix seconds, or None when the device has not been given a date. None is a distinct
    answer, not a reason to skip the check: the chain is still validated and still bound to the
    output, and only the freshness question is left unanswered.
    """
    try:
        backend, Name, Txt, parse_rr_stream, verify_rr_stream, ValidationError = _validator_imports()
    except ImportError as e:
        return Result(Status.UNAVAILABLE, hrn=hrn,
                      detail="this image cannot validate DNSSEC proofs: %s" % e)

    query_name = dns_name_for(hrn)
    if query_name is None:
        return Result(Status.RECORD_INVALID, hrn=hrn, backend=backend,
                      detail="%r is not a valid BIP-353 name" % hrn)

    # 1. The cryptography, before anything else. A bogus chain is a stronger and more useful
    #    statement than "no date available", so it must not be masked by a missing clock.
    try:
        verified = verify_rr_stream(parse_rr_stream(chain))
    except ValidationError as e:
        return Result(Status.CHAIN_INVALID, hrn=hrn, backend=backend,
                      detail="the DNSSEC chain did not validate: %s" % e)
    except Exception as e:
        # A malformed stream is a refusal, not a crash screen.
        return Result(Status.CHAIN_INVALID, hrn=hrn, backend=backend,
                      detail="the proof could not be read: %s" % e)

    valid_from = getattr(verified, "valid_from", None)
    expires = getattr(verified, "expires", None)

    # 2. The BIP-353 rules on top of the chain.
    txt_records = [rr.data for rr in verified.resolve_name(Name(query_name)) if isinstance(rr, Txt)]
    uri, reason = _payment_uri(txt_records)
    if uri is None:
        return Result(Status.RECORD_INVALID, hrn=hrn, backend=backend,
                      valid_from=valid_from, expires=expires, detail=reason)

    sp_address = silent_payment_address_from_uri(uri)

    # 3. Bind the proof to what is actually being paid.
    if sp_data is not None:
        if sp_address is None:
            return Result(Status.OUTPUT_MISMATCH, hrn=hrn, uri=uri, backend=backend,
                          valid_from=valid_from, expires=expires,
                          detail="this output is a silent payment but the name publishes no sp= address")
        matches, reason = _matches_output(sp_address, sp_data, network)
        if not matches:
            return Result(Status.OUTPUT_MISMATCH, hrn=hrn, uri=uri, sp_address=sp_address,
                          backend=backend, valid_from=valid_from, expires=expires, detail=reason)

    common = dict(hrn=hrn, uri=uri, sp_address=sp_address, backend=backend,
                  valid_from=valid_from, expires=expires)

    # 4. Freshness, last, because it is the only question a missing clock leaves open.
    if now is None:
        return Result(Status.NO_CLOCK,
                      detail="this device has no date, so the age of the proof is unknown", **common)
    if valid_from is not None and now < valid_from:
        return Result(Status.NOT_YET_VALID,
                      detail="the proof is not valid until later than this device's date", **common)
    if expires is not None and now > expires + EXPIRY_GRACE_SECONDS:
        return Result(Status.EXPIRED, detail="the proof has expired", **common)

    return Result(Status.VERIFIED, **common)
