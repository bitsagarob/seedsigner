import re

from seedsigner.models.settings_definition import SettingsConstants


"""
    BIP-353 payment name validation.

    A sending wallet resolves `user@domain` to payment instructions and puts the name and an
    RFC 9102 DNSSEC proof of the answer in the psbt, as PSBT_OUT_DNSSEC_PROOF. This validates
    that proof against the DNS root here rather than trusting the coordinator that sent it.

    It matters most for silent payments: a BIP-352 output is derived, so the sp1 string appears
    nowhere on chain and the review screen has no address to compare. A validated name is the
    only check available.
"""

# embit does not model key 0x35, so it lands in the output's `unknown` dict
PSBT_OUT_DNSSEC_PROOF = b"\x35"

# BIP-353 records live at <user>.user._bitcoin-payment.<domain>
BIP353_LABELS = "user._bitcoin-payment"

# The BIP allows an hour past expiry, to absorb the delay between building a psbt and signing it
EXPIRY_GRACE_SECONDS = 3600

BITCOIN_URI_PREFIX = "bitcoin:"


class Status:
    """
    The outcome of checking one output's proof. See `verify()`.

    Only VERIFIED means the name was checked against a known time. The rest are distinct on
    purpose: an expired proof, a device with no date and a proof for somebody else are three
    different situations and only the last is an attack.
    """

    VERIFIED = "VERIFIED"
    OUTPUT_MISMATCH = "OUTPUT_MISMATCH"
    CHAIN_INVALID = "CHAIN_INVALID"
    RECORD_INVALID = "RECORD_INVALID"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    NO_CLOCK = "NO_CLOCK"
    UNAVAILABLE = "UNAVAILABLE"


class Result:
    """What `verify()` decided, and enough to say why on screen."""

    def __init__(self, status, hrn=None, sp_address=None, detail=None):
        self.status = status
        self.hrn = hrn
        self.sp_address = sp_address
        self.detail = detail

    @property
    def is_verified(self):
        return self.status == Status.VERIFIED

    def __repr__(self):
        return "<bip353.Result %s hrn=%r detail=%r>" % (self.status, self.hrn, self.detail)


# Imported late so a missing pin cannot stop the device booting
def _validator_imports():
    from pydnssec_prover.rr import Name, Txt, parse_rr_stream
    from pydnssec_prover.validation import verify_rr_stream, ValidationError

    return Name, Txt, parse_rr_stream, verify_rr_stream, ValidationError


def read_proof(output):
    """(name, RFC 9102 chain) from one psbt output, or None.

    The field is `<1-byte length><name without the bitcoin sign><chain>`.
    """
    value = output.unknown.get(PSBT_OUT_DNSSEC_PROOF)
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
    """`user@domain` as the fully qualified `user.user._bitcoin-payment.domain.`, or None.

    Dots in the user part are allowed and become extra labels. Non-ASCII is refused rather than
    punycoded, so a homograph cannot be displayed as verified.
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
    """The one `bitcoin:` uri among the records, or (None, reason).

    BIP-353 says more than one is invalid: tolerating it lets whoever can add a record choose
    which instructions get paid.
    """
    candidates = []
    for data in txt_records:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text[:len(BITCOIN_URI_PREFIX)].lower() == BITCOIN_URI_PREFIX:
            candidates.append(text)

    if not candidates:
        return None, "no bitcoin: record under this name"
    if len(candidates) > 1:
        return None, "%d bitcoin: records, BIP-353 allows one" % len(candidates)
    return candidates[0], None


def silent_payment_address_from_uri(uri):
    if "?" not in uri:
        return None

    for pair in uri.split("?", 1)[1].split("&"):
        key, _sep, value = pair.partition("=")
        if key.lower() == "sp" and value:
            return value
    return None


def _matches_output(sp_address, sp_data, network):
    """Whether the address the proof vouches for is the one this output pays.

    Compared as keys, since the address is just those keys in bech32m. The network is checked
    separately and on the string, because the keys are identical across chains.
    """
    from embit.silent_payments.sp import decode_silent_payment_address

    is_mainnet = network == SettingsConstants.MAINNET
    if not sp_address.lower().startswith("sp1" if is_mainnet else "tsp1"):
        return False, "the proof is for a different network"

    try:
        scan_key, spend_key = decode_silent_payment_address(sp_address)
    except Exception as e:
        return False, "the address in the proof could not be read: %s" % e

    if scan_key.sec() != sp_data.scan_key.sec() or spend_key.sec() != sp_data.spend_key.sec():
        return False, "the proof covers a different recipient"

    return True, None


def verify(hrn, chain, now, sp_data=None, network=None):
    """Check one proof and say what the screen should say.

    `now` is unix seconds, or None when the device has not been given a date. None is a distinct
    answer: the chain is still validated and still bound to the output, only freshness is left open.

    `network` is required when `sp_data` is given, since the same keys are valid on either chain.
    """
    if sp_data is not None and network is None:
        raise ValueError("network is required to bind a proof to a silent payment output")

    try:
        Name, Txt, parse_rr_stream, verify_rr_stream, ValidationError = _validator_imports()
    except ImportError as e:
        return Result(Status.UNAVAILABLE, hrn=hrn, detail=str(e))

    query_name = dns_name_for(hrn)
    if query_name is None:
        return Result(Status.RECORD_INVALID, hrn=hrn, detail="not a valid BIP-353 name")

    # The cryptography first: a forged chain is a stronger statement than a missing clock, and
    # must not be masked by one.
    try:
        verified = verify_rr_stream(parse_rr_stream(chain))
    except ValidationError as e:
        return Result(Status.CHAIN_INVALID, hrn=hrn, detail=str(e))
    except Exception as e:
        return Result(Status.CHAIN_INVALID, hrn=hrn, detail="unreadable proof: %s" % e)

    txt_records = [rr.data for rr in verified.resolve_name(Name(query_name)) if isinstance(rr, Txt)]
    uri, reason = _payment_uri(txt_records)
    if uri is None:
        return Result(Status.RECORD_INVALID, hrn=hrn, detail=reason)

    sp_address = silent_payment_address_from_uri(uri)

    if sp_data is not None:
        if sp_address is None:
            return Result(Status.OUTPUT_MISMATCH, hrn=hrn,
                          detail="this name publishes no sp= address")
        matches, reason = _matches_output(sp_address, sp_data, network)
        if not matches:
            return Result(Status.OUTPUT_MISMATCH, hrn=hrn, sp_address=sp_address, detail=reason)

    if now is None:
        return Result(Status.NO_CLOCK, hrn=hrn, sp_address=sp_address)
    if verified.valid_from is not None and now < verified.valid_from:
        return Result(Status.NOT_YET_VALID, hrn=hrn, sp_address=sp_address)
    if verified.expires is not None and now > verified.expires + EXPIRY_GRACE_SECONDS:
        return Result(Status.EXPIRED, hrn=hrn, sp_address=sp_address)

    return Result(Status.VERIFIED, hrn=hrn, sp_address=sp_address)
