"""BIP-352 silent payments: key derivation and the two strings the device shows.

A silent payment address is built from two keys, not one. The scan key finds
payments meant for you; the spend key moves them. Splitting them is what lets a
watch-only wallet notice an arriving payment without ever being able to spend it,
and it is why the two strings below are very different things:

- the payment address (`sp1…` / `tsp1…`) is public. Give it to anyone.
- the scan key (`spscan1…` / `tspscan1…`) contains the scan PRIVATE key. Anyone
  holding it sees every payment you ever receive. It is not an address and must
  never be presented as one.

Derivation is BIP-352's, matching SeedSigner#769 so the two agree on what a given
seed means:

    scan   m/352h/{coin}h/0h/1h/0
    spend  m/352h/{coin}h/0h/0h/0

The encoding is embit's (`embit.silent_payments`, `embit.descriptor.sp`) rather
than hand-rolled here. An earlier version of this code carried its own bech32m
encoders because the embit release in use had no silent payments support; the
pinned embit does, and re-deriving the published SeedSigner#769 test vectors
against it matches all of them, so the local copies were deleted rather than
maintained in parallel.
"""

from embit import bip32
from embit.descriptor.sp import SPScanKey
from embit.networks import NETWORKS
from embit.silent_payments import generate_silent_payment_address

from seedsigner.helpers.embit_utils import get_embit_network_name
from seedsigner.models.settings_definition import SettingsConstants


# BIP-352 purpose, and the SLIP-44 coin types for the two chains that matter.
PURPOSE = 352
COIN_TYPE__MAINNET = 0
COIN_TYPE__TESTNET = 1


def coin_type_for(network: str) -> int:
    """Testnet, regtest and signet all share SLIP-44 coin type 1."""
    return COIN_TYPE__MAINNET if network == SettingsConstants.MAINNET else COIN_TYPE__TESTNET


def derive_keys(seed_bytes: bytes, network: str):
    """The scan private key and the spend private key for this seed.

    Returns both as private keys. Callers that only need to show something
    public must take `.get_public_key()` themselves, deliberately, so that
    handing out a private key is always a visible act at the call site.
    """
    coin = coin_type_for(network)
    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[get_embit_network_name(network)]["xprv"])
    scan = root.derive("m/%dh/%dh/0h/1h/0" % (PURPOSE, coin)).key
    spend = root.derive("m/%dh/%dh/0h/0h/0" % (PURPOSE, coin)).key
    return scan, spend


def payment_address(seed_bytes: bytes, network: str) -> str:
    """The public `sp1…` / `tsp1…` string. Safe to show, print and scan."""
    scan, spend = derive_keys(seed_bytes, network)
    return generate_silent_payment_address(
        scan, spend.get_public_key(), network=get_embit_network_name(network)
    )


def scan_key(seed_bytes: bytes, network: str) -> str:
    """The `spscan1…` / `tspscan1…` watch key. Contains a PRIVATE key.

    This is what a watch-only wallet imports in order to find your payments.
    Whoever holds it can see every payment you receive, for ever, and cannot be
    stopped without moving to a new seed. Treat it like an xpub, only worse:
    an xpub leaks addresses, this leaks the ability to detect every payment.
    """
    scan, spend = derive_keys(seed_bytes, network)
    return SPScanKey(
        scan, spend.get_public_key(), network=get_embit_network_name(network)
    ).encode()


def scan_key_descriptor(seed_bytes: bytes, network: str, fingerprint: str) -> str:
    """The key expression a coordinator imports, with its origin prefix.

    Sparrow's SeedSigner import path wraps whatever it scans in `sp(...)`, so
    this returns the INNER expression only. Returning a complete `sp(...)`
    descriptor produces `sp(sp(...))` on the other side and is rejected.
    No checksum, for the same reason.
    """
    coin = coin_type_for(network)
    origin = "%dh/%dh/0h" % (PURPOSE, coin)
    return "[%s/%s]%s" % (fingerprint, origin, scan_key(seed_bytes, network))
