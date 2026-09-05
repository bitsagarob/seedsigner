"""
    BIP-352 silent payments: key derivation and the two strings the device shows.

    The payment address (`sp1…`) is public. The scan key (`spscan1…`) contains the scan PRIVATE
    key: whoever holds it sees every payment you receive, so it must never be presented as an
    address.

    Derivation matches SeedSigner#769:
        scan   m/352h/{coin}h/0h/1h/0
        spend  m/352h/{coin}h/0h/0h/0
"""

from embit import bip32
from embit.networks import NETWORKS

from seedsigner.helpers.embit_utils import get_embit_network_name
from seedsigner.models.settings_definition import SettingsConstants


# The image pins embit through Buildroot, requirements.txt pins it for a desktop checkout. If
# they disagree the device should still boot, just without the menu.
def is_available() -> bool:
    try:
        _sp_imports()
    except ImportError:
        return False
    return True


def _sp_imports():
    from embit.descriptor.sp import SPScanKey
    from embit.silent_payments import generate_silent_payment_address

    return SPScanKey, generate_silent_payment_address


# BIP-352 purpose, and the SLIP-44 coin types for the two chains that matter.
PURPOSE = 352
COIN_TYPE__MAINNET = 0
COIN_TYPE__TESTNET = 1


def coin_type_for(network: str) -> int:
    """Testnet, regtest and signet all share SLIP-44 coin type 1."""
    return COIN_TYPE__MAINNET if network == SettingsConstants.MAINNET else COIN_TYPE__TESTNET


def derive_keys(seed_bytes: bytes, network: str):
    """The scan and spend private keys for this seed.

    Callers take `.get_public_key()` themselves, so handing out a private key is visible at the
    call site.
    """
    coin = coin_type_for(network)
    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[get_embit_network_name(network)]["xprv"])
    scan = root.derive("m/%dh/%dh/0h/1h/0" % (PURPOSE, coin)).key
    spend = root.derive("m/%dh/%dh/0h/0h/0" % (PURPOSE, coin)).key
    return scan, spend


def payment_address(seed_bytes: bytes, network: str) -> str:
    """The public `sp1…` / `tsp1…` string. Safe to show, print and scan."""
    _, generate_silent_payment_address = _sp_imports()
    scan, spend = derive_keys(seed_bytes, network)
    return generate_silent_payment_address(
        scan, spend.get_public_key(), network=get_embit_network_name(network)
    )


def scan_key(seed_bytes: bytes, network: str) -> str:
    """The `spscan1…` watch key. Contains a PRIVATE key.

    Whoever holds it sees every payment you receive, for ever, and cannot be stopped without a
    new seed.
    """
    SPScanKey, _ = _sp_imports()
    scan, spend = derive_keys(seed_bytes, network)
    return SPScanKey(
        scan, spend.get_public_key(), network=get_embit_network_name(network)
    ).encode()


def scan_key_descriptor(seed_bytes: bytes, network: str, fingerprint: str) -> str:
    """The key expression a coordinator imports, with its origin prefix.

    Sparrow wraps whatever it scans in `sp(...)`, so this returns the inner expression only, and
    no checksum.
    """
    coin = coin_type_for(network)
    origin = "%dh/%dh/0h" % (PURPOSE, coin)
    return "[%s/%s]%s" % (fingerprint, origin, scan_key(seed_bytes, network))
