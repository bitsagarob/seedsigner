import hmac
import os
from typing import Dict, List, NamedTuple, Optional

from embit.hashes import hash160, sha256, tagged_hash
from embit.script import Script
from embit.transaction import SIGHASH

from seedsigner.helpers import musig2 as m


"""
    MuSig2 signing from a psbt: the BIP-373 fields, the BIP-328 derivation, the two rounds,
    and the extra round a silent payment send needs.

    Everything is read from the psbt and checked against the coin being spent; the device
    stores no descriptor. Participant order comes from PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS,
    the aggregate's derivation is filed under the BIP-328 fingerprint of the aggregate, and
    the key-path aggregate after the taptweak must equal the scriptPubKey.

    Rounds, per key-path aggregate this seed belongs to:
      shares  (silent payment send only) write d_i*B_scan and a BIP-374 proof of it, per
              scan key. No output script exists yet, so nothing is signed.
      nonce   verify every co-signer's share and the output script, then publish a nonce.
              The secret half stays in RAM until the partial signature is made.
      signed  verify again, then write the partial signature and destroy the secret nonce.

    Only key-path aggregates are signed. Leaf participations are counted so the caller can
    say so.
"""

PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS = 0x1A
PSBT_IN_MUSIG2_PUB_NONCE = 0x1B
PSBT_IN_MUSIG2_PARTIAL_SIG = 0x1C
# BIP-375, for inputs that are not MuSig2
PSBT_IN_SP_ECDH_SHARE = 0x1D
PSBT_IN_SP_DLEQ = 0x1E
# Partial share and proof of a MuSig2 participant (macgyver13's proposal); key is
# <scan key><participant key>
PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE = 0x21
PSBT_IN_MUSIG2_PARTIAL_DLEQ = 0x22

# BIP-328
MUSIG2_CHAINCODE = sha256(b"MuSig2MuSig2MuSig2")
HARDENED = 0x80000000

SHARES = "shares"
NONCE = "nonce"
SIGNED = "signed"


class Musig2Error(Exception):
    """Refusal shown on screen; keep the message short."""


class SharesIncomplete(Exception):
    """A co-signer has not contributed yet; not an error."""


class Aggregate(NamedTuple):
    parent: bytes               # KeyAgg output, the 0x1a key
    participants: List[bytes]   # in aggregation order
    key: bytes                  # 33 bytes, the 0x1b/0x1c key component
    leaf_hash: Optional[bytes]  # None on the key path
    tweaks: List[bytes]
    is_xonly: List[bool]

    @property
    def is_keypath(self) -> bool:
        return self.leaf_hash is None


class Role(NamedTuple):
    input_index: int
    aggregate: Aggregate
    pubkey: bytes               # ours among the participants
    derivation: List[int]       # from our root to pubkey


class Policy(NamedTuple):
    threshold: int
    total: int

    def __str__(self):
        return "%d of %d" % (self.threshold, self.total)


class Progress(NamedTuple):
    stage: str
    signed: int
    waiting: int
    leaves: int                 # aggregates this seed is in but cannot key-path sign


def _fields(scope, field_type: int) -> Dict[bytes, bytes]:
    return {k[1:]: v for k, v in scope.unknown.items() if k and k[0] == field_type}


def has_musig2_fields(psbt) -> bool:
    return any(_fields(scope, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS) for scope in psbt.inputs)


def _derive(parent: bytes, path: List[int]):
    """BIP-328: walk the synthetic xpub; each step is a plain MuSig2 tweak."""
    chaincode = MUSIG2_CHAINCODE
    point = m.cpoint(parent)
    tweaks = []
    for index in path:
        if index >= HARDENED:
            raise Musig2Error("Hardened derivation of a MuSig2 key is impossible.")
        digest = hmac.new(chaincode, m.cbytes(point) + index.to_bytes(4, "big"), "sha512").digest()
        tweaks.append(digest[:32])
        chaincode = digest[32:]
        point = m.point_add(point, m.point_mul_base(m.int_from_bytes(digest[:32])))
        if point is None:
            raise Musig2Error("MuSig2 derivation reached infinity.")
    return tweaks, point


def read_aggregates(scope, input_index: int) -> List[Aggregate]:
    """Every aggregate the input describes, each checked to be well formed."""
    try:
        return _read_aggregates(scope)
    except (m.InvalidContributionError, ValueError, AssertionError, IndexError):
        raise Musig2Error("Input %d: the MuSig2 fields are malformed." % input_index)


def _read_aggregates(scope) -> List[Aggregate]:
    out = []
    for parent, blob in _fields(scope, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS).items():
        if len(parent) != 33 or not blob or len(blob) % 33:
            raise ValueError("participant list")
        participants = [blob[i:i + 33] for i in range(0, len(blob), 33)]
        if m.cbytes(m.key_agg(participants).Q) != parent:
            raise ValueError("participants do not aggregate to the key they are filed under")
        fingerprint = hash160(parent)[:4]
        entry = next(((leaves, der) for _, (leaves, der) in scope.taproot_bip32_derivations.items()
                      if der.fingerprint == fingerprint), None)
        if entry is None:
            raise ValueError("no derivation for the aggregate")
        leaf_hashes, der = entry
        tweaks, derived = _derive(parent, der.derivation)
        is_xonly = [False] * len(tweaks)
        if leaf_hashes:
            leaf_hash, key = leaf_hashes[0], m.cbytes(derived)
        else:
            leaf_hash = None
            merkle_root = scope.taproot_merkle_root or b""
            tweaks.append(tagged_hash("TapTweak", m.xbytes(derived) + merkle_root))
            is_xonly.append(True)
            key = m.cbytes(m.key_agg_and_tweak(participants, tweaks, is_xonly).Q)
        out.append(Aggregate(parent, participants, key, leaf_hash, tweaks, is_xonly))
    return out


def roles(psbt, root):
    """(key-path roles of this root, number of leaf roles it also has)."""
    keypath, leaves = [], 0
    for i, scope in enumerate(psbt.inputs):
        if not _fields(scope, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS):
            continue
        # Matched x-only: a taproot derivation has no parity byte, a participant key does.
        mine = {pub.xonly(): der.derivation for pub, (_, der) in scope.taproot_bip32_derivations.items()
                if der.fingerprint == root.my_fingerprint}
        for agg in read_aggregates(scope, i):
            pubkey = next((pk for pk in agg.participants if pk[1:] in mine), None)
            if pubkey is None:
                continue
            if agg.is_keypath:
                keypath.append(Role(i, agg, pubkey, mine[pubkey[1:]]))
            else:
                leaves += 1
    return keypath, leaves


def check_coin(psbt, role: Role) -> None:
    """The key-path aggregate must be the key that locks the coin."""
    spk = bytes(psbt.inputs[role.input_index].utxo.script_pubkey.data)
    if spk[:2] != b"\x51\x20" or spk[2:] != role.aggregate.key[1:]:
        raise Musig2Error("Input %d: the MuSig2 key does not lock this coin." % role.input_index)


def policy(psbt, role: Role) -> Optional[Policy]:
    """The t-of-n the coin's script tree encodes, or None when it is not a plain one."""
    scope = psbt.inputs[role.input_index]
    if scope.taproot_internal_key is None:
        return None
    aggregates = read_aggregates(scope, role.input_index)
    sizes = {len(a.participants) for a in aggregates}
    if len(sizes) != 1:
        return None
    threshold = sizes.pop()
    total = len({k for a in aggregates for k in a.participants})
    expected = 1
    for i in range(threshold):
        expected = expected * (total - i) // (i + 1)
    if threshold < 1 or total < threshold or len(aggregates) != expected:
        return None

    # One aggregate on the key path, every other one in its own <key> OP_CHECKSIG leaf.
    leaves = {}
    root = None
    for control_block, value in scope.taproot_scripts.items():
        script, version = bytes(value[:-1]), value[-1]
        if len(script) != 34 or script[0] != 0x20 or script[33] != 0xAC:
            return None
        leaf = tagged_hash("TapLeaf", bytes([version]) + b"\x22" + script)
        node = leaf
        for i in range(33, len(control_block), 32):
            sibling = bytes(control_block[i:i + 32])
            node = tagged_hash("TapBranch", min(node, sibling) + max(node, sibling))
        if root is not None and node != root:
            return None
        root, leaves[leaf] = node, script[1:33]
    if root is None or len(leaves) != len(aggregates) - 1:
        return None
    internal = scope.taproot_internal_key.xonly()
    for agg in aggregates:
        if agg.is_keypath:
            # The key-path aggregate before its taptweak is the internal key.
            plain = m.key_agg_and_tweak(agg.participants, agg.tweaks[:-1], agg.is_xonly[:-1]).Q
            if m.xbytes(plain) != internal:
                return None
        elif leaves.pop(agg.leaf_hash, None) != agg.key[1:]:
            return None
    if leaves:
        return None
    tweak = tagged_hash("TapTweak", internal + root)
    output = m.point_add(m.cpoint(b"\x02" + internal), m.point_mul_base(m.int_from_bytes(tweak)))
    if m.xbytes(output) != role.aggregate.key[1:]:
        return None
    return Policy(threshold, total)


def _key(field_type: int, role: Role, pubkey: bytes) -> bytes:
    key = bytes([field_type]) + pubkey + role.aggregate.key
    if role.aggregate.leaf_hash is not None:
        key += role.aggregate.leaf_hash
    return key


def pubnonces(psbt, role: Role) -> List[Optional[bytes]]:
    """Every participant's nonce in aggregation order; None where one is missing."""
    scope = psbt.inputs[role.input_index]
    return [scope.unknown.get(_key(PSBT_IN_MUSIG2_PUB_NONCE, role, pk)) for pk in role.aggregate.participants]


def write_pubnonce(psbt, role: Role, pubnonce: bytes) -> None:
    psbt.inputs[role.input_index].unknown[_key(PSBT_IN_MUSIG2_PUB_NONCE, role, role.pubkey)] = pubnonce


def partial_sig(psbt, role: Role) -> Optional[bytes]:
    return psbt.inputs[role.input_index].unknown.get(_key(PSBT_IN_MUSIG2_PARTIAL_SIG, role, role.pubkey))


def write_partial_sig(psbt, role: Role, sig: bytes) -> None:
    psbt.inputs[role.input_index].unknown[_key(PSBT_IN_MUSIG2_PARTIAL_SIG, role, role.pubkey)] = sig


def sighash(psbt, role: Role) -> bytes:
    return psbt.sighash(role.input_index, sighash=SIGHASH.DEFAULT)


# --- silent payment send ---------------------------------------------------------------

def _sp_groups(psbt):
    if not any(getattr(out, "sp_data", None) is not None for out in psbt.outputs):
        return {}, {}
    from embit.silent_payments.sp import group_sp_outputs_by_scan_key
    return group_sp_outputs_by_scan_key(psbt.outputs)


def sp_scan_keys(psbt) -> List[bytes]:
    return list(_sp_groups(psbt)[0])


def sp_scripts_missing(psbt) -> bool:
    return any(getattr(out, "sp_data", None) is not None
               and (out.script_pubkey is None or not len(out.script_pubkey.data))
               for out in psbt.outputs)


def _share_key(field_type: int, scan_key: bytes, pubkey: bytes) -> bytes:
    return bytes([field_type]) + scan_key + pubkey


def has_share(psbt, role: Role, scan_key: bytes) -> bool:
    return _share_key(PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE, scan_key, role.pubkey) in \
        psbt.inputs[role.input_index].unknown


def write_share(psbt, role: Role, secret: bytes, scan_key: bytes) -> None:
    from embit.silent_payments.dleq import generate_dleq_proof
    from embit.silent_payments.sp import _tweak_mul
    scope = psbt.inputs[role.input_index]
    scope.unknown[_share_key(PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE, scan_key, role.pubkey)] = \
        _tweak_mul(scan_key, bytes(secret))
    scope.unknown[_share_key(PSBT_IN_MUSIG2_PARTIAL_DLEQ, scan_key, role.pubkey)] = \
        generate_dleq_proof(bytes(secret), scan_key, r=os.urandom(32))


def _musig2_input_share(scope, agg: Aggregate, scan_key: bytes):
    """(input key, ECDH point) from the participants' shares, each proof checked."""
    from embit.silent_payments.dleq import verify_dleq_proof
    Q, gacc, tacc = m.key_agg_and_tweak(agg.participants, agg.tweaks, agg.is_xonly)
    g = 1 if m.has_even_y(Q) else m.n - 1
    acc = None
    for pk in agg.participants:
        share = scope.unknown.get(_share_key(PSBT_IN_MUSIG2_PARTIAL_ECDH_SHARE, scan_key, pk))
        proof = scope.unknown.get(_share_key(PSBT_IN_MUSIG2_PARTIAL_DLEQ, scan_key, pk))
        if share is None:
            raise SharesIncomplete()
        if proof is None or not verify_dleq_proof(pk, scan_key, share, proof):
            raise Musig2Error("A co-signer's silent payment share does not verify.")
        acc = m.point_add(acc, m.point_mul(m.cpoint(share), m.key_agg_coeff(agg.participants, pk)))
    ecdh = m.point_add(m.point_mul(acc, g * gacc % m.n), m.point_mul(m.cpoint(scan_key), g * tacc % m.n))
    if ecdh is None:
        raise Musig2Error("The silent payment shares sum to infinity.")
    return b"\x02" + m.xbytes(Q), m.cbytes(ecdh)


def _plain_input_share(scope, scan_key: bytes):
    """BIP-375 per-input share of an input that is not MuSig2, checked against its key."""
    from embit.silent_payments.dleq import verify_dleq_proof
    share = scope.unknown.get(bytes([PSBT_IN_SP_ECDH_SHARE]) + scan_key)
    proof = scope.unknown.get(bytes([PSBT_IN_SP_DLEQ]) + scan_key)
    if share is None:
        raise SharesIncomplete()
    spk = scope.script_pubkey
    if spk.script_type() == "p2tr":
        pubkey = b"\x02" + bytes(spk.data[2:34])
    else:
        pubkey = next((pub.sec() for pub in scope.bip32_derivations
                       if hash160(pub.sec()) == bytes(spk.data[2:22])), None)
    if pubkey is None or proof is None or not verify_dleq_proof(pubkey, scan_key, share, proof):
        raise Musig2Error("An input's silent payment share does not verify.")
    return pubkey, share


def expected_scripts(psbt) -> Dict[int, Script]:
    """{output index: script} for every silent payment output, from the verified shares."""
    from embit.silent_payments.sp import (_tweak_mul, derive_recipient_outputs,
                                          get_eligible_inputs, get_input_hash)
    groups, indices = _sp_groups(psbt)
    scripts = {}
    for scan_key, (_, spend_keys) in groups.items():
        A_sum = ecdh_sum = None
        for i in get_eligible_inputs(psbt.inputs):
            scope = psbt.inputs[i]
            keypath = [a for a in read_aggregates(scope, i) if a.is_keypath]
            if keypath:
                if len(keypath) != 1 or bytes(scope.script_pubkey.data) != b"\x51\x20" + keypath[0].key[1:]:
                    raise Musig2Error("Input %d: the MuSig2 key does not lock this coin." % i)
                pubkey, ecdh = _musig2_input_share(scope, keypath[0], scan_key)
            else:
                pubkey, ecdh = _plain_input_share(scope, scan_key)
            A_sum = m.point_add(A_sum, m.cpoint(pubkey))
            ecdh_sum = m.point_add(ecdh_sum, m.cpoint(ecdh))
        if A_sum is None:
            raise Musig2Error("No input can pay a silent payment address.")
        input_hash = get_input_hash([inp.vin for inp in psbt.inputs], m.cbytes(A_sum))
        outputs = derive_recipient_outputs(_tweak_mul(m.cbytes(ecdh_sum), input_hash), spend_keys)
        for pos, idx in enumerate(indices[scan_key]):
            scripts[idx] = Script(b"\x51\x20" + outputs[pos])
    return scripts


def check_scripts(psbt) -> None:
    """Every silent payment output must carry exactly the script the shares give."""
    try:
        expected = expected_scripts(psbt)
    except SharesIncomplete:
        raise Musig2Error("A co-signer's silent payment share is still missing.")
    for idx, script in expected.items():
        declared = psbt.outputs[idx].script_pubkey
        if declared is None or bytes(declared.data) != bytes(script.data):
            raise Musig2Error("Output %d does not pay the silent payment address shown." % idx)


# --- the rounds ------------------------------------------------------------------------

def _secret(root, role: Role) -> bytearray:
    secret = bytearray(root.derive(role.derivation).key.secret)
    if m.individual_pk(bytes(secret)) != role.pubkey:
        secret[:] = bytes(len(secret))
        raise Musig2Error("Input %d: this seed does not make the key claimed." % role.input_index)
    return secret


def _wipe(buf: bytearray) -> None:
    buf[:] = bytes(len(buf))


def _pubnonce(secnonce: bytearray) -> bytes:
    k1, k2 = m.int_from_bytes(bytes(secnonce[0:32])), m.int_from_bytes(bytes(secnonce[32:64]))
    return m.cbytes(m.point_mul_base(k1)) + m.cbytes(m.point_mul_base(k2))


def _refuse_mixed(psbt, root) -> None:
    """Inputs this seed could sign the ordinary way are not handled here."""
    for i, scope in enumerate(psbt.inputs):
        if _fields(scope, PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS):
            continue
        fingerprints = [der.fingerprint for der in scope.bip32_derivations.values()]
        fingerprints += [der.fingerprint for _, der in scope.taproot_bip32_derivations.values()]
        if root.my_fingerprint in fingerprints:
            raise Musig2Error("Input %d is not MuSig2. Mixed transactions are not supported." % i)


class Session:
    """Secret nonces between the two rounds, in RAM only, keyed by exactly what they may sign.

    Power off between rounds and the attempt restarts. Never write one to the card: a copied
    card that replays a nonce yields two signatures under one nonce, which leaks the key.
    """

    def __init__(self):
        self._nonces: Dict[tuple, bytearray] = {}

    def __len__(self):
        return len(self._nonces)

    def clear(self) -> None:
        for secnonce in self._nonces.values():
            _wipe(secnonce)
        self._nonces.clear()

    def advance(self, psbt, root) -> Progress:
        """Take whichever round each key-path aggregate of this seed is ready for."""
        keypath, leaves = roles(psbt, root)
        if not keypath:
            raise Musig2Error("This seed is not a key-path signer of this transaction.")
        _refuse_mixed(psbt, root)
        for role in keypath:
            check_coin(psbt, role)

        scan_keys = sp_scan_keys(psbt)
        if scan_keys and sp_scripts_missing(psbt):
            for role in keypath:
                secret = _secret(root, role)
                for scan_key in scan_keys:
                    if not has_share(psbt, role, scan_key):
                        write_share(psbt, role, secret, scan_key)
                _wipe(secret)
            return Progress(SHARES, 0, len(keypath), leaves)
        if scan_keys:
            check_scripts(psbt)

        signed = waiting = 0
        for role in keypath:
            msg = sighash(psbt, role)
            agg = role.aggregate
            existing = partial_sig(psbt, role)
            nonces = pubnonces(psbt, role)
            if existing is not None:
                if None in nonces or not m.partial_sig_verify(
                        existing, nonces, agg.participants, agg.tweaks, agg.is_xonly, msg,
                        agg.participants.index(role.pubkey)):
                    raise Musig2Error("Input %d carries a signature under this key that does not verify."
                                      % role.input_index)
                signed += 1
                continue

            key = (role.input_index, agg.key, role.pubkey, msg)
            if key not in self._nonces:
                secret = _secret(root, role)
                self._nonces[key] = m.nonce_gen(secret, role.pubkey, None, msg, None)[0]
                _wipe(secret)
            # Always written, so a lost read-back of the first round can be repeated.
            write_pubnonce(psbt, role, _pubnonce(self._nonces[key]))
            nonces = pubnonces(psbt, role)
            if None in nonces:
                waiting += 1
                continue

            secret = _secret(root, role)
            context = m.SessionContext(m.nonce_agg(nonces), agg.participants, agg.tweaks, agg.is_xonly, msg)
            try:
                sig = m.sign(self._nonces.pop(key), secret, context)
            finally:
                _wipe(secret)
            write_partial_sig(psbt, role, sig)
            signed += 1

        return Progress(SIGNED if signed and not waiting else NONCE, signed, waiting, leaves)
