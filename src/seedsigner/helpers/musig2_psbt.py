"""Wiring MuSig2 (BIP-327) to a PSBT: the BIP-373 fields and the tweak chain.

A PSBT carrying MuSig2 fields describes the whole arrangement, which is what
lets a device with no stored descriptor take part at all. Three things are read
out of it and none of them may be assumed instead:

  the participant order       BIP-390 sorts the keys, so `musig(A,B)` in a
                              descriptor can arrive as B,A. Aggregating in the
                              order a human wrote produces a different key and a
                              signature that fails with nothing to point at.
  the aggregate identifier    fields 0x1b and 0x1c are keyed by the key as it
                              finally appears, meaning tweaked by BIP-341 for a
                              key path spend and merely derived for a leaf. It
                              carries a real parity byte and is not normalised
                              to even, so it is copied out of the PSBT rather
                              than rebuilt.
  the derivation              BIP-328 turns the aggregate into a synthetic xpub
                              with a fixed chaincode, and the updater records the
                              path from it as an ordinary taproot derivation
                              whose fingerprint is that synthetic xpub's. Find
                              that entry and the tweak chain follows; the empty
                              leaf-hash list on it is what marks the key path.

Key path spends only, for now. Leaf participations are recognised and reported
so that the caller can say so, rather than being silently skipped: in a 2-of-3
the same seed usually sits in the key path pair and in a leaf as well, and a
device that quietly signed only one of them would look like it had finished.
"""

from typing import Dict, List, NamedTuple, Optional

from embit.hashes import hash160, sha256, tagged_hash
from embit.transaction import SIGHASH

from seedsigner.helpers import musig2 as m

FIELD_PARTICIPANTS = 0x1A
FIELD_PUBNONCE = 0x1B
FIELD_PARTIAL_SIG = 0x1C

# BIP-328: the chaincode every implementation must use for the synthetic xpub.
MUSIG2_CHAINCODE = sha256(b"MuSig2MuSig2MuSig2")

HARDENED = 0x80000000


class Musig2Error(Exception):
    pass


class Musig2Role(NamedTuple):
    """One aggregate key, on one input, that this seed is a participant in."""

    input_index: int
    parent_agg: bytes           # 33 bytes, the KeyAgg output, from the 0x1a key
    participants: List[bytes]   # 33 bytes each, in aggregation order
    my_pubkey: bytes            # 33 bytes, ours among the above
    my_index: int
    my_derivation: List[int]    # from our seed's root to my_pubkey
    agg_id: bytes               # 33 bytes, the 0x1b / 0x1c key component
    leaf_hash: Optional[bytes]  # None for a key path spend
    tweaks: List[bytes]
    is_xonly: List[bool]

    @property
    def is_keypath(self) -> bool:
        return self.leaf_hash is None


def scope_fields(scope, field_type: int) -> Dict[bytes, bytes]:
    """The BIP-373 entries of one type, keyed by everything after the type byte.

    embit has no named attributes for these, so they arrive in `unknown` and
    survive a round trip untouched, which is all this needs from it."""
    return {k[1:]: v for k, v in scope.unknown.items() if k and k[0] == field_type}


def _bip32_tweaks(parent_agg: bytes, path: List[int]):
    """Walk BIP-328's synthetic xpub down `path`, collecting the plain tweaks.

    Each unhardened step adds t*G to the aggregate, which is exactly a MuSig2
    plain tweak, so the chain can be handed to KeyAgg as-is."""
    import hmac

    chaincode = MUSIG2_CHAINCODE
    point = m.cpoint(parent_agg)
    tweaks = []
    for index in path:
        if index >= HARDENED:
            raise Musig2Error("hardened derivation of an aggregate key is impossible")
        digest = hmac.new(
            chaincode,
            m.cbytes(point) + index.to_bytes(4, "big"),
            "sha512",
        ).digest()
        tweaks.append(digest[:32])
        chaincode = digest[32:]
        point = m.point_add(point, m.point_mul_base(m.int_from_bytes(digest[:32])))
        if point is None:
            raise Musig2Error("aggregate derivation reached the point at infinity")
    return tweaks, point


def roles_for_root(psbt, root) -> List[Musig2Role]:
    """Every aggregate key on every input that `root` can sign for."""
    my_fingerprint = root.my_fingerprint
    roles = []

    for input_index, scope in enumerate(psbt.inputs):
        participants_by_agg = {
            agg: [blob[i:i + 33] for i in range(0, len(blob), 33)]
            for agg, blob in scope_fields(scope, FIELD_PARTICIPANTS).items()
        }
        if not participants_by_agg:
            continue

        # Our own participant keys on this input, by the path that makes them.
        #
        # Keyed x-only, and matched x-only below, because a taproot derivation
        # stores 32 bytes and cannot say which of the two points it means. The
        # participant list does carry a real parity byte, and about half of all
        # keys are odd, so comparing 33 bytes against 33 bytes silently finds
        # nothing for half the seeds that should have matched.
        mine = {
            pub.xonly(): der.derivation
            for pub, (_, der) in scope.taproot_bip32_derivations.items()
            if der.fingerprint == my_fingerprint
        }

        for parent_agg, participants in participants_by_agg.items():
            my_pubkey = next((pk for pk in participants if pk[1:] in mine), None)
            if my_pubkey is None:
                continue

            # BIP-328 makes the aggregate an xpub, so it has a fingerprint of
            # its own, and the updater files the path under it.
            agg_fingerprint = hash160(parent_agg)[:4]
            entry = next(
                ((leaves, der)
                 for _, (leaves, der) in scope.taproot_bip32_derivations.items()
                 if der.fingerprint == agg_fingerprint),
                None,
            )
            if entry is None:
                raise Musig2Error(
                    "input %d claims an aggregate key with no derivation for it" % input_index)
            leaf_hashes, agg_der = entry

            tweaks, derived = _bip32_tweaks(parent_agg, agg_der.derivation)
            is_xonly = [False] * len(tweaks)

            if leaf_hashes:
                # A leaf: the key in the script is the derived one, untweaked.
                leaf_hash = leaf_hashes[0]
                agg_id = m.cbytes(derived)
            else:
                leaf_hash = None
                merkle_root = scope.taproot_merkle_root or b""
                taptweak = tagged_hash("TapTweak", m.xbytes(derived) + merkle_root)
                tweaks = tweaks + [taptweak]
                is_xonly = is_xonly + [True]
                tweaked = m.key_agg_and_tweak(participants, tweaks, is_xonly)
                agg_id = m.cbytes(tweaked.Q)

            roles.append(Musig2Role(
                input_index=input_index,
                parent_agg=parent_agg,
                participants=participants,
                my_pubkey=my_pubkey,
                my_index=participants.index(my_pubkey),
                my_derivation=mine[my_pubkey[1:]],
                agg_id=agg_id,
                leaf_hash=leaf_hash,
                tweaks=tweaks,
                is_xonly=is_xonly,
            ))

    return roles


def verify_against_utxo(psbt, role: Musig2Role) -> None:
    """Recompute the output key and check it against the coin being spent.

    Worth the point arithmetic: it is the one check that catches a PSBT whose
    MuSig2 fields describe a different arrangement from the one that actually
    holds the money."""
    if not role.is_keypath:
        return
    tweaked = m.key_agg_and_tweak(role.participants, role.tweaks, role.is_xonly)
    script_pubkey = psbt.inputs[role.input_index].utxo.script_pubkey.data
    if script_pubkey[:2] != b"\x51\x20" or script_pubkey[2:] != m.xbytes(tweaked.Q):
        raise Musig2Error(
            "input %d: the aggregate key does not lock this coin" % role.input_index)


def sighash_for(psbt, role: Musig2Role) -> bytes:
    if not role.is_keypath:
        raise Musig2Error("leaf-path MuSig2 signing is not supported yet")
    return psbt.sighash(role.input_index, sighash=SIGHASH.DEFAULT)


def _field_key(field_type: int, role: Musig2Role) -> bytes:
    key = bytes([field_type]) + role.my_pubkey + role.agg_id
    if role.leaf_hash is not None:
        key += role.leaf_hash
    return key


def _suffix(role: Musig2Role, pubkey: bytes) -> bytes:
    suffix = pubkey + role.agg_id
    if role.leaf_hash is not None:
        suffix += role.leaf_hash
    return suffix


def write_pubnonce(psbt, role: Musig2Role, pubnonce: bytes) -> None:
    psbt.inputs[role.input_index].unknown[_field_key(FIELD_PUBNONCE, role)] = pubnonce


def write_partial_sig(psbt, role: Musig2Role, partial_sig: bytes) -> None:
    psbt.inputs[role.input_index].unknown[_field_key(FIELD_PARTIAL_SIG, role)] = partial_sig


def pubnonces(psbt, role: Musig2Role) -> Optional[List[bytes]]:
    """Every participant's nonce in aggregation order, or None if one is missing.

    A missing nonce means round one is not finished, which is a normal state and
    not an error: the caller shows the round one screen instead of the round two
    one."""
    present = scope_fields(psbt.inputs[role.input_index], FIELD_PUBNONCE)
    collected = [present.get(_suffix(role, pk)) for pk in role.participants]
    if any(nonce is None for nonce in collected):
        return None
    return collected
