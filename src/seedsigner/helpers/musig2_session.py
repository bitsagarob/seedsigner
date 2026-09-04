"""The two MuSig2 rounds, and the secret nonce that has to live between them.

Signing takes two passes. The first publishes a public nonce; the second, once
every other signer has published theirs, produces the partial signature. The
secret half of that nonce must survive from one to the other, and signing twice
with one secret nonce over two different messages lets anyone subtract out the
private key.

So it is held here, in memory, and nowhere else. A device with no writable state
is the easy case for this. Power the thing off between rounds and the session is
gone, the signing attempt fails, and the user starts over. That is the correct
failure: annoying, and not a lost key.

Writing it to the card instead would be worse than it looks. An attacker who
copies the card after round one, lets the spend complete, then restores the copy
and presents a different transaction gets two signatures under one nonce. Nothing
here can detect that, because detecting it needs a counter that cannot be rolled
back, and the device has no such thing by design. Encryption does not help; the
attacker never needs to read the file, only to put it back.

Entries are keyed by the message they were made for, so a secret nonce created
for one transaction can never be picked up for another. A changed transaction
simply misses the cache and starts a fresh first round.
"""

from typing import Dict, List, NamedTuple, Tuple

from seedsigner.helpers import musig2 as m
from seedsigner.helpers import musig2_psbt as mp

ROUND_ONE = "round_one"
SIGNED = "signed"


class Musig2Progress(NamedTuple):
    stage: str                  # ROUND_ONE or SIGNED
    signed_inputs: int
    waiting_inputs: int
    skipped_leaves: int


class Musig2Session:
    """Secret nonces, keyed by the exact thing they may be used to sign."""

    def __init__(self):
        self._secnonces: Dict[Tuple[int, bytes, bytes], bytearray] = {}

    def clear(self) -> None:
        for secnonce in self._secnonces.values():
            secnonce[:] = bytearray(len(secnonce))
        self._secnonces.clear()

    def __len__(self) -> int:
        return len(self._secnonces)

    def _key(self, role: mp.Musig2Role, msg: bytes):
        return (role.input_index, role.agg_id, msg)

    def has(self, role: mp.Musig2Role, msg: bytes) -> bool:
        return self._key(role, msg) in self._secnonces

    def begin(self, role: mp.Musig2Role, msg: bytes, secret_key: bytes) -> bytes:
        """Round one. Returns the public nonce to publish."""
        secnonce, pubnonce = m.nonce_gen(secret_key, role.my_pubkey, None, msg, None)
        self._secnonces[self._key(role, msg)] = secnonce
        return pubnonce

    def finish(self, role: mp.Musig2Role, msg: bytes, secret_key: bytes,
               pubnonces: List[bytes]) -> bytes:
        """Round two. Returns the partial signature; the secret nonce is spent."""
        key = self._key(role, msg)
        secnonce = self._secnonces.pop(key)
        session = m.SessionContext(m.nonce_agg(pubnonces), role.participants,
                                   role.tweaks, role.is_xonly, msg)
        # sign() zeroes the secnonce it is handed, which is why it is popped
        # first: a raise anywhere below must not leave a usable one behind.
        return m.sign(secnonce, secret_key, session)


def advance(psbt, root, session: Musig2Session) -> Musig2Progress:
    """Take whichever round each MuSig2 input is ready for, and write it in.

    One pass covers every input, and inputs may be at different rounds, so the
    result counts both rather than naming a single one."""
    roles = mp.roles_for_root(psbt, root)
    keypath = [r for r in roles if r.is_keypath]
    skipped = len(roles) - len(keypath)

    if not keypath:
        raise mp.Musig2Error("this seed is not a participant in any key-path aggregate")

    signed = 0
    waiting = 0
    done = 0
    for role in keypath:
        if mp.has_partial_sig(psbt, role):
            # Already signed, so there is nothing left that can be added. Say so
            # rather than starting a fresh first round: a new public nonce would
            # contradict the signature already written and the spend would stop
            # finalising, for a reason nobody would find quickly.
            done += 1
            continue

        mp.verify_against_utxo(psbt, role)
        msg = mp.sighash_for(psbt, role)
        secret_key = root.derive(role.my_derivation).key.secret
        if m.individual_pk(secret_key) != role.my_pubkey:
            raise mp.Musig2Error(
                "input %d: the seed does not make the key the PSBT claims" % role.input_index)

        if not session.has(role, msg):
            mp.write_pubnonce(psbt, role, session.begin(role, msg, secret_key))
            waiting += 1
            continue

        collected = mp.pubnonces(psbt, role)
        if collected is None:
            # We have published and someone else has not. Nothing to do but
            # hand the same PSBT back and wait to be asked again.
            waiting += 1
            continue

        mp.write_partial_sig(psbt, role, session.finish(role, msg, secret_key, collected))
        signed += 1

    return Musig2Progress(
        stage=SIGNED if (signed or done) and not waiting else ROUND_ONE,
        signed_inputs=signed + done,
        waiting_inputs=waiting,
        skipped_leaves=skipped,
    )
