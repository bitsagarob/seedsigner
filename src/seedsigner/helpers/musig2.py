"""MuSig2 (BIP-327): the specification's reference algorithms, on embit's curve arithmetic.

The device is a participant, never the coordinator, so PartialSigAgg and DeterministicSign
are not here. `sign` zeroes the secnonce it is handed and refuses one that is already zero,
as the specification requires: signing twice with one secnonce leaks the private key.
"""

from typing import List, NamedTuple, Optional, Tuple

from embit.hashes import tagged_hash
from embit.util.key import SECP256K1, SECP256K1_G, SECP256K1_ORDER as n

Point = Tuple[int, int]
p = 2**256 - 2**32 - 977

_INF_JAC = (0, 1, 0)


class InvalidContributionError(Exception):
    """A named signer sent something unusable. `contrib` says what was wrong."""

    def __init__(self, signer: Optional[int], contrib: str):
        self.signer = signer
        self.contrib = contrib


# ----------------------------------------------------------------- curve glue
#
# BIP-327 writes points as (x, y) with None for infinity; embit writes them as
# Jacobian (x, y, z) with z == 0 for infinity. Convert at the boundary and leave
# every algorithm below in the specification's own terms.

def _jac(P: Optional[Point]):
    return _INF_JAC if P is None else (P[0], P[1], 1)


def _aff(J) -> Optional[Point]:
    a = SECP256K1.affine(J)
    return None if a is None else (a[0], a[1])


def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    return _aff(SECP256K1.add(_jac(P1), _jac(P2)))


def point_mul(P: Optional[Point], d: int) -> Optional[Point]:
    if P is None:
        return None
    return _aff(SECP256K1.mul([(_jac(P), d % n)]))


def point_mul_base(d: int) -> Optional[Point]:
    return _aff(SECP256K1.mul([(SECP256K1_G, d % n)]))


def is_infinite(P: Optional[Point]) -> bool:
    return P is None


def x(P: Point) -> int:
    return P[0]


def y(P: Point) -> int:
    return P[1]


def has_even_y(P: Point) -> bool:
    assert not is_infinite(P)
    return y(P) % 2 == 0


def point_negate(P: Optional[Point]) -> Optional[Point]:
    if P is None:
        return P
    return (x(P), p - y(P))


def bytes_from_int(i: int) -> bytes:
    return i.to_bytes(32, "big")


def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")


def xbytes(P: Point) -> bytes:
    return bytes_from_int(x(P))


def cbytes(P: Point) -> bytes:
    a = b"\x02" if has_even_y(P) else b"\x03"
    return a + xbytes(P)


def cbytes_ext(P: Optional[Point]) -> bytes:
    if is_infinite(P):
        return (0).to_bytes(33, byteorder="big")
    assert P is not None
    return cbytes(P)


def lift_x(b: bytes) -> Optional[Point]:
    x_ = int_from_bytes(b)
    if x_ >= p:
        return None
    y_sq = (pow(x_, 3, p) + 7) % p
    y_ = pow(y_sq, (p + 1) // 4, p)
    if pow(y_, 2, p) != y_sq:
        return None
    return (x_, y_ if y_ & 1 == 0 else p - y_)


def cpoint(b: bytes) -> Point:
    if len(b) != 33:
        raise ValueError("x is not a valid compressed point.")
    P = lift_x(b[1:33])
    if P is None:
        raise ValueError("x is not a valid compressed point.")
    if b[0] == 2:
        return P
    elif b[0] == 3:
        P = point_negate(P)
        assert P is not None
        return P
    else:
        raise ValueError("x is not a valid compressed point.")


def cpoint_ext(b: bytes) -> Optional[Point]:
    if b == (0).to_bytes(33, "big"):
        return None
    else:
        return cpoint(b)


def individual_pk(seckey: bytes) -> bytes:
    d = int_from_bytes(seckey)
    if not 0 < d < n:
        raise ValueError("The secret key must be an integer in the range 1..n-1.")
    P = point_mul_base(d)
    assert P is not None
    return cbytes(P)


# ----------------------------------------------------------------- key aggregation

KeyAggContext = NamedTuple(
    "KeyAggContext", [("Q", Point), ("gacc", int), ("tacc", int)]
)


def get_xonly_pk(keyagg_ctx: KeyAggContext) -> bytes:
    Q, _, _ = keyagg_ctx
    return xbytes(Q)


def hash_keys(pubkeys: List[bytes]) -> bytes:
    return tagged_hash("KeyAgg list", b"".join(pubkeys))


def get_second_key(pubkeys: List[bytes]) -> bytes:
    for j in range(len(pubkeys)):
        if pubkeys[j] != pubkeys[0]:
            return pubkeys[j]
    return (0).to_bytes(33, byteorder="big")


def key_agg_coeff_internal(pubkeys: List[bytes], pk_: bytes, pk2: bytes) -> int:
    L = hash_keys(pubkeys)
    if pk_ == pk2:
        return 1
    return int_from_bytes(tagged_hash("KeyAgg coefficient", L + pk_)) % n


def key_agg_coeff(pubkeys: List[bytes], pk_: bytes) -> int:
    pk2 = get_second_key(pubkeys)
    return key_agg_coeff_internal(pubkeys, pk_, pk2)


def key_agg(pubkeys: List[bytes]) -> KeyAggContext:
    pk2 = get_second_key(pubkeys)
    Q = None
    for i in range(len(pubkeys)):
        try:
            P_i = cpoint(pubkeys[i])
        except ValueError:
            raise InvalidContributionError(i, "pubkey")
        a_i = key_agg_coeff_internal(pubkeys, pubkeys[i], pk2)
        Q = point_add(Q, point_mul(P_i, a_i))
    # Q is the point at infinity only with negligible probability.
    assert Q is not None
    gacc = 1
    tacc = 0
    return KeyAggContext(Q, gacc, tacc)


def apply_tweak(keyagg_ctx: KeyAggContext, tweak: bytes, is_xonly: bool) -> KeyAggContext:
    if len(tweak) != 32:
        raise ValueError("The tweak must be a 32-byte array.")
    Q, gacc, tacc = keyagg_ctx
    if is_xonly and not has_even_y(Q):
        g = n - 1
    else:
        g = 1
    t = int_from_bytes(tweak)
    if t >= n:
        raise ValueError("The tweak must be less than n.")
    Q_ = point_add(point_mul(Q, g), point_mul_base(t))
    if Q_ is None:
        raise ValueError("The result of tweaking cannot be infinity.")
    gacc_ = g * gacc % n
    tacc_ = (t + g * tacc) % n
    return KeyAggContext(Q_, gacc_, tacc_)


def key_agg_and_tweak(pubkeys: List[bytes], tweaks: List[bytes], is_xonly: List[bool]):
    if len(tweaks) != len(is_xonly):
        raise ValueError("The `tweaks` and `is_xonly` arrays must have the same length.")
    keyagg_ctx = key_agg(pubkeys)
    for i in range(len(tweaks)):
        keyagg_ctx = apply_tweak(keyagg_ctx, tweaks[i], is_xonly[i])
    return keyagg_ctx


# ----------------------------------------------------------------- nonces

def bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x_ ^ y_ for x_, y_ in zip(a, b))


def nonce_hash(rand: bytes, pk: bytes, aggpk: bytes, i: int,
               msg_prefixed: bytes, extra_in: bytes) -> int:
    buf = b""
    buf += rand
    buf += len(pk).to_bytes(1, "big")
    buf += pk
    buf += len(aggpk).to_bytes(1, "big")
    buf += aggpk
    buf += msg_prefixed
    buf += len(extra_in).to_bytes(4, "big")
    buf += extra_in
    buf += i.to_bytes(1, "big")
    return int_from_bytes(tagged_hash("MuSig/nonce", buf))


def nonce_gen_internal(rand_: bytes, sk: Optional[bytes], pk: bytes,
                       aggpk: Optional[bytes], msg: Optional[bytes],
                       extra_in: Optional[bytes]) -> Tuple[bytearray, bytes]:
    if sk is not None:
        rand = bytes_xor(sk, tagged_hash("MuSig/aux", rand_))
    else:
        rand = rand_
    if aggpk is None:
        aggpk = b""
    if msg is None:
        msg_prefixed = b"\x00"
    else:
        msg_prefixed = b"\x01"
        msg_prefixed += len(msg).to_bytes(8, "big")
        msg_prefixed += msg
    if extra_in is None:
        extra_in = b""
    k_1 = nonce_hash(rand, pk, aggpk, 0, msg_prefixed, extra_in) % n
    k_2 = nonce_hash(rand, pk, aggpk, 1, msg_prefixed, extra_in) % n
    # k_1 == 0 or k_2 == 0 cannot occur except with negligible probability.
    assert k_1 != 0
    assert k_2 != 0
    R_s1 = point_mul_base(k_1)
    R_s2 = point_mul_base(k_2)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    secnonce = bytearray(bytes_from_int(k_1) + bytes_from_int(k_2) + pk)
    return secnonce, pubnonce


def nonce_gen(sk: Optional[bytes], pk: bytes, aggpk: Optional[bytes],
              msg: Optional[bytes], extra_in: Optional[bytes],
              rand_: Optional[bytes] = None) -> Tuple[bytearray, bytes]:
    """Round one. `rand_` is for test vectors only; leave it None in production
    so the nonce comes from the system generator."""
    if sk is not None and len(sk) != 32:
        raise ValueError("The optional byte array sk must have length 32.")
    if aggpk is not None and len(aggpk) != 32:
        raise ValueError("The optional byte array aggpk must have length 32.")
    if rand_ is None:
        import os

        rand_ = os.urandom(32)
    return nonce_gen_internal(rand_, sk, pk, aggpk, msg, extra_in)


def nonce_agg(pubnonces: List[bytes]) -> bytes:
    u = len(pubnonces)
    aggnonce = b""
    for j in (1, 2):
        R_j = None
        for i in range(u):
            try:
                R_ij = cpoint(pubnonces[i][(j - 1) * 33: j * 33])
            except ValueError:
                raise InvalidContributionError(i, "pubnonce")
            R_j = point_add(R_j, R_ij)
        aggnonce += cbytes_ext(R_j)
    return aggnonce


# ----------------------------------------------------------------- signing

SessionContext = NamedTuple(
    "SessionContext",
    [
        ("aggnonce", bytes),
        ("pubkeys", List[bytes]),
        ("tweaks", List[bytes]),
        ("is_xonly", List[bool]),
        ("msg", bytes),
    ],
)


def get_session_values(session_ctx: SessionContext) -> Tuple[Point, int, int, int, Point, int]:
    (aggnonce, pubkeys, tweaks, is_xonly, msg) = session_ctx
    keyagg_ctx = key_agg_and_tweak(pubkeys, tweaks, is_xonly)
    (Q, gacc, tacc) = keyagg_ctx
    b = int_from_bytes(tagged_hash("MuSig/noncecoef", aggnonce + xbytes(Q) + msg)) % n
    try:
        R_1 = cpoint_ext(aggnonce[0:33])
        R_2 = cpoint_ext(aggnonce[33:66])
    except ValueError:
        # aggnonce is invalid, so the signer who produced it cannot be named
        raise InvalidContributionError(None, "aggnonce")
    R_ = point_add(R_1, point_mul(R_2, b))
    R = R_ if not is_infinite(R_) else point_mul_base(1)
    assert R is not None
    e = int_from_bytes(tagged_hash("BIP0340/challenge", xbytes(R) + xbytes(Q) + msg)) % n
    return (Q, gacc, tacc, b, R, e)


def get_session_key_agg_coeff(session_ctx: SessionContext, P: Point) -> int:
    (_, pubkeys, _, _, _) = session_ctx
    pk_ = cbytes(P)
    if pk_ not in pubkeys:
        raise ValueError("The signer's pubkey must be included in the list of pubkeys.")
    return key_agg_coeff(pubkeys, pk_)


def sign(secnonce: bytearray, sk: bytes, session_ctx: SessionContext) -> bytes:
    """Round two. The secnonce passed in is destroyed: see the module docstring."""
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    k_1_ = int_from_bytes(bytes(secnonce[0:32]))
    k_2_ = int_from_bytes(bytes(secnonce[32:64]))
    # Overwrite the secnonce argument with zeros so that a second call with the
    # same secnonce raises rather than reusing it.
    secnonce[:64] = bytearray(b"\x00" * 64)
    if not 0 < k_1_ < n:
        raise ValueError("first secnonce value is out of range.")
    if not 0 < k_2_ < n:
        raise ValueError("second secnonce value is out of range.")
    k_1 = k_1_ if has_even_y(R) else n - k_1_
    k_2 = k_2_ if has_even_y(R) else n - k_2_
    d_ = int_from_bytes(sk)
    if not 0 < d_ < n:
        raise ValueError("secret key value is out of range.")
    P = point_mul_base(d_)
    assert P is not None
    pk = cbytes(P)
    if not pk == secnonce[64:97]:
        raise ValueError("Public key does not match nonce_gen argument.")
    a = get_session_key_agg_coeff(session_ctx, P)
    g = 1 if has_even_y(Q) else n - 1
    d = g * gacc * d_ % n
    s = (k_1 + b * k_2 + e * a * d) % n
    psig = bytes_from_int(s)
    R_s1 = point_mul_base(k_1_)
    R_s2 = point_mul_base(k_2_)
    assert R_s1 is not None
    assert R_s2 is not None
    pubnonce = cbytes(R_s1) + cbytes(R_s2)
    # Optional correctness check. The result of signing is the same without it.
    assert partial_sig_verify_internal(psig, pubnonce, pk, session_ctx)
    return psig


def partial_sig_verify(psig: bytes, pubnonces: List[bytes], pubkeys: List[bytes],
                       tweaks: List[bytes], is_xonly: List[bool], msg: bytes,
                       i: int) -> bool:
    if len(pubnonces) != len(pubkeys):
        raise ValueError("The `pubnonces` and `pubkeys` arrays must have the same length.")
    if len(tweaks) != len(is_xonly):
        raise ValueError("The `tweaks` and `is_xonly` arrays must have the same length.")
    aggnonce = nonce_agg(pubnonces)
    session_ctx = SessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)
    return partial_sig_verify_internal(psig, pubnonces[i], pubkeys[i], session_ctx)


def partial_sig_verify_internal(psig: bytes, pubnonce: bytes, pk: bytes,
                                session_ctx: SessionContext) -> bool:
    (Q, gacc, _, b, R, e) = get_session_values(session_ctx)
    s = int_from_bytes(psig)
    if s >= n:
        return False
    R_s1 = cpoint(pubnonce[0:33])
    R_s2 = cpoint(pubnonce[33:66])
    Re_s_ = point_add(R_s1, point_mul(R_s2, b))
    Re_s = Re_s_ if has_even_y(R) else point_negate(Re_s_)
    P = cpoint(pk)
    a = get_session_key_agg_coeff(session_ctx, P)
    g = 1 if has_even_y(Q) else n - 1
    g_ = g * gacc % n
    return point_mul_base(s) == point_add(Re_s, point_mul(P, e * a * g_ % n))


def partial_sig_agg(psigs: List[bytes], session_ctx: SessionContext) -> bytes:
    """Sum the partial signatures into the one signature the chain sees.

    BIP-327's PartialSigAgg. It needs no secret and no seed, so whoever holds
    every partial signature can do it, which on a device means whichever seed
    happens to sign last. Doing it here rather than back at the coordinator is
    what lets an air-gapped signer hand back a finished transaction instead of
    a PSBT somebody else still has to assemble.
    """
    (Q, _, tacc, _, R, e) = get_session_values(session_ctx)
    s = 0
    for i, psig in enumerate(psigs):
        s_i = int_from_bytes(psig)
        if s_i >= n:
            raise InvalidContributionError(i, "psig")
        s = (s + s_i) % n
    g = 1 if has_even_y(Q) else n - 1
    s = (s + e * g * tacc) % n
    return xbytes(R) + bytes_from_int(s)
