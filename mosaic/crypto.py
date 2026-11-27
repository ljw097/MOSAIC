"""MOSAIC 암호 프리미티브.

- X25519 (Sphinx 헤더 공유비밀, 링크 핸드셰이크)
- ML-KEM-768 (링크 계층 하이브리드 포스트-양자 키 교환)
- ChaCha20 스트림, ChaCha20-Poly1305 AEAD
- HMAC-SHA256, BLAKE2b, HKDF-SHA256
- LIONESS 광폭 블록 암호 (Sphinx 페이로드: 태깅 공격 방어)
"""
from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32


def rand(n: int) -> bytes:
    return os.urandom(n)


# ---------------------------------------------------------------- X25519
def x25519(scalar: bytes, point: bytes) -> bytes:
    """clamp(scalar) * point (u 좌표). 클램핑된 스칼라 곱은 교환법칙이 성립하므로
    Sphinx 블라인딩을 X25519 함수만으로 구현할 수 있다."""
    return X25519PrivateKey.from_private_bytes(scalar).exchange(X25519PublicKey.from_public_bytes(point))


def x25519_pub(scalar: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(scalar).public_key().public_bytes_raw()


def x25519_keygen() -> tuple[bytes, bytes]:
    sk = rand(32)
    return sk, x25519_pub(sk)


# ---------------------------------------------------------------- ML-KEM-768
def mlkem_keygen() -> tuple[bytes, bytes]:
    """(seed64, public1184)"""
    k = mlkem.MLKEM768PrivateKey.generate()
    return k.private_bytes_raw(), k.public_key().public_bytes_raw()


def mlkem_encaps(pub: bytes) -> tuple[bytes, bytes]:
    """-> (shared_secret, ciphertext)"""
    ss, ct = mlkem.MLKEM768PublicKey.from_public_bytes(pub).encapsulate()
    return ss, ct


def mlkem_decaps(seed: bytes, ct: bytes) -> bytes:
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(seed).decapsulate(ct)


MLKEM_CT_LEN = 1088
MLKEM_PK_LEN = 1184


# ---------------------------------------------------------------- Ed25519
def ed_keygen() -> tuple[bytes, bytes]:
    k = ed25519.Ed25519PrivateKey.generate()
    return k.private_bytes_raw(), k.public_key().public_bytes_raw()


def ed_sign(sk: bytes, msg: bytes) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(sk).sign(msg)


def ed_verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- 해시/KDF/MAC
def h(*parts: bytes, n: int = 32) -> bytes:
    d = hashlib.blake2b(digest_size=n)
    for p in parts:
        d.update(len(p).to_bytes(4, "big"))
        d.update(p)
    return d.digest()


def kdf(secret: bytes, label: bytes, n: int = 32) -> bytes:
    return hashlib.blake2b(secret, digest_size=n, key=b"MOSAIC-v1", person=label[:16].ljust(16, b"\0")).digest()


def hkdf(ikm: bytes, info: bytes, n: int, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ikm)


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------- 스트림 암호
def stream(key: bytes, n: int, nonce: bytes = b"\0" * 16) -> bytes:
    enc = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
    return enc.update(b"\0" * n)


def xor(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    return (int.from_bytes(a[:n], "little") ^ int.from_bytes(b[:n], "little")).to_bytes(n, "little")


def stream_xor(key: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.ChaCha20(key, b"\0" * 16), mode=None).encryptor()
    return enc.update(data)


# ---------------------------------------------------------------- LIONESS
class Lioness:
    """4-라운드 LIONESS (Anderson & Biham). 페이로드 전체를 하나의 블록으로 다뤄
    한 비트만 변조돼도 전체가 무작위로 바뀐다 → 태깅(tagging) 공격 탐지 가능."""

    L = 32

    def __init__(self, key: bytes):
        self.k = [kdf(key, b"lioness-%d" % i) for i in range(4)]

    def _s(self, k: bytes, l: bytes, r: bytes) -> bytes:
        return stream_xor(xor(k, l), r)

    def _h(self, k: bytes, r: bytes) -> bytes:
        return hashlib.blake2b(r, digest_size=self.L, key=k).digest()

    def encrypt(self, m: bytes) -> bytes:
        l, r = m[: self.L], m[self.L:]
        r = self._s(self.k[0], l, r)
        l = xor(l, self._h(self.k[1], r))
        r = self._s(self.k[2], l, r)
        l = xor(l, self._h(self.k[3], r))
        return l + r

    def decrypt(self, c: bytes) -> bytes:
        l, r = c[: self.L], c[self.L:]
        l = xor(l, self._h(self.k[3], r))
        r = self._s(self.k[2], l, r)
        l = xor(l, self._h(self.k[1], r))
        r = self._s(self.k[0], l, r)
        return l + r


# ---------------------------------------------------------------- AEAD
class AEAD:
    def __init__(self, key: bytes):
        self._c = ChaCha20Poly1305(key)

    def seal(self, nonce: int, pt: bytes, ad: bytes = b"") -> bytes:
        return self._c.encrypt(nonce.to_bytes(12, "little"), pt, ad)

    def open(self, nonce: int, ct: bytes, ad: bytes = b"") -> bytes:
        return self._c.decrypt(nonce.to_bytes(12, "little"), ct, ad)
