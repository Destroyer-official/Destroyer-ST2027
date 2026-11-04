"""Crypto-agility interface for ST2027 (research-backed).

Provides abstract KEM / signature / AEAD interfaces and a concrete
CNSA 2.0 L5 provider. Call sites should depend on these interfaces so
algorithm swaps do not require call-site changes (CARS dimension d3).
"""

from __future__ import annotations

import abc
from typing import Tuple


class KEMProvider(abc.ABC):
    @abc.abstractmethod
    def keygen(self) -> Tuple[bytes, bytes]:
        ...

    @abc.abstractmethod
    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        ...

    @abc.abstractmethod
    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        ...

    @property
    @abc.abstractmethod
    def name(self) -> str:
        ...


class SignatureProvider(abc.ABC):
    @abc.abstractmethod
    def keygen(self) -> Tuple[bytes, bytes]:
        ...

    @abc.abstractmethod
    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        ...

    @abc.abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        ...

    @property
    @abc.abstractmethod
    def name(self) -> str:
        ...


class Cnsa2027KEM(KEMProvider):
    """ML-KEM-1024 via liboqs (FIPS 203)."""

    def __init__(self):
        from liboqs_wrapper import LibOQS_MLKEM_1024
        self._impl = LibOQS_MLKEM_1024()

    def keygen(self):
        return self._impl.keygen()

    def encaps(self, public_key):
        return self._impl.encaps(public_key)

    def decaps(self, secret_key, ciphertext):
        return self._impl.decaps(secret_key, ciphertext)

    @property
    def name(self) -> str:
        return "ML-KEM-1024"


class Cnsa2027Signature(SignatureProvider):
    """ML-DSA-87 via liboqs (FIPS 204)."""

    def __init__(self):
        from liboqs_wrapper import LibOQS_MLDSA_87
        self._impl = LibOQS_MLDSA_87()

    def keygen(self):
        return self._impl.keygen()

    def sign(self, secret_key, message):
        return self._impl.sign(secret_key, message)

    def verify(self, public_key, message, signature):
        try:
            self._impl.verify(public_key, message, signature)
            return True
        except Exception:
            return False

    @property
    def name(self) -> str:
        return "ML-DSA-87"


def get_default_kem() -> KEMProvider:
    return Cnsa2027KEM()


def get_default_signature() -> SignatureProvider:
    return Cnsa2027Signature()
