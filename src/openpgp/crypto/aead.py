"""AEAD algorithm names accepted by the rPGP Python bindings."""

from enum import Enum


class AeadAlgorithm(str, Enum):
    Eax = "eax"
    Ocb = "ocb"
    Gcm = "gcm"


__all__ = ["AeadAlgorithm"]
