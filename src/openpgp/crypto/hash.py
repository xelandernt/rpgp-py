"""Hash algorithm names accepted by the rPGP Python bindings."""

from enum import Enum


class HashAlgorithm(str, Enum):
    Sha1 = "sha1"
    Sha224 = "sha224"
    Sha256 = "sha256"
    Sha384 = "sha384"
    Sha512 = "sha512"
    Sha3_256 = "sha3-256"
    Sha3_512 = "sha3-512"


__all__ = ["HashAlgorithm"]
