"""Symmetric-key algorithm names accepted by the rPGP Python bindings."""

from enum import Enum


class SymmetricKeyAlgorithm(str, Enum):
    Aes128 = "aes128"
    Aes192 = "aes192"
    Aes256 = "aes256"


__all__ = ["SymmetricKeyAlgorithm"]
