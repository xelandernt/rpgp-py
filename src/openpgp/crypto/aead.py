"""Thin namespace for rPGP's native AEAD bindings."""

from .._openpgp import AeadAlgorithm, ChunkSize


__all__ = ["AeadAlgorithm", "ChunkSize"]
