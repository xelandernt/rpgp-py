"""Thin namespace for rPGP's native public-key algorithm binding."""

from .._openpgp import PublicKeyAlgorithm


__all__ = ["PublicKeyAlgorithm"]
