"""Public-key algorithm names exposed by rPGP."""

from enum import Enum


class PublicKeyAlgorithm(str, Enum):
    RSA = "rsa"
    RSAEncrypt = "rsa-encrypt"
    RSASign = "rsa-sign"
    ElgamalEncrypt = "elgamal-encrypt"
    DSA = "dsa"
    ECDH = "ecdh"
    ECDSA = "ecdsa"
    Elgamal = "elgamal"
    DiffieHellman = "diffie-hellman"
    EdDSALegacy = "eddsa-legacy"
    X25519 = "x25519"
    X448 = "x448"
    Ed25519 = "ed25519"
    Ed448 = "ed448"
    Unknown = "unknown"


__all__ = ["PublicKeyAlgorithm"]
