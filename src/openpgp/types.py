"""rPGP ``pgp::types`` compatibility namespace."""

from enum import Enum

from ._openpgp import (
    DsaPublicKey,
    DsaPublicParams,
    EcdhPublicParams,
    EcdsaPublicParams,
    Ed25519PublicParams,
    Ed448PublicParams,
    EdDsaLegacyPublicParams,
    ElgamalPublicParams,
    PacketHeaderVersion,
    PublicParams,
    RsaPublicKey,
    RsaPublicParams,
    S2kParams,
    StringToKey,
    UnknownPublicParams,
    X25519PublicParams,
    X448PublicParams,
)


class CompressionAlgorithm(str, Enum):
    Zip = "zip"
    Zlib = "zlib"
    Bzip2 = "bzip2"


class PacketHeaderVersionName(str, Enum):
    Old = "old"
    New = "new"


__all__ = [
    "CompressionAlgorithm",
    "DsaPublicKey",
    "DsaPublicParams",
    "EcdhPublicParams",
    "EcdsaPublicParams",
    "Ed25519PublicParams",
    "Ed448PublicParams",
    "EdDsaLegacyPublicParams",
    "ElgamalPublicParams",
    "PacketHeaderVersion",
    "PacketHeaderVersionName",
    "PublicParams",
    "RsaPublicKey",
    "RsaPublicParams",
    "S2kParams",
    "StringToKey",
    "UnknownPublicParams",
    "X25519PublicParams",
    "X448PublicParams",
]
