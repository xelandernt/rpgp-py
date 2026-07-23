"""Thin namespace for rPGP's native ASCII-armor bindings."""

from ._openpgp import (
    ArmorCrc24Status,
    BlockType,
    Dearmor,
    DearmorOptions,
    PKCS1Type,
    armor_write as write,
)

__all__ = [
    "ArmorCrc24Status",
    "BlockType",
    "Dearmor",
    "DearmorOptions",
    "PKCS1Type",
    "write",
]
