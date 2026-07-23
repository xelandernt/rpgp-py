"""Python bindings for rPGP with a Rust-shaped module layout."""

from . import armor, composed, crypto, errors, packet, ser, types, util
from ._openpgp import MAX_BUFFER_SIZE, VERSION

__all__ = [
    "MAX_BUFFER_SIZE",
    "VERSION",
    "armor",
    "composed",
    "crypto",
    "errors",
    "packet",
    "ser",
    "types",
    "util",
]
