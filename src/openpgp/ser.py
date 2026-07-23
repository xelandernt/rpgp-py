"""Thin namespace for native rPGP serialization helpers."""

from ._openpgp import (
    serialize,
    serialize_write as write,
    serialize_write_len as write_len,
)

__all__ = ["serialize", "write", "write_len"]
