"""Convenience helpers built on top of the Rust-shaped rPGP API."""

from ._openpgp import (
    encrypt_message_to_recipient,
    encrypt_message_to_recipient_bytes,
    encrypt_message_to_recipients,
    encrypt_message_to_recipients_bytes,
    encrypt_message_with_password,
    encrypt_message_with_password_bytes,
    encrypt_session_key_to_recipient,
    encrypt_session_key_with_password,
    sign_cleartext_message,
    sign_cleartext_message_many,
    sign_message,
    sign_message_many,
)

__all__ = [
    "encrypt_message_to_recipient",
    "encrypt_message_to_recipient_bytes",
    "encrypt_message_to_recipients",
    "encrypt_message_to_recipients_bytes",
    "encrypt_message_with_password",
    "encrypt_message_with_password_bytes",
    "encrypt_session_key_to_recipient",
    "encrypt_session_key_with_password",
    "sign_cleartext_message",
    "sign_cleartext_message_many",
    "sign_message",
    "sign_message_many",
]

for _name in __all__:
    globals()[_name].__module__ = __name__

del _name
