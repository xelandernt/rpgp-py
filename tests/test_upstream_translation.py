"""Upstream-style example translations using only Rust-shaped namespaces.

Each test mirrors a representative rPGP (`pgp` crate) workflow so that the
upstream documentation translates directly into Python. Imports are restricted to
the canonical ``openpgp.composed``, ``openpgp.packet``, and ``openpgp.types``
namespaces.
"""

import os

from openpgp.composed import (
    CleartextSignedMessage,
    DetachedSignature,
    EncryptionCaps,
    KeyType,
    Message,
    MessageBuilder,
    SecretKeyParamsBuilder,
    SignedPublicKey,
    SignedSecretKey,
    SubkeyParamsBuilder,
)
from openpgp.packet import PublicKey, SecretKey, Signature
from openpgp.types import StringToKey


class SecureRandom:
    def randbytes(self, n: int) -> bytes:
        return os.urandom(n)


def _generate_certificate(user_id: str) -> SignedSecretKey:
    return (
        SecretKeyParamsBuilder()
        .version(6)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .can_sign(True)
        .feature_seipd_v2(True)
        .primary_user_id(user_id)
        .preferred_symmetric_algorithms(["aes256", "aes192", "aes128"])
        .preferred_hash_algorithms(["sha256", "sha384", "sha512"])
        .preferred_compression_algorithms(["zlib", "zip"])
        .subkey(
            SubkeyParamsBuilder()
            .version(6)
            .key_type(KeyType.x25519())
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )


def test_generate_key_and_verify_bindings() -> None:
    secret_key = _generate_certificate("Alice <alice@example.com>")
    public_key = secret_key.to_public_key()

    secret_key.verify_bindings()
    public_key.verify_bindings()

    assert isinstance(public_key, SignedPublicKey)
    assert isinstance(secret_key, SignedSecretKey)
    assert public_key.fingerprint == secret_key.fingerprint
    assert isinstance(public_key.primary_key, PublicKey)
    assert isinstance(secret_key.primary_key, SecretKey)
    assert public_key.user_ids == ["Alice <alice@example.com>"]


def test_load_public_key_and_verify_inline_signed_message() -> None:
    secret_key = _generate_certificate("Bob <bob@example.com>")
    public_key = secret_key.to_public_key()

    reparsed, headers = SignedPublicKey.from_armor(public_key.to_armored())
    assert headers == {}

    signed = (
        MessageBuilder.from_bytes("", b"inline signed payload")
        .sign(secret_key)
        .to_armored_string()
    )
    message, _ = Message.from_armor(signed)
    verified = message.verify(reparsed)

    assert isinstance(verified, Signature)
    assert message.as_data_vec() == b"inline signed payload"


def test_detached_signature_create_and_verify() -> None:
    secret_key = _generate_certificate("Carol <carol@example.com>")
    public_key = secret_key.to_public_key()
    payload = b"detached payload"

    signature = DetachedSignature.sign_binary_data(
        SecureRandom(), secret_key, None, "sha256", payload
    )
    signature.verify(public_key, payload)

    assert signature.signature.typ() == "binary"
    assert signature.signature.hash_alg() == "sha256"

    reparsed, _ = DetachedSignature.from_armor(signature.to_armored())
    reparsed.verify(public_key, payload)


def test_message_builder_encrypt_and_sign_roundtrip() -> None:
    secret_key = _generate_certificate("Dave <dave@example.com>")
    public_key = secret_key.to_public_key()

    armored = (
        MessageBuilder.from_bytes("note.txt", b"top secret")
        .sign(secret_key)
        .seipd_v2("aes256", "ocb")
        .encrypt_to_key(public_key)
        .to_armored_string()
    )
    message, _ = Message.from_armor(armored)
    decrypted = message.decrypt(None, secret_key)

    assert decrypted.as_data_vec() == b"top secret"
    decrypted.verify(public_key)


def test_message_builder_password_encryption_roundtrip() -> None:
    armored = (
        MessageBuilder.from_bytes("note.txt", b"Hello, world!")
        .seipd_v2("aes256", "ocb")
        .encrypt_with_password(StringToKey.argon2(1, 4, 21), "hunter2")
        .to_armored_string()
    )
    message, _ = Message.from_armor(armored)
    assert message.decrypt_with_password("hunter2").as_data_string() == "Hello, world!"


def test_cleartext_signed_message_roundtrip() -> None:
    secret_key = _generate_certificate("Erin <erin@example.com>")
    public_key = secret_key.to_public_key()

    message = CleartextSignedMessage.sign("hello\n-world\n", secret_key)
    reparsed, _ = CleartextSignedMessage.from_armor(message.to_armored())

    assert reparsed.signed_text() == "hello\r\n-world\r\n"
    reparsed.verify(public_key)
