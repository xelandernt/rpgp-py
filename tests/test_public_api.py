"""Public API drift checks for the Rust-shaped ``openpgp`` namespaces.

These tests fail fast if the runtime extension, the namespace re-exports, or the
canonical Rust-shaped spellings drift from the intended surface. They are cheap
(no key generation) and act as a guard for the parity contract described in
``AGENTS.md``.
"""

import openpgp
from openpgp import composed, crypto, packet, types, util

EXPECTED_TOPLEVEL = {"composed", "crypto", "packet", "types", "util"}

EXPECTED_COMPOSED = {
    "ArmorOptions",
    "CleartextSignedMessage",
    "CompressedMessage",
    "DecryptedCompressedMessage",
    "DecryptedLiteralMessage",
    "DecryptedMessage",
    "DecryptedSignedMessage",
    "DetachedSignature",
    "EncryptedMessage",
    "EncryptionCaps",
    "KeyType",
    "LiteralMessage",
    "Message",
    "MessageBuilder",
    "SecretKeyParams",
    "SecretKeyParamsBuilder",
    "SignedKeyDetails",
    "SignedMessage",
    "SignedPublicKey",
    "SignedPublicSubKey",
    "SignedSecretKey",
    "SignedSecretSubKey",
    "SignedUser",
    "SignedUserAttribute",
    "SubkeyParams",
    "SubkeyParamsBuilder",
}

EXPECTED_PACKET = {
    "EncryptedDataPacket",
    "Features",
    "GnupgAeadData",
    "KeyFlags",
    "LiteralDataHeader",
    "Notation",
    "PublicKey",
    "PublicKeyEncryptedSessionKey",
    "PublicSubkey",
    "RevocationKey",
    "SecretKey",
    "SecretSubkey",
    "Signature",
    "SymEncryptedData",
    "SymEncryptedProtectedData",
    "SymKeyEncryptedSessionKey",
    "UserAttribute",
}

EXPECTED_TYPES = {
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
    "PublicParams",
    "RsaPublicKey",
    "RsaPublicParams",
    "S2kParams",
    "StringToKey",
    "UnknownPublicParams",
    "X25519PublicParams",
    "X448PublicParams",
}

EXPECTED_CRYPTO = {"aead", "hash", "public_key", "sym"}

EXPECTED_UTIL = {
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
}

# Names that must not reappear as public spellings once the alias layer is gone.
REMOVED_ALIASES = {
    "PublicKeyPacket",
    "PublicSubkeyPacket",
    "SecretKeyPacket",
    "SecretSubkeyPacket",
    "SignaturePacket",
    "PublicKeyEncryptedSessionKeyPacket",
    "SymKeyEncryptedSessionKeyPacket",
    "SymEncryptedDataPacket",
    "SymEncryptedProtectedDataPacket",
    "GnupgAeadDataPacket",
    "MessageInfo",
    "inspect_message",
    "inspect_message_bytes",
}


def test_toplevel_exposes_only_namespace_modules() -> None:
    assert set(openpgp.__all__) == EXPECTED_TOPLEVEL


def test_composed_exports_match_canonical_names() -> None:
    assert set(composed.__all__) == EXPECTED_COMPOSED
    for name in EXPECTED_COMPOSED:
        assert hasattr(composed, name)


def test_packet_exports_match_canonical_names() -> None:
    assert set(packet.__all__) == EXPECTED_PACKET
    for name in EXPECTED_PACKET:
        assert hasattr(packet, name)


def test_types_exports_match_canonical_names() -> None:
    assert set(types.__all__) == EXPECTED_TYPES
    for name in EXPECTED_TYPES:
        assert hasattr(types, name)


def test_crypto_exports_match_canonical_names() -> None:
    assert set(crypto.__all__) == EXPECTED_CRYPTO


def test_util_exports_match_convenience_helpers() -> None:
    assert set(util.__all__) == EXPECTED_UTIL
    for name in EXPECTED_UTIL:
        assert hasattr(util, name)
        assert getattr(util, name).__module__ == "openpgp.util"


def test_removed_alias_names_are_absent_from_extension() -> None:
    import openpgp._openpgp as extension

    for name in REMOVED_ALIASES:
        assert not hasattr(extension, name), f"{name} should have been removed"


def test_composed_and_packet_key_types_are_distinct() -> None:
    assert composed.SignedPublicKey is not packet.PublicKey
    assert composed.SignedSecretKey is not packet.SecretKey


def test_pyclass_names_match_python_binding_names() -> None:
    assert composed.SignedPublicKey.__name__ == "SignedPublicKey"
    assert composed.SignedSecretKey.__name__ == "SignedSecretKey"
    assert packet.PublicKey.__name__ == "PublicKey"
    assert packet.SecretKey.__name__ == "SecretKey"
    assert packet.Signature.__name__ == "Signature"


def test_pyclass_modules_match_python_namespaces() -> None:
    assert composed.SignedPublicKey.__module__ == "openpgp.composed"
    assert composed.SignedSecretKey.__module__ == "openpgp.composed"
    assert composed.Message.__module__ == "openpgp.composed"
    assert composed.MessageBuilder.__module__ == "openpgp.composed"
    assert packet.PublicKey.__module__ == "openpgp.packet"
    assert packet.SecretKey.__module__ == "openpgp.packet"
    assert packet.Signature.__module__ == "openpgp.packet"
    assert types.StringToKey.__module__ == "openpgp.types"
    assert types.S2kParams.__module__ == "openpgp.types"
