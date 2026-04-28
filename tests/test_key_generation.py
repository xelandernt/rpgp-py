from collections.abc import Callable
from pathlib import Path
from typing import Final, Literal, NamedTuple

import pytest

from openpgp import (
    EncryptionCaps,
    KeyType,
    Message,
    PacketHeaderVersion,
    PublicKey,
    SecretKey,
    SecretKeyParamsBuilder,
    SignatureInfo,
    S2kParams,
    StringToKey,
    SubkeyParamsBuilder,
    UserAttribute,
    encrypt_message_to_recipient,
    sign_message,
)


SymmetricPreferenceName = Literal["aes128", "aes192", "aes256"]
HashPreferenceName = Literal[
    "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-256", "sha3-512"
]
CompressionPreferenceName = Literal["zip", "zlib", "bzip2"]
KeyVersion = Literal[4, 6]

DEFAULT_SYMMETRIC_PREFERENCES: Final[list[SymmetricPreferenceName]] = [
    "aes256",
    "aes192",
    "aes128",
]
DEFAULT_HASH_PREFERENCES: Final[list[HashPreferenceName]] = [
    "sha256",
    "sha384",
    "sha512",
    "sha224",
]
DEFAULT_COMPRESSION_PREFERENCES: Final[list[CompressionPreferenceName]] = [
    "zlib",
    "zip",
]
AES256_ONLY: Final[list[SymmetricPreferenceName]] = ["aes256"]
SHA512_ONLY: Final[list[HashPreferenceName]] = ["sha512"]
ZLIB_ONLY: Final[list[CompressionPreferenceName]] = ["zlib"]
JPEG_USER_ATTRIBUTE_DATA: Final[bytes] = bytes.fromhex("ffd8ffe000104a464946000101")
FIXED_PRIMARY_CREATED_AT: Final[int] = 1_700_000_000
FIXED_SUBKEY_CREATED_AT: Final[int] = FIXED_PRIMARY_CREATED_AT + 123
FIXTURES = Path(__file__).resolve().parent / "fixtures"


class PacketHeaderInfo(NamedTuple):
    tag: int
    version: Literal["old", "new"]


SECRET_KEY_TAG: Final[int] = 5
PUBLIC_KEY_TAG: Final[int] = 6
SECRET_SUBKEY_TAG: Final[int] = 7
PUBLIC_SUBKEY_TAG: Final[int] = 14


def parse_packet_headers(data: bytes) -> list[PacketHeaderInfo]:
    """Parse fixed-length RFC 9580 packet headers from serialized key material."""
    headers: list[PacketHeaderInfo] = []
    offset = 0
    while offset < len(data):
        first_octet = data[offset]
        assert first_octet & 0x80 == 0x80

        if first_octet & 0x40:
            tag = first_octet & 0x3F
            length_octet = data[offset + 1]
            if length_octet < 192:
                header_len = 2
                packet_len = length_octet
            elif length_octet < 224:
                header_len = 3
                packet_len = ((length_octet - 192) << 8) + data[offset + 2] + 192
            else:
                assert length_octet == 255
                header_len = 6
                packet_len = int.from_bytes(data[offset + 2 : offset + 6], "big")
            headers.append(PacketHeaderInfo(tag=tag, version="new"))
        else:
            tag = (first_octet >> 2) & 0x0F
            length_type = first_octet & 0x03
            if length_type == 0:
                header_len = 2
                packet_len = data[offset + 1]
            elif length_type == 1:
                header_len = 3
                packet_len = int.from_bytes(data[offset + 1 : offset + 3], "big")
            else:
                assert length_type == 2
                header_len = 5
                packet_len = int.from_bytes(data[offset + 1 : offset + 5], "big")
            headers.append(PacketHeaderInfo(tag=tag, version="old"))

        offset += header_len + packet_len

    assert offset == len(data)
    return headers


def read_fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()


def build_modern_signing_key(version: KeyVersion) -> SecretKeyParamsBuilder:
    """Adapted from upstream builder.rs `key_gen_25519_rfc9580_short`."""
    return (
        SecretKeyParamsBuilder()
        .version(version)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .can_sign(True)
        .primary_user_id("Me-X <me-25519-rfc9580@mail.com>")
        .preferred_symmetric_algorithms(DEFAULT_SYMMETRIC_PREFERENCES)
        .preferred_hash_algorithms(DEFAULT_HASH_PREFERENCES)
        .preferred_compression_algorithms(DEFAULT_COMPRESSION_PREFERENCES)
    )


@pytest.mark.parametrize("version", [4, 6])
def test_generate_ed25519_x25519_key_roundtrips(version: KeyVersion) -> None:
    """Adapt upstream short key-generation coverage for RFC 9580 25519 keys."""
    secret_key = (
        build_modern_signing_key(version)
        .subkey(
            SubkeyParamsBuilder()
            .version(version)
            .key_type(KeyType.x25519())
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )

    public_key = secret_key.to_public_key()

    assert secret_key.secret_subkey_count == 1
    assert public_key.public_subkey_count == 1
    assert public_key.user_ids == ["Me-X <me-25519-rfc9580@mail.com>"]
    assert secret_key.revocation_signature_infos() == []
    assert public_key.revocation_signature_infos() == []

    secret_key.verify_bindings()
    public_key.verify_bindings()

    reparsed_secret, headers = SecretKey.from_armor(secret_key.to_armored())
    assert headers == {}
    reparsed_secret.verify_bindings()
    assert reparsed_secret.fingerprint == secret_key.fingerprint

    reparsed_public, headers = PublicKey.from_armor(public_key.to_armored())
    assert headers == {}
    reparsed_public.verify_bindings()
    assert reparsed_public.fingerprint == public_key.fingerprint

    signed = sign_message(b"generated payload", reparsed_secret)
    signed_message, _ = Message.from_armor(signed)
    signed_message.verify(reparsed_public)
    assert signed_message.payload_bytes() == b"generated payload"

    encrypted = encrypt_message_to_recipient(b"hello world", reparsed_public)
    encrypted_message, _ = Message.from_armor(encrypted)
    decrypted = encrypted_message.decrypt(reparsed_secret)
    assert decrypted.payload_bytes() == b"hello world"


def test_generate_legacy_curve25519_key_matches_docs_example() -> None:
    """Adapt the docs.rs composed-module example for legacy Curve25519 generation."""
    secret_key = (
        SecretKeyParamsBuilder()
        .key_type(KeyType.ed25519_legacy())
        .can_certify(False)
        .can_sign(True)
        .primary_user_id("Me <me@example.com>")
        .preferred_symmetric_algorithms(["aes128"])
        .preferred_hash_algorithms(["sha256"])
        .preferred_compression_algorithms([])
        .subkey(
            SubkeyParamsBuilder()
            .key_type(KeyType.ecdh("curve25519"))
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )

    public_key = secret_key.to_public_key()

    secret_key.verify_bindings()
    public_key.verify_bindings()
    assert public_key.user_ids == ["Me <me@example.com>"]

    encrypted = encrypt_message_to_recipient(b"Hello World", public_key)
    encrypted_message, _ = Message.from_armor(encrypted)
    decrypted = encrypted_message.decrypt(secret_key)
    assert decrypted.payload_bytes() == b"Hello World"


@pytest.mark.parametrize("version", [4, 6])
def test_generated_key_details_expose_version_algorithm_and_creation_time(
    version: KeyVersion,
) -> None:
    """Adapt rPGP KeyDetails metadata into Python-visible certificate inspection."""

    secret_key = (
        SecretKeyParamsBuilder()
        .version(version)
        .created_at(FIXED_PRIMARY_CREATED_AT)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .can_sign(True)
        .primary_user_id("alice")
        .subkey(
            SubkeyParamsBuilder()
            .version(version)
            .created_at(FIXED_SUBKEY_CREATED_AT)
            .key_type(KeyType.x25519())
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )
    public_key = secret_key.to_public_key()

    assert secret_key.version == version
    assert public_key.version == version
    assert secret_key.created_at == FIXED_PRIMARY_CREATED_AT
    assert public_key.created_at == FIXED_PRIMARY_CREATED_AT
    assert secret_key.public_key_algorithm == "ed25519"
    assert public_key.public_key_algorithm == "ed25519"

    secret_binding = secret_key.subkey_bindings()[0]
    public_binding = public_key.subkey_bindings()[0]
    assert secret_binding.version == version
    assert public_binding.version == version
    assert secret_binding.created_at == FIXED_SUBKEY_CREATED_AT
    assert public_binding.created_at == FIXED_SUBKEY_CREATED_AT
    assert secret_binding.public_key_algorithm == "x25519"
    assert public_binding.public_key_algorithm == "x25519"

    reparsed_secret, _ = SecretKey.from_armor(secret_key.to_armored())
    reparsed_public, _ = PublicKey.from_armor(public_key.to_armored())

    assert reparsed_secret.version == version
    assert reparsed_public.version == version
    assert reparsed_secret.created_at == FIXED_PRIMARY_CREATED_AT
    assert reparsed_public.created_at == FIXED_PRIMARY_CREATED_AT
    assert reparsed_secret.public_key_algorithm == "ed25519"
    assert reparsed_public.public_key_algorithm == "ed25519"

    reparsed_secret_binding = reparsed_secret.subkey_bindings()[0]
    reparsed_public_binding = reparsed_public.subkey_bindings()[0]
    assert reparsed_secret_binding.version == version
    assert reparsed_public_binding.version == version
    assert reparsed_secret_binding.created_at == FIXED_SUBKEY_CREATED_AT
    assert reparsed_public_binding.created_at == FIXED_SUBKEY_CREATED_AT
    assert reparsed_secret_binding.public_key_algorithm == "x25519"
    assert reparsed_public_binding.public_key_algorithm == "x25519"


@pytest.mark.parametrize("version", [4, 6])
def test_generated_ecdsa_and_ecdh_public_params_expose_curve_metadata(
    version: KeyVersion,
) -> None:
    """Expose `KeyDetails.public_params()` metadata for generated P-256 keys."""

    secret_key = (
        SecretKeyParamsBuilder()
        .version(version)
        .created_at(FIXED_PRIMARY_CREATED_AT)
        .key_type(KeyType.ecdsa("p256"))
        .can_certify(True)
        .can_sign(True)
        .primary_user_id("alice")
        .subkey(
            SubkeyParamsBuilder()
            .version(version)
            .created_at(FIXED_SUBKEY_CREATED_AT)
            .key_type(KeyType.ecdh("p256"))
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )
    public_key = secret_key.to_public_key()

    for key in (secret_key, public_key):
        params = key.public_params
        assert params.kind == "ecdsa"
        assert params.curve == "p256"
        assert params.is_supported is True
        assert params.curve_bits == 256
        assert params.secret_key_length == 32
        assert params.kdf_hash_algorithm is None
        assert params.kdf_symmetric_algorithm is None
        assert params.kdf_type is None

    for binding in (secret_key.subkey_bindings()[0], public_key.subkey_bindings()[0]):
        params = binding.public_params
        assert params.kind == "ecdh"
        assert params.curve == "p256"
        assert params.is_supported is True
        assert params.curve_bits == 256
        assert params.secret_key_length == 32
        assert params.kdf_hash_algorithm == "sha256"
        assert params.kdf_symmetric_algorithm == "aes128"

    reparsed_secret, _ = SecretKey.from_armor(secret_key.to_armored())
    reparsed_public, _ = PublicKey.from_armor(public_key.to_armored())

    assert reparsed_secret.public_params.curve == "p256"
    assert reparsed_public.public_params.curve == "p256"
    assert reparsed_secret.subkey_bindings()[0].public_params.curve == "p256"
    assert reparsed_public.subkey_bindings()[0].public_params.curve == "p256"


def test_legacy_curve25519_public_params_expose_curve_metadata() -> None:
    """The docs.rs legacy example should keep Ed25519 and Curve25519 metadata."""

    secret_key = (
        SecretKeyParamsBuilder()
        .created_at(FIXED_PRIMARY_CREATED_AT)
        .key_type(KeyType.ed25519_legacy())
        .can_certify(False)
        .can_sign(True)
        .primary_user_id("Me <me@example.com>")
        .preferred_symmetric_algorithms(["aes128"])
        .preferred_hash_algorithms(["sha256"])
        .preferred_compression_algorithms([])
        .subkey(
            SubkeyParamsBuilder()
            .created_at(FIXED_SUBKEY_CREATED_AT)
            .key_type(KeyType.ecdh("curve25519"))
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )
    public_key = secret_key.to_public_key()

    for key in (secret_key, public_key):
        params = key.public_params
        assert params.kind == "eddsa-legacy"
        assert params.curve == "ed25519"
        assert params.is_supported is True
        assert params.curve_bits == 256
        assert params.secret_key_length == 32

    for binding in (secret_key.subkey_bindings()[0], public_key.subkey_bindings()[0]):
        params = binding.public_params
        assert params.kind == "ecdh"
        assert params.curve == "curve25519"
        assert params.is_supported is True
        assert params.secret_key_length == 32
        assert params.kdf_hash_algorithm == "sha256"
        assert params.kdf_symmetric_algorithm == "aes128"
        assert params.kdf_type is not None

    reparsed_secret, _ = SecretKey.from_armor(secret_key.to_armored())
    reparsed_public, _ = PublicKey.from_armor(public_key.to_armored())

    assert reparsed_secret.public_params.curve == "ed25519"
    assert reparsed_public.public_params.curve == "ed25519"
    assert reparsed_secret.subkey_bindings()[0].public_params.curve == "curve25519"
    assert reparsed_public.subkey_bindings()[0].public_params.curve == "curve25519"


def test_dsa_public_params_expose_prime_size_for_generated_and_parsed_keys() -> None:
    secret_key = (
        SecretKeyParamsBuilder()
        .created_at(FIXED_PRIMARY_CREATED_AT)
        .key_type(KeyType.dsa(1024))
        .can_certify(True)
        .can_sign(True)
        .primary_user_id("alice")
        .build()
        .generate()
    )
    public_key = secret_key.to_public_key()

    for key in (secret_key, public_key):
        params = key.public_params
        assert params.kind == "dsa"
        assert params.dsa_bits == 1024
        assert params.rsa_bits is None
        assert params.curve is None
        assert params.curve_bits is None
        assert params.secret_key_length is None

    reparsed_secret, _ = SecretKey.from_armor(secret_key.to_armored())
    reparsed_public, _ = PublicKey.from_armor(public_key.to_armored())
    assert reparsed_secret.public_params.dsa_bits == 1024
    assert reparsed_public.public_params.dsa_bits == 1024


def test_rsa_public_params_expose_modulus_size_for_generated_and_parsed_keys() -> None:
    secret_key = (
        SecretKeyParamsBuilder()
        .created_at(FIXED_PRIMARY_CREATED_AT)
        .key_type(KeyType.rsa(2048))
        .can_certify(True)
        .can_sign(True)
        .primary_user_id("alice")
        .build()
        .generate()
    )
    public_key = secret_key.to_public_key()

    for key in (secret_key, public_key):
        params = key.public_params
        assert params.kind == "rsa"
        assert params.rsa_bits == 2048
        assert params.dsa_bits is None
        assert params.curve is None
        assert params.curve_bits is None
        assert params.secret_key_length is None

    reparsed_secret, _ = SecretKey.from_armor(secret_key.to_armored())
    reparsed_public, _ = PublicKey.from_armor(public_key.to_armored())
    assert reparsed_secret.public_params.rsa_bits == 2048
    assert reparsed_public.public_params.rsa_bits == 2048

    fixture_public_key, _ = PublicKey.from_armor(
        read_fixture_text("rsa-rsa-sample-1.asc")
    )
    assert fixture_public_key.public_params.rsa_bits == 2048
    assert fixture_public_key.subkey_bindings()[0].public_params.rsa_bits == 2048


def test_legacy_curve25519_key_details_expose_algorithm_categories() -> None:
    """The docs.rs legacy Curve25519 example exposes legacy and ECDH algorithm metadata."""

    secret_key = (
        SecretKeyParamsBuilder()
        .created_at(FIXED_PRIMARY_CREATED_AT)
        .key_type(KeyType.ed25519_legacy())
        .can_certify(False)
        .can_sign(True)
        .primary_user_id("Me <me@example.com>")
        .preferred_symmetric_algorithms(["aes128"])
        .preferred_hash_algorithms(["sha256"])
        .preferred_compression_algorithms([])
        .subkey(
            SubkeyParamsBuilder()
            .created_at(FIXED_SUBKEY_CREATED_AT)
            .key_type(KeyType.ecdh("curve25519"))
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )
    public_key = secret_key.to_public_key()

    assert secret_key.public_key_algorithm == "eddsa-legacy"
    assert public_key.public_key_algorithm == "eddsa-legacy"
    assert secret_key.created_at == FIXED_PRIMARY_CREATED_AT
    assert public_key.created_at == FIXED_PRIMARY_CREATED_AT

    secret_binding = secret_key.subkey_bindings()[0]
    public_binding = public_key.subkey_bindings()[0]
    assert secret_binding.public_key_algorithm == "ecdh"
    assert public_binding.public_key_algorithm == "ecdh"
    assert secret_binding.created_at == FIXED_SUBKEY_CREATED_AT
    assert public_binding.created_at == FIXED_SUBKEY_CREATED_AT


@pytest.mark.parametrize("version", [4, 6])
def test_generate_ecdsa_p256_ecdh_p256_key_roundtrips(version: KeyVersion) -> None:
    """Adapt upstream `key_gen_ecdsa_p256_*` coverage into Python bindings."""
    secret_key = (
        SecretKeyParamsBuilder()
        .version(version)
        .key_type(KeyType.ecdsa("p256"))
        .can_certify(True)
        .can_sign(True)
        .primary_user_id("Me-X <me-ecdsa@mail.com>")
        .preferred_symmetric_algorithms(DEFAULT_SYMMETRIC_PREFERENCES)
        .preferred_hash_algorithms(DEFAULT_HASH_PREFERENCES)
        .preferred_compression_algorithms(DEFAULT_COMPRESSION_PREFERENCES)
        .subkey(
            SubkeyParamsBuilder()
            .version(version)
            .key_type(KeyType.ecdh("p256"))
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )

    public_key = secret_key.to_public_key()
    secret_key.verify_bindings()
    public_key.verify_bindings()
    assert public_key.user_ids == ["Me-X <me-ecdsa@mail.com>"]


def test_generate_passphrase_protected_key_requires_password_for_signing() -> None:
    """Adapt the encrypted-key generation flow from upstream builder tests."""
    protected_key = (
        build_modern_signing_key(6)
        .passphrase("hello")
        .subkey(
            SubkeyParamsBuilder()
            .version(6)
            .key_type(KeyType.x25519())
            .passphrase("hello")
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )
    public_key = protected_key.to_public_key()

    reparsed_secret, _ = SecretKey.from_armor(protected_key.to_armored())

    with pytest.raises(ValueError):
        sign_message(b"payload", reparsed_secret)

    armored = sign_message(b"payload", reparsed_secret, password="hello")
    message, _ = Message.from_armor(armored)
    message.verify(public_key)
    assert message.payload_bytes() == b"payload"

    encrypted = encrypt_message_to_recipient(b"secret", public_key)
    encrypted_message, _ = Message.from_armor(encrypted)
    assert (
        encrypted_message.decrypt(reparsed_secret, "hello").payload_bytes() == b"secret"
    )


@pytest.mark.parametrize(
    ("builder", "match"),
    [
        (
            lambda: (
                SecretKeyParamsBuilder()
                .version(4)
                .key_type(KeyType.ed25519())
                .can_certify(True)
                .can_sign(True)
                .preferred_symmetric_algorithms(AES256_ONLY)
                .preferred_hash_algorithms(SHA512_ONLY)
                .preferred_compression_algorithms(ZLIB_ONLY)
                .subkey(
                    SubkeyParamsBuilder()
                    .version(4)
                    .key_type(KeyType.x25519())
                    .can_encrypt(EncryptionCaps.all())
                    .build()
                )
            ),
            "V4 keys must have a primary User ID",
        ),
        (
            lambda: (
                SecretKeyParamsBuilder()
                .version(6)
                .key_type(KeyType.ed25519())
                .can_certify(True)
                .can_sign(True)
                .primary_user_id("alice")
                .preferred_symmetric_algorithms(AES256_ONLY)
                .preferred_hash_algorithms(SHA512_ONLY)
                .preferred_compression_algorithms(ZLIB_ONLY)
                .subkey(
                    SubkeyParamsBuilder()
                    .version(4)
                    .key_type(KeyType.x25519())
                    .can_encrypt(EncryptionCaps.all())
                    .build()
                )
            ),
            "V6 primary key may not be combined with V4 subkey",
        ),
        (
            lambda: (
                SecretKeyParamsBuilder()
                .version(4)
                .key_type(KeyType.ed25519())
                .can_certify(True)
                .can_sign(True)
                .primary_user_id("alice")
                .preferred_symmetric_algorithms(AES256_ONLY)
                .preferred_hash_algorithms(SHA512_ONLY)
                .preferred_compression_algorithms(ZLIB_ONLY)
                .subkey(
                    SubkeyParamsBuilder()
                    .version(6)
                    .key_type(KeyType.x25519())
                    .can_encrypt(EncryptionCaps.all())
                    .build()
                )
            ),
            "primary key may not be combined with V6 subkey",
        ),
    ],
)
def test_builder_validation_errors_are_exposed_to_python(
    builder: Callable[[], SecretKeyParamsBuilder],
    match: str,
) -> None:
    """Adapt upstream builder validation failures into Python exceptions."""
    with pytest.raises(ValueError, match=match):
        builder().build()


@pytest.mark.parametrize(
    ("builder", "match"),
    [
        (
            lambda: (
                SecretKeyParamsBuilder()
                .version(6)
                .key_type(KeyType.ed25519())
                .can_certify(True)
                .can_sign(True)
                .primary_user_id("alice")
                .subkey(
                    SubkeyParamsBuilder()
                    .version(6)
                    .key_type(KeyType.x25519())
                    .can_sign(True)
                    .build()
                )
            ),
            "can not be used for signing keys",
        ),
        (
            lambda: (
                SecretKeyParamsBuilder()
                .version(6)
                .key_type(KeyType.ed25519())
                .can_certify(True)
                .can_sign(True)
                .primary_user_id("alice")
                .subkey(
                    SubkeyParamsBuilder()
                    .version(6)
                    .key_type(KeyType.ed25519())
                    .can_encrypt(EncryptionCaps.all())
                    .build()
                )
            ),
            "can not be used for encryption keys",
        ),
    ],
)
def test_key_type_validation_errors_are_exposed_to_python(
    builder: Callable[[], SecretKeyParamsBuilder],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        builder().build()


def test_key_type_capability_helpers_match_upstream_semantics() -> None:
    assert KeyType.ed25519().can_sign() is True
    assert KeyType.ed25519().can_encrypt() is False
    assert KeyType.x25519().can_sign() is False
    assert KeyType.x25519().can_encrypt() is True
    assert KeyType.rsa(2048).can_sign() is True
    assert KeyType.rsa(2048).can_encrypt() is True


def test_signing_capable_subkey_generation_verifies_bindings() -> None:
    """Adapt upstream `signing_capable_subkey` coverage with Python-visible assertions."""
    secret_key = (
        SecretKeyParamsBuilder()
        .version(6)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .primary_user_id("alice")
        .subkey(
            SubkeyParamsBuilder()
            .version(6)
            .key_type(KeyType.ed25519())
            .can_sign(True)
            .build()
        )
        .build()
        .generate()
    )

    public_key = secret_key.to_public_key()

    assert secret_key.secret_subkey_count == 1
    assert public_key.public_subkey_count == 1
    secret_key.verify_bindings()
    public_key.verify_bindings()


def test_signing_capable_subkey_bindings_expose_embedded_primary_key_binding() -> None:
    """Adapt upstream `signing_capable_subkey` to Python-visible subkey binding metadata."""
    secret_key = (
        SecretKeyParamsBuilder()
        .version(6)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .primary_user_id("alice")
        .subkey(
            SubkeyParamsBuilder()
            .version(6)
            .key_type(KeyType.ed25519())
            .can_sign(True)
            .build()
        )
        .build()
        .generate()
    )
    public_key = secret_key.to_public_key()

    secret_binding = secret_key.subkey_bindings()[0]
    public_binding = public_key.subkey_bindings()[0]

    assert secret_binding.fingerprint == public_binding.fingerprint
    assert secret_binding.key_id == public_binding.key_id

    secret_signature = secret_binding.signatures[0]
    public_signature = public_binding.signatures[0]
    assert secret_signature.signature_type == "subkey-binding"
    assert public_signature.signature_type == "subkey-binding"
    assert secret_signature.key_flags.sign is True
    assert public_signature.key_flags.sign is True

    secret_embedded = secret_signature.embedded_signature
    public_embedded = public_signature.embedded_signature
    assert secret_embedded is not None
    assert public_embedded is not None
    assert secret_embedded.signature_type == "primary-key-binding"
    assert public_embedded.signature_type == "primary-key-binding"

    reparsed_secret, _ = SecretKey.from_armor(secret_key.to_armored())
    reparsed_public, _ = PublicKey.from_armor(public_key.to_armored())
    assert (
        reparsed_secret.subkey_bindings()[0].signatures[0].embedded_signature
        is not None
    )
    assert (
        reparsed_public.subkey_bindings()[0].signatures[0].embedded_signature
        is not None
    )


def test_encryption_subkey_bindings_expose_key_flags_without_embedded_signature() -> (
    None
):
    """Encryption subkey bindings expose key flags without a back-signature."""
    secret_key = (
        build_modern_signing_key(6)
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
    public_key = secret_key.to_public_key()

    secret_signature = secret_key.subkey_bindings()[0].signatures[0]
    public_signature = public_key.subkey_bindings()[0].signatures[0]

    assert secret_signature.signature_type == "subkey-binding"
    assert public_signature.signature_type == "subkey-binding"
    assert secret_signature.key_flags.sign is False
    assert public_signature.key_flags.sign is False
    assert secret_signature.key_flags.encrypt_communications is True
    assert public_signature.key_flags.encrypt_communications is True
    assert secret_signature.key_flags.encrypt_storage is True
    assert public_signature.key_flags.encrypt_storage is True
    assert secret_signature.embedded_signature is None
    assert public_signature.embedded_signature is None


def build_certificate_metadata_key(
    version: KeyVersion,
    *,
    primary_user_id: str | None,
    feature_seipd_v1: bool = True,
    feature_seipd_v2: bool = False,
) -> SecretKey:
    """Adapt upstream certificate-metadata builder coverage into reusable helpers."""
    builder = (
        SecretKeyParamsBuilder()
        .version(version)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .can_sign(True)
        .feature_seipd_v1(feature_seipd_v1)
        .feature_seipd_v2(feature_seipd_v2)
        .preferred_symmetric_algorithms(AES256_ONLY)
        .preferred_hash_algorithms(SHA512_ONLY)
        .preferred_compression_algorithms(ZLIB_ONLY)
        .subkey(
            SubkeyParamsBuilder()
            .version(version)
            .key_type(KeyType.x25519())
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
    )
    if primary_user_id is not None:
        builder = builder.primary_user_id(primary_user_id)
    return builder.build().generate()


def assert_certificate_preferences_are_exposed_on_signature(
    info: SignatureInfo,
    *,
    has_features: bool,
    seipd_v1: bool,
    seipd_v2: bool,
) -> None:
    """Assert the self-signature metadata surfaced from upstream certificate builders."""
    assert info.preferred_symmetric_algorithms == ["aes256"]
    assert info.preferred_hash_algorithms == ["sha512"]
    assert info.preferred_compression_algorithms == ["zlib"]
    assert info.preferred_aead_algorithms == []
    assert info.preferred_key_server is None
    assert info.notations == []
    assert info.policy_uri is None
    assert info.revocation_key is None
    assert info.revocation_reason_code is None
    assert info.revocation_reason is None
    assert info.is_revocable is True
    assert info.exportable_certification is True
    assert info.key_flags.certify is True
    assert info.key_flags.sign is True
    assert info.key_flags.encrypt_communications is False
    assert info.key_flags.encrypt_storage is False
    assert info.key_flags.authenticate is False

    if has_features:
        assert info.features is not None
        assert info.features.seipd_v1 is seipd_v1
        assert info.features.seipd_v2 is seipd_v2
    else:
        assert info.features is None


def test_v4_certificate_metadata_is_exposed_on_primary_user_binding_signature() -> None:
    """Adapt upstream `test_cert_metadata_gen_v4_v4` into Python-visible metadata access."""
    secret_key = build_certificate_metadata_key(4, primary_user_id="alice")
    public_key = secret_key.to_public_key()

    assert secret_key.direct_signature_infos() == []
    assert public_key.direct_signature_infos() == []

    secret_bindings = secret_key.user_bindings()
    public_bindings = public_key.user_bindings()
    assert len(secret_bindings) == 1
    assert len(public_bindings) == 1

    secret_binding = secret_bindings[0]
    public_binding = public_bindings[0]
    assert secret_binding.user_id == "alice"
    assert secret_binding.is_primary is True
    assert len(secret_binding.signatures) == 1
    assert public_binding.user_id == "alice"
    assert public_binding.is_primary is True
    assert len(public_binding.signatures) == 1

    secret_info = secret_binding.signatures[0]
    public_info = public_binding.signatures[0]
    assert secret_info.signature_type == "cert-positive"
    assert public_info.signature_type == "cert-positive"
    assert_certificate_preferences_are_exposed_on_signature(
        secret_info,
        has_features=True,
        seipd_v1=True,
        seipd_v2=False,
    )
    assert_certificate_preferences_are_exposed_on_signature(
        public_info,
        has_features=True,
        seipd_v1=True,
        seipd_v2=False,
    )


def test_v6_certificate_metadata_moves_to_direct_key_signature() -> None:
    """Adapt upstream `test_cert_metadata_gen_v6_v6` into Python-visible metadata access."""
    secret_key = build_certificate_metadata_key(
        6,
        primary_user_id="alice",
        feature_seipd_v2=True,
    )
    public_key = secret_key.to_public_key()

    secret_direct_signatures = secret_key.direct_signature_infos()
    public_direct_signatures = public_key.direct_signature_infos()
    assert len(secret_direct_signatures) == 1
    assert len(public_direct_signatures) == 1

    secret_direct = secret_direct_signatures[0]
    public_direct = public_direct_signatures[0]
    assert secret_direct.signature_type == "direct-key"
    assert public_direct.signature_type == "direct-key"
    assert_certificate_preferences_are_exposed_on_signature(
        secret_direct,
        has_features=True,
        seipd_v1=True,
        seipd_v2=True,
    )
    assert_certificate_preferences_are_exposed_on_signature(
        public_direct,
        has_features=True,
        seipd_v1=True,
        seipd_v2=True,
    )

    secret_binding = secret_key.user_bindings()[0]
    public_binding = public_key.user_bindings()[0]
    secret_binding_info = secret_binding.signatures[0]
    public_binding_info = public_binding.signatures[0]
    assert secret_binding.user_id == "alice"
    assert secret_binding.is_primary is True
    assert public_binding.user_id == "alice"
    assert public_binding.is_primary is True
    assert secret_binding_info.preferred_symmetric_algorithms == []
    assert secret_binding_info.preferred_hash_algorithms == []
    assert secret_binding_info.preferred_compression_algorithms == []
    assert secret_binding_info.preferred_aead_algorithms == []
    assert public_binding_info.preferred_symmetric_algorithms == []
    assert public_binding_info.preferred_hash_algorithms == []
    assert public_binding_info.preferred_compression_algorithms == []
    assert public_binding_info.preferred_aead_algorithms == []
    assert secret_binding_info.key_flags.certify is False
    assert secret_binding_info.key_flags.sign is False
    assert public_binding_info.key_flags.certify is False
    assert public_binding_info.key_flags.sign is False
    assert secret_binding_info.features is None
    assert public_binding_info.features is None


def test_v6_id_less_certificate_still_exposes_direct_key_signature_metadata() -> None:
    """Adapt upstream `test_cert_metadata_gen_v6_v6_id_less` into Python-visible metadata access."""
    secret_key = build_certificate_metadata_key(
        6,
        primary_user_id=None,
        feature_seipd_v1=False,
        feature_seipd_v2=True,
    )
    public_key = secret_key.to_public_key()

    assert secret_key.user_bindings() == []
    assert public_key.user_bindings() == []

    secret_direct = secret_key.direct_signature_infos()
    public_direct = public_key.direct_signature_infos()
    assert len(secret_direct) == 1
    assert len(public_direct) == 1
    assert_certificate_preferences_are_exposed_on_signature(
        secret_direct[0],
        has_features=True,
        seipd_v1=False,
        seipd_v2=True,
    )
    assert_certificate_preferences_are_exposed_on_signature(
        public_direct[0],
        has_features=True,
        seipd_v1=False,
        seipd_v2=True,
    )


def test_user_attribute_image_packets_roundtrip_from_builder() -> None:
    """Adapt upstream `UserAttribute::new_image` behavior into builder coverage."""
    portrait = UserAttribute.image_jpeg(JPEG_USER_ATTRIBUTE_DATA)

    secret_key = build_modern_signing_key(4).user_attribute(portrait).build().generate()
    public_key = secret_key.to_public_key()

    secret_attributes = secret_key.user_attribute_bindings()
    public_attributes = public_key.user_attribute_bindings()
    assert len(secret_attributes) == 1
    assert len(public_attributes) == 1

    secret_attribute = secret_attributes[0]
    public_attribute = public_attributes[0]
    assert secret_attribute.user_attribute.kind == "image"
    assert public_attribute.user_attribute.kind == "image"
    assert secret_attribute.user_attribute.image_header_version == 1
    assert public_attribute.user_attribute.image_header_version == 1
    assert secret_attribute.user_attribute.image_format == "jpeg"
    assert public_attribute.user_attribute.image_format == "jpeg"
    assert secret_attribute.user_attribute.data == JPEG_USER_ATTRIBUTE_DATA
    assert public_attribute.user_attribute.data == JPEG_USER_ATTRIBUTE_DATA
    assert len(secret_attribute.signatures) == 1
    assert len(public_attribute.signatures) == 1
    assert secret_attribute.signatures[0].signature_type == "cert-positive"
    assert public_attribute.signatures[0].signature_type == "cert-positive"

    reparsed_secret, _ = SecretKey.from_armor(secret_key.to_armored())
    reparsed_public, _ = PublicKey.from_armor(public_key.to_armored())
    assert (
        reparsed_secret.user_attribute_bindings()[0].user_attribute.data
        == JPEG_USER_ATTRIBUTE_DATA
    )
    assert (
        reparsed_public.user_attribute_bindings()[0].user_attribute.data
        == JPEG_USER_ATTRIBUTE_DATA
    )


@pytest.mark.parametrize("version", [4, 6])
def test_user_attribute_sequence_builder_preserves_order(version: KeyVersion) -> None:
    """Adapt upstream builder list semantics for user-attribute sequences."""
    first = UserAttribute.image_jpeg(bytes.fromhex("ffd8ffdb00"))
    second = UserAttribute.image_jpeg(bytes.fromhex("ffd8ffee010203"))

    secret_key = (
        build_modern_signing_key(version)
        .user_attributes([first, second])
        .build()
        .generate()
    )

    attributes = secret_key.user_attribute_bindings()
    assert [binding.user_attribute.data for binding in attributes] == [
        bytes.fromhex("ffd8ffdb00"),
        bytes.fromhex("ffd8ffee010203"),
    ]
    for binding in attributes:
        assert binding.user_attribute.kind == "image"
        assert binding.user_attribute.image_format == "jpeg"
        assert binding.user_attribute.image_header_version == 1
        assert len(binding.signatures) == 1
        assert binding.signatures[0].signature_type == "cert-positive"


def test_s2k_params_reject_argon2_with_cfb_usage() -> None:
    """RFC 9580 forbids Argon2 S2K outside AEAD usage modes."""
    with pytest.raises(
        ValueError,
        match="Argon2 String-to-Key may only be used with AEAD S2K parameters",
    ):
        S2kParams.cfb("aes256", StringToKey.argon2(3, 4, 16))


def test_generate_passphrase_protected_key_supports_explicit_v4_cfb_s2k() -> None:
    """Adapt upstream secret-key S2K coverage to the builder API for V4 keys."""
    primary_s2k = S2kParams.cfb(
        "aes256",
        StringToKey.iterated(
            "sha512",
            96,
            salt=bytes.fromhex("0011223344556677"),
        ),
        iv=bytes.fromhex("00112233445566778899aabbccddeeff"),
    )
    subkey_s2k = S2kParams.cfb(
        "aes192",
        StringToKey.iterated(
            "sha256",
            224,
            salt=bytes.fromhex("8899aabbccddeeff"),
        ),
        iv=bytes.fromhex("ffeeddccbbaa99887766554433221100"),
    )

    protected_key = (
        build_modern_signing_key(4)
        .passphrase("hello")
        .s2k(primary_s2k)
        .subkey(
            SubkeyParamsBuilder()
            .version(4)
            .key_type(KeyType.x25519())
            .passphrase("hello")
            .s2k(subkey_s2k)
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )
    public_key = protected_key.to_public_key()

    reparsed_secret, _ = SecretKey.from_armor(protected_key.to_armored())

    primary_protection = reparsed_secret.primary_secret_s2k()
    assert primary_protection is not None
    assert primary_protection.usage == "cfb"
    assert primary_protection.symmetric_algorithm == "aes256"
    assert primary_protection.aead_algorithm is None
    assert primary_protection.iv == bytes.fromhex("00112233445566778899aabbccddeeff")
    assert primary_protection.nonce is None
    primary_string_to_key = primary_protection.string_to_key
    assert primary_string_to_key is not None
    assert primary_string_to_key.kind == "iterated-salted"
    assert primary_string_to_key.hash_algorithm == "sha512"
    assert primary_string_to_key.salt == bytes.fromhex("0011223344556677")
    assert primary_string_to_key.count == 96
    assert primary_string_to_key.passes is None
    assert primary_string_to_key.parallelism is None
    assert primary_string_to_key.memory_exponent is None

    subkey_protections = reparsed_secret.secret_subkey_s2ks()
    assert len(subkey_protections) == 1
    subkey_protection = subkey_protections[0]
    assert subkey_protection is not None
    assert subkey_protection.usage == "cfb"
    assert subkey_protection.symmetric_algorithm == "aes192"
    assert subkey_protection.aead_algorithm is None
    assert subkey_protection.iv == bytes.fromhex("ffeeddccbbaa99887766554433221100")
    assert subkey_protection.nonce is None
    subkey_string_to_key = subkey_protection.string_to_key
    assert subkey_string_to_key is not None
    assert subkey_string_to_key.kind == "iterated-salted"
    assert subkey_string_to_key.hash_algorithm == "sha256"
    assert subkey_string_to_key.salt == bytes.fromhex("8899aabbccddeeff")
    assert subkey_string_to_key.count == 224
    assert subkey_string_to_key.passes is None
    assert subkey_string_to_key.parallelism is None
    assert subkey_string_to_key.memory_exponent is None

    armored = sign_message(b"payload", reparsed_secret, password="hello")
    message, _ = Message.from_armor(armored)
    message.verify(public_key)
    assert message.payload_bytes() == b"payload"

    encrypted = encrypt_message_to_recipient(b"secret", public_key)
    encrypted_message, _ = Message.from_armor(encrypted)
    assert (
        encrypted_message.decrypt(reparsed_secret, "hello").payload_bytes() == b"secret"
    )


def test_generate_passphrase_protected_key_supports_explicit_v6_aead_s2k() -> None:
    """Adapt upstream Argon2-based S2K docs to explicit V6 builder control."""
    primary_s2k = S2kParams.aead(
        "aes256",
        "ocb",
        StringToKey.argon2(
            passes=3,
            parallelism=4,
            memory_exponent=16,
            salt=bytes.fromhex("00112233445566778899aabbccddeeff"),
        ),
        nonce=bytes.fromhex("00112233445566778899aabbccddee"),
    )
    subkey_s2k = S2kParams.aead(
        "aes128",
        "gcm",
        StringToKey.argon2(
            passes=1,
            parallelism=2,
            memory_exponent=18,
            salt=bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        ),
        nonce=bytes.fromhex("00112233445566778899aabb"),
    )

    protected_key = (
        build_modern_signing_key(6)
        .passphrase("hello")
        .s2k(primary_s2k)
        .subkey(
            SubkeyParamsBuilder()
            .version(6)
            .key_type(KeyType.x25519())
            .passphrase("hello")
            .s2k(subkey_s2k)
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )
    public_key = protected_key.to_public_key()

    reparsed_secret, _ = SecretKey.from_armor(protected_key.to_armored())

    primary_protection = reparsed_secret.primary_secret_s2k()
    assert primary_protection is not None
    assert primary_protection.usage == "aead"
    assert primary_protection.symmetric_algorithm == "aes256"
    assert primary_protection.aead_algorithm == "ocb"
    assert primary_protection.iv is None
    assert primary_protection.nonce == bytes.fromhex("00112233445566778899aabbccddee")
    primary_string_to_key = primary_protection.string_to_key
    assert primary_string_to_key is not None
    assert primary_string_to_key.kind == "argon2"
    assert primary_string_to_key.hash_algorithm is None
    assert primary_string_to_key.salt == bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )
    assert primary_string_to_key.count is None
    assert primary_string_to_key.passes == 3
    assert primary_string_to_key.parallelism == 4
    assert primary_string_to_key.memory_exponent == 16

    subkey_protections = reparsed_secret.secret_subkey_s2ks()
    assert len(subkey_protections) == 1
    subkey_protection = subkey_protections[0]
    assert subkey_protection is not None
    assert subkey_protection.usage == "aead"
    assert subkey_protection.symmetric_algorithm == "aes128"
    assert subkey_protection.aead_algorithm == "gcm"
    assert subkey_protection.iv is None
    assert subkey_protection.nonce == bytes.fromhex("00112233445566778899aabb")
    subkey_string_to_key = subkey_protection.string_to_key
    assert subkey_string_to_key is not None
    assert subkey_string_to_key.kind == "argon2"
    assert subkey_string_to_key.hash_algorithm is None
    assert subkey_string_to_key.salt == bytes.fromhex(
        "ffeeddccbbaa99887766554433221100"
    )
    assert subkey_string_to_key.count is None
    assert subkey_string_to_key.passes == 1
    assert subkey_string_to_key.parallelism == 2
    assert subkey_string_to_key.memory_exponent == 18

    armored = sign_message(b"payload", reparsed_secret, password="hello")
    message, _ = Message.from_armor(armored)
    message.verify(public_key)
    assert message.payload_bytes() == b"payload"

    encrypted = encrypt_message_to_recipient(b"secret", public_key)
    encrypted_message, _ = Message.from_armor(encrypted)
    assert (
        encrypted_message.decrypt(reparsed_secret, "hello").payload_bytes() == b"secret"
    )


def test_packet_version_builder_controls_primary_and_subkey_packet_framing() -> None:
    """Adapt the upstream packet-header version builder knobs into Python-visible bytes."""
    secret_key = (
        build_modern_signing_key(4)
        .packet_version(PacketHeaderVersion.old())
        .subkey(
            SubkeyParamsBuilder()
            .version(4)
            .key_type(KeyType.x25519())
            .packet_version(PacketHeaderVersion.new())
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )

    secret_headers = parse_packet_headers(secret_key.to_bytes())
    public_headers = parse_packet_headers(secret_key.to_public_key().to_bytes())

    assert [(header.tag, header.version) for header in secret_headers] == [
        (SECRET_KEY_TAG, "old"),
        (13, "new"),
        (2, "new"),
        (SECRET_SUBKEY_TAG, "new"),
        (2, "new"),
    ]
    assert [(header.tag, header.version) for header in public_headers] == [
        (PUBLIC_KEY_TAG, "old"),
        (13, "new"),
        (2, "new"),
        (PUBLIC_SUBKEY_TAG, "new"),
        (2, "new"),
    ]


@pytest.mark.parametrize(
    ("expected_version", "packet_version"),
    [("old", PacketHeaderVersion.old()), ("new", PacketHeaderVersion.new())],
)
def test_packet_version_roundtrips_through_secret_and_public_serialization(
    expected_version: Literal["old", "new"],
    packet_version: PacketHeaderVersion,
) -> None:
    """Packet framing should survive serialization and reparsing for generated certificates."""
    secret_key = (
        build_modern_signing_key(4)
        .packet_version(packet_version)
        .subkey(
            SubkeyParamsBuilder()
            .version(4)
            .key_type(KeyType.x25519())
            .packet_version(packet_version)
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )

    reparsed_secret = SecretKey.from_bytes(secret_key.to_bytes())
    reparsed_public = PublicKey.from_bytes(secret_key.to_public_key().to_bytes())

    assert [
        header.version
        for header in parse_packet_headers(reparsed_secret.to_bytes())
        if header.tag in {SECRET_KEY_TAG, SECRET_SUBKEY_TAG}
    ] == [
        expected_version,
        expected_version,
    ]
    assert [
        header.version
        for header in parse_packet_headers(reparsed_public.to_bytes())
        if header.tag in {PUBLIC_KEY_TAG, PUBLIC_SUBKEY_TAG}
    ] == [
        expected_version,
        expected_version,
    ]


def test_packet_header_version_instances_compare_by_value() -> None:
    """PacketHeaderVersion values should support typed inspection and equality checks."""

    assert PacketHeaderVersion.old().name == "old"
    assert PacketHeaderVersion.new().name == "new"
    assert PacketHeaderVersion.old() == PacketHeaderVersion.old()
    assert PacketHeaderVersion.new() == PacketHeaderVersion.new()
    assert PacketHeaderVersion.old() != PacketHeaderVersion.new()


@pytest.mark.parametrize(
    (
        "expected_primary_version",
        "expected_subkey_version",
        "primary_packet_version",
        "subkey_packet_version",
    ),
    [
        ("old", "new", PacketHeaderVersion.old(), PacketHeaderVersion.new()),
        ("new", "old", PacketHeaderVersion.new(), PacketHeaderVersion.old()),
    ],
)
def test_packet_version_is_exposed_on_keys_and_subkey_bindings(
    expected_primary_version: Literal["old", "new"],
    expected_subkey_version: Literal["old", "new"],
    primary_packet_version: PacketHeaderVersion,
    subkey_packet_version: PacketHeaderVersion,
) -> None:
    """Packet framing should be inspectable directly on generated keys and subkeys."""

    secret_key = (
        build_modern_signing_key(6)
        .packet_version(primary_packet_version)
        .subkey(
            SubkeyParamsBuilder()
            .version(6)
            .key_type(KeyType.x25519())
            .packet_version(subkey_packet_version)
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )
    public_key = secret_key.to_public_key()

    assert secret_key.packet_version == primary_packet_version
    assert public_key.packet_version == primary_packet_version
    assert secret_key.packet_version.name == expected_primary_version
    assert public_key.packet_version.name == expected_primary_version
    assert secret_key.subkey_bindings()[0].packet_version == subkey_packet_version
    assert public_key.subkey_bindings()[0].packet_version == subkey_packet_version
    assert (
        secret_key.subkey_bindings()[0].packet_version.name == expected_subkey_version
    )
    assert (
        public_key.subkey_bindings()[0].packet_version.name == expected_subkey_version
    )

    reparsed_secret = SecretKey.from_bytes(secret_key.to_bytes())
    reparsed_public = PublicKey.from_bytes(public_key.to_bytes())
    assert reparsed_secret.packet_version == primary_packet_version
    assert reparsed_public.packet_version == primary_packet_version
    assert reparsed_secret.subkey_bindings()[0].packet_version == subkey_packet_version
    assert reparsed_public.subkey_bindings()[0].packet_version == subkey_packet_version

    assert [
        header.version
        for header in parse_packet_headers(secret_key.to_bytes())
        if header.tag in {SECRET_KEY_TAG, SECRET_SUBKEY_TAG}
    ] == [
        expected_primary_version,
        expected_subkey_version,
    ]
    assert [
        header.version
        for header in parse_packet_headers(public_key.to_bytes())
        if header.tag in {PUBLIC_KEY_TAG, PUBLIC_SUBKEY_TAG}
    ] == [
        expected_primary_version,
        expected_subkey_version,
    ]
