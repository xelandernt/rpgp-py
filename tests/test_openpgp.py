import io
import json
import os
from pathlib import Path
from typing import Any, TypedDict, cast

import pytest

from openpgp.util import (
    encrypt_session_key_to_recipient,
    encrypt_session_key_with_password,
    sign_cleartext_message_many as _openpgp_sign_cleartext_message_many,
)
from openpgp.composed import (
    ArmorOptions,
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
from openpgp.packet import Signature
from openpgp.types import StringToKey


FIXTURES = Path(__file__).resolve().parent / "fixtures"
MULTI_OBJECT_DESERIALIZATION_FIXTURES = FIXTURES / "multi-object-deserialization"
BUNDLED_KEY_FINGERPRINTS = [
    "d1a66e1a23b182c9980f788cfbfcc82a015e7330",
    "cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9",
]
BUNDLED_SIGNATURE_HASH_ALGORITHMS = ["sha256", "sha512"]


class TestRng:
    def randbytes(self, n: int) -> bytes:
        return os.urandom(n)


def _message_builder_with_version(
    data: bytes,
    file_name: str,
    version: str,
    symmetric_algorithm: Any,
    aead_algorithm: Any,
) -> MessageBuilder:
    builder = MessageBuilder.from_bytes(file_name, data)
    if version == "seipd-v1":
        return builder.seipd_v1(symmetric_algorithm)
    if version == "seipd-v2":
        return builder.seipd_v2(symmetric_algorithm, aead_algorithm)
    raise ValueError(f"unsupported encryption version: {version}")


def _sign_message(
    data: bytes,
    signer: Any,
    password: str | None = None,
    file_name: str = "",
    hash_algorithm: Any = "sha256",
) -> str:
    return (
        MessageBuilder.from_bytes(file_name, data)
        .sign(signer, password, hash_algorithm)
        .to_armored_string()
    )


def _sign_message_many(
    data: bytes,
    signers: list[Any],
    passwords: list[str | None] | None = None,
    file_name: str = "",
    hash_algorithm: Any = "sha256",
) -> str:
    passwords = passwords or [None] * len(signers)
    builder = MessageBuilder.from_bytes(file_name, data)
    for signer, password in zip(signers, passwords):
        builder.sign(signer, password, hash_algorithm)
    return builder.to_armored_string()


def _encrypt_message_to_recipient(
    data: bytes,
    recipient: Any,
    file_name: str = "",
    version: str = "seipd-v2",
    symmetric_algorithm: Any = "aes256",
    aead_algorithm: Any = "ocb",
    compression: Any | None = None,
    session_key: bytes | None = None,
    anonymous_recipient: bool = False,
) -> str:
    return _encrypt_message_to_recipients(
        data,
        [recipient],
        file_name,
        version,
        symmetric_algorithm,
        aead_algorithm,
        compression,
        session_key,
        anonymous_recipient,
    )


def _encrypt_message_to_recipient_bytes(
    data: bytes,
    recipient: Any,
    file_name: str = "",
    version: str = "seipd-v2",
    symmetric_algorithm: Any = "aes256",
    aead_algorithm: Any = "ocb",
    compression: Any | None = None,
    session_key: bytes | None = None,
    anonymous_recipient: bool = False,
) -> bytes:
    return _encrypt_message_to_recipients_bytes(
        data,
        [recipient],
        file_name,
        version,
        symmetric_algorithm,
        aead_algorithm,
        compression,
        session_key,
        anonymous_recipient,
    )


def _encrypt_message_to_recipients(
    data: bytes,
    recipients: list[Any],
    file_name: str = "",
    version: str = "seipd-v2",
    symmetric_algorithm: Any = "aes256",
    aead_algorithm: Any = "ocb",
    compression: Any | None = None,
    session_key: bytes | None = None,
    anonymous_recipient: bool = False,
) -> str:
    return _configure_recipient_message_builder(
        data,
        recipients,
        file_name,
        version,
        symmetric_algorithm,
        aead_algorithm,
        compression,
        session_key,
        anonymous_recipient,
    ).to_armored_string()


def _encrypt_message_to_recipients_bytes(
    data: bytes,
    recipients: list[Any],
    file_name: str = "",
    version: str = "seipd-v2",
    symmetric_algorithm: Any = "aes256",
    aead_algorithm: Any = "ocb",
    compression: Any | None = None,
    session_key: bytes | None = None,
    anonymous_recipient: bool = False,
) -> bytes:
    return _configure_recipient_message_builder(
        data,
        recipients,
        file_name,
        version,
        symmetric_algorithm,
        aead_algorithm,
        compression,
        session_key,
        anonymous_recipient,
    ).to_vec()


def _configure_recipient_message_builder(
    data: bytes,
    recipients: list[Any],
    file_name: str,
    version: str,
    symmetric_algorithm: Any,
    aead_algorithm: Any,
    compression: Any | None,
    session_key: bytes | None,
    anonymous_recipient: bool,
) -> MessageBuilder:
    builder = _message_builder_with_version(
        data, file_name, version, symmetric_algorithm, aead_algorithm
    )
    if compression is not None:
        builder.compression(compression)
    if session_key is not None:
        builder.set_session_key(session_key)
    for recipient in recipients:
        if anonymous_recipient:
            builder.encrypt_to_key_anonymous(recipient)
        else:
            builder.encrypt_to_key(recipient)
    return builder


def _encrypt_message_with_password(
    data: bytes,
    password: str,
    file_name: str = "",
    version: str = "seipd-v2",
    symmetric_algorithm: Any = "aes256",
    aead_algorithm: Any = "ocb",
    compression: Any | None = None,
    session_key: bytes | None = None,
) -> str:
    return _configure_password_message_builder(
        data,
        password,
        file_name,
        version,
        symmetric_algorithm,
        aead_algorithm,
        compression,
        session_key,
    ).to_armored_string()


def _encrypt_message_with_password_bytes(
    data: bytes,
    password: str,
    file_name: str = "",
    version: str = "seipd-v2",
    symmetric_algorithm: Any = "aes256",
    aead_algorithm: Any = "ocb",
    compression: Any | None = None,
    session_key: bytes | None = None,
) -> bytes:
    return _configure_password_message_builder(
        data,
        password,
        file_name,
        version,
        symmetric_algorithm,
        aead_algorithm,
        compression,
        session_key,
    ).to_vec()


def _configure_password_message_builder(
    data: bytes,
    password: str,
    file_name: str,
    version: str,
    symmetric_algorithm: Any,
    aead_algorithm: Any,
    compression: Any | None,
    session_key: bytes | None,
) -> MessageBuilder:
    builder = _message_builder_with_version(
        data, file_name, version, symmetric_algorithm, aead_algorithm
    )
    if compression is not None:
        builder.compression(compression)
    if session_key is not None:
        builder.set_session_key(session_key)
    return builder.encrypt_with_password(StringToKey.argon2(1, 4, 21), password)


def _sign_cleartext_message(
    text: str,
    signer: Any,
    password: str | None = None,
    hash_algorithm: Any = "sha256",
) -> str:
    return CleartextSignedMessage.sign(
        text, signer, password, hash_algorithm
    ).to_armored()


def _sign_cleartext_message_many(
    text: str,
    signers: list[Any],
    passwords: list[str | None] | None = None,
    hash_algorithm: Any = "sha256",
) -> str:
    return _openpgp_sign_cleartext_message_many(
        text, signers, passwords, hash_algorithm
    )


def read_fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()


def read_fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class OpenPGPInteropDecryptCase(TypedDict):
    type: str
    decryptKey: str
    passphrase: str
    verifyKey: str
    filename: str
    textcontent: str


def read_fixture_json(name: str) -> OpenPGPInteropDecryptCase:
    return cast(OpenPGPInteropDecryptCase, json.loads(read_fixture_text(name)))


def load_public_key_fixture(name: str) -> SignedPublicKey:
    data = read_fixture_text(name)
    try:
        public_key, _ = SignedPublicKey.from_armor(data)
    except ValueError:
        secret_key, _ = SignedSecretKey.from_armor(data)
        return secret_key.to_public_key()
    else:
        return public_key


def generate_signing_and_encryption_key(user_id: str) -> SignedSecretKey:
    return (
        SecretKeyParamsBuilder()
        .version(6)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .can_sign(True)
        .feature_seipd_v2(True)
        .primary_user_id(user_id)
        .preferred_symmetric_algorithms(["aes256", "aes192", "aes128"])
        .preferred_hash_algorithms(["sha256", "sha384", "sha512", "sha224"])
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


def generate_subkey_signing_and_encryption_key(user_id: str) -> SignedSecretKey:
    return (
        SecretKeyParamsBuilder()
        .version(6)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .can_sign(False)
        .feature_seipd_v2(True)
        .primary_user_id(user_id)
        .preferred_symmetric_algorithms(["aes256", "aes192", "aes128"])
        .preferred_hash_algorithms(["sha256", "sha384", "sha512", "sha224"])
        .preferred_compression_algorithms(["zlib", "zip"])
        .subkey(
            SubkeyParamsBuilder()
            .version(6)
            .key_type(KeyType.ed25519())
            .can_sign(True)
            .build()
        )
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


def signature_index_for_key_id(sigs: list[Signature], key_id: str) -> int:
    return next(
        index for index, sig in enumerate(sigs) if key_id in sig.issuer_key_id()
    )


def signature_index_for_fingerprint(sigs: list[Signature], fingerprint: str) -> int:
    return next(
        index
        for index, sig in enumerate(sigs)
        if fingerprint in sig.issuer_fingerprint()
    )


PUBLIC_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----"""

SECRET_KEY = """-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----"""


def test_parse_public_key_from_armor() -> None:
    key, headers = SignedPublicKey.from_armor(PUBLIC_KEY)

    assert headers == {}
    assert key.fingerprint
    assert key.key_id
    assert key.public_subkey_count == 1
    assert key.user_ids == []
    assert key.details.revocation_signatures == []
    assert SignedPublicKey.from_bytes(key.to_bytes()).fingerprint == key.fingerprint
    key.verify_bindings()


def test_parse_secret_key_and_convert_to_public() -> None:
    secret_key, headers = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    assert headers == {}
    assert secret_key.secret_subkey_count == 1
    assert public_key.public_subkey_count == 1
    assert public_key.fingerprint == secret_key.fingerprint
    assert secret_key.user_ids == public_key.user_ids
    assert secret_key.details.revocation_signatures == []
    assert public_key.details.revocation_signatures == []
    secret_key.verify_bindings()


def test_round_trip_public_key_armor() -> None:
    key, _ = SignedPublicKey.from_armor(PUBLIC_KEY)
    reparsed, headers = SignedPublicKey.from_armor(key.to_armored())

    assert headers == {}
    assert reparsed.fingerprint == key.fingerprint


def test_key_deserializers_support_many_and_file_inputs() -> None:
    public_armor = (
        MULTI_OBJECT_DESERIALIZATION_FIXTURES / "public-keys.asc"
    ).read_text()
    public_bytes = (
        MULTI_OBJECT_DESERIALIZATION_FIXTURES / "public-keys.pgp"
    ).read_bytes()
    secret_armor = (
        MULTI_OBJECT_DESERIALIZATION_FIXTURES / "secret-keys.asc"
    ).read_text()
    secret_bytes = (
        MULTI_OBJECT_DESERIALIZATION_FIXTURES / "secret-keys.pgp"
    ).read_bytes()

    public_keys, public_headers = SignedPublicKey.from_armor_many(public_armor)
    assert public_headers == {}
    assert [key.fingerprint for key in public_keys] == BUNDLED_KEY_FINGERPRINTS
    assert [
        key.fingerprint for key in SignedPublicKey.from_bytes_many(public_bytes)
    ] == (BUNDLED_KEY_FINGERPRINTS)

    secret_keys, secret_headers = SignedSecretKey.from_armor_many(secret_armor)
    assert secret_headers == {}
    assert [key.fingerprint for key in secret_keys] == BUNDLED_KEY_FINGERPRINTS
    assert [
        key.fingerprint for key in SignedSecretKey.from_bytes_many(secret_bytes)
    ] == (BUNDLED_KEY_FINGERPRINTS)

    assert (
        SignedPublicKey.from_file(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "public-keys.pgp"
        ).fingerprint
        == BUNDLED_KEY_FINGERPRINTS[0]
    )
    assert (
        SignedSecretKey.from_file(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "secret-keys.pgp"
        ).fingerprint
        == BUNDLED_KEY_FINGERPRINTS[0]
    )
    assert (
        SignedPublicKey.from_armor_file(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "public-keys.asc"
        )[0].fingerprint
        == BUNDLED_KEY_FINGERPRINTS[0]
    )
    assert (
        SignedSecretKey.from_armor_file(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "secret-keys.asc"
        )[0].fingerprint
        == BUNDLED_KEY_FINGERPRINTS[0]
    )
    assert [
        key.fingerprint
        for key in SignedPublicKey.from_file_many(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "public-keys.pgp"
        )
    ] == BUNDLED_KEY_FINGERPRINTS
    assert [
        key.fingerprint
        for key in SignedSecretKey.from_file_many(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "secret-keys.pgp"
        )
    ] == BUNDLED_KEY_FINGERPRINTS
    assert [
        key.fingerprint
        for key in SignedPublicKey.from_armor_file_many(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "public-keys.asc"
        )[0]
    ] == BUNDLED_KEY_FINGERPRINTS
    assert [
        key.fingerprint
        for key in SignedSecretKey.from_armor_file_many(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "secret-keys.asc"
        )[0]
    ] == BUNDLED_KEY_FINGERPRINTS


def test_sign_and_verify_message() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = _sign_message(b"Hello world", secret_key)
    message, headers = Message.from_armor(armored)

    assert headers == {}
    assert message.kind == "signed"
    assert message.is_signed is True
    assert message.is_literal is False
    assert message.literal_mode() == "binary"
    assert message.literal_filename() == b""
    assert message.as_data_vec() == b"Hello world"
    assert message.as_data_string() == "Hello world"
    assert message.signatures()[0].notations() == []
    assert message.signatures()[0].revocation_key() is None
    message.verify(public_key)


def test_sign_message_supports_custom_hash_algorithm() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = _sign_message(b"Hello world", secret_key, hash_algorithm="sha512")
    message, _ = Message.from_armor(armored)
    info = message.signatures()[0]

    assert info.typ() == "binary"
    assert info.hash_alg() == "sha512"
    assert info.notations() == []
    assert info.revocation_key() is None
    message.verify(public_key)


def test_sign_message_accepts_secret_subkey() -> None:
    secret_key = generate_subkey_signing_and_encryption_key(
        "Subkey Signer <subkey@example.com>"
    )
    public_key = secret_key.to_public_key()
    signing_subkey = secret_key.secret_subkeys[0]

    armored = _sign_message(b"Hello from a subkey", signing_subkey)
    message, _ = Message.from_armor(armored)
    info = message.signatures()[0]

    assert info.issuer_fingerprint() == [signing_subkey.key.fingerprint]
    message.verify(public_key)


def test_sign_message_many_supports_multiple_signers() -> None:
    first_secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    second_secret_key = generate_signing_and_encryption_key(
        "Second <second@example.com>"
    )
    first_public_key = first_secret_key.to_public_key()
    second_public_key = second_secret_key.to_public_key()

    armored = _sign_message_many(
        b"multi-signed payload",
        [first_secret_key, second_secret_key],
        hash_algorithm="sha384",
    )
    message, _ = Message.from_armor(armored)
    sigs = message.signatures()

    assert message.signature_count() == 2
    assert len(sigs) == 2
    assert {sig.typ() for sig in sigs} == {"binary"}
    assert {sig.hash_alg() for sig in sigs} == {"sha384"}

    first_index = signature_index_for_fingerprint(sigs, first_public_key.fingerprint)
    second_index = signature_index_for_fingerprint(sigs, second_public_key.fingerprint)

    assert message.verify_signature(
        first_public_key, first_index
    ).issuer_fingerprint() == [first_public_key.fingerprint]
    assert message.verify_signature(
        second_public_key, second_index
    ).issuer_fingerprint() == [second_public_key.fingerprint]


def test_sign_and_verify_detached_signature() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    payload = b"detached payload"

    signature = DetachedSignature.sign_binary_data(
        TestRng(), secret_key, None, "sha256", payload
    )
    info = signature.signature

    assert info.typ() == "binary"
    assert info.hash_alg() == "sha256"
    assert info.notations() == []
    assert info.revocation_key() is None
    signature.verify(public_key, payload)
    assert (
        signature.verify_signature(public_key, payload).signed_hash_value()
        == info.signed_hash_value()
    )

    reparsed = DetachedSignature.from_bytes(signature.to_bytes())
    reparsed.verify(public_key, payload)

    armored_signature, headers = DetachedSignature.from_armor(signature.to_armored())
    assert headers == {}


def test_detached_signature_sign_binary_accepts_secret_subkey() -> None:
    secret_key = generate_subkey_signing_and_encryption_key(
        "Detached Subkey <subkey@example.com>"
    )
    public_key = secret_key.to_public_key()
    signing_subkey = secret_key.secret_subkeys[0]
    payload = b"detached subkey payload"

    signature = DetachedSignature.sign_binary_data(
        TestRng(), signing_subkey, None, "sha256", payload
    )

    assert signature.signature.issuer_fingerprint() == [signing_subkey.key.fingerprint]
    signature.verify(public_key, payload)
    armored_signature, headers = DetachedSignature.from_armor(signature.to_armored())
    assert headers == {}
    armored_signature.verify(public_key, payload)


def test_detached_signature_deserializers_support_many_and_file_inputs() -> None:
    payload = (MULTI_OBJECT_DESERIALIZATION_FIXTURES / "payload.bin").read_bytes()
    public_keys = SignedPublicKey.from_bytes_many(
        (MULTI_OBJECT_DESERIALIZATION_FIXTURES / "public-keys.pgp").read_bytes()
    )
    assert [key.fingerprint for key in public_keys] == BUNDLED_KEY_FINGERPRINTS

    armored_signatures, headers = DetachedSignature.from_armor_many(
        (MULTI_OBJECT_DESERIALIZATION_FIXTURES / "detached-signatures.asc").read_text()
    )
    assert headers == {}
    assert [signature.signature.hash_alg() for signature in armored_signatures] == (
        BUNDLED_SIGNATURE_HASH_ALGORITHMS
    )
    assert [
        signature.signature.issuer_fingerprint()[0] for signature in armored_signatures
    ] == (BUNDLED_KEY_FINGERPRINTS)
    for signature, public_key in zip(armored_signatures, public_keys):
        signature.verify(public_key, payload)

    binary_signatures = DetachedSignature.from_bytes_many(
        (MULTI_OBJECT_DESERIALIZATION_FIXTURES / "detached-signatures.pgp").read_bytes()
    )
    assert [signature.signature.hash_alg() for signature in binary_signatures] == (
        BUNDLED_SIGNATURE_HASH_ALGORITHMS
    )
    for signature, public_key in zip(binary_signatures, public_keys):
        signature.verify(public_key, payload)

    assert (
        DetachedSignature.from_file(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "detached-signatures.pgp"
        ).signature.hash_alg()
        == "sha256"
    )
    assert (
        DetachedSignature.from_armor_file(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "detached-signatures.asc"
        )[0].signature.hash_alg()
        == "sha256"
    )

    for signature, public_key in zip(
        DetachedSignature.from_file_many(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "detached-signatures.pgp"
        ),
        public_keys,
    ):
        signature.verify(public_key, payload)
    for signature, public_key in zip(
        DetachedSignature.from_armor_file_many(
            MULTI_OBJECT_DESERIALIZATION_FIXTURES / "detached-signatures.asc"
        )[0],
        public_keys,
    ):
        signature.verify(public_key, payload)


def test_detached_signature_supports_custom_hash_algorithm_for_binary_signatures() -> (
    None
):
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    signature = DetachedSignature.sign_binary_data(
        TestRng(), secret_key, None, "sha512", b"detached payload"
    )

    assert signature.signature.hash_alg() == "sha512"
    signature.verify(public_key, b"detached payload")


def test_detached_text_signature_uses_text_verification_helpers() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    text = "hello\nworld\n"

    signature = DetachedSignature.sign_text_data(
        TestRng(), secret_key, None, "sha384", text.encode()
    )
    info = signature.signature

    assert info.typ() == "text"
    assert info.hash_alg() == "sha384"
    signature.verify_text(public_key, "hello\r\nworld\r\n")
    assert signature.verify_text_signature(public_key, text).typ() == "text"


def test_detached_signature_verifies_when_made_by_signing_subkey() -> None:
    public_key = load_public_key_fixture("subkey-signed-1/cert.asc")
    payload = (FIXTURES / "subkey-signed-1/payload.bin").read_bytes()
    signature, _ = DetachedSignature.from_armor(
        read_fixture_text("subkey-signed-1/sig.asc")
    )

    signature.verify(public_key, payload)
    info = signature.verify_signature(public_key, payload)

    assert info.typ() == "binary"
    assert info.issuer_fingerprint()
    assert public_key.fingerprint not in info.issuer_fingerprint()


def test_detached_signature_verifies_streamed_file(tmp_path: Path) -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    payload = b"streamed payload" * 4096

    signature = DetachedSignature.sign_binary_data(
        TestRng(), secret_key, None, "sha256", payload
    )
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(payload)

    signature.verify_file(public_key, artifact)
    signature.verify_file(public_key, str(artifact))
    info = signature.verify_file_signature(public_key, artifact)

    assert info.typ() == "binary"
    assert info.hash_alg() == "sha256"


def test_detached_signature_verify_file_works_with_signing_subkey() -> None:
    public_key = load_public_key_fixture("subkey-signed-1/cert.asc")
    signature, _ = DetachedSignature.from_armor(
        read_fixture_text("subkey-signed-1/sig.asc")
    )

    signature.verify_file(public_key, FIXTURES / "subkey-signed-1/payload.bin")


def test_detached_signature_verify_file_fails_against_wrong_key() -> None:
    wrong_public_key = load_public_key_fixture("ed25519-cv25519-sample-1.asc")
    signature, _ = DetachedSignature.from_armor(
        read_fixture_text("subkey-signed-1/sig.asc")
    )

    with pytest.raises(
        ValueError,
        match="does not match the certificate primary key or any bound public subkey",
    ):
        signature.verify_file(
            wrong_public_key, FIXTURES / "subkey-signed-1/payload.bin"
        )


def test_detached_signature_verify_file_raises_for_missing_path(tmp_path: Path) -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    signature = DetachedSignature.sign_binary_data(
        TestRng(), secret_key, None, "sha256", b"x"
    )

    with pytest.raises(ValueError, match="No such file"):
        signature.verify_file(public_key, tmp_path / "does-not-exist.bin")


def test_detached_signature_fails_against_unrelated_certificate() -> None:
    wrong_public_key = load_public_key_fixture("ed25519-cv25519-sample-1.asc")
    payload = (FIXTURES / "subkey-signed-1/payload.bin").read_bytes()
    signature, _ = DetachedSignature.from_armor(
        read_fixture_text("subkey-signed-1/sig.asc")
    )

    with pytest.raises(
        ValueError,
        match="does not match the certificate primary key or any bound public subkey",
    ):
        signature.verify(wrong_public_key, payload)


def test_encrypt_and_decrypt_message_with_password_seipdv1() -> None:
    armored = _encrypt_message_with_password(
        b"secret payload",
        "hunter2",
        file_name="note.txt",
        version="seipd-v1",
    )
    message, headers = Message.from_armor(armored)

    assert headers == {}
    assert message.kind == "encrypted"
    with pytest.raises(ValueError, match="message must be decrypted"):
        message.as_data_string()

    decrypted = message.decrypt_with_password("hunter2")

    assert decrypted.kind == "literal"
    assert decrypted.literal_filename() == b""
    assert decrypted.signature_count() == 0
    assert decrypted.one_pass_signature_count() == 0
    assert decrypted.regular_signature_count() == 0
    assert decrypted.signatures() == []
    assert decrypted.as_data_string() == "secret payload"


def test_encrypt_and_decrypt_message_with_password_seipdv2_and_compression() -> None:
    armored = _encrypt_message_with_password(
        b"compressed payload",
        "opensesame",
        version="seipd-v2",
        compression="zlib",
    )
    message, _ = Message.from_armor(armored)
    decrypted = message.decrypt_with_password("opensesame")

    assert decrypted.kind == "compressed"
    assert decrypted.is_compressed is True
    assert decrypted.literal_mode() == "binary"
    assert decrypted.as_data_string() == "compressed payload"


def test_encrypt_and_decrypt_message_to_recipient() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = _encrypt_message_to_recipient(
        b"recipient payload",
        public_key,
        file_name="message.bin",
    )
    message, headers = Message.from_armor(armored)
    decrypted = message.decrypt(None, secret_key)

    assert headers == {}
    assert message.kind == "encrypted"
    assert decrypted.literal_filename() == b""
    assert decrypted.signatures() == []
    assert decrypted.as_data_vec() == b"recipient payload"

    with pytest.raises(ValueError, match="message was not signed"):
        decrypted.verify(public_key)


def test_encrypt_message_to_recipient_accepts_public_subkey() -> None:
    secret_key = generate_subkey_signing_and_encryption_key(
        "Encrypt Recipient <subkey@example.com>"
    )
    public_key = secret_key.to_public_key()
    encryption_subkey = public_key.public_subkeys[1]

    message_bytes = _encrypt_message_to_recipient_bytes(
        b"recipient subkey payload",
        encryption_subkey,
    )
    message = Message.from_bytes(message_bytes)

    assert (
        message.public_key_encrypted_session_key_packets()[0].recipient_fingerprint
        == encryption_subkey.key.fingerprint
    )
    assert (
        message.decrypt(None, secret_key).as_data_vec() == b"recipient subkey payload"
    )


def test_message_binary_round_trip_and_packet_access_for_recipient_message() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = _encrypt_message_to_recipient(
        b"packet payload", public_key, file_name="packet.bin"
    )
    message, headers = Message.from_armor(armored)
    reparsed = Message.from_bytes(message.to_bytes())

    assert headers == {}
    assert reparsed.decrypt(None, secret_key).as_data_vec() == b"packet payload"

    pkesks = message.public_key_encrypted_session_key_packets()
    skesks = message.symmetric_key_encrypted_session_key_packets()
    encrypted_data = message.encrypted_data_packet()

    assert len(pkesks) == 1
    assert skesks == []
    assert pkesks[0].version == 6
    assert pkesks[0].public_key_algorithm is not None
    assert pkesks[0].recipient_key_id is None
    assert (
        pkesks[0].recipient_fingerprint == public_key.public_subkeys[0].key.fingerprint
    )
    assert pkesks[0].recipient_is_anonymous is False
    assert pkesks[0].values_bytes() is not None
    assert pkesks[0].to_bytes()

    assert encrypted_data.kind == "seipd-v2"
    assert encrypted_data.version == 2
    assert encrypted_data.symmetric_algorithm == "aes256"
    assert encrypted_data.aead_algorithm == "ocb"
    assert encrypted_data.chunk_size is not None
    assert encrypted_data.salt is not None
    assert len(encrypted_data.salt) == 32
    assert encrypted_data.iv is None
    assert encrypted_data.data()
    assert encrypted_data.to_bytes()


def test_password_message_binary_output_and_skesk_packet_access() -> None:
    message_bytes = _encrypt_message_with_password_bytes(
        b"password packet payload",
        "hunter2",
        version="seipd-v2",
        symmetric_algorithm="aes128",
    )
    message = Message.from_bytes(message_bytes)
    encrypted_data = message.encrypted_data_packet()
    pkesks = message.public_key_encrypted_session_key_packets()
    skesks = message.symmetric_key_encrypted_session_key_packets()

    assert pkesks == []
    assert len(skesks) == 1
    assert skesks[0].version == 6
    assert skesks[0].symmetric_algorithm == "aes128"
    assert skesks[0].aead_algorithm == "ocb"
    assert skesks[0].string_to_key is not None
    assert skesks[0].encrypted_key is not None
    assert skesks[0].aead_iv is not None
    assert skesks[0].is_supported is True
    assert skesks[0].to_bytes()

    assert encrypted_data.kind == "seipd-v2"
    assert encrypted_data.symmetric_algorithm == "aes128"
    assert encrypted_data.aead_algorithm == "ocb"
    assert (
        message.decrypt_with_password("hunter2").as_data_vec()
        == b"password packet payload"
    )


def test_encrypt_to_recipient_with_custom_session_key_and_export_raw_pkesk() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    session_key = bytes(range(16))

    message_bytes = _encrypt_message_to_recipient_bytes(
        b"custom session key payload",
        public_key,
        version="seipd-v2",
        symmetric_algorithm="aes128",
        session_key=session_key,
    )
    message = Message.from_bytes(message_bytes)
    packet = encrypt_session_key_to_recipient(
        session_key,
        public_key,
        version="seipd-v2",
        symmetric_algorithm="aes128",
    )

    assert message.decrypt_with_session_key(session_key).as_data_vec() == (
        b"custom session key payload"
    )
    assert (
        message.decrypt(None, secret_key).as_data_vec() == b"custom session key payload"
    )
    assert packet.version == 6
    assert packet.recipient_fingerprint == public_key.public_subkeys[0].key.fingerprint
    assert packet.recipient_key_id is None
    assert packet.recipient_is_anonymous is False
    assert packet.public_key_algorithm is not None
    assert packet.values_bytes() is not None
    assert packet.to_bytes()


def test_message_builder_compression_round_trip() -> None:
    message_bytes = (
        MessageBuilder.from_bytes("payload.txt", b"hello builder")
        .compression("zlib")
        .to_vec()
    )
    message = Message.from_bytes(message_bytes)

    assert message.kind == "compressed"
    assert message.as_data_string() == "hello builder"


def test_message_builder_password_encryption_round_trip() -> None:
    armored = (
        MessageBuilder.from_bytes("payload.txt", b"Hello, world!")
        .seipd_v2("aes256", "ocb")
        .encrypt_with_password(StringToKey.argon2(1, 4, 21), "password")
        .to_armored_string()
    )
    message, headers = Message.from_armor(armored)

    assert headers == {}
    assert message.kind == "encrypted"
    assert message.decrypt_with_password("password").as_data_string() == "Hello, world!"


def test_message_builder_rejects_invalid_session_key_length() -> None:
    builder = MessageBuilder.from_bytes("payload.bin", b"abc").seipd_v2("aes128", "ocb")

    with pytest.raises(ValueError, match="session_key must be exactly 16 bytes"):
        builder.set_session_key(bytes(range(15)))


def test_message_builder_armor_options_control_headers_and_checksum() -> None:
    armored = (
        MessageBuilder.from_bytes("payload.txt", b"hello")
        .seipd_v1("aes256")
        .encrypt_with_password(StringToKey.iterated("sha256", 96), "hunter2")
        .to_armored_string(
            ArmorOptions({"Comment": ["builder test"]}, include_checksum=False)
        )
    )
    message, headers = Message.from_armor(armored)

    assert headers == {"Comment": ["builder test"]}
    assert "\n=" not in armored
    assert message.decrypt_with_password("hunter2").as_data_string() == "hello"


def test_message_builder_from_reader_data_mode_and_text_signature() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    message_bytes = (
        MessageBuilder.from_reader("payload.txt", io.BytesIO(b"hello\r\nworld\r\n"))
        .data_mode("utf8")
        .sign_text()
        .sign(secret_key)
        .to_vec()
    )
    message = Message.from_bytes(message_bytes)
    info = message.signatures()[0]

    assert message.literal_mode() == "utf8"
    assert message.as_data_string() == "hello\r\nworld\r\n"
    assert info.typ() == "text"
    message.verify(public_key)


def test_message_builder_session_key_returns_generated_and_overridden_values() -> None:
    builder = MessageBuilder.from_bytes("payload.bin", b"payload").seipd_v2(
        "aes128", "ocb"
    )

    generated = builder.session_key()
    assert len(generated) == 16

    custom = bytes(range(16))
    assert builder.set_session_key(custom).session_key() == custom


def test_message_builder_writer_and_file_outputs(tmp_path: Path) -> None:
    binary_writer = io.BytesIO()
    MessageBuilder.from_reader("payload.txt", io.BytesIO(b"writer payload")).to_writer(
        binary_writer
    )
    binary_message = Message.from_bytes(binary_writer.getvalue())
    assert binary_message.as_data_string() == "writer payload"

    text_writer = io.StringIO()
    MessageBuilder.from_bytes(
        "payload.txt", b"armored writer payload"
    ).to_armored_writer(text_writer)
    armored_message, headers = Message.from_armor(text_writer.getvalue())
    assert headers == {}
    assert armored_message.as_data_string() == "armored writer payload"

    binary_path = tmp_path / "nested" / "message.pgp"
    MessageBuilder.from_bytes("payload.txt", b"file payload").to_file(binary_path)
    assert (
        Message.from_bytes(binary_path.read_bytes()).as_data_string() == "file payload"
    )

    armored_path = tmp_path / "nested" / "message.asc"
    MessageBuilder.from_bytes("payload.txt", b"armored file payload").to_armored_file(
        armored_path,
        ArmorOptions({"Comment": ["file output"]}),
    )
    file_message, file_headers = Message.from_armor(armored_path.read_text())
    assert file_headers == {"Comment": ["file output"]}
    assert file_message.as_data_string() == "armored file payload"


def test_message_builder_can_sign_and_encrypt_to_subkeys() -> None:
    secret_key = generate_subkey_signing_and_encryption_key(
        "Builder Subkeys <builder@example.com>"
    )
    public_key = secret_key.to_public_key()
    signing_subkey = secret_key.secret_subkeys[0]
    encryption_subkey = public_key.public_subkeys[1]

    armored = (
        MessageBuilder.from_bytes("payload.txt", b"subkey builder payload")
        .sign(signing_subkey)
        .seipd_v2("aes256", "ocb")
        .encrypt_to_key(encryption_subkey)
        .to_armored_string()
    )
    message, _ = Message.from_armor(armored)
    decrypted = message.decrypt(None, secret_key)

    assert decrypted.as_data_vec() == b"subkey builder payload"
    assert decrypted.signatures()[0].issuer_fingerprint() == [
        signing_subkey.key.fingerprint
    ]
    decrypted.verify(public_key)


def test_password_encryption_with_custom_session_key_and_raw_skesk() -> None:
    session_key = bytes(range(16))
    message_bytes = _encrypt_message_with_password_bytes(
        b"custom password session key payload",
        "opensesame",
        version="seipd-v1",
        symmetric_algorithm="aes128",
        session_key=session_key,
    )
    message = Message.from_bytes(message_bytes)
    packet = encrypt_session_key_with_password(
        session_key,
        "opensesame",
        version="seipd-v1",
        symmetric_algorithm="aes128",
    )

    with pytest.raises(ValueError, match="symmetric_algorithm is required"):
        message.decrypt_with_session_key(session_key)

    assert (
        message.decrypt_with_session_key(
            session_key, symmetric_algorithm="aes128"
        ).as_data_string()
        == "custom password session key payload"
    )
    assert message.decrypt_with_password("opensesame").as_data_string() == (
        "custom password session key payload"
    )
    assert packet.version == 4
    assert packet.symmetric_algorithm == "aes128"
    assert packet.aead_algorithm is None
    assert packet.string_to_key is not None
    assert packet.encrypted_key is not None
    assert packet.aead_iv is None
    assert packet.is_supported is True
    assert packet.to_bytes()


@pytest.mark.parametrize(
    "case_name",
    [
        "gnupg-v1-001",
        "gnupg-v2-1-5-001",
    ],
)
def test_decrypted_signed_openpgp_interop_message_supports_signature_verification(
    case_name: str,
) -> None:
    """Adapt upstream decrypt+verify coverage from rpgp/tests/message_test.rs."""
    case = read_fixture_json(f"openpgp-interop/{case_name}.json")
    secret_key, _ = SignedSecretKey.from_armor(
        read_fixture_text(f"openpgp-interop/{case['decryptKey']}")
    )
    public_key, _ = SignedPublicKey.from_armor(
        read_fixture_text(f"openpgp-interop/{case['verifyKey']}")
    )
    message, _ = Message.from_armor(
        read_fixture_text(f"openpgp-interop/{case_name}.asc")
    )

    assert case["type"] == "decrypt"
    secret_key.verify_bindings()
    public_key.verify_bindings()

    decrypted = message.decrypt(case["passphrase"], secret_key)

    assert decrypted.kind == "compressed"
    assert decrypted.is_compressed is True
    assert decrypted.is_signed is False
    assert decrypted.is_literal is False
    assert decrypted.as_data_string() == case["textcontent"]
    assert decrypted.literal_filename() == case["filename"].encode()
    assert decrypted.signature_count() == 1
    assert decrypted.one_pass_signature_count() == 1
    assert decrypted.regular_signature_count() == 0

    sigs = decrypted.signatures()

    assert len(sigs) == 1
    assert sigs[0].typ() == "binary"
    assert sigs[0].hash_alg() is not None

    verified = decrypted.verify_signature(public_key)

    assert verified.typ() == sigs[0].typ()
    assert verified.hash_alg() == sigs[0].hash_alg()
    assert verified.signed_hash_value() == sigs[0].signed_hash_value()

    decrypted.verify(public_key)


def test_cleartext_sign_and_verify_round_trip() -> None:
    secret_key, _ = SignedSecretKey.from_armor(
        read_fixture_text("cleartext-key-01.asc")
    )
    public_key = secret_key.to_public_key()
    text = "hello\n-world-what-\nis up\n"

    armored = _sign_cleartext_message(text, secret_key)
    message, headers = CleartextSignedMessage.from_armor(armored)

    assert headers == {}
    assert "-----BEGIN PGP SIGNED MESSAGE-----" in armored
    assert "Hash: SHA256" in armored
    assert "- -world-what-" in message.text
    assert message.signed_text() == "hello\r\n-world-what-\r\nis up\r\n"
    message.verify(public_key)

    reparsed, round_trip_headers = CleartextSignedMessage.from_armor(
        message.to_armored()
    )
    assert round_trip_headers == {}
    assert reparsed.signed_text() == message.signed_text()


def test_sign_cleartext_message_supports_custom_hash_algorithm() -> None:
    secret_key, _ = SignedSecretKey.from_armor(
        read_fixture_text("cleartext-key-01.asc")
    )
    public_key = secret_key.to_public_key()

    armored = _sign_cleartext_message("hello\n", secret_key, hash_algorithm="sha512")
    message, _ = CleartextSignedMessage.from_armor(armored)

    assert message.signatures()[0].hash_alg() == "sha512"
    message.verify(public_key)


def test_cleartext_signed_message_classmethod_supports_custom_hash_algorithm() -> None:
    secret_key, _ = SignedSecretKey.from_armor(
        read_fixture_text("cleartext-key-01.asc")
    )
    public_key = secret_key.to_public_key()

    message = CleartextSignedMessage.sign(
        "hello\n", secret_key, hash_algorithm="sha512"
    )
    info = message.signatures()[0]

    assert info.typ() == "text"
    assert info.hash_alg() == "sha512"
    reparsed, _ = CleartextSignedMessage.from_armor(message.to_armored())
    reparsed.verify(public_key)


def test_sign_cleartext_message_many_supports_multiple_signers() -> None:
    first_secret_key, _ = SignedSecretKey.from_armor(
        read_fixture_text("cleartext-key-01.asc")
    )
    second_secret_key = generate_signing_and_encryption_key(
        "Second <second@example.com>"
    )
    first_public_key = first_secret_key.to_public_key()
    second_public_key = second_secret_key.to_public_key()

    armored = _sign_cleartext_message_many(
        "multi\ncleartext\npayload\n",
        [first_secret_key, second_secret_key],
        hash_algorithm="sha384",
    )
    message, _ = CleartextSignedMessage.from_armor(armored)
    sigs = message.signatures()

    assert message.signature_count() == 2
    assert {sig.typ() for sig in sigs} == {"text"}
    assert {sig.hash_alg() for sig in sigs} == {"sha384"}

    first_index = signature_index_for_fingerprint(sigs, first_public_key.fingerprint)
    second_index = signature_index_for_fingerprint(sigs, second_public_key.fingerprint)

    assert message.verify_signature(
        first_public_key, first_index
    ).issuer_fingerprint() == [first_public_key.fingerprint]
    assert message.verify_signature(
        second_public_key, second_index
    ).issuer_fingerprint() == [second_public_key.fingerprint]


def test_encrypt_session_key_to_recipient_supports_anonymous_recipient() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    packet = encrypt_session_key_to_recipient(
        bytes(range(16)),
        public_key,
        version="seipd-v2",
        symmetric_algorithm="aes128",
        anonymous_recipient=True,
    )

    assert packet.version == 6
    assert packet.recipient_is_anonymous is True
    assert packet.recipient_fingerprint is None
    assert packet.recipient_key_id is None


def test_encrypt_message_to_recipient_supports_anonymous_recipient() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = _encrypt_message_to_recipient(
        b"anonymous payload",
        public_key,
        anonymous_recipient=True,
    )
    message, _ = Message.from_armor(armored)
    pkesk = message.public_key_encrypted_session_key_packets()[0]

    assert pkesk.recipient_is_anonymous is True
    assert pkesk.recipient_fingerprint is None
    assert pkesk.recipient_key_id is None
    assert message.decrypt(None, secret_key).as_data_vec() == b"anonymous payload"


def test_encrypt_message_to_recipient_bytes_supports_anonymous_recipient() -> None:
    secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    message = Message.from_bytes(
        _encrypt_message_to_recipient_bytes(
            b"anonymous payload",
            public_key,
            anonymous_recipient=True,
        )
    )
    pkesk = message.public_key_encrypted_session_key_packets()[0]

    assert pkesk.recipient_is_anonymous is True
    assert pkesk.recipient_fingerprint is None
    assert pkesk.recipient_key_id is None
    assert message.decrypt(None, secret_key).as_data_vec() == b"anonymous payload"


def test_encrypt_message_to_recipients_encrypts_for_multiple_recipients() -> None:
    first_secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    second_secret_key = generate_signing_and_encryption_key(
        "Second <second@example.com>"
    )
    first_public_key = first_secret_key.to_public_key()
    second_public_key = second_secret_key.to_public_key()

    armored = _encrypt_message_to_recipients(
        b"shared payload",
        [first_public_key, second_public_key],
    )
    message, _ = Message.from_armor(armored)

    assert len(message.public_key_encrypted_session_key_packets()) == 2
    assert message.decrypt(None, first_secret_key).as_data_vec() == b"shared payload"
    assert message.decrypt(None, second_secret_key).as_data_vec() == b"shared payload"


def test_encrypt_message_to_recipients_bytes_supports_anonymous_recipients() -> None:
    first_secret_key, _ = SignedSecretKey.from_armor(SECRET_KEY)
    second_secret_key = generate_signing_and_encryption_key(
        "Second <second@example.com>"
    )
    first_public_key = first_secret_key.to_public_key()
    second_public_key = second_secret_key.to_public_key()

    message = Message.from_bytes(
        _encrypt_message_to_recipients_bytes(
            b"anonymous shared payload",
            [first_public_key, second_public_key],
            anonymous_recipient=True,
        )
    )
    pkesks = message.public_key_encrypted_session_key_packets()

    assert len(pkesks) == 2
    assert all(packet.recipient_is_anonymous for packet in pkesks)
    assert all(packet.recipient_fingerprint is None for packet in pkesks)
    assert all(packet.recipient_key_id is None for packet in pkesks)
    assert (
        message.decrypt(None, first_secret_key).as_data_vec()
        == b"anonymous shared payload"
    )
    assert (
        message.decrypt(None, second_secret_key).as_data_vec()
        == b"anonymous shared payload"
    )


def test_signed_message_signature_infos_and_indexed_verification() -> None:
    message, headers = Message.from_armor(read_fixture_text("signed-2-keys-1.asc"))
    rsa_public_key = load_public_key_fixture("rsa-rsa-sample-1.asc")
    ed_public_key = load_public_key_fixture("ed25519-cv25519-sample-1.asc")

    assert headers == {"Version": ["GnuPG v2"]}
    assert message.kind == "compressed"
    assert message.signature_count() == 2
    assert message.one_pass_signature_count() == 2
    assert message.regular_signature_count() == 0

    sigs = message.signatures()

    assert len(sigs) == 2
    assert {sig.typ() for sig in sigs} == {"binary"}
    assert {sig.hash_alg() for sig in sigs} == {"sha256"}
    assert {sig.signers_userid() for sig in sigs} == {
        "patrice.lumumba@example.net",
        "steve.biko@example.net",
    }

    rsa_index = signature_index_for_key_id(sigs, rsa_public_key.key_id)
    ed_index = signature_index_for_key_id(sigs, ed_public_key.key_id)

    assert message.verify_signature(rsa_public_key, rsa_index).issuer_key_id() == [
        rsa_public_key.key_id
    ]
    assert message.verify_signature(ed_public_key, ed_index).issuer_key_id() == [
        ed_public_key.key_id
    ]
    message.verify(rsa_public_key, index=rsa_index)
    message.verify(ed_public_key, index=ed_index)


def test_cleartext_multi_signature_infos_and_indexed_verification() -> None:
    message, headers = CleartextSignedMessage.from_armor(
        read_fixture_text("clearsig-2-keys-1.asc")
    )
    rsa_public_key = load_public_key_fixture("rsa-rsa-sample-1.asc")
    ed_public_key = load_public_key_fixture("ed25519-cv25519-sample-1.asc")

    assert headers == {"Version": ["GnuPG v2"]}
    assert message.signature_count() == 2

    sigs = message.signatures()

    assert len(sigs) == 2
    assert {sig.typ() for sig in sigs} == {"text"}
    assert {sig.hash_alg() for sig in sigs} == {"sha256"}
    assert {sig.signers_userid() for sig in sigs} == {
        "patrice.lumumba@example.net",
        "steve.biko@example.net",
    }

    rsa_index = signature_index_for_key_id(sigs, rsa_public_key.key_id)
    ed_index = signature_index_for_key_id(sigs, ed_public_key.key_id)

    assert message.verify_signature(rsa_public_key, rsa_index).issuer_key_id() == [
        rsa_public_key.key_id
    ]
    assert message.verify_signature(ed_public_key, ed_index).issuer_key_id() == [
        ed_public_key.key_id
    ]
    assert message.verify_signature(rsa_public_key).issuer_key_id() == [
        rsa_public_key.key_id
    ]


def test_rfc9580_v6_cleartext_signature_info_exposes_salt() -> None:
    secret_key, _ = SignedSecretKey.from_armor(
        read_fixture_text("rfc9580-v6-25519-annex-a-4/tsk.asc")
    )
    public_key = secret_key.to_public_key()
    message, headers = CleartextSignedMessage.from_armor(
        read_fixture_text("rfc9580-v6-25519-annex-a-4/csf.msg")
    )

    assert headers == {}
    assert message.signature_count() == 1

    info = message.verify_signature(public_key)
    assert info.version() == 6
    assert info.typ() == "text"
    assert info.hash_alg() == "sha512"
    assert info.issuer_fingerprint() == [public_key.fingerprint]
    salt = info.salt()
    assert salt is not None
    assert len(salt) == 32
    assert info.signed_hash_value() is not None
    assert message.signatures()[0].salt() == salt
