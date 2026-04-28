import json
from pathlib import Path
from typing import TypedDict, cast

import pytest

from openpgp import (
    CleartextSignedMessage,
    DetachedSignature,
    EncryptionCaps,
    KeyType,
    Message,
    PublicKey,
    SecretKey,
    SecretKeyParamsBuilder,
    SignatureInfo,
    SubkeyParamsBuilder,
    encrypt_message_to_recipient_bytes,
    encrypt_message_to_recipient,
    encrypt_message_to_recipients_bytes,
    encrypt_message_to_recipients,
    encrypt_message_with_password_bytes,
    encrypt_message_with_password,
    encrypt_session_key_to_recipient,
    encrypt_session_key_with_password,
    inspect_message,
    sign_cleartext_message,
    sign_cleartext_message_many,
    sign_message,
    sign_message_many,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures"


def read_fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()


class OpenPGPInteropDecryptCase(TypedDict):
    type: str
    decryptKey: str
    passphrase: str
    verifyKey: str
    filename: str
    textcontent: str


def read_fixture_json(name: str) -> OpenPGPInteropDecryptCase:
    return cast(OpenPGPInteropDecryptCase, json.loads(read_fixture_text(name)))


def load_public_key_fixture(name: str) -> PublicKey:
    data = read_fixture_text(name)
    try:
        public_key, _ = PublicKey.from_armor(data)
    except ValueError:
        secret_key, _ = SecretKey.from_armor(data)
        return secret_key.to_public_key()
    else:
        return public_key


def generate_signing_and_encryption_key(user_id: str) -> SecretKey:
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


def signature_index_for_key_id(infos: list[SignatureInfo], key_id: str) -> int:
    return next(
        index for index, info in enumerate(infos) if key_id in info.issuer_key_ids
    )


def signature_index_for_fingerprint(
    infos: list[SignatureInfo], fingerprint: str
) -> int:
    return next(
        index
        for index, info in enumerate(infos)
        if fingerprint in info.issuer_fingerprints
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
    key, headers = PublicKey.from_armor(PUBLIC_KEY)

    assert headers == {}
    assert key.fingerprint
    assert key.key_id
    assert key.public_subkey_count == 1
    assert key.user_ids == []
    assert key.revocation_signature_infos() == []
    assert PublicKey.from_bytes(key.to_bytes()).fingerprint == key.fingerprint
    key.verify_bindings()


def test_parse_secret_key_and_convert_to_public() -> None:
    secret_key, headers = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    assert headers == {}
    assert secret_key.secret_subkey_count == 1
    assert public_key.public_subkey_count == 1
    assert public_key.fingerprint == secret_key.fingerprint
    assert secret_key.user_ids == public_key.user_ids
    assert secret_key.revocation_signature_infos() == []
    assert public_key.revocation_signature_infos() == []
    secret_key.verify_bindings()


def test_round_trip_public_key_armor() -> None:
    key, _ = PublicKey.from_armor(PUBLIC_KEY)
    reparsed, headers = PublicKey.from_armor(key.to_armored())

    assert headers == {}
    assert reparsed.fingerprint == key.fingerprint


def test_sign_and_verify_message() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = sign_message(b"Hello world", secret_key)
    message, headers = Message.from_armor(armored)

    assert headers == {}
    assert message.kind == "signed"
    assert message.is_signed is True
    assert message.is_literal is False
    assert message.literal_mode() == "binary"
    assert message.literal_filename() == b""
    assert message.payload_bytes() == b"Hello world"
    assert message.payload_text() == "Hello world"
    assert message.signature_infos()[0].notations == []
    assert message.signature_infos()[0].revocation_key is None
    message.verify(public_key)


def test_sign_message_supports_custom_hash_algorithm() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = sign_message(b"Hello world", secret_key, hash_algorithm="sha512")
    message, _ = Message.from_armor(armored)
    info = message.signature_infos()[0]

    assert info.signature_type == "binary"
    assert info.hash_algorithm == "SHA512"
    assert info.notations == []
    assert info.revocation_key is None
    message.verify(public_key)


def test_sign_message_many_supports_multiple_signers() -> None:
    first_secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    second_secret_key = generate_signing_and_encryption_key(
        "Second <second@example.com>"
    )
    first_public_key = first_secret_key.to_public_key()
    second_public_key = second_secret_key.to_public_key()

    armored = sign_message_many(
        b"multi-signed payload",
        [first_secret_key, second_secret_key],
        hash_algorithm="sha384",
    )
    message, _ = Message.from_armor(armored)
    infos = message.signature_infos()

    assert message.signature_count() == 2
    assert len(infos) == 2
    assert {info.signature_type for info in infos} == {"binary"}
    assert {info.hash_algorithm for info in infos} == {"SHA384"}

    first_index = signature_index_for_fingerprint(infos, first_public_key.fingerprint)
    second_index = signature_index_for_fingerprint(infos, second_public_key.fingerprint)

    assert message.verify_signature(
        first_public_key, first_index
    ).issuer_fingerprints == [first_public_key.fingerprint]
    assert message.verify_signature(
        second_public_key, second_index
    ).issuer_fingerprints == [second_public_key.fingerprint]


def test_sign_and_verify_detached_signature() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    payload = b"detached payload"

    signature = DetachedSignature.sign_binary(payload, secret_key)
    info = signature.signature_info()

    assert info.signature_type == "binary"
    assert info.hash_algorithm == "SHA256"
    assert info.is_one_pass is False
    assert info.notations == []
    assert info.revocation_key is None
    signature.verify(public_key, payload)
    assert (
        signature.verify_signature(public_key, payload).signed_hash_value
        == info.signed_hash_value
    )

    reparsed = DetachedSignature.from_bytes(signature.to_bytes())
    reparsed.verify(public_key, payload)

    armored_signature, headers = DetachedSignature.from_armor(signature.to_armored())
    assert headers == {}
    armored_signature.verify(public_key, payload)


def test_detached_signature_supports_custom_hash_algorithm_for_binary_signatures() -> (
    None
):
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    signature = DetachedSignature.sign_binary(
        b"detached payload",
        secret_key,
        hash_algorithm="sha512",
    )

    assert signature.signature_info().hash_algorithm == "SHA512"
    signature.verify(public_key, b"detached payload")


def test_detached_text_signature_uses_text_verification_helpers() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    text = "hello\nworld\n"

    signature = DetachedSignature.sign_text(text, secret_key, hash_algorithm="sha384")
    info = signature.signature_info()

    assert info.signature_type == "text"
    assert info.hash_algorithm == "SHA384"
    signature.verify_text(public_key, "hello\r\nworld\r\n")
    assert signature.verify_text_signature(public_key, text).signature_type == "text"


def test_detached_signature_verifies_when_made_by_signing_subkey() -> None:
    public_key = load_public_key_fixture("subkey-signed-1/cert.asc")
    payload = (FIXTURES / "subkey-signed-1/payload.bin").read_bytes()
    signature, _ = DetachedSignature.from_armor(
        read_fixture_text("subkey-signed-1/sig.asc")
    )

    signature.verify(public_key, payload)
    info = signature.verify_signature(public_key, payload)

    assert info.signature_type == "binary"
    assert info.issuer_fingerprints
    assert public_key.fingerprint not in info.issuer_fingerprints


def test_detached_signature_verifies_streamed_file(tmp_path: Path) -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    payload = b"streamed payload" * 4096

    signature = DetachedSignature.sign_binary(payload, secret_key)
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(payload)

    signature.verify_file(public_key, artifact)
    signature.verify_file(public_key, str(artifact))


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
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    signature = DetachedSignature.sign_binary(b"x", secret_key)

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
    armored = encrypt_message_with_password(
        b"secret payload",
        "hunter2",
        file_name="note.txt",
        version="seipd-v1",
    )
    message, headers = Message.from_armor(armored)

    assert headers == {}
    assert inspect_message(armored).kind == "encrypted"
    assert message.kind == "encrypted"
    with pytest.raises(ValueError, match="message must be decrypted"):
        message.payload_text()

    decrypted = message.decrypt_with_password("hunter2")

    assert decrypted.kind == "literal"
    assert decrypted.literal_filename() == b""
    assert decrypted.signature_count() == 0
    assert decrypted.one_pass_signature_count() == 0
    assert decrypted.regular_signature_count() == 0
    assert decrypted.signature_infos() == []
    assert decrypted.payload_text() == "secret payload"


def test_encrypt_and_decrypt_message_with_password_seipdv2_and_compression() -> None:
    armored = encrypt_message_with_password(
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
    assert decrypted.payload_text() == "compressed payload"


def test_encrypt_and_decrypt_message_to_recipient() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = encrypt_message_to_recipient(
        b"recipient payload",
        public_key,
        file_name="message.bin",
    )
    message, headers = Message.from_armor(armored)
    decrypted = message.decrypt(secret_key)

    assert headers == {}
    assert message.kind == "encrypted"
    assert decrypted.literal_filename() == b""
    assert decrypted.signature_infos() == []
    assert decrypted.payload_bytes() == b"recipient payload"

    with pytest.raises(ValueError, match="message was not signed"):
        decrypted.verify(public_key)


def test_message_binary_round_trip_and_packet_access_for_recipient_message() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = encrypt_message_to_recipient(
        b"packet payload", public_key, file_name="packet.bin"
    )
    message, headers = Message.from_armor(armored)
    reparsed = Message.from_bytes(message.to_bytes())

    assert headers == {}
    assert reparsed.decrypt(secret_key).payload_bytes() == b"packet payload"

    pkesks = message.public_key_encrypted_session_key_packets()
    skesks = message.symmetric_key_encrypted_session_key_packets()
    encrypted_data = message.encrypted_data_packet()

    assert len(pkesks) == 1
    assert skesks == []
    assert pkesks[0].version == 6
    assert pkesks[0].public_key_algorithm is not None
    assert pkesks[0].recipient_key_id is None
    assert (
        pkesks[0].recipient_fingerprint == public_key.subkey_bindings()[0].fingerprint
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
    message_bytes = encrypt_message_with_password_bytes(
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
        message.decrypt_with_password("hunter2").payload_bytes()
        == b"password packet payload"
    )


def test_encrypt_to_recipient_with_custom_session_key_and_export_raw_pkesk() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    session_key = bytes(range(16))

    message_bytes = encrypt_message_to_recipient_bytes(
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

    assert message.decrypt_with_session_key(session_key).payload_bytes() == (
        b"custom session key payload"
    )
    assert message.decrypt(secret_key).payload_bytes() == b"custom session key payload"
    assert packet.version == 6
    assert packet.recipient_fingerprint == public_key.subkey_bindings()[0].fingerprint
    assert packet.recipient_key_id is None
    assert packet.recipient_is_anonymous is False
    assert packet.public_key_algorithm is not None
    assert packet.values_bytes() is not None
    assert packet.to_bytes()


def test_password_encryption_with_custom_session_key_and_raw_skesk() -> None:
    session_key = bytes(range(16))
    message_bytes = encrypt_message_with_password_bytes(
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
        ).payload_text()
        == "custom password session key payload"
    )
    assert message.decrypt_with_password("opensesame").payload_text() == (
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
    secret_key, _ = SecretKey.from_armor(
        read_fixture_text(f"openpgp-interop/{case['decryptKey']}")
    )
    public_key, _ = PublicKey.from_armor(
        read_fixture_text(f"openpgp-interop/{case['verifyKey']}")
    )
    message, _ = Message.from_armor(
        read_fixture_text(f"openpgp-interop/{case_name}.asc")
    )

    assert case["type"] == "decrypt"
    secret_key.verify_bindings()
    public_key.verify_bindings()

    decrypted = message.decrypt(secret_key, case["passphrase"])

    assert decrypted.kind == "compressed"
    assert decrypted.is_compressed is True
    assert decrypted.is_signed is False
    assert decrypted.is_literal is False
    assert decrypted.payload_text() == case["textcontent"]
    assert decrypted.literal_filename() == case["filename"].encode()
    assert decrypted.signature_count() == 1
    assert decrypted.one_pass_signature_count() == 1
    assert decrypted.regular_signature_count() == 0

    infos = decrypted.signature_infos()

    assert len(infos) == 1
    assert infos[0].signature_type == "binary"
    assert infos[0].hash_algorithm is not None
    assert infos[0].is_one_pass is True

    verified = decrypted.verify_signature(public_key)

    assert verified.signature_type == infos[0].signature_type
    assert verified.hash_algorithm == infos[0].hash_algorithm
    assert verified.signed_hash_value == infos[0].signed_hash_value
    assert verified.is_one_pass is True

    decrypted.verify(public_key)


def test_cleartext_sign_and_verify_round_trip() -> None:
    secret_key, _ = SecretKey.from_armor(read_fixture_text("cleartext-key-01.asc"))
    public_key = secret_key.to_public_key()
    text = "hello\n-world-what-\nis up\n"

    armored = sign_cleartext_message(text, secret_key)
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
    secret_key, _ = SecretKey.from_armor(read_fixture_text("cleartext-key-01.asc"))
    public_key = secret_key.to_public_key()

    armored = sign_cleartext_message("hello\n", secret_key, hash_algorithm="sha512")
    message, _ = CleartextSignedMessage.from_armor(armored)

    assert message.signature_infos()[0].hash_algorithm == "SHA512"
    message.verify(public_key)


def test_cleartext_signed_message_classmethod_supports_custom_hash_algorithm() -> None:
    secret_key, _ = SecretKey.from_armor(read_fixture_text("cleartext-key-01.asc"))
    public_key = secret_key.to_public_key()

    message = CleartextSignedMessage.sign(
        "hello\n", secret_key, hash_algorithm="sha512"
    )
    info = message.signature_infos()[0]

    assert info.signature_type == "text"
    assert info.hash_algorithm == "SHA512"
    reparsed, _ = CleartextSignedMessage.from_armor(message.to_armored())
    reparsed.verify(public_key)


def test_sign_cleartext_message_many_supports_multiple_signers() -> None:
    first_secret_key, _ = SecretKey.from_armor(
        read_fixture_text("cleartext-key-01.asc")
    )
    second_secret_key = generate_signing_and_encryption_key(
        "Second <second@example.com>"
    )
    first_public_key = first_secret_key.to_public_key()
    second_public_key = second_secret_key.to_public_key()

    armored = sign_cleartext_message_many(
        "multi\ncleartext\npayload\n",
        [first_secret_key, second_secret_key],
        hash_algorithm="sha384",
    )
    message, _ = CleartextSignedMessage.from_armor(armored)
    infos = message.signature_infos()

    assert message.signature_count() == 2
    assert {info.signature_type for info in infos} == {"text"}
    assert {info.hash_algorithm for info in infos} == {"SHA384"}

    first_index = signature_index_for_fingerprint(infos, first_public_key.fingerprint)
    second_index = signature_index_for_fingerprint(infos, second_public_key.fingerprint)

    assert message.verify_signature(
        first_public_key, first_index
    ).issuer_fingerprints == [first_public_key.fingerprint]
    assert message.verify_signature(
        second_public_key, second_index
    ).issuer_fingerprints == [second_public_key.fingerprint]


def test_encrypt_session_key_to_recipient_supports_anonymous_recipient() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
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
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = encrypt_message_to_recipient(
        b"anonymous payload",
        public_key,
        anonymous_recipient=True,
    )
    message, _ = Message.from_armor(armored)
    pkesk = message.public_key_encrypted_session_key_packets()[0]

    assert pkesk.recipient_is_anonymous is True
    assert pkesk.recipient_fingerprint is None
    assert pkesk.recipient_key_id is None
    assert message.decrypt(secret_key).payload_bytes() == b"anonymous payload"


def test_encrypt_message_to_recipient_bytes_supports_anonymous_recipient() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    message = Message.from_bytes(
        encrypt_message_to_recipient_bytes(
            b"anonymous payload",
            public_key,
            anonymous_recipient=True,
        )
    )
    pkesk = message.public_key_encrypted_session_key_packets()[0]

    assert pkesk.recipient_is_anonymous is True
    assert pkesk.recipient_fingerprint is None
    assert pkesk.recipient_key_id is None
    assert message.decrypt(secret_key).payload_bytes() == b"anonymous payload"


def test_encrypt_message_to_recipients_encrypts_for_multiple_recipients() -> None:
    first_secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    second_secret_key = generate_signing_and_encryption_key(
        "Second <second@example.com>"
    )
    first_public_key = first_secret_key.to_public_key()
    second_public_key = second_secret_key.to_public_key()

    armored = encrypt_message_to_recipients(
        b"shared payload",
        [first_public_key, second_public_key],
    )
    message, _ = Message.from_armor(armored)

    assert len(message.public_key_encrypted_session_key_packets()) == 2
    assert message.decrypt(first_secret_key).payload_bytes() == b"shared payload"
    assert message.decrypt(second_secret_key).payload_bytes() == b"shared payload"


def test_encrypt_message_to_recipients_bytes_supports_anonymous_recipients() -> None:
    first_secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    second_secret_key = generate_signing_and_encryption_key(
        "Second <second@example.com>"
    )
    first_public_key = first_secret_key.to_public_key()
    second_public_key = second_secret_key.to_public_key()

    message = Message.from_bytes(
        encrypt_message_to_recipients_bytes(
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
        message.decrypt(first_secret_key).payload_bytes() == b"anonymous shared payload"
    )
    assert (
        message.decrypt(second_secret_key).payload_bytes()
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

    infos = message.signature_infos()

    assert len(infos) == 2
    assert {info.signature_type for info in infos} == {"binary"}
    assert {info.hash_algorithm for info in infos} == {"SHA256"}
    assert {info.signer_user_id for info in infos} == {
        "patrice.lumumba@example.net",
        "steve.biko@example.net",
    }
    assert all(info.is_one_pass for info in infos)

    rsa_index = signature_index_for_key_id(infos, rsa_public_key.key_id)
    ed_index = signature_index_for_key_id(infos, ed_public_key.key_id)

    assert message.verify_signature(rsa_public_key, rsa_index).issuer_key_ids == [
        rsa_public_key.key_id
    ]
    assert message.verify_signature(ed_public_key, ed_index).issuer_key_ids == [
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

    infos = message.signature_infos()

    assert len(infos) == 2
    assert {info.signature_type for info in infos} == {"text"}
    assert {info.hash_algorithm for info in infos} == {"SHA256"}
    assert {info.signer_user_id for info in infos} == {
        "patrice.lumumba@example.net",
        "steve.biko@example.net",
    }
    assert all(info.is_one_pass is False for info in infos)

    rsa_index = signature_index_for_key_id(infos, rsa_public_key.key_id)
    ed_index = signature_index_for_key_id(infos, ed_public_key.key_id)

    assert message.verify_signature(rsa_public_key, rsa_index).issuer_key_ids == [
        rsa_public_key.key_id
    ]
    assert message.verify_signature(ed_public_key, ed_index).issuer_key_ids == [
        ed_public_key.key_id
    ]
    assert message.verify_signature(rsa_public_key).issuer_key_ids == [
        rsa_public_key.key_id
    ]


def test_rfc9580_v6_cleartext_signature_info_exposes_salt() -> None:
    secret_key, _ = SecretKey.from_armor(
        read_fixture_text("rfc9580-v6-25519-annex-a-4/tsk.asc")
    )
    public_key = secret_key.to_public_key()
    message, headers = CleartextSignedMessage.from_armor(
        read_fixture_text("rfc9580-v6-25519-annex-a-4/csf.msg")
    )

    assert headers == {}
    assert message.signature_count() == 1

    info = message.verify_signature(public_key)
    assert info.version == 6
    assert info.signature_type == "text"
    assert info.hash_algorithm == "SHA512"
    assert info.issuer_fingerprints == [public_key.fingerprint]
    assert info.salt is not None
    assert len(info.salt) == 32
    assert info.signed_hash_value is not None
    assert message.signature_infos()[0].salt == info.salt
