# rpgp-py

[![Supported versions](https://img.shields.io/pypi/pyversions/that-depends.svg)](https://pypi.python.org/pypi/brave-api-client)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/rpgp-py?period=monthly&units=ABBREVIATION&left_color=BLACK&right_color=GREEN&left_text=downloads%2Fmonth)](https://pepy.tech/projects/rpgp-py)
[![GitHub stars](https://img.shields.io/github/stars/xelandernt/rpgp-py)](https://github.com/xelandernt/rpgp-py/stargazers)
[![pyrefly](https://img.shields.io/endpoint?url=https://pyrefly.org/badge.json)](https://github.com/facebook/pyrefly)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Python bindings for [`rPGP`](https://github.com/rpgp/rpgp), exposed as the `openpgp` package.

- support for RFC 9580
- a typed Python surface (`.pyi` stubs ship with the package),
- wheels for Python 3.10+,
- Rust-shaped namespaces (`openpgp.composed`, `openpgp.packet`, `openpgp.types`, `openpgp.crypto`) that mirror the upstream `pgp` crate,
- optional convenience helpers in `openpgp.util`,
- a `MessageBuilder`-driven API for common signing/encryption workflows,
- detailed inspection APIs for packets, signatures, key bindings, and generated key material.

## Why use `rpgp-py` instead of `PGPy` or `PGPy13`?

Broadly:

- **RFC 9580 coverage:** `rpgp-py` follows the Rust `pgp` crate, which targets newer OpenPGP work such as RFC 9580-compatible v6 key material and modern curves/packet handling. `PGPy` and `PGPy13` are still RFC 4880.
- **Rust core:** the cryptographic core is implemented in Rust and exposed through a Python-first API.
- **Typed builders and inspectors:** the package exposes typed builders for key generation plus rich metadata for self-signatures, key flags, features, user bindings, S2K settings, and public-key parameters.
- **Python 3.13 support:** `PGPy` still imports `imghdr`, which was removed from the standard library in Python 3.13. `PGPy13` exists as a compatibility fork; `rpgp-py` targets current Python directly.

## Installation

```bash
pip install rpgp-py
```

## Reference documentation

When you need the underlying Rust semantics or want to compare behaviour against upstream docs, these are the useful references:

- [`rPGP` on GitHub](https://github.com/rpgp/rpgp)
- [`pgp` crate API docs on docs.rs](https://docs.rs/pgp/latest/pgp/)
- [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580)

## Breaking changes in 0.20.0

Version `0.20.0` updates the underlying Rust `pgp` crate to `0.20.0` and reshapes
the Python API around the upstream module layout so that rPGP docs translate
directly. The public surface is now organized into Rust-shaped namespaces:

- `openpgp.composed` mirrors `pgp::composed`: `SignedPublicKey`,
  `SignedSecretKey`, `Message`, `MessageBuilder`, `DetachedSignature`,
  `CleartextSignedMessage`, the key-generation builders, and `ArmorOptions`.
- `openpgp.packet` mirrors `pgp::packet`: `PublicKey`, `SecretKey`,
  `PublicSubkey`, `SecretSubkey`, `Signature`, `PublicKeyEncryptedSessionKey`,
  and the encrypted-data packet types.
- `openpgp.types` mirrors `pgp::types`: public-parameter objects, `StringToKey`,
  `S2kParams`, and `PacketHeaderVersion`.
- `openpgp.crypto.*` mirrors `pgp::crypto::*` algorithm names.
- `openpgp.util` contains binding-specific convenience helpers such as
  `sign_message`, `sign_cleartext_message`, `encrypt_message_to_recipient`, and
  `encrypt_message_with_password`.

Top-level `openpgp` now exposes only these namespace modules; object and helper
aliases were removed. Convenience helpers are available from `openpgp.util`
instead of as top-level `openpgp` functions. Compatibility spellings from
earlier releases were removed rather than deprecated:

- transferable keys are `openpgp.composed.SignedPublicKey` /
  `openpgp.composed.SignedSecretKey` (the old top-level `PublicKey` / `SecretKey`
  now name the *packet* types in `openpgp.packet`),
- message payload access uses the Rust-shaped `Message.as_data_vec()` /
  `Message.as_data_string()` (the `payload_bytes` / `payload_text` convenience
  names were removed),
- signing, encryption, and cleartext workflows go through `MessageBuilder`,
  `DetachedSignature`, and `CleartextSignedMessage` instead of top-level helper
  functions.

`Message.from_armor()` and `Message.from_bytes()` return concrete message
variants where possible, such as `LiteralMessage`, `CompressedMessage`,
`SignedMessage`, and `EncryptedMessage`. Key and subkey access follows the
upstream object graph: `public_key.primary_key`, `public_key.details`,
`public_key.public_subkeys[0].key`, and `secret_key.secret_subkeys[0].key`.
For quick message classification, parse with `openpgp.composed.Message` and use
the message object's `kind`, `is_nested`, and `headers` properties.

## Use cases

### 1. Parse and inspect transferable keys

```python
from openpgp.composed import SignedPublicKey, SignedSecretKey

public_key, _ = SignedPublicKey.from_armor(public_key_armor)
public_key.verify_bindings()

secret_key, _ = SignedSecretKey.from_armor(secret_key_armor)
assert secret_key.to_public_key().fingerprint == public_key.fingerprint
assert public_key.primary_key.fingerprint == public_key.fingerprint
assert public_key.details.users[0].id == public_key.user_ids[0]

if public_key.public_subkeys:
    signed_subkey = public_key.public_subkeys[0]
    assert signed_subkey.signatures[0].typ() == "subkey-binding"
if secret_key.secret_subkeys:
    signed_secret_subkey = secret_key.secret_subkeys[0]
    assert (
        signed_secret_subkey.signed_public_key().key.fingerprint
        == signed_secret_subkey.key.fingerprint
    )
```

The primary API mirrors upstream Rust objects: `SignedPublicKey` and
`SignedSecretKey` are transferable signed keys (`pgp::composed`), `primary_key`
is the `openpgp.packet` key packet, `details` contains signed users and signature
packets, and subkeys are `SignedPublicSubKey` or `SignedSecretSubKey` objects with
nested `key` packets and packet-shaped `signatures`. `public_params` returns typed
public-parameter objects (from `openpgp.types`) with variant fields such as RSA
`key.n`/`key.e`, DSA `key.p`/`key.q`/`key.g`/`key.y`, ECDSA `key`, ECDH
`p`/`hash`/`alg_sym`, and Ed/X key bytes where the upstream crate exposes them.

### 2. Sign and verify messages and detached signatures

```python
from openpgp.composed import DetachedSignature, Message, MessageBuilder


class SecureRandom:
    def randbytes(self, n: int) -> bytes:
        import os

        return os.urandom(n)


signed = (
    MessageBuilder.from_bytes("", b"hello world")
    .sign(secret_key)
    .to_armored_string()
)
message, _ = Message.from_armor(signed)
message.verify(public_key)
assert message.as_data_string() == "hello world"

signature = DetachedSignature.sign_binary_data(
    SecureRandom(), secret_key, None, "sha256", b"hello world"
)
signature.verify(public_key, b"hello world")
info = signature.signature
assert info.typ() == "binary"
assert info.hash_alg() == "sha256"

text_signature = DetachedSignature.sign_text_data(
    SecureRandom(), secret_key, None, "sha512", b"hello\nworld\n"
)
text_signature.verify_text(public_key, "hello\r\nworld\r\n")
assert text_signature.signature.hash_alg() == "sha512"

multi_signed = (
    MessageBuilder.from_bytes("", b"hello world")
    .sign(secret_key, None, "sha384")
    .sign(other_secret_key, None, "sha384")
    .to_armored_string()
)
multi_message, _ = Message.from_armor(multi_signed)
assert multi_message.signature_count() == 2
```

### 3. Work with cleartext signatures

```python
from openpgp.composed import CleartextSignedMessage

message = CleartextSignedMessage.sign("hello\n-world\n", secret_key)
armored = message.to_armored()
reparsed, _ = CleartextSignedMessage.from_armor(armored)

assert reparsed.signed_text() == "hello\r\n-world\r\n"
assert reparsed.signature_count() == 1
reparsed.verify(public_key)
```

### 4. Encrypt and decrypt OpenPGP messages

Recipient encryption:

```python
from openpgp.composed import Message, MessageBuilder

recipient_encrypted = (
    MessageBuilder.from_bytes("", b"secret")
    .seipd_v2("aes256", "ocb")
    .encrypt_to_key(public_key)
    .to_armored_string()
)
recipient_message, _ = Message.from_armor(recipient_encrypted)
recipient_decrypted = recipient_message.decrypt(None, secret_key)
assert recipient_decrypted.as_data_vec() == b"secret"

shared_encrypted = (
    MessageBuilder.from_bytes("", b"secret")
    .seipd_v2("aes256", "ocb")
    .encrypt_to_key_anonymous(public_key)
    .encrypt_to_key_anonymous(other_public_key)
    .to_armored_string()
)
shared_message, _ = Message.from_armor(shared_encrypted)
packets = shared_message.public_key_encrypted_session_key_packets()
assert len(packets) == 2
assert all(packet.recipient_is_anonymous for packet in packets)
```

Password encryption:

```python
from openpgp.composed import Message, MessageBuilder
from openpgp.types import StringToKey

password_encrypted = (
    MessageBuilder.from_bytes("", b"secret")
    .seipd_v2("aes256", "ocb")
    .encrypt_with_password(StringToKey.argon2(1, 4, 21), "hunter2")
    .to_armored_string()
)
password_message, _ = Message.from_armor(password_encrypted)
password_decrypted = password_message.decrypt_with_password("hunter2")
assert password_decrypted.as_data_string() == "secret"
```

Binary output, packet access, and caller-supplied session keys:

```python
from openpgp.composed import Message, MessageBuilder

session_key = bytes(range(16))
message_bytes = (
    MessageBuilder.from_bytes("", b"secret")
    .seipd_v2("aes128", "ocb")
    .set_session_key(session_key)
    .encrypt_to_key(public_key)
    .to_vec()
)

message = Message.from_bytes(message_bytes)
pkesk = message.public_key_encrypted_session_key_packets()[0]
edata = message.edata

assert pkesk.recipient_is_anonymous is False
assert edata.kind == "seipd-v2"
assert message.decrypt_with_session_key(session_key).as_data_vec() == b"secret"

raw_pkesk = pkesk.to_bytes()
assert raw_pkesk
```

### 5. Build messages with the upstream-style `MessageBuilder` API

```python
from openpgp.composed import ArmorOptions, Message, MessageBuilder
from openpgp.types import StringToKey

armored = (
    MessageBuilder.from_bytes("hello.txt", b"Hello, world!")
    .compression("zlib")
    .seipd_v2("aes256", "ocb")
    .encrypt_with_password(StringToKey.argon2(1, 4, 21), "hunter2")
    .to_armored_string(
        ArmorOptions({"Comment": ["built with MessageBuilder"]}, include_checksum=False)
    )
)

message, headers = Message.from_armor(armored)
decrypted = message.decrypt_with_password("hunter2")

assert headers == {"Comment": ["built with MessageBuilder"]}
assert decrypted.kind == "compressed"
assert decrypted.as_data_string() == "Hello, world!"
assert "\n=" not in armored
```

The same builder surface also accepts operational subkey objects when you want the
Rust docs' subkey-oriented examples to translate directly:

```python
subkey_signed_and_encrypted = (
    MessageBuilder.from_bytes("hello.txt", b"Hello, world!")
    .sign(secret_key.secret_subkeys[0])
    .seipd_v2("aes256", "ocb")
    .encrypt_to_key(public_key.public_subkeys[0])
    .to_armored_string()
)
```

It also exposes the remaining simple builder workflow methods for file-like objects
and literal/signature mode selection:

```python
import io

from openpgp.composed import Message, MessageBuilder

writer = io.StringIO()

(
    MessageBuilder.from_reader("notes.txt", io.BytesIO(b"hello\r\nworld\r\n"))
    .data_mode("utf8")
    .sign_text()
    .sign(secret_key)
    .to_armored_writer(writer)
)

message, _ = Message.from_armor(writer.getvalue())
assert message.literal_mode() == "utf8"
assert message.signatures()[0].typ() == "text"
```

### 6. Generate modern RFC 9580-compatible key material

```python
from openpgp.composed import (
    EncryptionCaps,
    KeyType,
    Message,
    MessageBuilder,
    SecretKeyParamsBuilder,
    SubkeyParamsBuilder,
)
from openpgp.packet import UserAttribute
from openpgp.types import PacketHeaderVersion

secret_key = (
    SecretKeyParamsBuilder()
    .version(6)
    .created_at(1_700_000_000)
    .key_type(KeyType.ed25519())
    .can_certify(True)
    .can_sign(True)
    .packet_version(PacketHeaderVersion.new())
    .feature_seipd_v2(True)
    .primary_user_id("Me <me@example.com>")
    .preferred_symmetric_algorithms(["aes256", "aes192", "aes128"])
    .preferred_hash_algorithms(["sha256", "sha384", "sha512", "sha224"])
    .preferred_compression_algorithms(["zlib", "zip"])
    .user_attribute(UserAttribute.image_jpeg(bytes.fromhex("ffd8ffe000104a464946000101")))
    .subkey(
        SubkeyParamsBuilder()
        .version(6)
        .created_at(1_700_000_123)
        .key_type(KeyType.x25519())
        .packet_version(PacketHeaderVersion.new())
        .can_encrypt(EncryptionCaps.all())
        .build()
    )
    .build()
    .generate()
)

public_key = secret_key.to_public_key()
secret_key.verify_bindings()
public_key.verify_bindings()

assert secret_key.version == 6
assert public_key.public_key_algorithm == "ed25519"
assert public_key.public_params.kind == "ed25519"
assert public_key.public_params.curve == "ed25519"
assert len(public_key.public_params.key) == 32
assert public_key.packet_version == PacketHeaderVersion.new()

signed = MessageBuilder.from_bytes("", b"generated payload").sign(secret_key).to_armored_string()
message, _ = Message.from_armor(signed)
message.verify(public_key)
assert message.as_data_vec() == b"generated payload"

encrypted = (
    MessageBuilder.from_bytes("", b"secret")
    .seipd_v2("aes256", "ocb")
    .encrypt_to_key(public_key)
    .to_armored_string()
)
encrypted_message, _ = Message.from_armor(encrypted)
assert encrypted_message.decrypt(None, secret_key).as_data_vec() == b"secret"
```

### 7. Customize secret-key S2K protection for generated keys

```python
from openpgp.composed import (
    EncryptionCaps,
    KeyType,
    SecretKeyParamsBuilder,
    SubkeyParamsBuilder,
)
from openpgp.types import S2kParams, StringToKey

secret_key = (
    SecretKeyParamsBuilder()
    .version(6)
    .key_type(KeyType.ed25519())
    .can_certify(True)
    .can_sign(True)
    .primary_user_id("Me <me@example.com>")
    .passphrase("hunter2")
    .s2k(
        S2kParams.aead(
            "aes256",
            "ocb",
            StringToKey.argon2(3, 4, 16),
        )
    )
    .subkey(
        SubkeyParamsBuilder()
        .version(6)
        .key_type(KeyType.x25519())
        .can_encrypt(EncryptionCaps.all())
        .passphrase("hunter2")
        .s2k(
            S2kParams.cfb(
                "aes128",
                StringToKey.iterated("sha256", 96),
            )
        )
        .build()
    )
    .build()
    .generate()
)

primary_s2k = secret_key.primary_secret_s2k()
assert primary_s2k.usage == "aead"
assert primary_s2k.aead_algorithm == "ocb"
assert primary_s2k.string_to_key is not None
assert primary_s2k.string_to_key.kind == "argon2"
```

## Benchmarks

### Median runtime graph (1 KiB payload, lower is better)

![Grouped benchmark chart for the shared workflows](docs/benchmarks/median-runtime.svg)

`rpgp-py` is substantially faster: roughly **9x–71x** faster for key parsing and **25x–48x** faster for the sign/verify and recipient-encryption loops.

### Password-encryption benchmark

![Grouped benchmark chart for password encryption and decryption](docs/benchmarks/password-runtime.svg)

This result is shown separately: `rpgp-py` defaults to modern **SEIPDv2 + AEAD (OCB)** password-protected messages, while `PGPy`/`PGPy13` remain RFC 4880-era implementations.

### Table of results

| Operation                       |   rpgp-py |     PGPy13 |       PGPy |
|---------------------------------|----------:|-----------:|-----------:|
| Parse armored public key        |  0.011 ms |   0.786 ms |   0.776 ms |
| Parse armored secret key        |  0.156 ms |   1.473 ms |   1.455 ms |
| Detached sign + verify          |  2.453 ms |  61.329 ms |  61.420 ms |
| Encrypt + decrypt to recipient  |  2.537 ms | 122.726 ms | 120.701 ms |
| Encrypt + decrypt with password | 62.369 ms |  50.346 ms |  50.289 ms |


### Reproduction

To make that comparison reproducible, the repository now ships:

- `scripts/benchmark.py` – an isolated benchmark runner,
- `docs/benchmarks/results.json` – the committed raw results used below.

```bash
uv run --python 3.12 python scripts/benchmark.py
```

## Versioning

`rpgp-py`'s version will reflect the major and minor version of the underlying `pgp` crate. 
The patch version will be incremented for both Python-facing API changes and for any internal changes that require a new build of the Rust core, such as dependency updates or bug fixes.

## Development

See the list of useful commands by running:

```bash
just
```

## Acknowledgements

Many thanks to the [`rPGP`](https://github.com/rpgp/rpgp) contributors and maintainers for building and documenting the Rust OpenPGP implementation that powers this package.

## License

This repository is distributed under the [MIT License](LICENSE).
