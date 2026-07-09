# rpgp-py

[![Supported versions](https://img.shields.io/pypi/pyversions/rpgp-py.svg)](https://pypi.org/project/rpgp-py/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/rpgp-py?period=monthly&units=ABBREVIATION&left_color=BLACK&right_color=GREEN&left_text=downloads%2Fmonth)](https://pepy.tech/projects/rpgp-py)
[![GitHub stars](https://img.shields.io/github/stars/xelandernt/rpgp-py)](https://github.com/xelandernt/rpgp-py/stargazers)
[![pyrefly](https://img.shields.io/endpoint?url=https://pyrefly.org/badge.json)](https://github.com/facebook/pyrefly)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Python bindings for [`rPGP`](https://github.com/rpgp/rpgp), exposed as the
`openpgp` package.

## Installation

```bash
pip install rpgp-py
```

Requires Python 3.10 or newer.

## API layout

The top-level `openpgp` package exposes namespace modules only. Import the API
from the namespace that matches the upstream Rust module:

| Python namespace | Purpose |
| --- | --- |
| `openpgp.composed` | Transferable keys, messages, signatures, message builders, and key-generation builders. |
| `openpgp.packet` | Packet-shaped objects such as key packets, signatures, session-key packets, features, flags, and encrypted data packets. |
| `openpgp.types` | Public-parameter objects, S2K configuration, packet header versions, and shared type helpers. |
| `openpgp.crypto` | Crypto algorithm namespaces. |
| `openpgp.util` | Binding-specific helper functions built on top of the Rust-shaped API. |

The core names intentionally mirror rPGP. For example, transferable keys are
`SignedPublicKey` and `SignedSecretKey` in `openpgp.composed`, while key packets
are `PublicKey`, `SecretKey`, `PublicSubkey`, and `SecretSubkey` in
`openpgp.packet`.

## Functionality

`rpgp-py` can:

- parse armored and binary public keys, secret keys, detached signatures, and
  OpenPGP messages,
- inspect transferable key details, users, subkeys, signatures, packet versions,
  key flags, features, public parameters, and S2K metadata,
- verify key bindings, signed messages, detached signatures, and cleartext
  signatures,
- build signed, compressed, password-encrypted, and recipient-encrypted
  messages,
- decrypt messages with secret keys, passwords, or caller-supplied session keys,
- generate modern OpenPGP key material, including v6 Ed25519/X25519 keys,
- use RFC 9580-era features exposed by rPGP, including SEIPD v2, OCB, and
  Argon2 S2K,
- use convenience helpers from `openpgp.util` when you want one-call signing or
  encryption.

## Usage

### Parse and inspect keys

```python
from openpgp.composed import SignedPublicKey, SignedSecretKey

public_key, headers = SignedPublicKey.from_armor(public_key_armor)
secret_key, _ = SignedSecretKey.from_armor(secret_key_armor)

public_key.verify_bindings()
secret_key.verify_bindings()

assert secret_key.to_public_key().fingerprint == public_key.fingerprint
assert public_key.primary_key.fingerprint == public_key.fingerprint
assert public_key.details.users[0].id == public_key.user_ids[0]

for signed_subkey in public_key.public_subkeys:
    print(signed_subkey.key.fingerprint)
    print(signed_subkey.signatures[0].typ())

params = public_key.public_params
print(params.kind)
```

### Sign and verify a message

```python
from openpgp.composed import Message, MessageBuilder

armored = (
    MessageBuilder.from_bytes("message.txt", b"hello world")
    .sign(secret_key, None, "sha256")
    .to_armored_string()
)

message, _ = Message.from_armor(armored)
signature = message.verify(public_key)

assert signature.hash_alg() == "sha256"
assert message.as_data_string() == "hello world"
```

### Create and verify a detached signature

```python
import os

from openpgp.composed import DetachedSignature


class SecureRandom:
    def randbytes(self, n: int) -> bytes:
        return os.urandom(n)


signature = DetachedSignature.sign_binary_data(
    SecureRandom(),
    secret_key,
    None,
    "sha512",
    b"payload",
)

signature.verify(public_key, b"payload")
assert signature.signature.hash_alg() == "sha512"
```

### Work with cleartext signatures

```python
from openpgp.composed import CleartextSignedMessage

cleartext = CleartextSignedMessage.sign("hello\n-world\n", secret_key)
armored = cleartext.to_armored()

reparsed, _ = CleartextSignedMessage.from_armor(armored)
reparsed.verify(public_key)

assert reparsed.signed_text() == "hello\r\n-world\r\n"
assert reparsed.signature_count() == 1
```

### Encrypt to a recipient

```python
from openpgp.composed import Message, MessageBuilder

armored = (
    MessageBuilder.from_bytes("secret.txt", b"secret payload")
    .seipd_v2("aes256", "ocb")
    .encrypt_to_key(public_key)
    .to_armored_string()
)

message, _ = Message.from_armor(armored)
decrypted = message.decrypt(None, secret_key)

assert decrypted.as_data_vec() == b"secret payload"
```

For anonymous recipients or multi-recipient messages, keep chaining recipient
operations:

```python
armored = (
    MessageBuilder.from_bytes("shared.txt", b"shared payload")
    .seipd_v2("aes256", "ocb")
    .encrypt_to_key_anonymous(first_public_key)
    .encrypt_to_key(second_public_key)
    .to_armored_string()
)
```

### Encrypt with a password

```python
from openpgp.composed import Message, MessageBuilder
from openpgp.types import StringToKey

armored = (
    MessageBuilder.from_bytes("", b"password protected")
    .seipd_v2("aes256", "ocb")
    .encrypt_with_password(StringToKey.argon2(1, 4, 21), "hunter2")
    .to_armored_string()
)

message, _ = Message.from_armor(armored)
decrypted = message.decrypt_with_password("hunter2")

assert decrypted.as_data_string() == "password protected"
```

### Inspect encrypted packets and use a session key

```python
from openpgp.composed import Message, MessageBuilder

session_key = bytes(range(16))
message_bytes = (
    MessageBuilder.from_bytes("", b"packet payload")
    .seipd_v2("aes128", "ocb")
    .set_session_key(session_key)
    .encrypt_to_key(public_key)
    .to_vec()
)

message = Message.from_bytes(message_bytes)
pkesk = message.public_key_encrypted_session_key_packets()[0]
edata = message.encrypted_data_packet()

assert pkesk.recipient_is_anonymous is False
assert edata.kind == "seipd-v2"
assert message.decrypt_with_session_key(session_key).as_data_vec() == b"packet payload"
```

### Generate key material

```python
from openpgp.composed import (
    EncryptionCaps,
    KeyType,
    SecretKeyParamsBuilder,
    SubkeyParamsBuilder,
)
from openpgp.types import PacketHeaderVersion, S2kParams, StringToKey

secret_key = (
    SecretKeyParamsBuilder()
    .version(6)
    .key_type(KeyType.ed25519())
    .packet_version(PacketHeaderVersion.new())
    .can_certify(True)
    .can_sign(True)
    .feature_seipd_v2(True)
    .primary_user_id("Me <me@example.com>")
    .passphrase("hunter2")
    .s2k(S2kParams.aead("aes256", "ocb", StringToKey.argon2(3, 4, 16)))
    .subkey(
        SubkeyParamsBuilder()
        .version(6)
        .key_type(KeyType.x25519())
        .packet_version(PacketHeaderVersion.new())
        .can_encrypt(EncryptionCaps.all())
        .build()
    )
    .generate()
)

public_key = secret_key.to_public_key()

secret_key.verify_bindings()
public_key.verify_bindings()

assert public_key.public_key_algorithm == "ed25519"
assert public_key.public_params.kind == "ed25519"
```

### Use convenience helpers

Use `openpgp.util` when you want compact helpers instead of manually building a
message pipeline:

```python
from openpgp.util import encrypt_message_to_recipient, sign_message

signed = sign_message(b"hello", secret_key)
encrypted = encrypt_message_to_recipient(b"secret", public_key)
```

The helper namespace also includes multi-signer, cleartext, byte-output,
multi-recipient, password-encryption, and session-key helpers.

## Reference documentation

- [`rPGP` on GitHub](https://github.com/rpgp/rpgp)
- [`pgp` crate API docs on docs.rs](https://docs.rs/pgp/latest/pgp/)
- [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580)

## Development

This project uses `uv`, `maturin`, and `just`.

Install development dependencies:

```bash
just install
```

Build the extension in the current environment:

```bash
uv run --no-sync maturin develop
```

Run checks:

```bash
just lint
just typecheck
just test
```

Run a single Python test file:

```bash
uv run --no-sync pytest tests/test_openpgp.py -q
```

Build a wheel:

```bash
uv build
```

After changing Rust sources, rebuild with `uv run --no-sync maturin develop`
before running Python tests.

## Versioning

`rpgp-py` follows the major and minor version of the underlying `pgp` crate. The
patch version is incremented for Python-facing API changes and Rust-core build
updates such as dependency updates or bug fixes.

## Acknowledgements

Thanks to the [`rPGP`](https://github.com/rpgp/rpgp) contributors and
maintainers for the Rust OpenPGP implementation that powers this package.

## License

This repository is distributed under the [MIT License](LICENSE).
