# Changelog

## Unreleased

### Changed

- Reworked the public Python API so its class structure more closely matches the underlying `pgp` crate:
  - `PublicKey` / `SecretKey` now expose `primary_key`, `details`, `public_subkeys`, and `secret_subkeys`.
  - `Message.from_armor()` / `Message.from_bytes()` now return message variant classes such as `LiteralMessage`, `CompressedMessage`, `SignedMessage`, and `EncryptedMessage`.
  - `EncryptedMessage` now exposes `esk` and `edata` packet-variant accessors in addition to the existing compatibility helpers.
  - `public_params` now returns typed public-parameter variants such as `RsaPublicParams`, `EcdsaPublicParams`, `EcdhPublicParams`, `Ed25519PublicParams`, and `X25519PublicParams`.
  - The hierarchy is now exposed directly from the Rust extension instead of a separate Python wrapper layer.

### Added

- Added compatibility aliases that mirror upstream naming more directly, including `SignedPublicKey` and `SignedSecretKey`.
- Added hierarchy-focused tests covering key graphs, message variants, packet variants, and typed public-parameter variants.

### Compatibility

- The existing inspector-style helpers are still available, including `direct_signature_infos()`, `revocation_signature_infos()`, `user_bindings()`, `subkey_bindings()`, `public_key_encrypted_session_key_packets()`, `symmetric_key_encrypted_session_key_packets()`, and `encrypted_data_packet()`.
