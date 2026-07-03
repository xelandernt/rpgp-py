use crate::conversions::*;
use crate::hierarchy::{
    PublicKeyPacket, SecretKeyPacket, SignedKeyDetails, SignedPublicSubKey as PySignedPublicSubKey,
    SignedSecretSubKey as PySignedSecretSubKey, public_key_packet_object, public_params_object,
    secret_key_packet_object, signed_key_details_from_raw, signed_public_subkey_from_raw,
    signed_secret_subkey_from_raw,
};
use crate::info::{lossy_user_ids, public_key_algorithm_name};
use crate::key_params::*;
use crate::serialization::*;
use crate::*;
use pgp::composed::{
    Encryption as PgpEncryption, EncryptionSeipdV1, EncryptionSeipdV2,
    MessageBuilder as PgpMessageBuilder,
};
use pyo3::{prelude::PyRef, types::PyAny};
use std::{io::Read, path::PathBuf};

/// A transferable OpenPGP public key (certificate) as defined by RFC 9580.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct PublicKey {
    pub(crate) inner: SignedPublicKey,
}

#[pymethods]
impl PublicKey {
    /// Parse an ASCII-armored transferable public key.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedPublicKey::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse multiple ASCII-armored transferable public keys from one armored input.
    #[staticmethod]
    fn from_armor_many(data: &str) -> PyResult<(Vec<Self>, Headers)> {
        let (iter, headers) = SignedPublicKey::from_string_many(data).map_err(to_py_err)?;
        let keys = iter
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((keys, headers))
    }

    /// Parse a binary transferable public key.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = SignedPublicKey::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse multiple binary transferable public keys from concatenated packet bytes.
    #[staticmethod]
    fn from_bytes_many(data: &[u8]) -> PyResult<Vec<Self>> {
        SignedPublicKey::from_bytes_many(Cursor::new(data))
            .map_err(to_py_err)?
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    /// Parse a single binary transferable public key from a file.
    #[staticmethod]
    fn from_file(path: PathBuf) -> PyResult<Self> {
        let inner = SignedPublicKey::from_file(&path).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse multiple binary transferable public keys from a file of concatenated packet bytes.
    #[staticmethod]
    fn from_file_many(path: PathBuf) -> PyResult<Vec<Self>> {
        SignedPublicKey::from_file_many(&path)
            .map_err(to_py_err)?
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    /// Parse a single ASCII-armored transferable public key from a file.
    #[staticmethod]
    fn from_armor_file(path: PathBuf) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedPublicKey::from_armor_file(&path).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse multiple ASCII-armored transferable public keys from one armored file.
    #[staticmethod]
    fn from_armor_file_many(path: PathBuf) -> PyResult<(Vec<Self>, Headers)> {
        let (iter, headers) = SignedPublicKey::from_armor_file_many(&path).map_err(to_py_err)?;
        let keys = iter
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((keys, headers))
    }

    /// The RFC 9580 fingerprint of the primary key.
    #[getter]
    fn fingerprint(&self) -> String {
        self.inner.fingerprint().to_string()
    }

    /// The legacy key identifier of the primary key.
    #[getter]
    fn key_id(&self) -> String {
        self.inner.legacy_key_id().to_string()
    }

    /// The OpenPGP key-packet version number of the primary key.
    #[getter]
    fn version(&self) -> u8 {
        key_version_number(self.inner.primary_key.version())
    }

    /// The primary key packet's creation time as seconds since the Unix epoch.
    #[getter]
    fn created_at(&self) -> u32 {
        self.inner.primary_key.created_at().as_secs()
    }

    /// The primary key packet's public-key algorithm.
    #[getter]
    fn public_key_algorithm(&self) -> String {
        public_key_algorithm_name(self.inner.primary_key.algorithm()).to_string()
    }

    /// Structured algorithm-specific public-key metadata from `KeyDetails.public_params()`.
    #[getter]
    fn public_params(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        public_params_object(py, self.inner.primary_key.public_params())
    }

    /// The RFC 9580 packet-header framing used by the primary key packet.
    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.inner.primary_key.packet_header_version(),
        }
    }

    /// The number of public subkeys attached to the certificate.
    #[getter]
    fn public_subkey_count(&self) -> usize {
        self.inner.public_subkeys.len()
    }

    /// The primary key packet.
    #[getter]
    fn primary_key(&self, py: Python<'_>) -> PyResult<Py<PublicKeyPacket>> {
        public_key_packet_object(py, &self.inner.primary_key)
    }

    /// Shared key details, user bindings, and direct signatures.
    #[getter]
    fn details(&self) -> SignedKeyDetails {
        signed_key_details_from_raw(&self.inner.details)
    }

    /// UTF-8 decoded user IDs, with invalid octets replaced lossily.
    #[getter]
    fn user_ids(&self) -> Vec<String> {
        lossy_user_ids(&self.inner.details)
    }

    /// The public subkey objects attached to the certificate.
    #[getter]
    fn public_subkeys(&self, py: Python<'_>) -> PyResult<Vec<PySignedPublicSubKey>> {
        self.inner
            .public_subkeys
            .iter()
            .map(|subkey| signed_public_subkey_from_raw(py, subkey))
            .collect()
    }

    /// Verify the certificate's self-signatures and subkey binding signatures.
    fn verify_bindings(&self) -> PyResult<()> {
        self.inner.verify_bindings().map_err(to_py_err)
    }

    /// Serialize the transferable public key to binary packet bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Serialize the transferable public key as ASCII armor.
    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "PublicKey(fingerprint='{}', key_id='{}')",
            self.fingerprint(),
            self.key_id()
        )
    }
}

/// A transferable OpenPGP secret key, including any secret subkeys.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct SecretKey {
    pub(crate) inner: SignedSecretKey,
}

#[pymethods]
impl SecretKey {
    /// Parse an ASCII-armored transferable secret key.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedSecretKey::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse multiple ASCII-armored transferable secret keys from one armored input.
    #[staticmethod]
    fn from_armor_many(data: &str) -> PyResult<(Vec<Self>, Headers)> {
        let (iter, headers) = SignedSecretKey::from_string_many(data).map_err(to_py_err)?;
        let keys = iter
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((keys, headers))
    }

    /// Parse a binary transferable secret key.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = SignedSecretKey::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse multiple binary transferable secret keys from concatenated packet bytes.
    #[staticmethod]
    fn from_bytes_many(data: &[u8]) -> PyResult<Vec<Self>> {
        SignedSecretKey::from_bytes_many(Cursor::new(data))
            .map_err(to_py_err)?
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    /// Parse a single binary transferable secret key from a file.
    #[staticmethod]
    fn from_file(path: PathBuf) -> PyResult<Self> {
        let inner = SignedSecretKey::from_file(&path).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse multiple binary transferable secret keys from a file of concatenated packet bytes.
    #[staticmethod]
    fn from_file_many(path: PathBuf) -> PyResult<Vec<Self>> {
        SignedSecretKey::from_file_many(&path)
            .map_err(to_py_err)?
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    /// Parse a single ASCII-armored transferable secret key from a file.
    #[staticmethod]
    fn from_armor_file(path: PathBuf) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedSecretKey::from_armor_file(&path).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse multiple ASCII-armored transferable secret keys from one armored file.
    #[staticmethod]
    fn from_armor_file_many(path: PathBuf) -> PyResult<(Vec<Self>, Headers)> {
        let (iter, headers) = SignedSecretKey::from_armor_file_many(&path).map_err(to_py_err)?;
        let keys = iter
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((keys, headers))
    }

    /// The RFC 9580 fingerprint of the primary key.
    #[getter]
    fn fingerprint(&self) -> String {
        self.inner
            .primary_key
            .public_key()
            .fingerprint()
            .to_string()
    }

    /// The legacy key identifier of the primary key.
    #[getter]
    fn key_id(&self) -> String {
        self.inner
            .primary_key
            .public_key()
            .legacy_key_id()
            .to_string()
    }

    /// The OpenPGP key-packet version number of the primary key.
    #[getter]
    fn version(&self) -> u8 {
        key_version_number(self.inner.primary_key.version())
    }

    /// The primary key packet's creation time as seconds since the Unix epoch.
    #[getter]
    fn created_at(&self) -> u32 {
        self.inner.primary_key.created_at().as_secs()
    }

    /// The primary key packet's public-key algorithm.
    #[getter]
    fn public_key_algorithm(&self) -> String {
        public_key_algorithm_name(self.inner.primary_key.algorithm()).to_string()
    }

    /// Structured algorithm-specific public-key metadata from `KeyDetails.public_params()`.
    #[getter]
    fn public_params(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        public_params_object(py, self.inner.primary_key.public_params())
    }

    /// The RFC 9580 packet-header framing used by the primary secret-key packet.
    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.inner.primary_key.packet_header_version(),
        }
    }

    /// The number of public subkeys attached to the secret key.
    #[getter]
    fn public_subkey_count(&self) -> usize {
        self.inner.public_subkeys.len()
    }

    /// The number of secret subkeys attached to the secret key.
    #[getter]
    fn secret_subkey_count(&self) -> usize {
        self.inner.secret_subkeys.len()
    }

    /// The primary secret-key packet.
    #[getter]
    fn primary_key(&self, py: Python<'_>) -> PyResult<Py<SecretKeyPacket>> {
        secret_key_packet_object(py, &self.inner.primary_key)
    }

    /// Shared key details, user bindings, and direct signatures.
    #[getter]
    fn details(&self) -> SignedKeyDetails {
        signed_key_details_from_raw(&self.inner.details)
    }

    /// UTF-8 decoded user IDs, with invalid octets replaced lossily.
    #[getter]
    fn user_ids(&self) -> Vec<String> {
        lossy_user_ids(&self.inner.details)
    }

    /// Return the primary secret key packet's RFC 9580 S2K protection parameters.
    ///
    /// Unprotected keys return an ``S2kParams`` instance with usage ``"unprotected"``.
    fn primary_secret_s2k(&self) -> PyS2kParams {
        s2k_params_from_secret_params(self.inner.primary_key.secret_params())
    }

    /// The public subkey views attached to the secret certificate.
    #[getter]
    fn public_subkeys(&self, py: Python<'_>) -> PyResult<Vec<PySignedPublicSubKey>> {
        self.inner
            .public_subkeys
            .iter()
            .map(|subkey| signed_public_subkey_from_raw(py, subkey))
            .collect()
    }

    /// The secret subkey objects attached to the certificate.
    #[getter]
    fn secret_subkeys(&self, py: Python<'_>) -> PyResult<Vec<PySignedSecretSubKey>> {
        self.inner
            .secret_subkeys
            .iter()
            .map(|subkey| signed_secret_subkey_from_raw(py, subkey))
            .collect()
    }

    /// Return RFC 9580 S2K protection parameters for each secret subkey packet.
    fn secret_subkey_s2ks(&self) -> Vec<PyS2kParams> {
        self.inner
            .secret_subkeys
            .iter()
            .map(|subkey| s2k_params_from_secret_params(subkey.key.secret_params()))
            .collect()
    }

    /// Verify the secret key's self-signatures and subkey binding signatures.
    fn verify_bindings(&self) -> PyResult<()> {
        self.inner.verify_bindings().map_err(to_py_err)
    }

    /// Drop the secret key material and return the corresponding public certificate.
    fn to_public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.to_public_key(),
        }
    }

    /// Serialize the transferable secret key to binary packet bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Serialize the transferable secret key as ASCII armor.
    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "SecretKey(fingerprint='{}', key_id='{}')",
            self.fingerprint(),
            self.key_id()
        )
    }
}

#[derive(Clone)]
pub(crate) enum PublicRecipient {
    Certificate(SignedPublicKey),
    Subkey(SignedPublicSubKey),
}

impl PublicRecipient {
    pub(crate) fn encrypt_to_message_builder_v1<'a, R: Read>(
        &'a self,
        builder: &mut PgpMessageBuilder<'a, R, EncryptionSeipdV1>,
        anonymous_recipient: bool,
    ) -> PyResult<()> {
        match self {
            Self::Certificate(recipient) => {
                if let Some(subkey) = recipient
                    .public_subkeys
                    .iter()
                    .find(|subkey| subkey.algorithm().can_encrypt())
                {
                    if anonymous_recipient {
                        builder
                            .encrypt_to_key_anonymous(rand::thread_rng(), subkey)
                            .map_err(to_py_err)?;
                    } else {
                        builder
                            .encrypt_to_key(rand::thread_rng(), subkey)
                            .map_err(to_py_err)?;
                    }
                } else if recipient.algorithm().can_encrypt() {
                    if anonymous_recipient {
                        builder
                            .encrypt_to_key_anonymous(rand::thread_rng(), recipient)
                            .map_err(to_py_err)?;
                    } else {
                        builder
                            .encrypt_to_key(rand::thread_rng(), recipient)
                            .map_err(to_py_err)?;
                    }
                } else {
                    return Err(to_py_err(
                        "public key does not contain an encryption-capable primary key or subkey",
                    ));
                }
            }
            Self::Subkey(subkey) => {
                if !subkey.algorithm().can_encrypt() {
                    return Err(to_py_err("public subkey is not encryption-capable"));
                }
                if anonymous_recipient {
                    builder
                        .encrypt_to_key_anonymous(rand::thread_rng(), subkey)
                        .map_err(to_py_err)?;
                } else {
                    builder
                        .encrypt_to_key(rand::thread_rng(), subkey)
                        .map_err(to_py_err)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn encrypt_to_message_builder_v2<'a, R: Read>(
        &'a self,
        builder: &mut PgpMessageBuilder<'a, R, EncryptionSeipdV2>,
        anonymous_recipient: bool,
    ) -> PyResult<()> {
        match self {
            Self::Certificate(recipient) => {
                if let Some(subkey) = recipient
                    .public_subkeys
                    .iter()
                    .find(|subkey| subkey.algorithm().can_encrypt())
                {
                    if anonymous_recipient {
                        builder
                            .encrypt_to_key_anonymous(rand::thread_rng(), subkey)
                            .map_err(to_py_err)?;
                    } else {
                        builder
                            .encrypt_to_key(rand::thread_rng(), subkey)
                            .map_err(to_py_err)?;
                    }
                } else if recipient.algorithm().can_encrypt() {
                    if anonymous_recipient {
                        builder
                            .encrypt_to_key_anonymous(rand::thread_rng(), recipient)
                            .map_err(to_py_err)?;
                    } else {
                        builder
                            .encrypt_to_key(rand::thread_rng(), recipient)
                            .map_err(to_py_err)?;
                    }
                } else {
                    return Err(to_py_err(
                        "public key does not contain an encryption-capable primary key or subkey",
                    ));
                }
            }
            Self::Subkey(subkey) => {
                if !subkey.algorithm().can_encrypt() {
                    return Err(to_py_err("public subkey is not encryption-capable"));
                }
                if anonymous_recipient {
                    builder
                        .encrypt_to_key_anonymous(rand::thread_rng(), subkey)
                        .map_err(to_py_err)?;
                } else {
                    builder
                        .encrypt_to_key(rand::thread_rng(), subkey)
                        .map_err(to_py_err)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn encrypt_session_key(
        &self,
        session_key: &PgpRawSessionKey,
        version: EncryptionVersion,
        symmetric_algorithm: SymmetricKeyAlgorithm,
        anonymous_recipient: bool,
    ) -> PyResult<PgpPublicKeyEncryptedSessionKey> {
        let packet = match self {
            Self::Certificate(recipient) => {
                if let Some(subkey) = recipient
                    .public_subkeys
                    .iter()
                    .find(|subkey| subkey.algorithm().can_encrypt())
                {
                    match version {
                        EncryptionVersion::SeipdV1 => {
                            PgpPublicKeyEncryptedSessionKey::from_session_key_v3(
                                rand::thread_rng(),
                                session_key,
                                symmetric_algorithm,
                                subkey,
                            )
                            .map_err(to_py_err)
                        }
                        EncryptionVersion::SeipdV2 => {
                            PgpPublicKeyEncryptedSessionKey::from_session_key_v6(
                                rand::thread_rng(),
                                session_key,
                                subkey,
                            )
                            .map_err(to_py_err)
                        }
                    }
                } else if recipient.algorithm().can_encrypt() {
                    match version {
                        EncryptionVersion::SeipdV1 => {
                            PgpPublicKeyEncryptedSessionKey::from_session_key_v3(
                                rand::thread_rng(),
                                session_key,
                                symmetric_algorithm,
                                recipient,
                            )
                            .map_err(to_py_err)
                        }
                        EncryptionVersion::SeipdV2 => {
                            PgpPublicKeyEncryptedSessionKey::from_session_key_v6(
                                rand::thread_rng(),
                                session_key,
                                recipient,
                            )
                            .map_err(to_py_err)
                        }
                    }
                } else {
                    Err(to_py_err(
                        "public key does not contain an encryption-capable primary key or subkey",
                    ))
                }
            }
            Self::Subkey(subkey) => {
                if !subkey.algorithm().can_encrypt() {
                    return Err(to_py_err("public subkey is not encryption-capable"));
                }
                match version {
                    EncryptionVersion::SeipdV1 => {
                        PgpPublicKeyEncryptedSessionKey::from_session_key_v3(
                            rand::thread_rng(),
                            session_key,
                            symmetric_algorithm,
                            subkey,
                        )
                        .map_err(to_py_err)
                    }
                    EncryptionVersion::SeipdV2 => {
                        PgpPublicKeyEncryptedSessionKey::from_session_key_v6(
                            rand::thread_rng(),
                            session_key,
                            subkey,
                        )
                        .map_err(to_py_err)
                    }
                }
            }
        }?;

        Ok(if anonymous_recipient {
            match packet {
                PgpPublicKeyEncryptedSessionKey::V3 {
                    packet_header,
                    id: _,
                    pk_algo,
                    values,
                } => PgpPublicKeyEncryptedSessionKey::V3 {
                    packet_header,
                    id: KeyId::WILDCARD,
                    pk_algo,
                    values,
                },
                PgpPublicKeyEncryptedSessionKey::V6 {
                    packet_header,
                    fingerprint: _,
                    pk_algo,
                    values,
                } => PgpPublicKeyEncryptedSessionKey::V6 {
                    packet_header,
                    fingerprint: None,
                    pk_algo,
                    values,
                },
                other => other,
            }
        } else {
            packet
        })
    }
}

#[derive(Clone)]
pub(crate) enum SecretSigner {
    Certificate(SignedSecretKey),
    Subkey(SignedSecretSubKey),
}

impl SecretSigner {
    pub(crate) fn apply_message_signature<'a, R: Read, E: PgpEncryption>(
        &'a self,
        builder: &mut PgpMessageBuilder<'a, R, E>,
        password: Password,
        hash_algorithm: HashAlgorithm,
    ) {
        match self {
            Self::Certificate(signer) => {
                builder.sign(&signer.primary_key, password, hash_algorithm);
            }
            Self::Subkey(subkey) => {
                builder.sign(&subkey.key, password, hash_algorithm);
            }
        }
    }

    pub(crate) fn cleartext_signature(
        &self,
        text: &str,
        password: &Password,
        hash_algorithm: HashAlgorithm,
    ) -> pgp::errors::Result<Signature> {
        match self {
            Self::Certificate(signer) => PgpDetachedSignature::sign_text_data(
                rand::thread_rng(),
                &signer.primary_key,
                password,
                hash_algorithm,
                Cursor::new(text.as_bytes()),
            )
            .map(|signature| signature.signature),
            Self::Subkey(subkey) => PgpDetachedSignature::sign_text_data(
                rand::thread_rng(),
                &subkey.key,
                password,
                hash_algorithm,
                Cursor::new(text.as_bytes()),
            )
            .map(|signature| signature.signature),
        }
    }
}

pub(crate) fn public_recipient_from_python(
    py: Python<'_>,
    recipient: Py<PyAny>,
) -> PyResult<PublicRecipient> {
    let recipient = recipient.bind(py);
    if let Ok(public_key) = recipient.extract::<PyRef<'_, PublicKey>>() {
        return Ok(PublicRecipient::Certificate(public_key.inner.clone()));
    }
    if let Ok(subkey) = recipient.extract::<PyRef<'_, PySignedPublicSubKey>>() {
        return Ok(PublicRecipient::Subkey(subkey.inner.clone()));
    }
    Err(to_py_err(
        "recipient must be a PublicKey or SignedPublicSubKey",
    ))
}

pub(crate) fn public_recipients_from_python(
    py: Python<'_>,
    recipients: Vec<Py<PyAny>>,
) -> PyResult<Vec<PublicRecipient>> {
    if recipients.is_empty() {
        return Err(to_py_err("at least one recipient is required"));
    }

    recipients
        .into_iter()
        .map(|recipient| public_recipient_from_python(py, recipient))
        .collect()
}

pub(crate) fn secret_signer_from_python(
    py: Python<'_>,
    signer: Py<PyAny>,
) -> PyResult<SecretSigner> {
    let signer = signer.bind(py);
    if let Ok(secret_key) = signer.extract::<PyRef<'_, SecretKey>>() {
        return Ok(SecretSigner::Certificate(secret_key.inner.clone()));
    }
    if let Ok(subkey) = signer.extract::<PyRef<'_, PySignedSecretSubKey>>() {
        return Ok(SecretSigner::Subkey(subkey.inner.clone()));
    }
    Err(to_py_err(
        "signer must be a SecretKey or SignedSecretSubKey",
    ))
}

pub(crate) fn signer_entries_from_python(
    py: Python<'_>,
    signers: Vec<Py<PyAny>>,
    passwords: Option<Vec<Option<String>>>,
) -> PyResult<(Vec<SecretSigner>, Vec<Password>)> {
    if signers.is_empty() {
        return Err(to_py_err("at least one signer is required"));
    }

    let passwords = passwords.unwrap_or_else(|| vec![None; signers.len()]);
    if passwords.len() != signers.len() {
        return Err(to_py_err("password count must match signer count"));
    }

    let signers = signers
        .into_iter()
        .map(|signer| secret_signer_from_python(py, signer))
        .collect::<PyResult<Vec<_>>>()?;
    let passwords = passwords
        .into_iter()
        .map(|password| password_from_option(password.as_deref()))
        .collect::<Vec<_>>();
    Ok((signers, passwords))
}
