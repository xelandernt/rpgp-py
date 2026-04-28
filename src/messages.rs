use crate::conversions::*;
use crate::info::*;
use crate::keys::*;
use crate::packets::*;
use crate::serialization::*;
use crate::*;
use pgp::{
    packet::{
        PublicKey as PgpPublicKeyPacket, PublicSubkey as PgpPublicSubkeyPacket, SubpacketData,
    },
    types::{Fingerprint, VerifyingKey},
};
use std::{
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
};

/// A parsed OpenPGP message.
///
/// The message may be literal, compressed, signed, or encrypted.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct Message {
    pub(crate) source: Vec<u8>,
    pub(crate) info: MessageInfo,
}

pub(crate) fn owned_message_from_source(source: Vec<u8>) -> PyResult<Message> {
    let info = inspect_message_from_source(&source).map_err(to_py_err)?;
    Ok(Message { source, info })
}

enum SelectedVerifier<'a> {
    Primary(&'a SignedPublicKey),
    Subkey(&'a SignedPublicSubKey),
}

enum OwnedVerifier {
    Primary(PgpPublicKeyPacket),
    Subkey(PgpPublicSubkeyPacket),
}

impl OwnedVerifier {
    fn verify_signature_reader<R>(&self, signature: &Signature, data: R) -> PyResult<()>
    where
        R: Read,
    {
        match self {
            Self::Primary(key) => signature.verify(key, data).map_err(to_py_err),
            Self::Subkey(subkey) => signature.verify(subkey, data).map_err(to_py_err),
        }
    }
}

impl SelectedVerifier<'_> {
    fn as_dyn(&self) -> &dyn VerifyingKey {
        match self {
            Self::Primary(key) => *key,
            Self::Subkey(subkey) => *subkey,
        }
    }

    fn legacy_key_id(&self) -> KeyId {
        match self {
            Self::Primary(key) => key.legacy_key_id(),
            Self::Subkey(subkey) => subkey.legacy_key_id(),
        }
    }

    fn verify_detached(&self, signature: &PgpDetachedSignature, data: &[u8]) -> PyResult<()> {
        match self {
            Self::Primary(key) => signature.verify(key, data).map_err(to_py_err),
            Self::Subkey(subkey) => signature.verify(subkey, data).map_err(to_py_err),
        }
    }

    fn verify_signature(&self, signature: &Signature, data: &[u8]) -> PyResult<()> {
        match self {
            Self::Primary(key) => signature.verify(key, Cursor::new(data)).map_err(to_py_err),
            Self::Subkey(subkey) => signature
                .verify(subkey, Cursor::new(data))
                .map_err(to_py_err),
        }
    }
}

fn verifier_for_issuer_fingerprint<'a>(
    certificate: &'a SignedPublicKey,
    issuer_fingerprint: &Fingerprint,
) -> PyResult<SelectedVerifier<'a>> {
    if certificate.fingerprint() == *issuer_fingerprint {
        return Ok(SelectedVerifier::Primary(certificate));
    }

    let subkey = certificate
        .public_subkeys
        .iter()
        .find(|subkey| subkey.fingerprint() == *issuer_fingerprint)
        .ok_or_else(|| {
            to_py_err(
                "signature issuer fingerprint does not match the certificate primary key or any bound public subkey",
            )
        })?;
    subkey
        .verify_bindings(&certificate.primary_key)
        .map_err(to_py_err)?;
    Ok(SelectedVerifier::Subkey(subkey))
}

fn verifier_for_issuer_key_id<'a>(
    certificate: &'a SignedPublicKey,
    issuer_key_id: &KeyId,
) -> PyResult<SelectedVerifier<'a>> {
    if certificate.legacy_key_id() == *issuer_key_id {
        return Ok(SelectedVerifier::Primary(certificate));
    }

    let subkey = certificate
        .public_subkeys
        .iter()
        .find(|subkey| subkey.legacy_key_id() == *issuer_key_id)
        .ok_or_else(|| {
            to_py_err(
                "signature issuer key id does not match the certificate primary key or any bound public subkey",
            )
        })?;
    subkey
        .verify_bindings(&certificate.primary_key)
        .map_err(to_py_err)?;
    Ok(SelectedVerifier::Subkey(subkey))
}

/// Resolve which certificate key should be used to verify a signature.
///
/// Selection is based on the signature's own issuer metadata, using **hashed**
/// subpackets only. Unhashed subpackets are advisory per RFC 9580 §5.2.3 and
/// are deliberately ignored for selection.
///
/// Precedence:
///   1. Use the Hashed Issuer Fingerprint subpacket, if present. This must match
///      the primary key or a bound public subkey. If a hashed Issuer Key ID is
///      also present, it must resolve to the same component key.
///   2. Use the Hashed Issuer Key ID (or the fixed field on v3 signatures). This
///      must match the primary key or a bound public subkey.
///   3. Fall back to the primary key, if neither of the above are found.
///
/// Returns an error if a stated issuer cannot be matched to the certificate,
/// if the two hashed identifiers disagree, or if a matched subkey's binding
/// signature does not verify against the primary key.
fn select_verifier_for_signature<'a>(
    certificate: &'a SignedPublicKey,
    signature: &Signature,
) -> PyResult<SelectedVerifier<'a>> {
    let Some(config) = signature.config() else {
        return Ok(SelectedVerifier::Primary(certificate));
    };

    let issuer_fingerprint = config
        .hashed_subpackets()
        .filter_map(|subpacket| {
            if let SubpacketData::IssuerFingerprint(fingerprint) = &subpacket.data {
                Some(fingerprint)
            } else {
                None
            }
        })
        .last();

    let issuer_key_id = match &config.version_specific {
        SignatureVersionSpecific::V2 { issuer_key_id, .. }
        | SignatureVersionSpecific::V3 { issuer_key_id, .. } => Some(issuer_key_id),
        _ => config
            .hashed_subpackets()
            .filter_map(|subpacket| {
                if let SubpacketData::IssuerKeyId(key_id) = &subpacket.data {
                    Some(key_id)
                } else {
                    None
                }
            })
            .last(),
    };

    if let Some(issuer_fingerprint) = issuer_fingerprint {
        let verifier = verifier_for_issuer_fingerprint(certificate, issuer_fingerprint)?;
        if let Some(issuer_key_id) = issuer_key_id {
            if verifier.legacy_key_id() != *issuer_key_id {
                return Err(to_py_err(
                    "hashed issuer fingerprint and issuer key id refer to different certificate keys",
                ));
            }
        }
        return Ok(verifier);
    }

    if let Some(issuer_key_id) = issuer_key_id {
        return verifier_for_issuer_key_id(certificate, issuer_key_id);
    }

    Ok(SelectedVerifier::Primary(certificate))
}

pub(crate) fn decrypted_message_from_parsed(
    mut message: PgpMessage<'_>,
) -> PyResult<DecryptedMessage> {
    let (kind, is_nested, is_signed, is_compressed, is_literal) = match &message {
        PgpMessage::Literal { is_nested, .. } => ("literal", *is_nested, false, false, true),
        PgpMessage::Compressed { is_nested, .. } => ("compressed", *is_nested, false, true, false),
        PgpMessage::Signed { is_nested, .. } => ("signed", *is_nested, true, false, false),
        PgpMessage::Encrypted { .. } => {
            return Err(to_py_err("message is still encrypted after decryption"));
        }
    };

    while message.is_compressed() {
        message = message.decompress().map_err(to_py_err)?;
    }

    let literal_mode = message
        .literal_data_header()
        .map(|header| data_mode_name(header.mode()));
    let literal_filename = message
        .literal_data_header()
        .map(|header| header.file_name().to_vec());
    let payload = message.as_data_vec().map_err(to_py_err)?;
    let signatures = match &message {
        PgpMessage::Signed { reader, .. } => reader
            .signatures()
            .ok_or_else(|| to_py_err("cannot inspect signatures before reading the message"))?
            .iter()
            .map(decrypted_signature_from_full_signature)
            .collect(),
        _ => Vec::new(),
    };

    Ok(DecryptedMessage {
        kind: kind.to_string(),
        is_nested,
        is_signed,
        is_compressed,
        is_literal,
        payload,
        literal_mode,
        literal_filename,
        signatures,
    })
}

pub(crate) fn signature_infos_from_signed_message(
    mut message: PgpMessage<'_>,
) -> PyResult<Vec<SignatureInfo>> {
    message.as_data_vec().map_err(to_py_err)?;

    match &message {
        PgpMessage::Signed { reader, .. } => Ok(reader
            .signatures()
            .ok_or_else(|| to_py_err("cannot inspect signatures before reading the message"))?
            .iter()
            .map(signature_info_from_full_signature)
            .collect()),
        PgpMessage::Encrypted { .. } => Err(to_py_err(
            "message must be decrypted before inspecting signatures",
        )),
        _ => Ok(Vec::new()),
    }
}

pub(crate) fn verify_message_signature_info(
    mut message: PgpMessage<'_>,
    key: &SignedPublicKey,
    index: usize,
) -> PyResult<SignatureInfo> {
    message.as_data_vec().map_err(to_py_err)?;

    let (info, verifier) = match &message {
        PgpMessage::Signed { reader, .. } => {
            let signatures = reader
                .signatures()
                .ok_or_else(|| to_py_err("cannot verify signatures before reading the message"))?;
            let signature = signatures
                .get(index)
                .ok_or_else(|| to_py_err("signature index out of range"))?;
            let verifier = select_verifier_for_signature(key, signature.signature())?;
            (signature_info_from_full_signature(signature), verifier)
        }
        PgpMessage::Encrypted { .. } => {
            return Err(to_py_err(
                "message must be decrypted before verifying signatures",
            ));
        }
        PgpMessage::Literal { .. } => {
            return Err(to_py_err("message was not signed"));
        }
        PgpMessage::Compressed { .. } => {
            return Err(to_py_err(
                "message must be decompressed before verifying signatures",
            ));
        }
    };

    message
        .verify_nested_explicit(index, verifier.as_dyn())
        .map_err(to_py_err)?;
    Ok(info)
}

pub(crate) fn detached_binary_signature_from_data(
    data: &[u8],
    key: &SignedSecretKey,
    password: &Password,
    hash_algorithm: HashAlgorithm,
) -> PyResult<PgpDetachedSignature> {
    PgpDetachedSignature::sign_binary_data(
        rand::thread_rng(),
        &key.primary_key,
        password,
        hash_algorithm,
        Cursor::new(data),
    )
    .map_err(to_py_err)
}

pub(crate) fn detached_text_signature_from_text(
    text: &str,
    key: &SignedSecretKey,
    password: &Password,
    hash_algorithm: HashAlgorithm,
) -> PyResult<PgpDetachedSignature> {
    PgpDetachedSignature::sign_text_data(
        rand::thread_rng(),
        &key.primary_key,
        password,
        hash_algorithm,
        Cursor::new(text.as_bytes()),
    )
    .map_err(to_py_err)
}

pub(crate) fn cleartext_signed_message_from_signers(
    text: &str,
    signers: &[(SignedSecretKey, Password)],
    hash_algorithm: HashAlgorithm,
) -> PyResult<PgpCleartextSignedMessage> {
    if signers.is_empty() {
        return Err(to_py_err("at least one signer is required"));
    }

    PgpCleartextSignedMessage::new_many(text, |normalized_text| {
        signers
            .iter()
            .map(|(signer, password)| {
                PgpDetachedSignature::sign_text_data(
                    rand::thread_rng(),
                    &signer.primary_key,
                    password,
                    hash_algorithm,
                    Cursor::new(normalized_text.as_bytes()),
                )
                .map(|signature| signature.signature)
            })
            .collect()
    })
    .map_err(to_py_err)
}

#[pymethods]
impl Message {
    /// Parse an ASCII-armored OpenPGP message.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let info = inspect_message_from_source(data.as_bytes()).map_err(to_py_err)?;
        let headers = info.headers.clone().unwrap_or_default();
        Ok((
            Self {
                source: data.as_bytes().to_vec(),
                info,
            },
            headers,
        ))
    }

    /// Parse a binary OpenPGP message.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        owned_message_from_source(data.to_vec())
    }

    /// Return the message as binary OpenPGP packet bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        binary_message_source(&self.source, &self.info.headers)
    }

    /// The top-level message kind: literal, compressed, signed, or encrypted.
    #[getter]
    fn kind(&self) -> String {
        self.info.kind.clone()
    }

    /// Whether this message was nested inside another OpenPGP message layer.
    #[getter]
    fn is_nested(&self) -> bool {
        self.info.is_nested
    }

    /// ASCII-armor headers if the message was parsed from armor.
    #[getter]
    fn headers(&self) -> Option<Headers> {
        self.info.headers.clone()
    }

    /// Whether the top-level message is signed.
    #[getter]
    fn is_signed(&self) -> bool {
        self.kind() == "signed"
    }

    /// Whether the top-level message is compressed.
    #[getter]
    fn is_compressed(&self) -> bool {
        self.kind() == "compressed"
    }

    /// Whether the top-level message is literal data.
    #[getter]
    fn is_literal(&self) -> bool {
        self.kind() == "literal"
    }

    /// Read the inner payload as bytes, automatically decompressing nested compressed layers.
    fn payload_bytes(&self) -> PyResult<Vec<u8>> {
        payload_bytes_from_source(&self.source)
    }

    /// Read the inner payload as UTF-8 text, automatically decompressing nested compressed layers.
    fn payload_text(&self) -> PyResult<String> {
        payload_text_from_source(&self.source)
    }

    /// Return the literal data mode after automatic decompression, if a literal layer exists.
    fn literal_mode(&self) -> PyResult<Option<String>> {
        literal_mode_from_source(&self.source)
    }

    /// Return the literal file name octets after automatic decompression, if available.
    fn literal_filename(&self) -> PyResult<Option<Vec<u8>>> {
        literal_filename_from_source(&self.source)
    }

    /// Return the number of signatures after automatic decompression.
    ///
    /// For signed messages this includes both one-pass and prefixed signatures.
    fn signature_count(&self) -> PyResult<usize> {
        signature_count_from_source(&self.source)
    }

    /// Return the number of one-pass signatures after automatic decompression.
    fn one_pass_signature_count(&self) -> PyResult<usize> {
        one_pass_signature_count_from_source(&self.source)
    }

    /// Return the number of prefixed (non-one-pass) signatures after automatic decompression.
    fn regular_signature_count(&self) -> PyResult<usize> {
        regular_signature_count_from_source(&self.source)
    }

    /// Return metadata for each signature packet on a signed message.
    ///
    /// This reads the message to the end to finalize one-pass signature verification state,
    /// mirroring the requirements of RFC 9580 one-pass signatures.
    fn signature_infos(&self) -> PyResult<Vec<SignatureInfo>> {
        signature_infos_from_source(&self.source)
    }

    /// Return the top-level public-key encrypted session key packets on an encrypted message.
    fn public_key_encrypted_session_key_packets(
        &self,
    ) -> PyResult<Vec<PublicKeyEncryptedSessionKeyPacket>> {
        let (public_key_packets, _, _) =
            top_level_encryption_packets_from_source(&self.source, &self.info.headers)?;
        Ok(public_key_packets)
    }

    /// Return the top-level password-encrypted session key packets on an encrypted message.
    fn symmetric_key_encrypted_session_key_packets(
        &self,
    ) -> PyResult<Vec<SymKeyEncryptedSessionKeyPacket>> {
        let (_, symmetric_key_packets, _) =
            top_level_encryption_packets_from_source(&self.source, &self.info.headers)?;
        Ok(symmetric_key_packets)
    }

    /// Return the top-level encrypted data packet on an encrypted message.
    fn encrypted_data_packet(&self) -> PyResult<EncryptedDataPacket> {
        let (_, _, encrypted_data_packet) =
            top_level_encryption_packets_from_source(&self.source, &self.info.headers)?;
        Ok(encrypted_data_packet)
    }

    /// Verify a specific signature on the message and return its metadata.
    ///
    /// The default index of ``0`` corresponds to the first signature reported by
    /// :meth:`signature_infos`.
    #[pyo3(signature = (key, index=0))]
    fn verify_signature(&self, key: PyRef<'_, PublicKey>, index: usize) -> PyResult<SignatureInfo> {
        verify_signature_from_source(&self.source, &key.inner, index)
    }

    /// Verify a signed message against a public key.
    ///
    /// By default, this verifies the first signature on the message. Pass ``index`` to target a
    /// later signature in a multi-signed message.
    #[pyo3(signature = (key, index=0))]
    fn verify(&self, key: PyRef<'_, PublicKey>, index: usize) -> PyResult<()> {
        let _ = self.verify_signature(key, index)?;
        Ok(())
    }

    /// Decrypt an encrypted message using a secret key and optional key-protection password.
    ///
    /// The returned :class:`DecryptedMessage` preserves signature-inspection and verification
    /// helpers so encrypted-and-signed messages can still be verified after decryption.
    #[pyo3(signature = (key, password=None))]
    fn decrypt(
        &self,
        key: PyRef<'_, SecretKey>,
        password: Option<&str>,
    ) -> PyResult<DecryptedMessage> {
        let key_password = password_from_option(password);
        let (message, _) = parse_message(&self.source).map_err(to_py_err)?;
        let decrypted = message
            .decrypt(&key_password, &key.inner)
            .map_err(to_py_err)?;
        decrypted_message_from_parsed(decrypted)
    }

    /// Decrypt an encrypted message using a message password.
    ///
    /// The returned :class:`DecryptedMessage` preserves signature-inspection helpers for any
    /// signed payload revealed by decryption.
    fn decrypt_with_password(&self, password: &str) -> PyResult<DecryptedMessage> {
        let message_password = Password::from(password);
        let (message, _) = parse_message(&self.source).map_err(to_py_err)?;
        let decrypted = message
            .decrypt_with_password(&message_password)
            .map_err(to_py_err)?;
        decrypted_message_from_parsed(decrypted)
    }

    /// Decrypt an encrypted message with a raw session key.
    ///
    /// For SEIPD v1 messages, ``symmetric_algorithm`` is required because the encrypted data packet
    /// does not encode the algorithm. For SEIPD v2 messages the algorithm is inferred from the
    /// packet and any provided value must match.
    #[pyo3(signature = (session_key, symmetric_algorithm=None))]
    fn decrypt_with_session_key(
        &self,
        session_key: &[u8],
        symmetric_algorithm: Option<&str>,
    ) -> PyResult<DecryptedMessage> {
        let plain_session_key = plain_session_key_from_message_source(
            &self.source,
            &self.info.headers,
            session_key,
            symmetric_algorithm,
        )?;
        let (message, _) = parse_message(&self.source).map_err(to_py_err)?;
        let decrypted = message
            .decrypt_with_session_key(plain_session_key)
            .map_err(to_py_err)?;
        decrypted_message_from_parsed(decrypted)
    }

    fn __repr__(&self) -> String {
        format!(
            "Message(kind='{}', is_nested={})",
            self.info.kind, self.info.is_nested
        )
    }
}

/// A decrypted OpenPGP message with eagerly extracted payload, metadata, and signatures.
///
/// The decrypted payload is materialized once so Python code can continue inspecting or verifying
/// signed content that was revealed by decryption.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct DecryptedMessage {
    pub(crate) kind: String,
    pub(crate) is_nested: bool,
    pub(crate) is_signed: bool,
    pub(crate) is_compressed: bool,
    pub(crate) is_literal: bool,
    pub(crate) payload: Vec<u8>,
    pub(crate) literal_mode: Option<String>,
    pub(crate) literal_filename: Option<Vec<u8>>,
    pub(crate) signatures: Vec<DecryptedSignature>,
}

#[pymethods]
impl DecryptedMessage {
    /// The top-level decrypted message kind.
    #[getter]
    fn kind(&self) -> String {
        self.kind.clone()
    }

    /// Whether the decrypted message was nested inside another message layer.
    #[getter]
    fn is_nested(&self) -> bool {
        self.is_nested
    }

    /// Whether the decrypted top-level message is signed.
    #[getter]
    fn is_signed(&self) -> bool {
        self.is_signed
    }

    /// Whether the decrypted top-level message is compressed.
    #[getter]
    fn is_compressed(&self) -> bool {
        self.is_compressed
    }

    /// Whether the decrypted top-level message is literal data.
    #[getter]
    fn is_literal(&self) -> bool {
        self.is_literal
    }

    /// The decrypted payload bytes after automatic decompression.
    fn payload_bytes(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// The decrypted payload as UTF-8 text.
    fn payload_text(&self) -> PyResult<String> {
        String::from_utf8(self.payload.clone()).map_err(to_py_err)
    }

    /// The literal data mode after automatic decompression, if a literal layer exists.
    fn literal_mode(&self) -> Option<String> {
        self.literal_mode.clone()
    }

    /// The literal file name octets after automatic decompression, if available.
    fn literal_filename(&self) -> Option<Vec<u8>> {
        self.literal_filename.clone()
    }

    /// Return the number of signatures revealed by decryption and automatic decompression.
    fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Return the number of one-pass signatures revealed by decryption.
    fn one_pass_signature_count(&self) -> usize {
        self.signatures
            .iter()
            .filter(|signature| signature.is_one_pass)
            .count()
    }

    /// Return the number of prefixed (non-one-pass) signatures revealed by decryption.
    fn regular_signature_count(&self) -> usize {
        self.signatures
            .iter()
            .filter(|signature| !signature.is_one_pass)
            .count()
    }

    /// Return metadata for every signature packet revealed by decryption.
    fn signature_infos(&self) -> Vec<SignatureInfo> {
        self.signatures
            .iter()
            .map(signature_info_from_decrypted_signature)
            .collect()
    }

    /// Verify a specific signature on the decrypted payload and return its metadata.
    ///
    /// The default index of ``0`` corresponds to the first signature reported by
    /// :meth:`signature_infos`.
    #[pyo3(signature = (key, index=0))]
    fn verify_signature(&self, key: PyRef<'_, PublicKey>, index: usize) -> PyResult<SignatureInfo> {
        if self.signatures.is_empty() {
            return Err(to_py_err("message was not signed"));
        }

        let signature = self
            .signatures
            .get(index)
            .ok_or_else(|| to_py_err("signature index out of range"))?;
        let verifier = select_verifier_for_signature(&key.inner, &signature.signature)?;
        verifier.verify_signature(&signature.signature, self.payload.as_slice())?;
        Ok(signature_info_from_decrypted_signature(signature))
    }

    /// Verify a signed decrypted payload against a public key.
    ///
    /// By default, this verifies the first signature on the decrypted payload. Pass ``index`` to
    /// target a later signature in a multi-signed payload.
    #[pyo3(signature = (key, index=0))]
    fn verify(&self, key: PyRef<'_, PublicKey>, index: usize) -> PyResult<()> {
        let _ = self.verify_signature(key, index)?;
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "DecryptedMessage(kind='{}', is_nested={})",
            self.kind, self.is_nested
        )
    }
}

/// A detached OpenPGP signature packet sequence.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct DetachedSignature {
    pub(crate) inner: PgpDetachedSignature,
}

#[pymethods]
impl DetachedSignature {
    /// Parse an ASCII-armored detached signature.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = PgpDetachedSignature::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse a binary detached signature.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = PgpDetachedSignature::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Create a detached binary signature using the selected hash algorithm.
    #[staticmethod]
    #[pyo3(signature = (data, key, password=None, hash_algorithm="sha256"))]
    fn sign_binary(
        data: &[u8],
        key: PyRef<'_, SecretKey>,
        password: Option<&str>,
        hash_algorithm: &str,
    ) -> PyResult<Self> {
        let password = password_from_option(password);
        let hash_algorithm = hash_algorithm_from_name(hash_algorithm)?;
        let inner =
            detached_binary_signature_from_data(data, &key.inner, &password, hash_algorithm)?;
        Ok(Self { inner })
    }

    /// Create a detached text signature over UTF-8 text.
    ///
    /// Text signatures normalize line endings during signing and verification, making them stable
    /// across LF and CRLF representations of the same text.
    #[staticmethod]
    #[pyo3(signature = (text, key, password=None, hash_algorithm="sha256"))]
    fn sign_text(
        text: &str,
        key: PyRef<'_, SecretKey>,
        password: Option<&str>,
        hash_algorithm: &str,
    ) -> PyResult<Self> {
        let password = password_from_option(password);
        let hash_algorithm = hash_algorithm_from_name(hash_algorithm)?;
        let inner = detached_text_signature_from_text(text, &key.inner, &password, hash_algorithm)?;
        Ok(Self { inner })
    }

    /// Return metadata for the detached signature packet.
    fn signature_info(&self) -> SignatureInfo {
        signature_info_from_signature(&self.inner.signature, false)
    }

    /// Verify a detached signature against a public key and payload.
    fn verify(&self, key: PyRef<'_, PublicKey>, data: &[u8]) -> PyResult<()> {
        let verifier = select_verifier_for_signature(&key.inner, &self.inner.signature)?;
        verifier.verify_detached(&self.inner, data)
    }

    /// Verify a detached signature and return its metadata.
    fn verify_signature(&self, key: PyRef<'_, PublicKey>, data: &[u8]) -> PyResult<SignatureInfo> {
        self.verify(key, data)?;
        Ok(self.signature_info())
    }

    /// Verify a detached signature against a public key by streaming the payload from a file.
    fn verify_file(
        &self,
        py: Python<'_>,
        key: PyRef<'_, PublicKey>,
        path: PathBuf,
    ) -> PyResult<()> {
        let selected_verifier = select_verifier_for_signature(&key.inner, &self.inner.signature)?;
        // Subkey bindings are verified before SelectedVerifier::Subkey is returned.
        let verifier = match selected_verifier {
            SelectedVerifier::Primary(key) => OwnedVerifier::Primary(key.primary_key.clone()),
            SelectedVerifier::Subkey(subkey) => OwnedVerifier::Subkey(subkey.key.clone()),
        };
        let signature = self.inner.signature.clone();
        py.detach(move || {
            let file = File::open(path).map_err(to_py_err)?;
            verifier.verify_signature_reader(&signature, BufReader::new(file))
        })
    }

    /// Verify a detached text signature against UTF-8 text.
    ///
    /// Text verification normalizes line endings, matching the semantics of text signatures.
    fn verify_text(&self, key: PyRef<'_, PublicKey>, text: &str) -> PyResult<()> {
        self.verify(key, text.as_bytes())
    }

    /// Verify a detached text signature and return its metadata.
    ///
    /// Text verification normalizes line endings, matching the semantics of text signatures.
    fn verify_text_signature(
        &self,
        key: PyRef<'_, PublicKey>,
        text: &str,
    ) -> PyResult<SignatureInfo> {
        self.verify_text(key, text)?;
        Ok(self.signature_info())
    }

    /// Serialize the detached signature to binary packet bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Serialize the detached signature as ASCII armor.
    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        "DetachedSignature()".to_string()
    }
}

/// A cleartext signed message, following RFC 9580 section 7.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct CleartextSignedMessage {
    pub(crate) inner: PgpCleartextSignedMessage,
}

#[pymethods]
impl CleartextSignedMessage {
    /// Parse an ASCII-armored cleartext signed message.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = PgpCleartextSignedMessage::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Create a cleartext signed message using the selected hash algorithm.
    #[staticmethod]
    #[pyo3(signature = (text, key, password=None, hash_algorithm="sha256"))]
    fn sign(
        text: &str,
        key: PyRef<'_, SecretKey>,
        password: Option<&str>,
        hash_algorithm: &str,
    ) -> PyResult<Self> {
        let password = password_from_option(password);
        let hash_algorithm = hash_algorithm_from_name(hash_algorithm)?;
        let signers = vec![(key.inner.clone(), password)];
        let inner = cleartext_signed_message_from_signers(text, &signers, hash_algorithm)?;
        Ok(Self { inner })
    }

    /// The dash-escaped cleartext body exactly as serialized inside the framework.
    #[getter]
    fn text(&self) -> String {
        self.inner.text().to_string()
    }

    /// The normalized text that is hashed and verified, using CRLF line endings.
    fn signed_text(&self) -> String {
        self.inner.signed_text()
    }

    /// Return the number of signatures attached to the cleartext framework.
    fn signature_count(&self) -> usize {
        self.inner.signatures().len()
    }

    /// Return metadata for every cleartext signature packet.
    fn signature_infos(&self) -> Vec<SignatureInfo> {
        self.inner
            .signatures()
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect()
    }

    /// Verify at least one cleartext signature against the given public key and return metadata.
    ///
    /// If ``index`` is provided, only that signature packet is verified.
    #[pyo3(signature = (key, index=None))]
    fn verify_signature(
        &self,
        key: PyRef<'_, PublicKey>,
        index: Option<usize>,
    ) -> PyResult<SignatureInfo> {
        let signed_text = self.inner.signed_text();
        let signatures = self.inner.signatures();

        if let Some(index) = index {
            let signature = signatures
                .get(index)
                .ok_or_else(|| to_py_err("signature index out of range"))?;
            let verifier = select_verifier_for_signature(&key.inner, signature)?;
            verifier.verify_signature(signature, signed_text.as_bytes())?;
            return Ok(signature_info_from_signature(signature, false));
        }

        let mut last_selector_error: Option<PyErr> = None;
        for signature in signatures {
            let verifier = match select_verifier_for_signature(&key.inner, signature) {
                Ok(verifier) => verifier,
                Err(err) => {
                    last_selector_error = Some(err);
                    continue;
                }
            };
            if verifier
                .verify_signature(signature, signed_text.as_bytes())
                .is_ok()
            {
                return Ok(signature_info_from_signature(signature, false));
            }
        }

        Err(last_selector_error.unwrap_or_else(|| to_py_err("no matching signature found")))
    }

    /// Verify at least one cleartext signature against the given public key.
    ///
    /// If ``index`` is provided, only that signature packet is verified.
    #[pyo3(signature = (key, index=None))]
    fn verify(&self, key: PyRef<'_, PublicKey>, index: Option<usize>) -> PyResult<()> {
        let _ = self.verify_signature(key, index)?;
        Ok(())
    }

    /// Serialize the cleartext signed message as ASCII armor.
    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "CleartextSignedMessage(signature_count={})",
            self.inner.signatures().len()
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use pgp::{
        composed::{MessageBuilder, SubpacketConfig},
        packet::Subpacket,
    };
    use rand::thread_rng;

    fn generate_signing_subkey_certificate() -> (SignedSecretKey, SignedPublicKey) {
        let params = PgpSecretKeyParamsBuilder::default()
            .version(KeyVersion::V6)
            .key_type(PgpKeyType::Ed25519)
            .can_certify(true)
            .primary_user_id("alice".into())
            .subkey(
                PgpSubkeyParamsBuilder::default()
                    .version(KeyVersion::V6)
                    .key_type(PgpKeyType::Ed25519)
                    .can_sign(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let secret_key = params.generate(thread_rng()).unwrap();
        let public_key = SignedPublicKey::from(secret_key.clone());
        (secret_key, public_key)
    }

    #[test]
    fn select_verifier_for_signature_uses_signing_subkey_when_hashed_issuer_fingerprint_matches() {
        let (secret_key, public_key) = generate_signing_subkey_certificate();
        let signing_subkey = &secret_key.secret_subkeys[0].key;
        let signature = PgpDetachedSignature::sign_binary_data(
            thread_rng(),
            signing_subkey,
            &Password::empty(),
            HashAlgorithm::Sha256,
            Cursor::new(b"payload"),
        )
        .unwrap();

        let verifier = select_verifier_for_signature(&public_key, &signature.signature).unwrap();
        match verifier {
            SelectedVerifier::Subkey(subkey) => {
                assert_eq!(
                    subkey.fingerprint(),
                    public_key.public_subkeys[0].fingerprint()
                );
            }
            SelectedVerifier::Primary(_) => panic!("expected signing subkey verifier"),
        }
    }

    #[test]
    fn select_verifier_for_signature_falls_back_to_primary_without_hashed_issuer_metadata() {
        let (secret_key, public_key) = generate_signing_subkey_certificate();
        let signing_subkey = &secret_key.secret_subkeys[0].key;
        let signature = PgpDetachedSignature::sign_binary_data_with_subpackets(
            thread_rng(),
            signing_subkey,
            &Password::empty(),
            HashAlgorithm::Sha256,
            Cursor::new(b"payload"),
            SubpacketConfig::UserDefined {
                hashed: vec![
                    Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
                        .unwrap(),
                ],
                unhashed: vec![],
            },
        )
        .unwrap();

        let verifier = select_verifier_for_signature(&public_key, &signature.signature).unwrap();
        match verifier {
            SelectedVerifier::Primary(_) => {}
            SelectedVerifier::Subkey(_) => panic!("expected primary-key fallback"),
        }
    }

    #[test]
    fn verify_message_signature_info_accepts_bound_signing_subkey_signatures() {
        let (secret_key, public_key) = generate_signing_subkey_certificate();
        let signing_subkey = &secret_key.secret_subkeys[0].key;
        let mut builder = MessageBuilder::from_bytes("", b"payload".as_slice());
        builder.sign(signing_subkey, Password::empty(), HashAlgorithm::Sha256);
        let signed_message = builder.to_vec(&mut thread_rng()).unwrap();
        let (message, _) = parse_message(&signed_message).unwrap();

        let info = verify_message_signature_info(message, &public_key, 0).unwrap();
        assert_eq!(
            info.issuer_fingerprints,
            vec![public_key.public_subkeys[0].fingerprint().to_string()]
        );
    }
}
