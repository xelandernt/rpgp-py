use crate::composed::keys::*;
use crate::conversions::*;
use crate::info::*;
use crate::packet::{
    encrypted::*,
    signatures::{Signature as PacketSignature, signature_packet_from_raw},
};
use crate::serialization::*;
use crate::*;
use pgp::{
    packet::{PublicKey as PgpPublicKey, PublicSubkey as PgpPublicSubkey, SubpacketData},
    types::{Fingerprint, VerifyingKey},
};
use pyo3::types::PyAny;
use rand::{CryptoRng, RngCore};
use std::{
    fs::{self, File},
    io::{BufReader, Read},
    path::PathBuf,
};

/// A parsed OpenPGP message.
///
/// The message may be literal, compressed, signed, or encrypted.
#[pyclass(subclass, module = "openpgp.composed", from_py_object)]
#[derive(Clone)]
pub(crate) struct Message {
    pub(crate) source: Vec<u8>,
    pub(crate) info: MessageSummary,
}

#[pyclass(extends = Message, module = "openpgp.composed", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct LiteralMessage;

#[pyclass(extends = Message, module = "openpgp.composed", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct CompressedMessage;

#[pyclass(extends = Message, module = "openpgp.composed", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SignedMessage;

#[pyclass(extends = Message, module = "openpgp.composed", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct EncryptedMessage;

#[pyclass(module = "openpgp.packet", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct LiteralDataHeader {
    mode: String,
    file_name: Vec<u8>,
    created: u32,
}

#[pymethods]
impl LiteralDataHeader {
    #[getter]
    fn mode(&self) -> String {
        self.mode.clone()
    }

    #[getter]
    fn file_name(&self) -> Vec<u8> {
        self.file_name.clone()
    }

    #[getter]
    fn created(&self) -> u32 {
        self.created
    }

    fn __repr__(&self) -> String {
        format!(
            "LiteralDataHeader(mode='{}', file_name={:?}, created={})",
            self.mode, self.file_name, self.created
        )
    }
}

fn literal_data_header_from_raw(header: &pgp::packet::LiteralDataHeader) -> LiteralDataHeader {
    LiteralDataHeader {
        mode: data_mode_name(header.mode()).to_string(),
        file_name: header.file_name().to_vec(),
        created: header.created().as_secs(),
    }
}

pub(crate) fn owned_message_from_source(source: Vec<u8>) -> PyResult<Message> {
    let info = message_summary_from_source(&source).map_err(to_py_err)?;
    Ok(Message { source, info })
}

pub(crate) fn message_object_from_source(py: Python<'_>, source: Vec<u8>) -> PyResult<Py<PyAny>> {
    let base = owned_message_from_source(source)?;

    match base.info.kind.as_str() {
        "literal" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(LiteralMessage),
        )?
        .into_any()),
        "compressed" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(CompressedMessage),
        )?
        .into_any()),
        "signed" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(SignedMessage),
        )?
        .into_any()),
        "encrypted" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(EncryptedMessage),
        )?
        .into_any()),
        _ => Err(to_py_err("unknown message kind")),
    }
}

enum SelectedVerifier<'a> {
    Primary(&'a PgpSignedPublicKey),
    Subkey(&'a PgpSignedPublicSubKey),
}

enum OwnedVerifier {
    Primary(PgpPublicKey),
    Subkey(PgpPublicSubkey),
}

struct PythonCryptoRng<'py> {
    py: Python<'py>,
    rng: Py<PyAny>,
}

impl RngCore for PythonCryptoRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("python rng randbytes(n) failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        let bytes = self
            .rng
            .bind(self.py)
            .call_method1("randbytes", (dest.len(),))
            .and_then(|value| value.extract::<Vec<u8>>())
            .map_err(|error| rand::Error::new(std::io::Error::other(error.to_string())))?;
        if bytes.len() != dest.len() {
            return Err(rand::Error::new(std::io::Error::other(
                "python rng returned the wrong number of bytes",
            )));
        }
        dest.copy_from_slice(&bytes);
        Ok(())
    }
}

impl CryptoRng for PythonCryptoRng<'_> {}

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
    certificate: &'a PgpSignedPublicKey,
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
    certificate: &'a PgpSignedPublicKey,
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
    certificate: &'a PgpSignedPublicKey,
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
        if let Some(issuer_key_id) = issuer_key_id
            && verifier.legacy_key_id() != *issuer_key_id
        {
            return Err(to_py_err(
                "hashed issuer fingerprint and issuer key id refer to different certificate keys",
            ));
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

pub(crate) fn cleartext_signed_message_from_signers(
    text: &str,
    signers: &[(SecretSigner, Password)],
    hash_algorithm: HashAlgorithm,
) -> PyResult<PgpCleartextSignedMessage> {
    if signers.is_empty() {
        return Err(to_py_err("at least one signer is required"));
    }

    PgpCleartextSignedMessage::new_many(text, |normalized_text| {
        signers
            .iter()
            .map(|(signer, password)| {
                signer.cleartext_signature(normalized_text, password, hash_algorithm)
            })
            .collect()
    })
    .map_err(to_py_err)
}

#[pymethods]
impl Message {
    /// Parse an ASCII-armored OpenPGP message.
    #[staticmethod]
    fn from_armor(py: Python<'_>, data: &str) -> PyResult<(Py<PyAny>, Headers)> {
        let info = message_summary_from_source(data.as_bytes()).map_err(to_py_err)?;
        let headers = info.headers.clone().unwrap_or_default();
        Ok((
            message_object_from_source(py, data.as_bytes().to_vec())?,
            headers,
        ))
    }

    /// Parse a binary OpenPGP message.
    #[staticmethod]
    fn from_bytes(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyAny>> {
        message_object_from_source(py, data.to_vec())
    }

    /// Parse a binary OpenPGP message from a file.
    #[staticmethod]
    fn from_file(py: Python<'_>, path: PathBuf) -> PyResult<Py<PyAny>> {
        let data = fs::read(path).map_err(to_py_err)?;
        message_object_from_source(py, data)
    }

    /// Parse an ASCII-armored OpenPGP message from a file.
    #[staticmethod]
    fn from_armor_file(py: Python<'_>, path: PathBuf) -> PyResult<(Py<PyAny>, Headers)> {
        let data = fs::read_to_string(path).map_err(to_py_err)?;
        Self::from_armor(py, &data)
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
    fn as_data_vec(&self) -> PyResult<Vec<u8>> {
        payload_bytes_from_source(&self.source)
    }

    /// Read the inner payload as UTF-8 text, automatically decompressing nested compressed layers.
    fn as_data_string(&self) -> PyResult<String> {
        payload_text_from_source(&self.source)
    }

    /// Return the literal data header after automatic decompression, if a literal layer exists.
    fn literal_data_header(&self) -> PyResult<Option<LiteralDataHeader>> {
        let message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        Ok(message
            .literal_data_header()
            .map(literal_data_header_from_raw))
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

    /// Return signature packets for each signature on a signed message.
    ///
    /// This reads the message to the end to finalize one-pass signature verification state,
    /// mirroring the requirements of RFC 9580 one-pass signatures.
    fn signatures(&self) -> PyResult<Vec<PacketSignature>> {
        let mut message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        message.as_data_vec().map_err(to_py_err)?;

        match &message {
            PgpMessage::Signed { reader, .. } => Ok(reader
                .signatures()
                .ok_or_else(|| to_py_err("cannot inspect signatures before reading the message"))?
                .iter()
                .map(|sig| signature_packet_from_raw(sig.signature()))
                .collect()),
            PgpMessage::Encrypted { .. } => Err(to_py_err(
                "message must be decrypted before inspecting signatures",
            )),
            _ => Ok(Vec::new()),
        }
    }

    /// Return the top-level public-key encrypted session key packets on an encrypted message.
    fn public_key_encrypted_session_key_packets(
        &self,
    ) -> PyResult<Vec<PublicKeyEncryptedSessionKey>> {
        let (public_key_packets, _, _) =
            top_level_encryption_packets_from_source(&self.source, &self.info.headers)?;
        Ok(public_key_packets)
    }

    /// Return the top-level password-encrypted session key packets on an encrypted message.
    fn symmetric_key_encrypted_session_key_packets(
        &self,
    ) -> PyResult<Vec<SymKeyEncryptedSessionKey>> {
        let (_, symmetric_key_packets, _) =
            top_level_encryption_packets_from_source(&self.source, &self.info.headers)?;
        Ok(symmetric_key_packets)
    }

    /// Return the top-level encrypted data packet on an encrypted message.
    fn encrypted_data_packet(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let (_, _, encrypted_data_packet) =
            top_level_encryption_packets_from_source(&self.source, &self.info.headers)?;
        encrypted_data_packet_object(py, encrypted_data_packet)
    }

    /// Verify a specific signature on the message and return the verified signature packet.
    ///
    /// The default index of ``0`` corresponds to the first signature reported by
    /// :meth:`signatures`.
    #[pyo3(signature = (key, index=0))]
    fn verify_signature(
        &self,
        key: PyRef<'_, SignedPublicKey>,
        index: usize,
    ) -> PyResult<PacketSignature> {
        let mut message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        message.as_data_vec().map_err(to_py_err)?;

        let (signature, verifier) = match &message {
            PgpMessage::Signed { reader, .. } => {
                let signatures = reader.signatures().ok_or_else(|| {
                    to_py_err("cannot verify signatures before reading the message")
                })?;
                let signature = signatures
                    .get(index)
                    .ok_or_else(|| to_py_err("signature index out of range"))?;
                let verifier = select_verifier_for_signature(&key.inner, signature.signature())?;
                (signature_packet_from_raw(signature.signature()), verifier)
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
        Ok(signature)
    }

    /// Verify a signed message against a public key.
    ///
    /// By default, this verifies the first signature on the message. Pass ``index`` to target a
    /// later signature in a multi-signed message.
    #[pyo3(signature = (key, index=0))]
    fn verify(&self, key: PyRef<'_, SignedPublicKey>, index: usize) -> PyResult<PacketSignature> {
        self.verify_signature(key, index)
    }

    /// Decrypt an encrypted message using a secret key and optional key-protection password.
    ///
    /// The returned :class:`DecryptedMessage` preserves signature-inspection and verification
    /// helpers so encrypted-and-signed messages can still be verified after decryption.
    #[pyo3(signature = (password, key))]
    fn decrypt(
        &self,
        py: Python<'_>,
        password: Option<&str>,
        key: PyRef<'_, SignedSecretKey>,
    ) -> PyResult<Py<PyAny>> {
        let key_password = password_from_option(password);
        let (message, _) = parse_message(&self.source).map_err(to_py_err)?;
        let decrypted = message
            .decrypt(&key_password, &key.inner)
            .map_err(to_py_err)?;
        decrypted_message_object(py, decrypted_message_from_parsed(decrypted)?)
    }

    /// Decrypt an encrypted message using a message password.
    ///
    /// The returned :class:`DecryptedMessage` preserves signature-inspection helpers for any
    /// signed payload revealed by decryption.
    fn decrypt_with_password(&self, py: Python<'_>, password: &str) -> PyResult<Py<PyAny>> {
        let message_password = Password::from(password);
        let (message, _) = parse_message(&self.source).map_err(to_py_err)?;
        let decrypted = message
            .decrypt_with_password(&message_password)
            .map_err(to_py_err)?;
        decrypted_message_object(py, decrypted_message_from_parsed(decrypted)?)
    }

    /// Decrypt an encrypted message with a raw session key.
    ///
    /// For SEIPD v1 messages, ``symmetric_algorithm`` is required because the encrypted data packet
    /// does not encode the algorithm. For SEIPD v2 messages the algorithm is inferred from the
    /// packet and any provided value must match.
    #[pyo3(signature = (session_key, symmetric_algorithm=None))]
    fn decrypt_with_session_key(
        &self,
        py: Python<'_>,
        session_key: &[u8],
        symmetric_algorithm: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
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
        decrypted_message_object(py, decrypted_message_from_parsed(decrypted)?)
    }

    fn __repr__(&self) -> String {
        format!(
            "Message(kind='{}', is_nested={})",
            self.info.kind, self.info.is_nested
        )
    }
}

#[pymethods]
impl EncryptedMessage {
    #[getter]
    fn esk(slf: PyRef<'_, Self>, py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
        let base: PyRef<'_, Message> = slf.into_super();
        let (public_key_packets, symmetric_key_packets, _) =
            top_level_encryption_packets_from_source(&base.source, &base.info.headers)?;

        let mut packets =
            Vec::with_capacity(public_key_packets.len() + symmetric_key_packets.len());
        for packet in public_key_packets {
            packets.push(Py::new(py, packet)?.into_any());
        }
        for packet in symmetric_key_packets {
            packets.push(Py::new(py, packet)?.into_any());
        }
        Ok(packets)
    }

    #[getter]
    fn edata(slf: PyRef<'_, Self>, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let base: PyRef<'_, Message> = slf.into_super();
        let (_, _, encrypted_data_packet) =
            top_level_encryption_packets_from_source(&base.source, &base.info.headers)?;
        encrypted_data_packet_object(py, encrypted_data_packet)
    }
}

/// A decrypted OpenPGP message with eagerly extracted payload, metadata, and signatures.
///
/// The decrypted payload is materialized once so Python code can continue inspecting or verifying
/// signed content that was revealed by decryption.
#[pyclass(subclass, module = "openpgp.composed", from_py_object)]
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

#[pyclass(extends = DecryptedMessage, module = "openpgp.composed", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct DecryptedLiteralMessage;

#[pyclass(extends = DecryptedMessage, module = "openpgp.composed", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct DecryptedCompressedMessage;

#[pyclass(extends = DecryptedMessage, module = "openpgp.composed", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct DecryptedSignedMessage;

pub(crate) fn decrypted_message_object(
    py: Python<'_>,
    message: DecryptedMessage,
) -> PyResult<Py<PyAny>> {
    match message.kind.as_str() {
        "literal" => Ok(Py::new(
            py,
            PyClassInitializer::from(message).add_subclass(DecryptedLiteralMessage),
        )?
        .into_any()),
        "compressed" => Ok(Py::new(
            py,
            PyClassInitializer::from(message).add_subclass(DecryptedCompressedMessage),
        )?
        .into_any()),
        "signed" => Ok(Py::new(
            py,
            PyClassInitializer::from(message).add_subclass(DecryptedSignedMessage),
        )?
        .into_any()),
        _ => Ok(Py::new(py, message)?.into_any()),
    }
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
    fn as_data_vec(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// The decrypted payload as UTF-8 text.
    fn as_data_string(&self) -> PyResult<String> {
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

    /// Return signature packets for every signature revealed by decryption.
    fn signatures(&self) -> Vec<PacketSignature> {
        self.signatures
            .iter()
            .map(|sig| signature_packet_from_raw(&sig.signature))
            .collect()
    }

    /// Verify a specific signature on the decrypted payload and return the verified signature packet.
    ///
    /// The default index of ``0`` corresponds to the first signature reported by
    /// :meth:`signatures`.
    #[pyo3(signature = (key, index=0))]
    fn verify_signature(
        &self,
        key: PyRef<'_, SignedPublicKey>,
        index: usize,
    ) -> PyResult<PacketSignature> {
        if self.signatures.is_empty() {
            return Err(to_py_err("message was not signed"));
        }

        let signature = self
            .signatures
            .get(index)
            .ok_or_else(|| to_py_err("signature index out of range"))?;
        let verifier = select_verifier_for_signature(&key.inner, &signature.signature)?;
        verifier.verify_signature(&signature.signature, self.payload.as_slice())?;
        Ok(signature_packet_from_raw(&signature.signature))
    }

    /// Verify a signed decrypted payload against a public key.
    ///
    /// By default, this verifies the first signature on the decrypted payload. Pass ``index`` to
    /// target a later signature in a multi-signed payload.
    #[pyo3(signature = (key, index=0))]
    fn verify(&self, key: PyRef<'_, SignedPublicKey>, index: usize) -> PyResult<PacketSignature> {
        self.verify_signature(key, index)
    }

    fn __repr__(&self) -> String {
        format!(
            "DecryptedMessage(kind='{}', is_nested={})",
            self.kind, self.is_nested
        )
    }
}

/// A detached OpenPGP signature packet sequence.
#[pyclass(module = "openpgp.composed", from_py_object)]
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

    /// Parse multiple ASCII-armored detached signatures from one armored input.
    #[staticmethod]
    fn from_armor_many(data: &str) -> PyResult<(Vec<Self>, Headers)> {
        let (iter, headers) = PgpDetachedSignature::from_string_many(data).map_err(to_py_err)?;
        let signatures = iter
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((signatures, headers))
    }

    /// Parse a binary detached signature.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = PgpDetachedSignature::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse multiple binary detached signatures from concatenated packet bytes.
    #[staticmethod]
    fn from_bytes_many(data: &[u8]) -> PyResult<Vec<Self>> {
        PgpDetachedSignature::from_bytes_many(Cursor::new(data))
            .map_err(to_py_err)?
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    /// Parse a single binary detached signature from a file.
    #[staticmethod]
    fn from_file(path: PathBuf) -> PyResult<Self> {
        let inner = PgpDetachedSignature::from_file(&path).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse multiple binary detached signatures from a file of concatenated packet bytes.
    #[staticmethod]
    fn from_file_many(path: PathBuf) -> PyResult<Vec<Self>> {
        PgpDetachedSignature::from_file_many(&path)
            .map_err(to_py_err)?
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    /// Parse a single ASCII-armored detached signature from a file.
    #[staticmethod]
    fn from_armor_file(path: PathBuf) -> PyResult<(Self, Headers)> {
        let (inner, headers) = PgpDetachedSignature::from_armor_file(&path).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse multiple ASCII-armored detached signatures from one armored file.
    #[staticmethod]
    fn from_armor_file_many(path: PathBuf) -> PyResult<(Vec<Self>, Headers)> {
        let (iter, headers) =
            PgpDetachedSignature::from_armor_file_many(&path).map_err(to_py_err)?;
        let signatures = iter
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((signatures, headers))
    }

    /// Create a detached binary signature using the Rust argument order.
    ///
    /// The ``rng`` argument must provide ``randbytes(n) -> bytes`` and is forwarded to rPGP.
    #[staticmethod]
    #[pyo3(signature = (rng, key, password, hash_algorithm, data))]
    fn sign_binary_data(
        py: Python<'_>,
        rng: Py<PyAny>,
        key: Py<PyAny>,
        password: Option<&str>,
        hash_algorithm: &str,
        data: &[u8],
    ) -> PyResult<Self> {
        let password = password_from_option(password);
        let hash_algorithm = hash_algorithm_from_name(hash_algorithm)?;
        let signer = secret_signer_from_python(py, key)?;
        let rng = PythonCryptoRng { py, rng };
        let inner = match signer {
            SecretSigner::Certificate(signer) => PgpDetachedSignature::sign_binary_data(
                rng,
                &signer.primary_key,
                &password,
                hash_algorithm,
                data,
            )
            .map_err(to_py_err),
            SecretSigner::Subkey(subkey) => PgpDetachedSignature::sign_binary_data(
                rng,
                &subkey.key,
                &password,
                hash_algorithm,
                data,
            )
            .map_err(to_py_err),
        }?;
        Ok(Self { inner })
    }

    /// Create a detached text signature using the Rust argument order.
    ///
    /// The ``rng`` argument must provide ``randbytes(n) -> bytes`` and is forwarded to rPGP.
    #[staticmethod]
    #[pyo3(signature = (rng, key, password, hash_algorithm, data))]
    fn sign_text_data(
        py: Python<'_>,
        rng: Py<PyAny>,
        key: Py<PyAny>,
        password: Option<&str>,
        hash_algorithm: &str,
        data: &[u8],
    ) -> PyResult<Self> {
        let password = password_from_option(password);
        let hash_algorithm = hash_algorithm_from_name(hash_algorithm)?;
        let signer = secret_signer_from_python(py, key)?;
        let rng = PythonCryptoRng { py, rng };
        let inner = match signer {
            SecretSigner::Certificate(signer) => PgpDetachedSignature::sign_text_data(
                rng,
                &signer.primary_key,
                &password,
                hash_algorithm,
                Cursor::new(data),
            )
            .map_err(to_py_err),
            SecretSigner::Subkey(subkey) => PgpDetachedSignature::sign_text_data(
                rng,
                &subkey.key,
                &password,
                hash_algorithm,
                Cursor::new(data),
            )
            .map_err(to_py_err),
        }?;
        Ok(Self { inner })
    }

    #[getter]
    fn signature(&self) -> PacketSignature {
        signature_packet_from_raw(&self.inner.signature)
    }

    /// Verify a detached signature against a public key and payload.
    fn verify(&self, key: PyRef<'_, SignedPublicKey>, data: &[u8]) -> PyResult<()> {
        let verifier = select_verifier_for_signature(&key.inner, &self.inner.signature)?;
        verifier.verify_detached(&self.inner, data)
    }

    /// Verify a detached signature and return the signature packet.
    fn verify_signature(
        &self,
        key: PyRef<'_, SignedPublicKey>,
        data: &[u8],
    ) -> PyResult<PacketSignature> {
        self.verify(key, data)?;
        Ok(self.signature())
    }

    /// Verify a detached signature against a public key by streaming the payload from a file.
    fn verify_file(
        &self,
        py: Python<'_>,
        key: PyRef<'_, SignedPublicKey>,
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

    /// Verify a detached signature streamed from a file and return the signature packet.
    fn verify_file_signature(
        &self,
        py: Python<'_>,
        key: PyRef<'_, SignedPublicKey>,
        path: PathBuf,
    ) -> PyResult<PacketSignature> {
        self.verify_file(py, key, path)?;
        Ok(self.signature())
    }

    /// Verify a detached text signature against UTF-8 text.
    ///
    /// Text verification normalizes line endings, matching the semantics of text signatures.
    fn verify_text(&self, key: PyRef<'_, SignedPublicKey>, text: &str) -> PyResult<()> {
        self.verify(key, text.as_bytes())
    }

    /// Verify a detached text signature and return the signature packet.
    ///
    /// Text verification normalizes line endings, matching the semantics of text signatures.
    fn verify_text_signature(
        &self,
        key: PyRef<'_, SignedPublicKey>,
        text: &str,
    ) -> PyResult<PacketSignature> {
        self.verify_text(key, text)?;
        Ok(self.signature())
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
#[pyclass(module = "openpgp.composed", from_py_object)]
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
        py: Python<'_>,
        text: &str,
        key: Py<PyAny>,
        password: Option<&str>,
        hash_algorithm: &str,
    ) -> PyResult<Self> {
        let password = password_from_option(password);
        let hash_algorithm = hash_algorithm_from_name(hash_algorithm)?;
        let signer = secret_signer_from_python(py, key)?;
        let signers = vec![(signer, password)];
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

    /// Return signature packets for every cleartext signature.
    fn signatures(&self) -> Vec<PacketSignature> {
        self.inner
            .signatures()
            .iter()
            .map(signature_packet_from_raw)
            .collect()
    }

    /// Verify at least one cleartext signature against the given public key and return the verified signature packet.
    ///
    /// If ``index`` is provided, only that signature packet is verified.
    #[pyo3(signature = (key, index=None))]
    fn verify_signature(
        &self,
        key: PyRef<'_, SignedPublicKey>,
        index: Option<usize>,
    ) -> PyResult<PacketSignature> {
        let signed_text = self.inner.signed_text();
        let signatures = self.inner.signatures();

        if let Some(index) = index {
            let signature = signatures
                .get(index)
                .ok_or_else(|| to_py_err("signature index out of range"))?;
            let verifier = select_verifier_for_signature(&key.inner, signature)?;
            verifier.verify_signature(signature, signed_text.as_bytes())?;
            return Ok(signature_packet_from_raw(signature));
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
                return Ok(signature_packet_from_raw(signature));
            }
        }

        Err(last_selector_error.unwrap_or_else(|| to_py_err("no matching signature found")))
    }

    /// Verify at least one cleartext signature against the given public key.
    ///
    /// If ``index`` is provided, only that signature packet is verified.
    #[pyo3(signature = (key, index=None))]
    fn verify(
        &self,
        key: PyRef<'_, SignedPublicKey>,
        index: Option<usize>,
    ) -> PyResult<PacketSignature> {
        self.verify_signature(key, index)
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

    fn generate_signing_subkey_certificate() -> (PgpSignedSecretKey, PgpSignedPublicKey) {
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
        let public_key = PgpSignedPublicKey::from(secret_key.clone());
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
    fn verify_message_signature_accepts_bound_signing_subkey_signatures() {
        let (secret_key, public_key) = generate_signing_subkey_certificate();
        let signing_subkey = &secret_key.secret_subkeys[0].key;
        let mut builder = MessageBuilder::from_bytes("", b"payload".as_slice());
        builder.sign(signing_subkey, Password::empty(), HashAlgorithm::Sha256);
        let signed_message = builder.to_vec(&mut thread_rng()).unwrap();
        let mut message = parse_message(&signed_message).unwrap().0;
        message.as_data_vec().unwrap();

        let sig = match &message {
            PgpMessage::Signed { reader, .. } => reader.signatures().unwrap()[0].signature(),
            _ => panic!("expected signed message"),
        };
        let verifier = select_verifier_for_signature(&public_key, sig).unwrap();
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
}
