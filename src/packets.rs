use crate::conversions::*;
use crate::info::*;
use crate::key_params::*;
use crate::serialization::*;
use crate::*;
use pyo3::types::PyAny;

pub(crate) fn pkesk_version_number(version: pgp::types::PkeskVersion) -> u8 {
    match version {
        pgp::types::PkeskVersion::V3 => 3,
        pgp::types::PkeskVersion::V6 => 6,
        pgp::types::PkeskVersion::Other(value) => value,
    }
}

pub(crate) fn skesk_version_number(version: pgp::types::SkeskVersion) -> u8 {
    match version {
        pgp::types::SkeskVersion::V4 => 4,
        pgp::types::SkeskVersion::V5 => 5,
        pgp::types::SkeskVersion::V6 => 6,
        pgp::types::SkeskVersion::Other(value) => value,
    }
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
pub(crate) struct PublicKeyEncryptedSessionKeyPacket {
    pub(crate) inner: PgpPublicKeyEncryptedSessionKey,
}

#[pymethods]
impl PublicKeyEncryptedSessionKeyPacket {
    #[getter]
    fn version(&self) -> u8 {
        pkesk_version_number(self.inner.version())
    }

    #[getter]
    fn public_key_algorithm(&self) -> Option<String> {
        self.inner
            .algorithm()
            .ok()
            .map(|algorithm| public_key_algorithm_name(algorithm).to_string())
    }

    #[getter]
    fn recipient_key_id(&self) -> Option<String> {
        self.inner
            .id()
            .ok()
            .filter(|key_id| !key_id.is_wildcard())
            .map(|key_id| key_id.to_string())
    }

    #[getter]
    fn recipient_fingerprint(&self) -> Option<String> {
        self.inner
            .fingerprint()
            .ok()
            .and_then(|fingerprint| fingerprint.map(|fingerprint| fingerprint.to_string()))
    }

    #[getter]
    fn recipient_is_anonymous(&self) -> bool {
        match self.inner.version() {
            pgp::types::PkeskVersion::V3 => self
                .inner
                .id()
                .map(|key_id| key_id.is_wildcard())
                .unwrap_or(false),
            pgp::types::PkeskVersion::V6 => self
                .inner
                .fingerprint()
                .map(|fingerprint| fingerprint.is_none())
                .unwrap_or(false),
            pgp::types::PkeskVersion::Other(_) => false,
        }
    }

    fn values_bytes(&self) -> PyResult<Option<Vec<u8>>> {
        match self.inner.values() {
            Ok(values) => serialize_packet_body(values).map(Some),
            Err(_) => Ok(None),
        }
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        serialize_packet_with_header(&self.inner)
    }

    fn __repr__(&self) -> String {
        format!(
            "PublicKeyEncryptedSessionKeyPacket(version={}, public_key_algorithm={:?})",
            self.version(),
            self.public_key_algorithm()
        )
    }
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
pub(crate) struct SymKeyEncryptedSessionKeyPacket {
    pub(crate) inner: PgpSymKeyEncryptedSessionKey,
}

pub(crate) fn skesk_aead_algorithm(packet: &PgpSymKeyEncryptedSessionKey) -> Option<String> {
    match packet {
        PgpSymKeyEncryptedSessionKey::V5 { aead, .. }
        | PgpSymKeyEncryptedSessionKey::V6 { aead, .. } => {
            Some(normalized_algorithm_name(AeadAlgorithm::from(aead)))
        }
        _ => None,
    }
}

pub(crate) fn skesk_aead_iv(packet: &PgpSymKeyEncryptedSessionKey) -> Option<Vec<u8>> {
    match packet {
        PgpSymKeyEncryptedSessionKey::V5 { aead, .. }
        | PgpSymKeyEncryptedSessionKey::V6 { aead, .. } => Some(match aead {
            pgp::packet::AeadProps::Eax { iv } => iv.to_vec(),
            pgp::packet::AeadProps::Ocb { iv } => iv.to_vec(),
            pgp::packet::AeadProps::Gcm { iv } => iv.to_vec(),
        }),
        _ => None,
    }
}

#[pymethods]
impl SymKeyEncryptedSessionKeyPacket {
    #[getter]
    fn version(&self) -> u8 {
        skesk_version_number(self.inner.version())
    }

    #[getter]
    fn symmetric_algorithm(&self) -> Option<String> {
        self.inner
            .sym_algorithm()
            .map(|algorithm| normalized_algorithm_name(algorithm))
    }

    #[getter]
    fn aead_algorithm(&self) -> Option<String> {
        skesk_aead_algorithm(&self.inner)
    }

    #[getter]
    fn string_to_key(&self) -> Option<PyStringToKey> {
        self.inner.s2k().map(|string_to_key| PyStringToKey {
            inner: string_to_key.clone(),
        })
    }

    #[getter]
    fn encrypted_key(&self) -> Option<Vec<u8>> {
        self.inner
            .encrypted_key()
            .map(|encrypted_key| encrypted_key.to_vec())
    }

    #[getter]
    fn aead_iv(&self) -> Option<Vec<u8>> {
        skesk_aead_iv(&self.inner)
    }

    #[getter]
    fn is_supported(&self) -> bool {
        self.inner.is_supported()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        serialize_packet_with_header(&self.inner)
    }

    fn __repr__(&self) -> String {
        format!(
            "SymKeyEncryptedSessionKeyPacket(version={}, symmetric_algorithm={:?})",
            self.version(),
            self.symmetric_algorithm()
        )
    }
}

#[pyclass(subclass, module = "openpgp")]
#[derive(Clone)]
pub(crate) struct EncryptedDataPacket {
    pub(crate) kind: String,
    pub(crate) version: Option<u8>,
    pub(crate) symmetric_algorithm: Option<String>,
    pub(crate) aead_algorithm: Option<String>,
    pub(crate) chunk_size: Option<u8>,
    pub(crate) salt: Option<Vec<u8>>,
    pub(crate) iv: Option<Vec<u8>>,
    pub(crate) data: Vec<u8>,
    pub(crate) packet_bytes: Vec<u8>,
}

#[pyclass(extends = EncryptedDataPacket, module = "openpgp")]
#[derive(Clone)]
pub(crate) struct SymEncryptedDataPacket;

#[pyclass(extends = EncryptedDataPacket, module = "openpgp")]
#[derive(Clone)]
pub(crate) struct SymEncryptedProtectedDataPacket;

#[pyclass(extends = EncryptedDataPacket, module = "openpgp")]
#[derive(Clone)]
pub(crate) struct GnupgAeadDataPacket;

pub(crate) fn encrypted_data_packet_from_packet(
    packet: PgpPacket,
) -> PyResult<EncryptedDataPacket> {
    match packet {
        PgpPacket::SymEncryptedData(packet) => Ok(EncryptedDataPacket {
            kind: "sed".to_string(),
            version: None,
            symmetric_algorithm: None,
            aead_algorithm: None,
            chunk_size: None,
            salt: None,
            iv: None,
            data: packet.data().to_vec(),
            packet_bytes: serialize_packet_with_header(&packet)?,
        }),
        PgpPacket::SymEncryptedProtectedData(packet) => {
            let packet_bytes = serialize_packet_with_header(&packet)?;
            let data = packet.data().to_vec();
            match packet.config() {
                PgpSymEncryptedProtectedDataConfig::V1 => Ok(EncryptedDataPacket {
                    kind: "seipd-v1".to_string(),
                    version: Some(1),
                    symmetric_algorithm: None,
                    aead_algorithm: None,
                    chunk_size: None,
                    salt: None,
                    iv: None,
                    data,
                    packet_bytes,
                }),
                PgpSymEncryptedProtectedDataConfig::V2 {
                    sym_alg,
                    aead,
                    chunk_size,
                    salt,
                } => Ok(EncryptedDataPacket {
                    kind: "seipd-v2".to_string(),
                    version: Some(2),
                    symmetric_algorithm: Some(normalized_algorithm_name(sym_alg)),
                    aead_algorithm: Some(normalized_algorithm_name(aead)),
                    chunk_size: Some((*chunk_size).into()),
                    salt: Some(salt.to_vec()),
                    iv: None,
                    data,
                    packet_bytes,
                }),
            }
        }
        PgpPacket::GnupgAeadData(packet) => {
            let packet_bytes = serialize_packet_with_header(&packet)?;
            let body = serialize_packet_body(&packet)?;
            if body.len() < 4 {
                return Err(to_py_err("invalid GnuPG AEAD packet body"));
            }
            let aead = AeadAlgorithm::from(body[2]);
            let iv_size = aead.iv_size();
            if body.len() < 4 + iv_size {
                return Err(to_py_err("invalid GnuPG AEAD packet body"));
            }

            Ok(EncryptedDataPacket {
                kind: "gnupg-aead".to_string(),
                version: Some(body[0]),
                symmetric_algorithm: Some(normalized_algorithm_name(SymmetricKeyAlgorithm::from(
                    body[1],
                ))),
                aead_algorithm: Some(normalized_algorithm_name(aead)),
                chunk_size: Some(body[3]),
                salt: None,
                iv: Some(body[4..4 + iv_size].to_vec()),
                data: body[4 + iv_size..].to_vec(),
                packet_bytes,
            })
        }
        _ => Err(to_py_err("expected an encrypted data packet")),
    }
}

pub(crate) fn encrypted_data_packet_object(
    py: Python<'_>,
    packet: EncryptedDataPacket,
) -> PyResult<Py<PyAny>> {
    let kind = packet.kind.clone();

    match kind.as_str() {
        "sed" => Ok(Py::new(
            py,
            PyClassInitializer::from(packet).add_subclass(SymEncryptedDataPacket),
        )?
        .into_any()),
        "gnupg-aead" => Ok(Py::new(
            py,
            PyClassInitializer::from(packet).add_subclass(GnupgAeadDataPacket),
        )?
        .into_any()),
        _ => Ok(Py::new(
            py,
            PyClassInitializer::from(packet).add_subclass(SymEncryptedProtectedDataPacket),
        )?
        .into_any()),
    }
}

pub(crate) fn top_level_encryption_packets_from_source(
    source: &[u8],
    headers: &Option<Headers>,
) -> PyResult<(
    Vec<PublicKeyEncryptedSessionKeyPacket>,
    Vec<SymKeyEncryptedSessionKeyPacket>,
    EncryptedDataPacket,
)> {
    let packets = parse_top_level_packets(source, headers)?;
    let mut public_key_packets = Vec::new();
    let mut symmetric_key_packets = Vec::new();
    let mut encrypted_data_packet = None;

    for packet in packets {
        match packet {
            PgpPacket::PublicKeyEncryptedSessionKey(packet) => {
                public_key_packets.push(PublicKeyEncryptedSessionKeyPacket { inner: packet });
            }
            PgpPacket::SymKeyEncryptedSessionKey(packet) => {
                symmetric_key_packets.push(SymKeyEncryptedSessionKeyPacket { inner: packet });
            }
            PgpPacket::SymEncryptedData(_)
            | PgpPacket::SymEncryptedProtectedData(_)
            | PgpPacket::GnupgAeadData(_) => {
                if encrypted_data_packet.is_some() {
                    return Err(to_py_err(
                        "message contains multiple encrypted data packets at the top level",
                    ));
                }
                encrypted_data_packet = Some(encrypted_data_packet_from_packet(packet)?);
            }
            PgpPacket::Marker(_) | PgpPacket::Padding(_) => {}
            _ => {
                return Err(to_py_err(
                    "message is not a top-level encrypted packet sequence",
                ));
            }
        }
    }

    let encrypted_data_packet = encrypted_data_packet
        .ok_or_else(|| to_py_err("message does not contain a top-level encrypted data packet"))?;
    Ok((
        public_key_packets,
        symmetric_key_packets,
        encrypted_data_packet,
    ))
}

pub(crate) fn plain_session_key_from_message_source(
    source: &[u8],
    headers: &Option<Headers>,
    session_key: &[u8],
    symmetric_algorithm: Option<&str>,
) -> PyResult<PgpPlainSessionKey> {
    let (_, _, encrypted_data_packet) = top_level_encryption_packets_from_source(source, headers)?;

    match encrypted_data_packet.kind.as_str() {
        "seipd-v1" => {
            let symmetric_algorithm = symmetric_algorithm
                .ok_or_else(|| {
                    to_py_err(
                        "symmetric_algorithm is required when decrypting a SEIPD v1 message with a raw session key",
                    )
                })
                .and_then(symmetric_algorithm_from_name)?;
            let key = raw_session_key_from_bytes(session_key, symmetric_algorithm)?;
            Ok(PgpPlainSessionKey::V3_4 {
                sym_alg: symmetric_algorithm,
                key,
            })
        }
        "seipd-v2" => {
            let expected_algorithm = encrypted_data_packet
                .symmetric_algorithm
                .as_deref()
                .ok_or_else(|| to_py_err("SEIPD v2 packet did not expose a symmetric algorithm"))
                .and_then(symmetric_algorithm_from_name)?;
            if let Some(provided_algorithm) = symmetric_algorithm {
                let provided_algorithm = symmetric_algorithm_from_name(provided_algorithm)?;
                if provided_algorithm != expected_algorithm {
                    return Err(to_py_err(
                        "symmetric_algorithm does not match the algorithm encoded in the SEIPD v2 packet",
                    ));
                }
            }
            let key = raw_session_key_from_bytes(session_key, expected_algorithm)?;
            Ok(PgpPlainSessionKey::V6 { key })
        }
        "sed" => Err(to_py_err(
            "legacy SymEncryptedData packets are not supported by decrypt_with_session_key",
        )),
        "gnupg-aead" => Err(to_py_err(
            "GnuPG AEAD packets are not supported by decrypt_with_session_key",
        )),
        _ => Err(to_py_err("message is not encrypted")),
    }
}

#[pymethods]
impl EncryptedDataPacket {
    #[getter]
    fn kind(&self) -> String {
        self.kind.clone()
    }

    #[getter]
    fn version(&self) -> Option<u8> {
        self.version
    }

    #[getter]
    fn symmetric_algorithm(&self) -> Option<String> {
        self.symmetric_algorithm.clone()
    }

    #[getter]
    fn aead_algorithm(&self) -> Option<String> {
        self.aead_algorithm.clone()
    }

    #[getter]
    fn chunk_size(&self) -> Option<u8> {
        self.chunk_size
    }

    #[getter]
    fn salt(&self) -> Option<Vec<u8>> {
        self.salt.clone()
    }

    #[getter]
    fn iv(&self) -> Option<Vec<u8>> {
        self.iv.clone()
    }

    fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.packet_bytes.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "EncryptedDataPacket(kind='{}', version={:?})",
            self.kind, self.version
        )
    }
}
