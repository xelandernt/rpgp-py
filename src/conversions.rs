use crate::*;

pub(crate) fn password_from_option(password: Option<&str>) -> Password {
    match password {
        Some(password) if !password.is_empty() => password.into(),
        _ => Password::empty(),
    }
}

pub(crate) fn key_version_from_number(version: u8) -> PyResult<KeyVersion> {
    match version {
        4 => Ok(KeyVersion::V4),
        6 => Ok(KeyVersion::V6),
        _ => Err(to_py_err("unsupported key version; expected 4 or 6")),
    }
}

pub(crate) fn timestamp_from_seconds(seconds: u32) -> Timestamp {
    Timestamp::from_secs(seconds)
}

pub(crate) fn key_version_number(version: KeyVersion) -> u8 {
    version.into()
}

pub(crate) fn hash_algorithm_from_name(name: &str) -> PyResult<HashAlgorithm> {
    match name.to_ascii_lowercase().as_str() {
        "sha1" => Ok(HashAlgorithm::Sha1),
        "sha224" => Ok(HashAlgorithm::Sha224),
        "sha256" => Ok(HashAlgorithm::Sha256),
        "sha384" => Ok(HashAlgorithm::Sha384),
        "sha512" => Ok(HashAlgorithm::Sha512),
        "sha3-256" | "sha3_256" => Ok(HashAlgorithm::Sha3_256),
        "sha3-512" | "sha3_512" => Ok(HashAlgorithm::Sha3_512),
        _ => Err(to_py_err(
            "unsupported hash algorithm; expected 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3-256', or 'sha3-512'",
        )),
    }
}

pub(crate) fn required_compression_algorithm_from_name(
    name: &str,
) -> PyResult<CompressionAlgorithm> {
    compression_algorithm_from_name(Some(name))?
        .ok_or_else(|| to_py_err("compression algorithm is required"))
}

pub(crate) fn curve_from_name(name: &str) -> PyResult<ECCCurve> {
    match name.to_ascii_lowercase().as_str() {
        "curve25519" => Ok(ECCCurve::Curve25519),
        "ed25519" => Ok(ECCCurve::Ed25519),
        "p256" => Ok(ECCCurve::P256),
        "p384" => Ok(ECCCurve::P384),
        "p521" => Ok(ECCCurve::P521),
        "brainpoolp256r1" => Ok(ECCCurve::BrainpoolP256r1),
        "brainpoolp384r1" => Ok(ECCCurve::BrainpoolP384r1),
        "brainpoolp512r1" => Ok(ECCCurve::BrainpoolP512r1),
        "secp256k1" => Ok(ECCCurve::Secp256k1),
        _ => Err(to_py_err(
            "unsupported elliptic-curve name; expected 'curve25519', 'p256', 'p384', 'p521', 'brainpoolp256r1', 'brainpoolp384r1', 'brainpoolp512r1', or 'secp256k1'",
        )),
    }
}

pub(crate) fn dsa_key_size_from_bits(bits: u32) -> PyResult<PgpDsaKeySize> {
    match bits {
        1024 => Ok(PgpDsaKeySize::B1024),
        2048 => Ok(PgpDsaKeySize::B2048),
        3072 => Ok(PgpDsaKeySize::B3072),
        _ => Err(to_py_err(
            "unsupported DSA key size; expected 1024, 2048, or 3072 bits",
        )),
    }
}

pub(crate) fn symmetric_algorithms_from_names(
    values: Vec<String>,
) -> PyResult<SmallVec<[SymmetricKeyAlgorithm; 8]>> {
    values
        .into_iter()
        .map(|value| symmetric_algorithm_from_name(&value))
        .collect()
}

pub(crate) fn hash_algorithms_from_names(
    values: Vec<String>,
) -> PyResult<SmallVec<[HashAlgorithm; 8]>> {
    values
        .into_iter()
        .map(|value| hash_algorithm_from_name(&value))
        .collect()
}

pub(crate) fn compression_algorithms_from_names(
    values: Vec<String>,
) -> PyResult<SmallVec<[CompressionAlgorithm; 8]>> {
    values
        .into_iter()
        .map(|value| required_compression_algorithm_from_name(&value))
        .collect()
}

pub(crate) fn aead_algorithm_preferences_from_names(
    values: Vec<(String, String)>,
) -> PyResult<SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>> {
    values
        .into_iter()
        .map(|(symmetric_algorithm, aead_algorithm)| {
            Ok((
                symmetric_algorithm_from_name(&symmetric_algorithm)?,
                aead_algorithm_from_name(&aead_algorithm)?,
            ))
        })
        .collect()
}

pub(crate) fn curve_name(curve: &ECCCurve) -> &'static str {
    match curve {
        ECCCurve::Curve25519 => "curve25519",
        ECCCurve::Ed25519 => "ed25519",
        ECCCurve::P256 => "p256",
        ECCCurve::P384 => "p384",
        ECCCurve::P521 => "p521",
        ECCCurve::BrainpoolP256r1 => "brainpoolp256r1",
        ECCCurve::BrainpoolP384r1 => "brainpoolp384r1",
        ECCCurve::BrainpoolP512r1 => "brainpoolp512r1",
        ECCCurve::Secp256k1 => "secp256k1",
        ECCCurve::Unknown(_) => "unknown",
    }
}

pub(crate) fn key_type_name(key_type: &PgpKeyType) -> String {
    match key_type {
        PgpKeyType::Rsa(bits) => format!("rsa({bits})"),
        PgpKeyType::ECDH(curve) => format!("ecdh('{}')", curve_name(curve)),
        PgpKeyType::Ed25519Legacy => "ed25519_legacy".to_string(),
        PgpKeyType::ECDSA(curve) => format!("ecdsa('{}')", curve_name(curve)),
        PgpKeyType::Dsa(PgpDsaKeySize::B1024) => "dsa(1024)".to_string(),
        PgpKeyType::Dsa(PgpDsaKeySize::B2048) => "dsa(2048)".to_string(),
        PgpKeyType::Dsa(PgpDsaKeySize::B3072) => "dsa(3072)".to_string(),
        PgpKeyType::Ed25519 => "ed25519".to_string(),
        PgpKeyType::Ed448 => "ed448".to_string(),
        PgpKeyType::X25519 => "x25519".to_string(),
        PgpKeyType::X448 => "x448".to_string(),
    }
}

pub(crate) fn data_mode_name(mode: DataMode) -> String {
    match mode {
        DataMode::Binary => "binary",
        DataMode::Text => "text",
        DataMode::Utf8 => "utf8",
        DataMode::Mime => "mime",
        DataMode::Other(_) => "other",
    }
    .to_string()
}

pub(crate) fn normalized_algorithm_name(value: impl std::fmt::Debug) -> String {
    format!("{value:?}").to_ascii_lowercase().replace('_', "-")
}

pub(crate) fn symmetric_algorithm_names(values: &[SymmetricKeyAlgorithm]) -> Vec<String> {
    values
        .iter()
        .map(normalized_algorithm_name)
        .collect::<Vec<_>>()
}

pub(crate) fn hash_algorithm_names(values: &[HashAlgorithm]) -> Vec<String> {
    values
        .iter()
        .map(normalized_algorithm_name)
        .collect::<Vec<_>>()
}

pub(crate) fn compression_algorithm_names(values: &[CompressionAlgorithm]) -> Vec<String> {
    values
        .iter()
        .map(normalized_algorithm_name)
        .collect::<Vec<_>>()
}

pub(crate) fn aead_algorithm_preference_names(
    values: &[(SymmetricKeyAlgorithm, AeadAlgorithm)],
) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(symmetric_algorithm, aead_algorithm)| {
            (
                normalized_algorithm_name(symmetric_algorithm),
                normalized_algorithm_name(aead_algorithm),
            )
        })
        .collect::<Vec<_>>()
}

pub(crate) fn packet_header_version_name(version: PgpPacketHeaderVersion) -> &'static str {
    match version {
        PgpPacketHeaderVersion::Old => "old",
        PgpPacketHeaderVersion::New => "new",
    }
}

pub(crate) fn string_to_key_kind_name(value: &PgpStringToKey) -> &'static str {
    match value {
        PgpStringToKey::Simple { .. } => "simple",
        PgpStringToKey::Salted { .. } => "salted",
        PgpStringToKey::Reserved { .. } => "reserved",
        PgpStringToKey::IteratedAndSalted { .. } => "iterated-salted",
        PgpStringToKey::Argon2 { .. } => "argon2",
        PgpStringToKey::Private { .. } => "private",
        PgpStringToKey::Other { .. } => "other",
    }
}

pub(crate) fn s2k_usage_name(value: &PgpS2kParams) -> &'static str {
    match value {
        PgpS2kParams::Unprotected => "unprotected",
        PgpS2kParams::LegacyCfb { .. } => "legacy-cfb",
        PgpS2kParams::Aead { .. } => "aead",
        PgpS2kParams::Cfb { .. } => "cfb",
        PgpS2kParams::MalleableCfb { .. } => "malleable-cfb",
    }
}

#[derive(Clone, Copy)]
pub(crate) enum EncryptionVersion {
    SeipdV1,
    SeipdV2,
}

pub(crate) fn encryption_version_from_name(name: &str) -> PyResult<EncryptionVersion> {
    match name.to_ascii_lowercase().as_str() {
        "seipd-v1" => Ok(EncryptionVersion::SeipdV1),
        "seipd-v2" => Ok(EncryptionVersion::SeipdV2),
        _ => Err(to_py_err(
            "unsupported encryption container; expected 'seipd-v1' or 'seipd-v2'",
        )),
    }
}

pub(crate) fn symmetric_algorithm_from_name(name: &str) -> PyResult<SymmetricKeyAlgorithm> {
    match name.to_ascii_lowercase().as_str() {
        "aes128" => Ok(SymmetricKeyAlgorithm::AES128),
        "aes192" => Ok(SymmetricKeyAlgorithm::AES192),
        "aes256" => Ok(SymmetricKeyAlgorithm::AES256),
        _ => Err(to_py_err(
            "unsupported symmetric algorithm; expected 'aes128', 'aes192', or 'aes256'",
        )),
    }
}

pub(crate) fn aead_algorithm_from_name(name: &str) -> PyResult<AeadAlgorithm> {
    match name.to_ascii_lowercase().as_str() {
        "eax" => Ok(AeadAlgorithm::Eax),
        "ocb" => Ok(AeadAlgorithm::Ocb),
        "gcm" => Ok(AeadAlgorithm::Gcm),
        _ => Err(to_py_err(
            "unsupported AEAD algorithm; expected 'eax', 'ocb', or 'gcm'",
        )),
    }
}

pub(crate) fn compression_algorithm_from_name(
    name: Option<&str>,
) -> PyResult<Option<CompressionAlgorithm>> {
    match name.map(str::to_ascii_lowercase).as_deref() {
        None => Ok(None),
        Some("zip") => Ok(Some(CompressionAlgorithm::ZIP)),
        Some("zlib") => Ok(Some(CompressionAlgorithm::ZLIB)),
        Some("bzip2") => Ok(Some(CompressionAlgorithm::BZip2)),
        _ => Err(to_py_err(
            "unsupported compression algorithm; expected 'zip', 'zlib', or 'bzip2'",
        )),
    }
}
