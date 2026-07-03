use crate::conversions::*;
use crate::*;
use rsa::traits::PublicKeyParts;

pub(crate) fn parse_message(
    source: &[u8],
) -> Result<(PgpMessage<'_>, Option<Headers>), pgp::errors::Error> {
    PgpMessage::from_reader(Cursor::new(source))
}

pub(crate) fn inspect_message_from_source(
    source: &[u8],
) -> Result<MessageInfo, pgp::errors::Error> {
    let (message, headers) = parse_message(source)?;
    Ok(message_info_from_parts(message, headers))
}

pub(crate) fn message_info_from_ref(
    message: &PgpMessage<'_>,
    headers: Option<Headers>,
) -> MessageInfo {
    let (kind, is_nested) = match message {
        PgpMessage::Literal { is_nested, .. } => ("literal", *is_nested),
        PgpMessage::Compressed { is_nested, .. } => ("compressed", *is_nested),
        PgpMessage::Signed { is_nested, .. } => ("signed", *is_nested),
        PgpMessage::Encrypted { is_nested, .. } => ("encrypted", *is_nested),
    };

    MessageInfo {
        kind: kind.to_string(),
        is_nested,
        headers,
    }
}

pub(crate) fn message_info_from_parts(
    message: PgpMessage<'_>,
    headers: Option<Headers>,
) -> MessageInfo {
    message_info_from_ref(&message, headers)
}

pub(crate) fn parse_message_info_from_reader(
    reader: Cursor<&[u8]>,
) -> Result<MessageInfo, pgp::errors::Error> {
    let (message, headers) = PgpMessage::from_reader(reader)?;
    Ok(message_info_from_parts(message, headers))
}

pub(crate) fn prepare_message_for_content(
    source: &[u8],
) -> Result<PgpMessage<'_>, pgp::errors::Error> {
    let (mut message, _) = parse_message(source)?;
    while message.is_compressed() {
        message = message.decompress()?;
    }
    Ok(message)
}

pub(crate) fn payload_bytes_from_source(source: &[u8]) -> PyResult<Vec<u8>> {
    let mut message = prepare_message_for_content(source).map_err(to_py_err)?;
    if matches!(message, PgpMessage::Encrypted { .. }) {
        return Err(to_py_err(
            "message must be decrypted before reading payload",
        ));
    }
    message.as_data_vec().map_err(to_py_err)
}

pub(crate) fn payload_text_from_source(source: &[u8]) -> PyResult<String> {
    let mut message = prepare_message_for_content(source).map_err(to_py_err)?;
    if matches!(message, PgpMessage::Encrypted { .. }) {
        return Err(to_py_err(
            "message must be decrypted before reading payload",
        ));
    }
    message.as_data_string().map_err(to_py_err)
}

pub(crate) fn literal_mode_from_source(source: &[u8]) -> PyResult<Option<String>> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    Ok(message
        .literal_data_header()
        .map(|header| data_mode_name(header.mode())))
}

pub(crate) fn literal_filename_from_source(source: &[u8]) -> PyResult<Option<Vec<u8>>> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    Ok(message
        .literal_data_header()
        .map(|header| header.file_name().to_vec()))
}

pub(crate) fn signature_count_from_source(source: &[u8]) -> PyResult<usize> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    match message {
        PgpMessage::Signed { reader, .. } => Ok(reader.num_signatures()),
        PgpMessage::Encrypted { .. } => Err(to_py_err(
            "message must be decrypted before inspecting signatures",
        )),
        _ => Ok(0),
    }
}

pub(crate) fn one_pass_signature_count_from_source(source: &[u8]) -> PyResult<usize> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    match message {
        PgpMessage::Signed { reader, .. } => Ok(reader.num_one_pass_signatures()),
        PgpMessage::Encrypted { .. } => Err(to_py_err(
            "message must be decrypted before inspecting signatures",
        )),
        _ => Ok(0),
    }
}

pub(crate) fn regular_signature_count_from_source(source: &[u8]) -> PyResult<usize> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    match message {
        PgpMessage::Signed { reader, .. } => Ok(reader.num_regular_signatures()),
        PgpMessage::Encrypted { .. } => Err(to_py_err(
            "message must be decrypted before inspecting signatures",
        )),
        _ => Ok(0),
    }
}

pub(crate) fn public_key_algorithm_name(algorithm: PgpPublicKeyAlgorithm) -> &'static str {
    match algorithm {
        PgpPublicKeyAlgorithm::RSA => "rsa",
        PgpPublicKeyAlgorithm::RSAEncrypt => "rsa-encrypt",
        PgpPublicKeyAlgorithm::RSASign => "rsa-sign",
        PgpPublicKeyAlgorithm::ElgamalEncrypt => "elgamal-encrypt",
        PgpPublicKeyAlgorithm::DSA => "dsa",
        PgpPublicKeyAlgorithm::ECDH => "ecdh",
        PgpPublicKeyAlgorithm::ECDSA => "ecdsa",
        PgpPublicKeyAlgorithm::Elgamal => "elgamal",
        PgpPublicKeyAlgorithm::DiffieHellman => "diffie-hellman",
        PgpPublicKeyAlgorithm::EdDSALegacy => "eddsa-legacy",
        PgpPublicKeyAlgorithm::X25519 => "x25519",
        PgpPublicKeyAlgorithm::X448 => "x448",
        PgpPublicKeyAlgorithm::Ed25519 => "ed25519",
        PgpPublicKeyAlgorithm::Ed448 => "ed448",
        PgpPublicKeyAlgorithm::Private100 => "private-100",
        PgpPublicKeyAlgorithm::Private101 => "private-101",
        PgpPublicKeyAlgorithm::Private102 => "private-102",
        PgpPublicKeyAlgorithm::Private103 => "private-103",
        PgpPublicKeyAlgorithm::Private104 => "private-104",
        PgpPublicKeyAlgorithm::Private105 => "private-105",
        PgpPublicKeyAlgorithm::Private106 => "private-106",
        PgpPublicKeyAlgorithm::Private107 => "private-107",
        PgpPublicKeyAlgorithm::Private108 => "private-108",
        PgpPublicKeyAlgorithm::Private109 => "private-109",
        PgpPublicKeyAlgorithm::Private110 => "private-110",
        PgpPublicKeyAlgorithm::Unknown(_) => "unknown",
        _ => "unknown",
    }
}

pub(crate) fn public_params_kind_name(params: &PgpPublicParams) -> &'static str {
    match params {
        PgpPublicParams::RSA(_) => "rsa",
        PgpPublicParams::DSA(_) => "dsa",
        PgpPublicParams::ECDSA(_) => "ecdsa",
        PgpPublicParams::ECDH(_) => "ecdh",
        PgpPublicParams::Elgamal(_) => "elgamal",
        PgpPublicParams::EdDSALegacy(_) => "eddsa-legacy",
        PgpPublicParams::Ed25519(_) => "ed25519",
        PgpPublicParams::X25519(_) => "x25519",
        PgpPublicParams::X448(_) => "x448",
        PgpPublicParams::Ed448(_) => "ed448",
        PgpPublicParams::Unknown { .. } => "unknown",
    }
}

pub(crate) fn curve_name_from_ecc_curve(curve: &ECCCurve) -> Option<&'static str> {
    match curve {
        ECCCurve::Curve25519Legacy => Some("curve25519"),
        ECCCurve::Ed25519Legacy => Some("ed25519"),
        ECCCurve::P256 => Some("p256"),
        ECCCurve::P384 => Some("p384"),
        ECCCurve::P521 => Some("p521"),
        ECCCurve::BrainpoolP256r1 => Some("brainpoolp256r1"),
        ECCCurve::BrainpoolP384r1 => Some("brainpoolp384r1"),
        ECCCurve::BrainpoolP512r1 => Some("brainpoolp512r1"),
        ECCCurve::Secp256k1 => Some("secp256k1"),
        ECCCurve::Unknown(_) => None,
    }
}

pub(crate) fn curve_bit_length_from_ecc_curve(curve: &ECCCurve) -> Option<u16> {
    match curve {
        ECCCurve::Curve25519Legacy
        | ECCCurve::Ed25519Legacy
        | ECCCurve::P256
        | ECCCurve::BrainpoolP256r1
        | ECCCurve::Secp256k1 => Some(256),
        ECCCurve::P384 | ECCCurve::BrainpoolP384r1 => Some(384),
        ECCCurve::P521 => Some(521),
        ECCCurve::BrainpoolP512r1 => Some(512),
        ECCCurve::Unknown(_) => None,
    }
}

pub(crate) fn curve_secret_key_length_from_ecc_curve(curve: &ECCCurve) -> Option<usize> {
    match curve {
        ECCCurve::Curve25519Legacy
        | ECCCurve::Ed25519Legacy
        | ECCCurve::P256
        | ECCCurve::BrainpoolP256r1
        | ECCCurve::Secp256k1 => Some(32),
        ECCCurve::P384 | ECCCurve::BrainpoolP384r1 => Some(48),
        ECCCurve::P521 => Some(66),
        ECCCurve::BrainpoolP512r1 => Some(64),
        ECCCurve::Unknown(_) => None,
    }
}

pub(crate) fn empty_public_params_info(kind: &str) -> PublicParamsInfo {
    PublicParamsInfo {
        kind: kind.to_string(),
        curve: None,
        curve_oid: None,
        curve_alias: None,
        curve_bits: None,
        dsa_bits: None,
        rsa_bits: None,
        secret_key_length: None,
        is_supported: None,
        kdf_hash_algorithm: None,
        kdf_symmetric_algorithm: None,
        kdf_type: None,
    }
}

pub(crate) fn set_curve_metadata(info: &mut PublicParamsInfo, curve: &ECCCurve) {
    info.curve = curve_name_from_ecc_curve(curve).map(str::to_string);
    info.curve_oid = Some(curve.oid_str());
    info.curve_alias = curve.alias().map(str::to_string);
    info.curve_bits = curve_bit_length_from_ecc_curve(curve);
    info.secret_key_length = curve_secret_key_length_from_ecc_curve(curve);
}

pub(crate) fn public_params_info_from_params(params: &PgpPublicParams) -> PublicParamsInfo {
    let kind = public_params_kind_name(params);
    let mut info = empty_public_params_info(kind);

    match params {
        PgpPublicParams::RSA(params) => {
            info.rsa_bits = u32::try_from(params.key.n().bits()).ok();
        }
        PgpPublicParams::DSA(params) => {
            info.dsa_bits = u32::try_from(params.key.components().p().bits()).ok();
        }
        PgpPublicParams::ECDSA(params) => match params {
            PgpEcdsaPublicParams::P256 { .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P256);
                info.is_supported = Some(true);
            }
            PgpEcdsaPublicParams::P384 { .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P384);
                info.is_supported = Some(true);
            }
            PgpEcdsaPublicParams::P521 { .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P521);
                info.is_supported = Some(true);
            }
            PgpEcdsaPublicParams::Secp256k1 { .. } => {
                set_curve_metadata(&mut info, &ECCCurve::Secp256k1);
                info.is_supported = Some(true);
            }
            PgpEcdsaPublicParams::Unsupported { curve, .. } => {
                set_curve_metadata(&mut info, curve);
                info.is_supported = Some(false);
            }
        },
        PgpPublicParams::ECDH(params) => match params {
            PgpEcdhPublicParams::Curve25519Legacy {
                hash,
                alg_sym,
                ecdh_kdf_type,
                ..
            } => {
                set_curve_metadata(&mut info, &ECCCurve::Curve25519Legacy);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
                info.kdf_type = Some(normalized_algorithm_name(ecdh_kdf_type));
            }
            PgpEcdhPublicParams::P256 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P256);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::P384 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P384);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::P521 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P521);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::Brainpool256 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::BrainpoolP256r1);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::Brainpool384 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::BrainpoolP384r1);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::Brainpool512 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::BrainpoolP512r1);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::Unsupported { curve, .. } => {
                set_curve_metadata(&mut info, curve);
                info.is_supported = Some(false);
            }
        },
        PgpPublicParams::EdDSALegacy(params) => match params {
            PgpEddsaLegacyPublicParams::Ed25519 { .. } => {
                set_curve_metadata(&mut info, &ECCCurve::Ed25519Legacy);
                info.is_supported = Some(true);
            }
            PgpEddsaLegacyPublicParams::Unsupported { curve, .. } => {
                set_curve_metadata(&mut info, curve);
                info.is_supported = Some(false);
            }
        },
        PgpPublicParams::Ed25519(_) => {
            set_curve_metadata(&mut info, &ECCCurve::Ed25519Legacy);
            info.is_supported = Some(true);
        }
        PgpPublicParams::X25519(_) => {
            set_curve_metadata(&mut info, &ECCCurve::Curve25519Legacy);
            info.is_supported = Some(true);
        }
        _ => {}
    }

    info
}

pub(crate) fn lossy_user_ids(details: &pgp::composed::SignedKeyDetails) -> Vec<String> {
    details
        .users
        .iter()
        .map(|user| String::from_utf8_lossy(user.id.id()).into_owned())
        .collect()
}

pub(crate) fn user_attribute_kind_name(attribute: &PgpUserAttribute) -> &'static str {
    match attribute.typ() {
        PgpUserAttributeType::Image => "image",
        PgpUserAttributeType::Unknown(_) => "unknown",
    }
}

pub(crate) fn user_attribute_data(attribute: &PgpUserAttribute) -> Vec<u8> {
    match attribute {
        PgpUserAttribute::Image { data, .. } | PgpUserAttribute::Unknown { data, .. } => {
            data.to_vec()
        }
    }
}

pub(crate) fn user_attribute_image_header_version(attribute: &PgpUserAttribute) -> Option<u8> {
    match attribute {
        PgpUserAttribute::Image {
            header: PgpImageHeader::V1(_),
            ..
        } => Some(1),
        PgpUserAttribute::Image {
            header: PgpImageHeader::Unknown { version, .. },
            ..
        } => Some(*version),
        PgpUserAttribute::Unknown { .. } => None,
    }
}

pub(crate) fn user_attribute_image_format(attribute: &PgpUserAttribute) -> Option<String> {
    match attribute {
        PgpUserAttribute::Image {
            header: PgpImageHeader::V1(PgpImageHeaderV1::Jpeg { .. }),
            ..
        } => Some("jpeg".to_string()),
        PgpUserAttribute::Image {
            header: PgpImageHeader::V1(PgpImageHeaderV1::Unknown { format, .. }),
            ..
        } => Some(format!("unknown({format:#x})")),
        PgpUserAttribute::Image {
            header: PgpImageHeader::Unknown { .. },
            ..
        }
        | PgpUserAttribute::Unknown { .. } => None,
    }
}

pub(crate) fn signature_version_number(version: SignatureVersion) -> u8 {
    match version {
        SignatureVersion::V2 => 2,
        SignatureVersion::V3 => 3,
        SignatureVersion::V4 => 4,
        SignatureVersion::V5 => 5,
        SignatureVersion::V6 => 6,
        SignatureVersion::Other(value) => value,
    }
}

pub(crate) fn signature_type_name(signature_type: SignatureType) -> String {
    match signature_type {
        SignatureType::Binary => "binary",
        SignatureType::Text => "text",
        SignatureType::Standalone => "standalone",
        SignatureType::CertGeneric => "cert-generic",
        SignatureType::CertPersona => "cert-persona",
        SignatureType::CertCasual => "cert-casual",
        SignatureType::CertPositive => "cert-positive",
        SignatureType::SubkeyBinding => "subkey-binding",
        SignatureType::KeyBinding => "primary-key-binding",
        SignatureType::Key => "direct-key",
        SignatureType::KeyRevocation => "key-revocation",
        SignatureType::SubkeyRevocation => "subkey-revocation",
        SignatureType::CertRevocation => "cert-revocation",
        SignatureType::Timestamp => "timestamp",
        SignatureType::ThirdParty => "third-party",
        SignatureType::Other(_) => "other",
    }
    .to_string()
}

pub(crate) fn signature_salt(signature: &Signature) -> Option<Vec<u8>> {
    signature
        .config()
        .and_then(|config| match &config.version_specific {
            SignatureVersionSpecific::V6 { salt } => Some(salt.clone()),
            _ => None,
        })
}

pub(crate) fn key_flags_from_key_flags(key_flags: &PgpKeyFlags) -> KeyFlags {
    KeyFlags {
        certify: key_flags.certify(),
        sign: key_flags.sign(),
        encrypt_communications: key_flags.encrypt_comms(),
        encrypt_storage: key_flags.encrypt_storage(),
        authenticate: key_flags.authentication(),
        shared: key_flags.shared(),
        draft_decrypt_forwarded: key_flags.draft_decrypt_forwarded(),
        group: key_flags.group(),
        adsk: key_flags.adsk(),
        timestamping: key_flags.timestamping(),
    }
}

pub(crate) fn features_from_features(features: &PgpFeatures) -> Features {
    Features {
        seipd_v1: features.seipd_v1(),
        seipd_v2: features.seipd_v2(),
    }
}

pub(crate) fn notation_from_notation(notation: &PgpNotation) -> Notation {
    Notation {
        human_readable: notation.readable,
        name: notation.name.to_vec(),
        value: notation.value.to_vec(),
    }
}

pub(crate) fn revocation_key_class_id(class: PgpRevocationKeyClass) -> u8 {
    match class {
        PgpRevocationKeyClass::Default => 0x80,
        PgpRevocationKeyClass::Sensitive => 0xC0,
    }
}

pub(crate) fn revocation_key_class_name(class: PgpRevocationKeyClass) -> &'static str {
    match class {
        PgpRevocationKeyClass::Default => "default",
        PgpRevocationKeyClass::Sensitive => "sensitive",
    }
}

pub(crate) fn revocation_key_from_revocation_key(
    revocation_key: &PgpRevocationKey,
) -> RevocationKey {
    RevocationKey {
        class_id: revocation_key_class_id(revocation_key.class),
        class_name: revocation_key_class_name(revocation_key.class).to_string(),
        public_key_algorithm: public_key_algorithm_name(revocation_key.algorithm).to_string(),
        fingerprint: revocation_key.fingerprint.to_vec(),
    }
}

#[derive(Clone)]
pub(crate) struct DecryptedSignature {
    pub(crate) signature: Signature,
    pub(crate) is_one_pass: bool,
}

pub(crate) fn decrypted_signature_from_full_signature(
    signature: &FullSignaturePacket,
) -> DecryptedSignature {
    DecryptedSignature {
        signature: signature.signature().clone(),
        is_one_pass: matches!(signature, FullSignaturePacket::Ops { .. }),
    }
}

/// Decoded RFC 9580 key-flags subpacket metadata.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone, Copy)]
pub(crate) struct KeyFlags {
    pub(crate) certify: bool,
    pub(crate) sign: bool,
    pub(crate) encrypt_communications: bool,
    pub(crate) encrypt_storage: bool,
    pub(crate) authenticate: bool,
    pub(crate) shared: bool,
    pub(crate) draft_decrypt_forwarded: bool,
    pub(crate) group: bool,
    pub(crate) adsk: bool,
    pub(crate) timestamping: bool,
}

#[pymethods]
impl KeyFlags {
    /// Whether the key may certify other keys and user IDs.
    #[getter]
    fn certify(&self) -> bool {
        self.certify
    }

    /// Whether the key may create data signatures.
    #[getter]
    fn sign(&self) -> bool {
        self.sign
    }

    /// Whether the key may encrypt communications.
    #[getter]
    fn encrypt_communications(&self) -> bool {
        self.encrypt_communications
    }

    /// Whether the key may encrypt storage.
    #[getter]
    fn encrypt_storage(&self) -> bool {
        self.encrypt_storage
    }

    /// Whether the key may be used for authentication.
    #[getter]
    fn authenticate(&self) -> bool {
        self.authenticate
    }

    /// Whether the key is marked as split or shared between multiple holders.
    #[getter]
    fn shared(&self) -> bool {
        self.shared
    }

    /// Whether the draft forwarded-decryption key-flag bit is set.
    #[getter]
    fn draft_decrypt_forwarded(&self) -> bool {
        self.draft_decrypt_forwarded
    }

    /// Whether the key belongs to a group key-management arrangement.
    #[getter]
    fn group(&self) -> bool {
        self.group
    }

    /// Whether the key is marked for additional decryption subkeys (ADSK).
    #[getter]
    fn adsk(&self) -> bool {
        self.adsk
    }

    /// Whether the key may create trusted timestamps.
    #[getter]
    fn timestamping(&self) -> bool {
        self.timestamping
    }

    fn __repr__(&self) -> String {
        format!(
            "KeyFlags(certify={}, sign={}, encrypt_communications={}, encrypt_storage={}, authenticate={})",
            self.certify,
            self.sign,
            self.encrypt_communications,
            self.encrypt_storage,
            self.authenticate,
        )
    }
}

#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct UserAttribute {
    pub(crate) inner: PgpUserAttribute,
}

#[pymethods]
impl UserAttribute {
    /// Create an RFC 9580 image user attribute with the standard JPEG header framing.
    #[staticmethod]
    fn image_jpeg(data: &[u8]) -> PyResult<Self> {
        let inner = PgpUserAttribute::new_image(data.to_vec().into()).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// The normalized RFC 9580 user-attribute type name.
    #[getter]
    fn kind(&self) -> String {
        user_attribute_kind_name(&self.inner).to_string()
    }

    /// The raw user-attribute payload bytes.
    #[getter]
    fn data(&self) -> Vec<u8> {
        user_attribute_data(&self.inner)
    }

    /// The image-header version for image attributes, if present.
    #[getter]
    fn image_header_version(&self) -> Option<u8> {
        user_attribute_image_header_version(&self.inner)
    }

    /// The normalized image format for image attributes, if present.
    #[getter]
    fn image_format(&self) -> Option<String> {
        user_attribute_image_format(&self.inner)
    }

    fn __repr__(&self) -> String {
        format!(
            "UserAttribute(kind='{}', data_len={})",
            self.kind(),
            self.data().len()
        )
    }
}

/// Decoded RFC 9580 Features subpacket metadata.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone, Copy)]
pub(crate) struct Features {
    pub(crate) seipd_v1: bool,
    pub(crate) seipd_v2: bool,
}

#[pymethods]
impl Features {
    /// Whether the issuer advertises support for SEIPD v1 packets.
    #[getter]
    fn seipd_v1(&self) -> bool {
        self.seipd_v1
    }

    /// Whether the issuer advertises support for SEIPD v2 packets.
    #[getter]
    fn seipd_v2(&self) -> bool {
        self.seipd_v2
    }

    fn __repr__(&self) -> String {
        format!(
            "Features(seipd_v1={}, seipd_v2={})",
            self.seipd_v1, self.seipd_v2
        )
    }
}

/// Structured `KeyDetails.public_params()` metadata for a key packet.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct PublicParamsInfo {
    pub(crate) kind: String,
    pub(crate) curve: Option<String>,
    pub(crate) curve_oid: Option<String>,
    pub(crate) curve_alias: Option<String>,
    pub(crate) curve_bits: Option<u16>,
    pub(crate) dsa_bits: Option<u32>,
    pub(crate) rsa_bits: Option<u32>,
    pub(crate) secret_key_length: Option<usize>,
    pub(crate) is_supported: Option<bool>,
    pub(crate) kdf_hash_algorithm: Option<String>,
    pub(crate) kdf_symmetric_algorithm: Option<String>,
    pub(crate) kdf_type: Option<String>,
}

#[pymethods]
impl PublicParamsInfo {
    /// The normalized `PublicParams` variant name.
    #[getter]
    fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The normalized ECC curve name, when this key uses an elliptic-curve algorithm.
    #[getter]
    fn curve(&self) -> Option<String> {
        self.curve.clone()
    }

    /// The IETF OID string for elliptic-curve based keys, when available.
    #[getter]
    fn curve_oid(&self) -> Option<String> {
        self.curve_oid.clone()
    }

    /// The alternate curve alias exposed by rPGP, when available.
    #[getter]
    fn curve_alias(&self) -> Option<String> {
        self.curve_alias.clone()
    }

    /// The nominal elliptic-curve size in bits, when available.
    #[getter]
    fn curve_bits(&self) -> Option<u16> {
        self.curve_bits
    }

    /// The encoded DSA prime size in bits, when this key uses DSA public parameters.
    #[getter]
    fn dsa_bits(&self) -> Option<u32> {
        self.dsa_bits
    }

    /// The encoded RSA modulus size in bits, when this key uses RSA public parameters.
    #[getter]
    fn rsa_bits(&self) -> Option<u32> {
        self.rsa_bits
    }

    /// The expected secret-key length in bytes for supported ECC algorithms, when available.
    #[getter]
    fn secret_key_length(&self) -> Option<usize> {
        self.secret_key_length
    }

    /// Whether rPGP recognizes and parses the curve-specific key material.
    #[getter]
    fn is_supported(&self) -> Option<bool> {
        self.is_supported
    }

    /// The ECDH KDF hash algorithm, when encoded in the public parameters.
    #[getter]
    fn kdf_hash_algorithm(&self) -> Option<String> {
        self.kdf_hash_algorithm.clone()
    }

    /// The ECDH KDF symmetric algorithm, when encoded in the public parameters.
    #[getter]
    fn kdf_symmetric_algorithm(&self) -> Option<String> {
        self.kdf_symmetric_algorithm.clone()
    }

    /// The ECDH KDF flavor for Curve25519 packets, when encoded.
    #[getter]
    fn kdf_type(&self) -> Option<String> {
        self.kdf_type.clone()
    }

    fn __repr__(&self) -> String {
        match &self.curve {
            Some(curve) => format!("PublicParamsInfo(kind='{}', curve='{}')", self.kind, curve),
            None => format!("PublicParamsInfo(kind='{}')", self.kind),
        }
    }
}

/// Decoded RFC 9580 signature-notation metadata.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct Notation {
    pub(crate) human_readable: bool,
    pub(crate) name: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

#[pymethods]
impl Notation {
    /// Whether the notation value is intended to be human-readable text.
    #[getter]
    fn human_readable(&self) -> bool {
        self.human_readable
    }

    /// The raw notation name bytes.
    #[getter]
    fn name(&self) -> Vec<u8> {
        self.name.clone()
    }

    /// The raw notation value bytes.
    #[getter]
    fn value(&self) -> Vec<u8> {
        self.value.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "Notation(human_readable={}, name_len={}, value_len={})",
            self.human_readable,
            self.name.len(),
            self.value.len()
        )
    }
}

/// Decoded designated-revocation-key metadata from a signature.
///
/// This reflects the deprecated RFC 9580 revocation-key subpacket, when present.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct RevocationKey {
    pub(crate) class_id: u8,
    pub(crate) class_name: String,
    pub(crate) public_key_algorithm: String,
    pub(crate) fingerprint: Vec<u8>,
}

#[pymethods]
impl RevocationKey {
    /// The numeric revocation-key class octet.
    #[getter]
    fn class_id(&self) -> u8 {
        self.class_id
    }

    /// The normalized revocation-key class name.
    #[getter]
    fn class_name(&self) -> String {
        self.class_name.clone()
    }

    /// The public-key algorithm carried by the revocation-key subpacket.
    #[getter]
    fn public_key_algorithm(&self) -> String {
        self.public_key_algorithm.clone()
    }

    /// The raw revocation-key fingerprint bytes carried by the signature subpacket.
    #[getter]
    fn fingerprint(&self) -> Vec<u8> {
        self.fingerprint.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "RevocationKey(class_name='{}', public_key_algorithm='{}', fingerprint_len={})",
            self.class_name,
            self.public_key_algorithm,
            self.fingerprint.len()
        )
    }
}

/// Lightweight metadata about an OpenPGP message.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct MessageInfo {
    pub(crate) kind: String,
    pub(crate) is_nested: bool,
    pub(crate) headers: Option<Headers>,
}

#[pymethods]
impl MessageInfo {
    /// The top-level message kind: literal, compressed, signed, or encrypted.
    #[getter]
    fn kind(&self) -> String {
        self.kind.clone()
    }

    /// Whether this message was nested inside another message layer.
    #[getter]
    fn is_nested(&self) -> bool {
        self.is_nested
    }

    /// ASCII-armor headers if the message was parsed from armor.
    #[getter]
    fn headers(&self) -> Option<Headers> {
        self.headers.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "MessageInfo(kind='{}', is_nested={})",
            self.kind, self.is_nested
        )
    }
}
