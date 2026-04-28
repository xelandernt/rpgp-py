use crate::conversions::*;
use crate::key_params::*;
use crate::messages::*;
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

pub(crate) fn signature_infos_from_source(source: &[u8]) -> PyResult<Vec<SignatureInfo>> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    signature_infos_from_signed_message(message)
}

pub(crate) fn verify_signature_from_source(
    source: &[u8],
    key: &SignedPublicKey,
    index: usize,
) -> PyResult<SignatureInfo> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    verify_message_signature_info(message, key, index)
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
        ECCCurve::Curve25519 => Some("curve25519"),
        ECCCurve::Ed25519 => Some("ed25519"),
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
        ECCCurve::Curve25519
        | ECCCurve::Ed25519
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
        ECCCurve::Curve25519
        | ECCCurve::Ed25519
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
            PgpEcdhPublicParams::Curve25519 {
                hash,
                alg_sym,
                ecdh_kdf_type,
                ..
            } => {
                set_curve_metadata(&mut info, &ECCCurve::Curve25519);
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
                set_curve_metadata(&mut info, &ECCCurve::Ed25519);
                info.is_supported = Some(true);
            }
            PgpEddsaLegacyPublicParams::Unsupported { curve, .. } => {
                set_curve_metadata(&mut info, curve);
                info.is_supported = Some(false);
            }
        },
        PgpPublicParams::Ed25519(_) => {
            set_curve_metadata(&mut info, &ECCCurve::Ed25519);
            info.is_supported = Some(true);
        }
        PgpPublicParams::X25519(_) => {
            set_curve_metadata(&mut info, &ECCCurve::Curve25519);
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

pub(crate) fn key_flags_info_from_key_flags(key_flags: &PgpKeyFlags) -> KeyFlagsInfo {
    KeyFlagsInfo {
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

pub(crate) fn features_info_from_features(features: &PgpFeatures) -> FeaturesInfo {
    FeaturesInfo {
        seipd_v1: features.seipd_v1(),
        seipd_v2: features.seipd_v2(),
    }
}

pub(crate) fn signature_notation_info_from_notation(
    notation: &PgpNotation,
) -> SignatureNotationInfo {
    SignatureNotationInfo {
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

pub(crate) fn revocation_key_info_from_revocation_key(
    revocation_key: &PgpRevocationKey,
) -> RevocationKeyInfo {
    RevocationKeyInfo {
        class_id: revocation_key_class_id(revocation_key.class),
        class_name: revocation_key_class_name(revocation_key.class).to_string(),
        public_key_algorithm: public_key_algorithm_name(revocation_key.algorithm).to_string(),
        fingerprint: revocation_key.fingerprint.to_vec(),
    }
}

pub(crate) fn signature_info_from_signature(
    signature: &Signature,
    is_one_pass: bool,
) -> SignatureInfo {
    let key_flags = signature.key_flags();
    SignatureInfo {
        version: signature_version_number(signature.version()),
        signature_type: signature.typ().map(signature_type_name),
        hash_algorithm: signature.hash_alg().map(|algorithm| algorithm.to_string()),
        public_key_algorithm: signature
            .config()
            .map(|config| public_key_algorithm_name(config.pub_alg).to_string()),
        issuer_key_ids: signature
            .issuer_key_id()
            .iter()
            .map(|key_id| key_id.to_string())
            .collect(),
        issuer_fingerprints: signature
            .issuer_fingerprint()
            .iter()
            .map(|fingerprint| fingerprint.to_string())
            .collect(),
        creation_time: signature.created().map(|timestamp| timestamp.as_secs()),
        key_expiration_seconds: signature
            .key_expiration_time()
            .map(|duration| duration.as_secs()),
        signature_expiration_seconds: signature
            .signature_expiration_time()
            .map(|duration| duration.as_secs()),
        revocation_reason_code: signature
            .revocation_reason_code()
            .map(|code| (*code).into()),
        revocation_reason: signature
            .revocation_reason_string()
            .map(|reason| String::from_utf8_lossy(reason.as_ref()).into_owned()),
        signer_user_id: signature
            .signers_userid()
            .map(|user_id| String::from_utf8_lossy(user_id.as_ref()).into_owned()),
        signed_hash_value: signature
            .signed_hash_value()
            .map(|signed_hash_value| signed_hash_value.to_vec()),
        salt: signature_salt(signature),
        preferred_symmetric_algorithms: symmetric_algorithm_names(
            signature.preferred_symmetric_algs(),
        ),
        preferred_hash_algorithms: hash_algorithm_names(signature.preferred_hash_algs()),
        preferred_compression_algorithms: compression_algorithm_names(
            signature.preferred_compression_algs(),
        ),
        preferred_aead_algorithms: aead_algorithm_preference_names(signature.preferred_aead_algs()),
        preferred_key_server: signature.preferred_key_server().map(str::to_owned),
        notations: signature
            .notations()
            .into_iter()
            .map(signature_notation_info_from_notation)
            .collect(),
        revocation_key: signature
            .revocation_key()
            .map(revocation_key_info_from_revocation_key),
        policy_uri: signature.policy_uri().map(str::to_owned),
        is_revocable: signature.is_revocable(),
        exportable_certification: signature.exportable_certification(),
        key_flags: key_flags_info_from_key_flags(&key_flags),
        features: signature.features().map(features_info_from_features),
        embedded_signature: signature
            .embedded_signature()
            .map(|embedded| Box::new(signature_info_from_signature(embedded, false))),
        is_one_pass,
    }
}

pub(crate) fn signature_info_from_full_signature(signature: &FullSignaturePacket) -> SignatureInfo {
    let is_one_pass = matches!(signature, FullSignaturePacket::Ops { .. });
    signature_info_from_signature(signature.signature(), is_one_pass)
}

pub(crate) fn direct_signature_infos_from_details(
    details: &pgp::composed::SignedKeyDetails,
) -> Vec<SignatureInfo> {
    details
        .direct_signatures
        .iter()
        .map(|signature| signature_info_from_signature(signature, false))
        .collect::<Vec<_>>()
}

pub(crate) fn revocation_signature_infos_from_details(
    details: &pgp::composed::SignedKeyDetails,
) -> Vec<SignatureInfo> {
    details
        .revocation_signatures
        .iter()
        .map(|signature| signature_info_from_signature(signature, false))
        .collect::<Vec<_>>()
}

pub(crate) fn user_binding_info_from_signed_user(user: &pgp::types::SignedUser) -> UserBindingInfo {
    UserBindingInfo {
        user_id: String::from_utf8_lossy(user.id.id()).into_owned(),
        is_primary: user.is_primary(),
        signatures: user
            .signatures
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect::<Vec<_>>(),
    }
}

pub(crate) fn user_binding_infos_from_details(
    details: &pgp::composed::SignedKeyDetails,
) -> Vec<UserBindingInfo> {
    details
        .users
        .iter()
        .map(user_binding_info_from_signed_user)
        .collect::<Vec<_>>()
}

pub(crate) fn user_attribute_binding_info_from_signed_user_attribute(
    attribute: &pgp::types::SignedUserAttribute,
) -> UserAttributeBindingInfo {
    UserAttributeBindingInfo {
        user_attribute: UserAttribute {
            inner: attribute.attr.clone(),
        },
        signatures: attribute
            .signatures
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect::<Vec<_>>(),
    }
}

pub(crate) fn user_attribute_binding_infos_from_details(
    details: &pgp::composed::SignedKeyDetails,
) -> Vec<UserAttributeBindingInfo> {
    details
        .user_attributes
        .iter()
        .map(user_attribute_binding_info_from_signed_user_attribute)
        .collect::<Vec<_>>()
}

pub(crate) fn subkey_binding_info_from_signed_public_subkey(
    subkey: &SignedPublicSubKey,
) -> SubkeyBindingInfo {
    SubkeyBindingInfo {
        fingerprint: subkey.key.fingerprint().to_string(),
        key_id: subkey.key.legacy_key_id().to_string(),
        version: key_version_number(subkey.key.version()),
        created_at: subkey.key.created_at().as_secs(),
        public_key_algorithm: public_key_algorithm_name(subkey.key.algorithm()).to_string(),
        public_params: public_params_info_from_params(subkey.key.public_params()),
        packet_version: subkey.key.packet_header_version(),
        signatures: subkey
            .signatures
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect::<Vec<_>>(),
    }
}

pub(crate) fn subkey_binding_info_from_signed_secret_subkey(
    subkey: &SignedSecretSubKey,
) -> SubkeyBindingInfo {
    SubkeyBindingInfo {
        fingerprint: subkey.key.public_key().fingerprint().to_string(),
        key_id: subkey.key.public_key().legacy_key_id().to_string(),
        version: key_version_number(subkey.key.version()),
        created_at: subkey.key.created_at().as_secs(),
        public_key_algorithm: public_key_algorithm_name(subkey.key.algorithm()).to_string(),
        public_params: public_params_info_from_params(subkey.key.public_params()),
        packet_version: subkey.key.packet_header_version(),
        signatures: subkey
            .signatures
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect::<Vec<_>>(),
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

pub(crate) fn signature_info_from_decrypted_signature(
    signature: &DecryptedSignature,
) -> SignatureInfo {
    signature_info_from_signature(&signature.signature, signature.is_one_pass)
}

/// Decoded RFC 9580 key-flags subpacket metadata.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone, Copy)]
pub(crate) struct KeyFlagsInfo {
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
impl KeyFlagsInfo {
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
            "KeyFlagsInfo(certify={}, sign={}, encrypt_communications={}, encrypt_storage={}, authenticate={})",
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

/// A signed user attribute and its attached certification self-signatures.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct UserAttributeBindingInfo {
    pub(crate) user_attribute: UserAttribute,
    pub(crate) signatures: Vec<SignatureInfo>,
}

#[pymethods]
impl UserAttributeBindingInfo {
    /// The underlying user-attribute packet metadata.
    #[getter]
    fn user_attribute(&self) -> UserAttribute {
        self.user_attribute.clone()
    }

    /// Metadata for every certification signature attached to this user attribute.
    #[getter]
    fn signatures(&self) -> Vec<SignatureInfo> {
        self.signatures.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "UserAttributeBindingInfo(kind='{}', signature_count={})",
            self.user_attribute.kind(),
            self.signatures.len()
        )
    }
}

/// Decoded RFC 9580 Features subpacket metadata.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone, Copy)]
pub(crate) struct FeaturesInfo {
    pub(crate) seipd_v1: bool,
    pub(crate) seipd_v2: bool,
}

#[pymethods]
impl FeaturesInfo {
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
            "FeaturesInfo(seipd_v1={}, seipd_v2={})",
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

/// A subkey and its attached binding or revocation signatures.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct SubkeyBindingInfo {
    pub(crate) fingerprint: String,
    pub(crate) key_id: String,
    pub(crate) version: u8,
    pub(crate) created_at: u32,
    pub(crate) public_key_algorithm: String,
    pub(crate) public_params: PublicParamsInfo,
    pub(crate) packet_version: PgpPacketHeaderVersion,
    pub(crate) signatures: Vec<SignatureInfo>,
}

#[pymethods]
impl SubkeyBindingInfo {
    /// The RFC 9580 fingerprint of the subkey packet.
    #[getter]
    fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    /// The legacy key identifier of the subkey packet.
    #[getter]
    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    /// The OpenPGP key-packet version number of this subkey.
    #[getter]
    fn version(&self) -> u8 {
        self.version
    }

    /// The subkey packet's creation time as seconds since the Unix epoch.
    #[getter]
    fn created_at(&self) -> u32 {
        self.created_at
    }

    /// The subkey packet's public-key algorithm.
    #[getter]
    fn public_key_algorithm(&self) -> String {
        self.public_key_algorithm.clone()
    }

    /// Structured algorithm-specific public-key metadata from `KeyDetails.public_params()`.
    #[getter]
    fn public_params(&self) -> PublicParamsInfo {
        self.public_params.clone()
    }

    /// The RFC 9580 packet-header framing used by this subkey packet.
    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.packet_version,
        }
    }

    /// Metadata for every binding or revocation signature attached to this subkey.
    #[getter]
    fn signatures(&self) -> Vec<SignatureInfo> {
        self.signatures.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "SubkeyBindingInfo(fingerprint='{}', key_id='{}', packet_version='{}', signature_count={})",
            self.fingerprint,
            self.key_id,
            packet_header_version_name(self.packet_version),
            self.signatures.len()
        )
    }
}

/// A user ID and its attached certification self-signatures.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct UserBindingInfo {
    pub(crate) user_id: String,
    pub(crate) is_primary: bool,
    pub(crate) signatures: Vec<SignatureInfo>,
}

#[pymethods]
impl UserBindingInfo {
    /// The user ID bytes decoded lossily as UTF-8.
    #[getter]
    fn user_id(&self) -> String {
        self.user_id.clone()
    }

    /// Whether any attached certification marks this as the primary user ID.
    #[getter]
    fn is_primary(&self) -> bool {
        self.is_primary
    }

    /// Metadata for every certification signature attached to this user ID.
    #[getter]
    fn signatures(&self) -> Vec<SignatureInfo> {
        self.signatures.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "UserBindingInfo(user_id={:?}, is_primary={}, signature_count={})",
            self.user_id,
            self.is_primary,
            self.signatures.len()
        )
    }
}

/// Decoded RFC 9580 signature-notation metadata.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct SignatureNotationInfo {
    pub(crate) human_readable: bool,
    pub(crate) name: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

#[pymethods]
impl SignatureNotationInfo {
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
            "SignatureNotationInfo(human_readable={}, name_len={}, value_len={})",
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
pub(crate) struct RevocationKeyInfo {
    pub(crate) class_id: u8,
    pub(crate) class_name: String,
    pub(crate) public_key_algorithm: String,
    pub(crate) fingerprint: Vec<u8>,
}

#[pymethods]
impl RevocationKeyInfo {
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
            "RevocationKeyInfo(class_name='{}', public_key_algorithm='{}', fingerprint_len={})",
            self.class_name,
            self.public_key_algorithm,
            self.fingerprint.len()
        )
    }
}

/// Metadata extracted from an OpenPGP data signature packet.
///
/// The fields mirror the RFC 9580 signature packet configuration, including issuer subpackets,
/// the 16-bit signed hash prefix, version-6 salts, and certificate self-signature metadata such
/// as key flags, features, preferred algorithm lists, notations, and revocation-key metadata when
/// present.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct SignatureInfo {
    pub(crate) version: u8,
    pub(crate) signature_type: Option<String>,
    pub(crate) hash_algorithm: Option<String>,
    pub(crate) public_key_algorithm: Option<String>,
    pub(crate) issuer_key_ids: Vec<String>,
    pub(crate) issuer_fingerprints: Vec<String>,
    pub(crate) creation_time: Option<u32>,
    pub(crate) key_expiration_seconds: Option<u32>,
    pub(crate) signature_expiration_seconds: Option<u32>,
    pub(crate) revocation_reason_code: Option<u8>,
    pub(crate) revocation_reason: Option<String>,
    pub(crate) signer_user_id: Option<String>,
    pub(crate) signed_hash_value: Option<Vec<u8>>,
    pub(crate) salt: Option<Vec<u8>>,
    pub(crate) preferred_symmetric_algorithms: Vec<String>,
    pub(crate) preferred_hash_algorithms: Vec<String>,
    pub(crate) preferred_compression_algorithms: Vec<String>,
    pub(crate) preferred_aead_algorithms: Vec<(String, String)>,
    pub(crate) preferred_key_server: Option<String>,
    pub(crate) notations: Vec<SignatureNotationInfo>,
    pub(crate) revocation_key: Option<RevocationKeyInfo>,
    pub(crate) policy_uri: Option<String>,
    pub(crate) is_revocable: bool,
    pub(crate) exportable_certification: bool,
    pub(crate) key_flags: KeyFlagsInfo,
    pub(crate) features: Option<FeaturesInfo>,
    pub(crate) embedded_signature: Option<Box<SignatureInfo>>,
    pub(crate) is_one_pass: bool,
}

#[pymethods]
impl SignatureInfo {
    /// The signature packet version number.
    #[getter]
    fn version(&self) -> u8 {
        self.version
    }

    /// The RFC 9580 signature type name, if this packet used a known signature format.
    #[getter]
    fn signature_type(&self) -> Option<String> {
        self.signature_type.clone()
    }

    /// The declared hash algorithm name, if this packet used a known signature format.
    #[getter]
    fn hash_algorithm(&self) -> Option<String> {
        self.hash_algorithm.clone()
    }

    /// The declared public-key algorithm name, if this packet used a known signature format.
    #[getter]
    fn public_key_algorithm(&self) -> Option<String> {
        self.public_key_algorithm.clone()
    }

    /// Any issuer key IDs from issuer-related subpackets.
    #[getter]
    fn issuer_key_ids(&self) -> Vec<String> {
        self.issuer_key_ids.clone()
    }

    /// Any issuer fingerprints from issuer fingerprint subpackets.
    #[getter]
    fn issuer_fingerprints(&self) -> Vec<String> {
        self.issuer_fingerprints.clone()
    }

    /// The signature creation time as seconds since the Unix epoch, if present.
    #[getter]
    fn creation_time(&self) -> Option<u32> {
        self.creation_time
    }

    /// The key-expiration interval declared by this signature, in seconds from creation time.
    ///
    /// This reflects metadata carried by a self-signature or binding signature, not a resolved
    /// top-level key expiry for the certificate as a whole.
    #[getter]
    fn key_expiration_seconds(&self) -> Option<u32> {
        self.key_expiration_seconds
    }

    /// The signature expiration interval in seconds, if present.
    #[getter]
    fn signature_expiration_seconds(&self) -> Option<u32> {
        self.signature_expiration_seconds
    }

    /// The numeric RFC 9580 revocation-reason code carried by this signature, if present.
    #[getter]
    fn revocation_reason_code(&self) -> Option<u8> {
        self.revocation_reason_code
    }

    /// The revocation-reason text carried by this signature, lossily decoded as UTF-8.
    #[getter]
    fn revocation_reason(&self) -> Option<String> {
        self.revocation_reason.clone()
    }

    /// The signer's declared user ID from hashed subpackets, lossily decoded as UTF-8.
    #[getter]
    fn signer_user_id(&self) -> Option<String> {
        self.signer_user_id.clone()
    }

    /// The two-octet signed hash prefix stored in the signature packet, if available.
    #[getter]
    fn signed_hash_value(&self) -> Option<Vec<u8>> {
        self.signed_hash_value.clone()
    }

    /// The RFC 9580 version-6 signature salt, if this is a version-6 signature.
    #[getter]
    fn salt(&self) -> Option<Vec<u8>> {
        self.salt.clone()
    }

    /// Preferred symmetric algorithms advertised by this signature, normalized to lower-case.
    #[getter]
    fn preferred_symmetric_algorithms(&self) -> Vec<String> {
        self.preferred_symmetric_algorithms.clone()
    }

    /// Preferred hash algorithms advertised by this signature, normalized to lower-case.
    #[getter]
    fn preferred_hash_algorithms(&self) -> Vec<String> {
        self.preferred_hash_algorithms.clone()
    }

    /// Preferred compression algorithms advertised by this signature, normalized to lower-case.
    #[getter]
    fn preferred_compression_algorithms(&self) -> Vec<String> {
        self.preferred_compression_algorithms.clone()
    }

    /// Preferred AEAD algorithm pairs advertised by this signature, normalized to lower-case.
    #[getter]
    fn preferred_aead_algorithms(&self) -> Vec<(String, String)> {
        self.preferred_aead_algorithms.clone()
    }

    /// The preferred key-server URI advertised by this signature, if present.
    #[getter]
    fn preferred_key_server(&self) -> Option<String> {
        self.preferred_key_server.clone()
    }

    /// Any notation-data subpackets carried by the signature.
    #[getter]
    fn notations(&self) -> Vec<SignatureNotationInfo> {
        self.notations.clone()
    }

    /// The deprecated designated-revocation-key subpacket, if present.
    #[getter]
    fn revocation_key(&self) -> Option<RevocationKeyInfo> {
        self.revocation_key.clone()
    }

    /// The signature policy URI advertised by this signature, if present.
    #[getter]
    fn policy_uri(&self) -> Option<String> {
        self.policy_uri.clone()
    }

    /// Whether this signature says the certified object may later be revoked.
    #[getter]
    fn is_revocable(&self) -> bool {
        self.is_revocable
    }

    /// Whether this certification signature is exportable to other implementations.
    #[getter]
    fn exportable_certification(&self) -> bool {
        self.exportable_certification
    }

    /// Decoded RFC 9580 key-flag bits advertised by this signature.
    #[getter]
    fn key_flags(&self) -> KeyFlagsInfo {
        self.key_flags
    }

    /// Decoded RFC 9580 feature-advertisement bits, if the signature carries them.
    #[getter]
    fn features(&self) -> Option<FeaturesInfo> {
        self.features
    }

    /// An embedded signature, such as the primary-key binding on a signing-capable subkey.
    #[getter]
    fn embedded_signature(&self) -> Option<SignatureInfo> {
        self.embedded_signature.as_deref().cloned()
    }

    /// Whether the signature originated from a one-pass signature packet.
    #[getter]
    fn is_one_pass(&self) -> bool {
        self.is_one_pass
    }

    fn __repr__(&self) -> String {
        format!(
            "SignatureInfo(version={}, signature_type={:?}, hash_algorithm={:?}, is_one_pass={})",
            self.version, self.signature_type, self.hash_algorithm, self.is_one_pass
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

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::SignedKeyDetails;
    use pgp::packet::Notation;
    use pgp::packet::RevocationCode;
    use pgp::packet::{Subpacket, SubpacketData};
    use pgp::types::{RevocationKey, RevocationKeyClass, SignatureBytes};

    #[test]
    fn signature_info_exposes_key_expiration_seconds() {
        let signature = Signature::v4(
            PacketHeader::from_parts(
                PgpPacketHeaderVersion::New,
                Tag::Signature,
                PacketLength::Fixed(0),
            )
            .expect("signature header"),
            SignatureType::Key,
            PgpPublicKeyAlgorithm::RSA,
            HashAlgorithm::Sha256,
            [0, 0],
            SignatureBytes::Mpis(vec![]),
            vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                    1_700_000_000,
                )))
                .expect("creation subpacket"),
                Subpacket::regular(SubpacketData::KeyExpirationTime(
                    pgp::types::Duration::from_secs(86_400),
                ))
                .expect("key expiration subpacket"),
            ],
            vec![],
        );

        let info = signature_info_from_signature(&signature, false);

        assert_eq!(info.key_expiration_seconds, Some(86_400));
        assert_eq!(info.key_expiration_seconds(), Some(86_400));
    }

    #[test]
    fn signature_info_exposes_policy_metadata() {
        let signature = Signature::v4(
            PacketHeader::from_parts(
                PgpPacketHeaderVersion::New,
                Tag::Signature,
                PacketLength::Fixed(0),
            )
            .expect("signature header"),
            SignatureType::CertPositive,
            PgpPublicKeyAlgorithm::RSA,
            HashAlgorithm::Sha256,
            [0, 0],
            SignatureBytes::Mpis(vec![]),
            vec![
                Subpacket::regular(SubpacketData::PreferredKeyServer(
                    "https://keys.example.test".to_string(),
                ))
                .expect("preferred key server subpacket"),
                Subpacket::regular(SubpacketData::PolicyURI(
                    "https://policy.example.test".to_string(),
                ))
                .expect("policy uri subpacket"),
                Subpacket::regular(SubpacketData::Revocable(false)).expect("revocable subpacket"),
                Subpacket::regular(SubpacketData::ExportableCertification(false))
                    .expect("exportable certification subpacket"),
            ],
            vec![],
        );

        let info = signature_info_from_signature(&signature, false);

        assert_eq!(
            info.preferred_key_server(),
            Some("https://keys.example.test".to_string())
        );
        assert_eq!(
            info.policy_uri(),
            Some("https://policy.example.test".to_string())
        );
        assert!(!info.is_revocable());
        assert!(!info.exportable_certification());
    }

    #[test]
    fn signature_info_exposes_revocation_reason_metadata() {
        let signature = Signature::v4(
            PacketHeader::from_parts(
                PgpPacketHeaderVersion::New,
                Tag::Signature,
                PacketLength::Fixed(0),
            )
            .expect("signature header"),
            SignatureType::KeyRevocation,
            PgpPublicKeyAlgorithm::RSA,
            HashAlgorithm::Sha256,
            [0, 0],
            SignatureBytes::Mpis(vec![]),
            vec![
                Subpacket::regular(SubpacketData::RevocationReason(
                    RevocationCode::KeyRetired,
                    b"superseded".as_slice().into(),
                ))
                .expect("revocation reason subpacket"),
            ],
            vec![],
        );

        let info = signature_info_from_signature(&signature, false);

        assert_eq!(info.revocation_reason_code(), Some(3));
        assert_eq!(info.revocation_reason(), Some("superseded".to_string()));
    }

    #[test]
    fn signature_info_exposes_notation_and_revocation_key_metadata() {
        let signature = Signature::v4(
            PacketHeader::from_parts(
                PgpPacketHeaderVersion::New,
                Tag::Signature,
                PacketLength::Fixed(0),
            )
            .expect("signature header"),
            SignatureType::Key,
            PgpPublicKeyAlgorithm::RSA,
            HashAlgorithm::Sha256,
            [0, 0],
            SignatureBytes::Mpis(vec![]),
            vec![
                Subpacket::regular(SubpacketData::Notation(Notation {
                    readable: true,
                    name: b"example@rpgp-py".as_slice().into(),
                    value: b"binding".as_slice().into(),
                }))
                .expect("notation subpacket"),
                Subpacket::regular(SubpacketData::RevocationKey(RevocationKey::new(
                    RevocationKeyClass::Sensitive,
                    PgpPublicKeyAlgorithm::Ed25519,
                    &[0xAB; 20],
                )))
                .expect("revocation key subpacket"),
            ],
            vec![],
        );

        let info = signature_info_from_signature(&signature, false);
        let notations = info.notations();
        let revocation_key = info.revocation_key().expect("revocation key");

        assert_eq!(notations.len(), 1);
        assert!(notations[0].human_readable());
        assert_eq!(notations[0].name(), b"example@rpgp-py".to_vec());
        assert_eq!(notations[0].value(), b"binding".to_vec());
        assert_eq!(revocation_key.class_id(), 0xC0);
        assert_eq!(revocation_key.class_name(), "sensitive".to_string());
        assert_eq!(revocation_key.public_key_algorithm(), "ed25519".to_string());
        assert_eq!(revocation_key.fingerprint(), vec![0xAB; 20]);
    }

    #[test]
    fn revocation_signature_infos_exposes_key_revocation_signatures() {
        let revocation = Signature::v4(
            PacketHeader::from_parts(
                PgpPacketHeaderVersion::New,
                Tag::Signature,
                PacketLength::Fixed(0),
            )
            .expect("signature header"),
            SignatureType::KeyRevocation,
            PgpPublicKeyAlgorithm::RSA,
            HashAlgorithm::Sha256,
            [0, 0],
            SignatureBytes::Mpis(vec![]),
            vec![],
            vec![],
        );
        let details = SignedKeyDetails::new(vec![revocation], vec![], vec![], vec![]);

        let infos = revocation_signature_infos_from_details(&details);

        assert_eq!(infos.len(), 1);
        assert_eq!(
            infos[0].signature_type(),
            Some("key-revocation".to_string())
        );
    }
}
