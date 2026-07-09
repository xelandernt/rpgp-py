use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
};

use pgp::{
    armor::Dearmor,
    composed::{
        ArmorOptions, CleartextSignedMessage as PgpCleartextSignedMessage, Deserializable,
        DetachedSignature as PgpDetachedSignature, DsaKeySize as PgpDsaKeySize,
        EncryptionCaps as PgpEncryptionCaps, FullSignaturePacket, KeyType as PgpKeyType,
        Message as PgpMessage, MessageBuilder, PlainSessionKey as PgpPlainSessionKey,
        RawSessionKey as PgpRawSessionKey, SecretKeyParams as PgpSecretKeyParams,
        SecretKeyParamsBuilder as PgpSecretKeyParamsBuilder, SignedPublicKey as PgpSignedPublicKey,
        SignedPublicSubKey as PgpSignedPublicSubKey, SignedSecretKey as PgpSignedSecretKey,
        SignedSecretSubKey as PgpSignedSecretSubKey, SubkeyParams as PgpSubkeyParams,
        SubkeyParamsBuilder as PgpSubkeyParamsBuilder,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        ecc_curve::ECCCurve,
        hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm as PgpPublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::{
        DataMode, Features as PgpFeatures, ImageHeader as PgpImageHeader,
        ImageHeaderV1 as PgpImageHeaderV1, KeyFlags as PgpKeyFlags, Notation as PgpNotation,
        Packet as PgpPacket, PacketHeader, PacketParser, PacketTrait,
        PublicKeyEncryptedSessionKey as PgpPublicKeyEncryptedSessionKey, Signature, SignatureType,
        SignatureVersion, SignatureVersionSpecific,
        SymEncryptedProtectedDataConfig as PgpSymEncryptedProtectedDataConfig,
        SymKeyEncryptedSessionKey as PgpSymKeyEncryptedSessionKey,
        UserAttribute as PgpUserAttribute, UserAttributeType as PgpUserAttributeType,
    },
    ser::Serialize,
    types::{
        CompressionAlgorithm, EcdhPublicParams as PgpEcdhPublicParams,
        EcdsaPublicParams as PgpEcdsaPublicParams,
        EddsaLegacyPublicParams as PgpEddsaLegacyPublicParams, KeyDetails, KeyId, KeyVersion,
        PacketHeaderVersion as PgpPacketHeaderVersion, PacketLength, Password,
        PublicParams as PgpPublicParams, RevocationKey as PgpRevocationKey,
        RevocationKeyClass as PgpRevocationKeyClass, S2kParams as PgpS2kParams,
        SecretParams as PgpSecretParams, StringToKey as PgpStringToKey, Tag, Timestamp,
    },
};
use pyo3::{
    basic::CompareOp,
    exceptions::PyValueError,
    prelude::*,
    types::{PyModule, PyModuleMethods},
};
use rand::Rng;
use smallvec::SmallVec;

type Headers = BTreeMap<String, Vec<String>>;

fn to_py_err(error: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(error.to_string())
}

mod composed;
mod conversions;
mod info;
mod packet;
mod serialization;
mod types;
mod util;

#[pymodule]
pub(crate) fn _openpgp(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<composed::PyArmorOptions>()?;
    module.add_class::<composed::PyMessageBuilder>()?;
    module.add_class::<composed::EncryptionCaps>()?;
    module.add_class::<types::PyPacketHeaderVersion>()?;
    module.add_class::<composed::KeyType>()?;
    module.add_class::<types::PyStringToKey>()?;
    module.add_class::<types::PyS2kParams>()?;
    module.add_class::<composed::SubkeyParams>()?;
    module.add_class::<composed::SubkeyParamsBuilder>()?;
    module.add_class::<composed::SecretKeyParams>()?;
    module.add_class::<composed::SecretKeyParamsBuilder>()?;
    module.add_class::<types::PublicParams>()?;
    module.add_class::<types::RsaPublicKey>()?;
    module.add_class::<types::DsaPublicKey>()?;
    module.add_class::<types::RsaPublicParams>()?;
    module.add_class::<types::DsaPublicParams>()?;
    module.add_class::<types::EcdsaPublicParams>()?;
    module.add_class::<types::EcdhPublicParams>()?;
    module.add_class::<types::ElgamalPublicParams>()?;
    module.add_class::<types::EdDsaLegacyPublicParams>()?;
    module.add_class::<types::Ed25519PublicParams>()?;
    module.add_class::<types::X25519PublicParams>()?;
    module.add_class::<types::X448PublicParams>()?;
    module.add_class::<types::Ed448PublicParams>()?;
    module.add_class::<types::UnknownPublicParams>()?;
    module.add_class::<packet::PublicKey>()?;
    module.add_class::<packet::PublicSubkey>()?;
    module.add_class::<packet::SecretKey>()?;
    module.add_class::<packet::SecretSubkey>()?;
    module.add_class::<packet::Signature>()?;
    module.add_class::<composed::SignedUser>()?;
    module.add_class::<composed::SignedUserAttribute>()?;
    module.add_class::<composed::SignedKeyDetails>()?;
    module.add_class::<composed::SignedPublicSubKey>()?;
    module.add_class::<composed::SignedSecretSubKey>()?;
    module.add_class::<composed::SignedPublicKey>()?;
    module.add_class::<composed::SignedSecretKey>()?;
    module.add_class::<packet::PublicKeyEncryptedSessionKey>()?;
    module.add_class::<packet::SymKeyEncryptedSessionKey>()?;
    module.add_class::<packet::EncryptedDataPacket>()?;
    module.add_class::<packet::SymEncryptedData>()?;
    module.add_class::<packet::SymEncryptedProtectedData>()?;
    module.add_class::<packet::GnupgAeadData>()?;
    module.add_class::<composed::Message>()?;
    module.add_class::<composed::DecryptedMessage>()?;
    module.add_class::<composed::messages::LiteralDataHeader>()?;
    module.add_class::<composed::LiteralMessage>()?;
    module.add_class::<composed::messages::CompressedMessage>()?;
    module.add_class::<composed::SignedMessage>()?;
    module.add_class::<composed::EncryptedMessage>()?;
    module.add_class::<composed::DecryptedLiteralMessage>()?;
    module.add_class::<composed::DecryptedCompressedMessage>()?;
    module.add_class::<composed::DecryptedSignedMessage>()?;
    module.add_class::<info::KeyFlags>()?;
    module.add_class::<info::UserAttribute>()?;
    module.add_class::<info::Features>()?;
    module.add_class::<info::Notation>()?;
    module.add_class::<info::RevocationKey>()?;
    module.add_class::<composed::DetachedSignature>()?;
    module.add_class::<composed::CleartextSignedMessage>()?;
    util::register(module)?;
    Ok(())
}
