use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    sync::Mutex,
};

use pgp::{
    armor::Dearmor,
    composed::{
        ArmorOptions, CleartextSignedMessage as PgpCleartextSignedMessage, Deserializable,
        DetachedSignature as PgpDetachedSignature, DsaKeySize as PgpDsaKeySize,
        EncryptionCaps as PgpEncryptionCaps, FullSignaturePacket, KeyType as PgpKeyType,
        Message as PgpMessage, MessageBuilder, PlainSessionKey as PgpPlainSessionKey,
        RawSessionKey as PgpRawSessionKey, SecretKeyParams as PgpSecretKeyParams,
        SecretKeyParamsBuilder as PgpSecretKeyParamsBuilder, SignedPublicKey, SignedPublicSubKey,
        SignedSecretKey, SignedSecretSubKey, SubkeyParams as PgpSubkeyParams,
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

mod api;
mod conversions;
mod hierarchy;
mod info;
mod key_params;
mod keys;
mod messages;
mod packets;
mod serialization;

#[pymodule]
pub(crate) fn _openpgp(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<key_params::EncryptionCaps>()?;
    module.add_class::<key_params::PyPacketHeaderVersion>()?;
    module.add_class::<key_params::KeyType>()?;
    module.add_class::<key_params::PyStringToKey>()?;
    module.add_class::<key_params::PyS2kParams>()?;
    module.add_class::<key_params::SubkeyParams>()?;
    module.add_class::<key_params::SubkeyParamsBuilder>()?;
    module.add_class::<key_params::SecretKeyParams>()?;
    module.add_class::<key_params::SecretKeyParamsBuilder>()?;
    module.add_class::<hierarchy::PublicParams>()?;
    module.add_class::<hierarchy::RsaPublicParams>()?;
    module.add_class::<hierarchy::DsaPublicParams>()?;
    module.add_class::<hierarchy::EcdsaPublicParams>()?;
    module.add_class::<hierarchy::EcdhPublicParams>()?;
    module.add_class::<hierarchy::ElgamalPublicParams>()?;
    module.add_class::<hierarchy::EdDsaLegacyPublicParams>()?;
    module.add_class::<hierarchy::Ed25519PublicParams>()?;
    module.add_class::<hierarchy::X25519PublicParams>()?;
    module.add_class::<hierarchy::X448PublicParams>()?;
    module.add_class::<hierarchy::Ed448PublicParams>()?;
    module.add_class::<hierarchy::UnknownPublicParams>()?;
    module.add_class::<hierarchy::PublicKeyPacket>()?;
    module.add_class::<hierarchy::PublicSubkeyPacket>()?;
    module.add_class::<hierarchy::SecretKeyPacket>()?;
    module.add_class::<hierarchy::SecretSubkeyPacket>()?;
    module.add_class::<hierarchy::SignedKeyDetails>()?;
    module.add_class::<hierarchy::SignedPublicSubKey>()?;
    module.add_class::<hierarchy::SignedSecretSubKey>()?;
    module.add_class::<keys::PublicKey>()?;
    module.add_class::<keys::SecretKey>()?;
    module.add_class::<packets::PublicKeyEncryptedSessionKeyPacket>()?;
    module.add_class::<packets::SymKeyEncryptedSessionKeyPacket>()?;
    module.add_class::<packets::EncryptedDataPacket>()?;
    module.add_class::<packets::SymEncryptedDataPacket>()?;
    module.add_class::<packets::SymEncryptedProtectedDataPacket>()?;
    module.add_class::<packets::GnupgAeadDataPacket>()?;
    module.add_class::<messages::Message>()?;
    module.add_class::<messages::DecryptedMessage>()?;
    module.add_class::<messages::LiteralMessage>()?;
    module.add_class::<messages::CompressedMessage>()?;
    module.add_class::<messages::SignedMessage>()?;
    module.add_class::<messages::EncryptedMessage>()?;
    module.add_class::<messages::DecryptedLiteralMessage>()?;
    module.add_class::<messages::DecryptedCompressedMessage>()?;
    module.add_class::<messages::DecryptedSignedMessage>()?;
    module.add_class::<info::KeyFlagsInfo>()?;
    module.add_class::<info::UserAttribute>()?;
    module.add_class::<info::UserAttributeBindingInfo>()?;
    module.add_class::<info::FeaturesInfo>()?;
    module.add_class::<info::PublicParamsInfo>()?;
    module.add_class::<info::SubkeyBindingInfo>()?;
    module.add_class::<info::UserBindingInfo>()?;
    module.add_class::<info::SignatureNotationInfo>()?;
    module.add_class::<info::RevocationKeyInfo>()?;
    module.add_class::<info::SignatureInfo>()?;
    module.add_class::<messages::DetachedSignature>()?;
    module.add_class::<messages::CleartextSignedMessage>()?;
    module.add_class::<info::MessageInfo>()?;
    api::register(module)?;
    Ok(())
}
