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

mod builder;
mod conversions;
mod hierarchy;
mod info;
mod key_params;
mod keys;
mod messages;
mod packets;
mod serialization;
mod util;

#[pymodule]
pub(crate) fn _openpgp(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<builder::PyArmorOptions>()?;
    module.add_class::<builder::PyMessageBuilder>()?;
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
    module.add_class::<hierarchy::RsaPublicKey>()?;
    module.add_class::<hierarchy::DsaPublicKey>()?;
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
    module.add_class::<hierarchy::PublicKey>()?;
    module.add_class::<hierarchy::PublicSubkey>()?;
    module.add_class::<hierarchy::SecretKey>()?;
    module.add_class::<hierarchy::SecretSubkey>()?;
    module.add_class::<hierarchy::Signature>()?;
    module.add_class::<hierarchy::SignedUser>()?;
    module.add_class::<hierarchy::SignedUserAttribute>()?;
    module.add_class::<hierarchy::SignedKeyDetails>()?;
    module.add_class::<hierarchy::SignedPublicSubKey>()?;
    module.add_class::<hierarchy::SignedSecretSubKey>()?;
    module.add_class::<keys::SignedPublicKey>()?;
    module.add_class::<keys::SignedSecretKey>()?;
    module.add_class::<packets::PublicKeyEncryptedSessionKey>()?;
    module.add_class::<packets::SymKeyEncryptedSessionKey>()?;
    module.add_class::<packets::EncryptedDataPacket>()?;
    module.add_class::<packets::SymEncryptedData>()?;
    module.add_class::<packets::SymEncryptedProtectedData>()?;
    module.add_class::<packets::GnupgAeadData>()?;
    module.add_class::<messages::Message>()?;
    module.add_class::<messages::DecryptedMessage>()?;
    module.add_class::<messages::LiteralDataHeader>()?;
    module.add_class::<messages::LiteralMessage>()?;
    module.add_class::<messages::CompressedMessage>()?;
    module.add_class::<messages::SignedMessage>()?;
    module.add_class::<messages::EncryptedMessage>()?;
    module.add_class::<messages::DecryptedLiteralMessage>()?;
    module.add_class::<messages::DecryptedCompressedMessage>()?;
    module.add_class::<messages::DecryptedSignedMessage>()?;
    module.add_class::<info::KeyFlags>()?;
    module.add_class::<info::UserAttribute>()?;
    module.add_class::<info::Features>()?;
    module.add_class::<info::Notation>()?;
    module.add_class::<info::RevocationKey>()?;
    module.add_class::<messages::DetachedSignature>()?;
    module.add_class::<messages::CleartextSignedMessage>()?;
    util::register(module)?;
    Ok(())
}
