use crate::conversions::key_version_number;
use crate::info::*;
use crate::key_params::*;
use crate::serialization::s2k_params_from_secret_params;
use crate::*;
use pgp::{
    composed::{
        SignedKeyDetails as PgpSignedKeyDetails, SignedPublicSubKey as PgpSignedPublicSubKey,
        SignedSecretSubKey as PgpSignedSecretSubKey,
    },
    packet::{
        PublicKey as PgpPublicKeyPacket, PublicSubkey as PgpPublicSubkeyPacket,
        SecretKey as PgpSecretKeyPacket, SecretSubkey as PgpSecretSubkeyPacket,
    },
    types::{KeyDetails as PgpKeyDetails, PublicParams as PgpPublicParams},
};
use pyo3::types::PyAny;

#[pyclass(subclass, module = "openpgp")]
#[derive(Clone)]
pub(crate) struct PublicParams {
    pub(crate) info: PublicParamsInfo,
}

macro_rules! public_params_variant {
    ($name:ident) => {
        #[pyclass(extends = PublicParams, module = "openpgp")]
        #[derive(Clone)]
        pub(crate) struct $name;
    };
}

public_params_variant!(RsaPublicParams);
public_params_variant!(DsaPublicParams);
public_params_variant!(EcdsaPublicParams);
public_params_variant!(EcdhPublicParams);
public_params_variant!(ElgamalPublicParams);
public_params_variant!(EdDsaLegacyPublicParams);
public_params_variant!(Ed25519PublicParams);
public_params_variant!(X25519PublicParams);
public_params_variant!(X448PublicParams);
public_params_variant!(Ed448PublicParams);
public_params_variant!(UnknownPublicParams);

#[pymethods]
impl PublicParams {
    #[getter]
    fn info(&self) -> PublicParamsInfo {
        self.info.clone()
    }

    #[getter]
    fn kind(&self) -> String {
        self.info.kind.clone()
    }

    #[getter]
    fn curve(&self) -> Option<String> {
        self.info.curve.clone()
    }

    #[getter]
    fn curve_oid(&self) -> Option<String> {
        self.info.curve_oid.clone()
    }

    #[getter]
    fn curve_alias(&self) -> Option<String> {
        self.info.curve_alias.clone()
    }

    #[getter]
    fn curve_bits(&self) -> Option<u16> {
        self.info.curve_bits
    }

    #[getter]
    fn rsa_bits(&self) -> Option<u32> {
        self.info.rsa_bits
    }

    #[getter]
    fn secret_key_length(&self) -> Option<usize> {
        self.info.secret_key_length
    }

    #[getter]
    fn is_supported(&self) -> Option<bool> {
        self.info.is_supported
    }

    #[getter]
    fn kdf_hash_algorithm(&self) -> Option<String> {
        self.info.kdf_hash_algorithm.clone()
    }

    #[getter]
    fn kdf_symmetric_algorithm(&self) -> Option<String> {
        self.info.kdf_symmetric_algorithm.clone()
    }

    #[getter]
    fn kdf_type(&self) -> Option<String> {
        self.info.kdf_type.clone()
    }

    fn __repr__(&self) -> String {
        match &self.info.curve {
            Some(curve) => format!("{}(curve='{}')", self.info.kind, curve),
            None => format!("{}()", self.info.kind),
        }
    }
}

pub(crate) fn public_params_object_from_info(
    py: Python<'_>,
    info: PublicParamsInfo,
) -> PyResult<Py<PyAny>> {
    let kind = info.kind.clone();
    let base = PublicParams { info };

    match kind.as_str() {
        "rsa" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(RsaPublicParams),
        )?
        .into_any()),
        "dsa" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(DsaPublicParams),
        )?
        .into_any()),
        "ecdsa" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(EcdsaPublicParams),
        )?
        .into_any()),
        "ecdh" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(EcdhPublicParams),
        )?
        .into_any()),
        "elgamal" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(ElgamalPublicParams),
        )?
        .into_any()),
        "eddsa-legacy" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(EdDsaLegacyPublicParams),
        )?
        .into_any()),
        "ed25519" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(Ed25519PublicParams),
        )?
        .into_any()),
        "x25519" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(X25519PublicParams),
        )?
        .into_any()),
        "x448" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(X448PublicParams),
        )?
        .into_any()),
        "ed448" => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(Ed448PublicParams),
        )?
        .into_any()),
        _ => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(UnknownPublicParams),
        )?
        .into_any()),
    }
}

pub(crate) fn public_params_object(
    py: Python<'_>,
    params: &PgpPublicParams,
) -> PyResult<Py<PyAny>> {
    public_params_object_from_info(py, public_params_info_from_params(params))
}

#[derive(Clone)]
struct KeyPacketData {
    fingerprint: String,
    key_id: String,
    version: u8,
    created_at: u32,
    public_key_algorithm: String,
    public_params_info: PublicParamsInfo,
    packet_version: PgpPacketHeaderVersion,
}

fn key_packet_data_from_details(
    key: &impl PgpKeyDetails,
    packet_version: PgpPacketHeaderVersion,
) -> KeyPacketData {
    KeyPacketData {
        fingerprint: key.fingerprint().to_string(),
        key_id: key.legacy_key_id().to_string(),
        version: key_version_number(key.version()),
        created_at: key.created_at().as_secs(),
        public_key_algorithm: public_key_algorithm_name(key.algorithm()).to_string(),
        public_params_info: public_params_info_from_params(key.public_params()),
        packet_version,
    }
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
pub(crate) struct PublicKeyPacket {
    data: KeyPacketData,
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
pub(crate) struct PublicSubkeyPacket {
    data: KeyPacketData,
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
pub(crate) struct SecretKeyPacket {
    data: KeyPacketData,
    secret_s2k: PyS2kParams,
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
pub(crate) struct SecretSubkeyPacket {
    data: KeyPacketData,
    secret_s2k: PyS2kParams,
}

#[pymethods]
impl PublicKeyPacket {
    #[getter]
    fn fingerprint(&self) -> String {
        self.data.fingerprint.clone()
    }

    #[getter]
    fn key_id(&self) -> String {
        self.data.key_id.clone()
    }

    #[getter]
    fn version(&self) -> u8 {
        self.data.version
    }

    #[getter]
    fn created_at(&self) -> u32 {
        self.data.created_at
    }

    #[getter]
    fn public_key_algorithm(&self) -> String {
        self.data.public_key_algorithm.clone()
    }

    #[getter]
    fn public_params(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        public_params_object_from_info(py, self.data.public_params_info.clone())
    }

    #[getter]
    fn public_params_info(&self) -> PublicParamsInfo {
        self.data.public_params_info.clone()
    }

    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.data.packet_version,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "PublicKeyPacket(fingerprint='{}', key_id='{}')",
            self.data.fingerprint, self.data.key_id
        )
    }
}

#[pymethods]
impl PublicSubkeyPacket {
    #[getter]
    fn fingerprint(&self) -> String {
        self.data.fingerprint.clone()
    }

    #[getter]
    fn key_id(&self) -> String {
        self.data.key_id.clone()
    }

    #[getter]
    fn version(&self) -> u8 {
        self.data.version
    }

    #[getter]
    fn created_at(&self) -> u32 {
        self.data.created_at
    }

    #[getter]
    fn public_key_algorithm(&self) -> String {
        self.data.public_key_algorithm.clone()
    }

    #[getter]
    fn public_params(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        public_params_object_from_info(py, self.data.public_params_info.clone())
    }

    #[getter]
    fn public_params_info(&self) -> PublicParamsInfo {
        self.data.public_params_info.clone()
    }

    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.data.packet_version,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "PublicSubkeyPacket(fingerprint='{}', key_id='{}')",
            self.data.fingerprint, self.data.key_id
        )
    }
}

#[pymethods]
impl SecretKeyPacket {
    #[getter]
    fn fingerprint(&self) -> String {
        self.data.fingerprint.clone()
    }

    #[getter]
    fn key_id(&self) -> String {
        self.data.key_id.clone()
    }

    #[getter]
    fn version(&self) -> u8 {
        self.data.version
    }

    #[getter]
    fn created_at(&self) -> u32 {
        self.data.created_at
    }

    #[getter]
    fn public_key_algorithm(&self) -> String {
        self.data.public_key_algorithm.clone()
    }

    #[getter]
    fn public_params(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        public_params_object_from_info(py, self.data.public_params_info.clone())
    }

    #[getter]
    fn public_params_info(&self) -> PublicParamsInfo {
        self.data.public_params_info.clone()
    }

    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.data.packet_version,
        }
    }

    #[getter]
    fn secret_s2k(&self) -> PyS2kParams {
        self.secret_s2k.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "SecretKeyPacket(fingerprint='{}', key_id='{}')",
            self.data.fingerprint, self.data.key_id
        )
    }
}

#[pymethods]
impl SecretSubkeyPacket {
    #[getter]
    fn fingerprint(&self) -> String {
        self.data.fingerprint.clone()
    }

    #[getter]
    fn key_id(&self) -> String {
        self.data.key_id.clone()
    }

    #[getter]
    fn version(&self) -> u8 {
        self.data.version
    }

    #[getter]
    fn created_at(&self) -> u32 {
        self.data.created_at
    }

    #[getter]
    fn public_key_algorithm(&self) -> String {
        self.data.public_key_algorithm.clone()
    }

    #[getter]
    fn public_params(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        public_params_object_from_info(py, self.data.public_params_info.clone())
    }

    #[getter]
    fn public_params_info(&self) -> PublicParamsInfo {
        self.data.public_params_info.clone()
    }

    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.data.packet_version,
        }
    }

    #[getter]
    fn secret_s2k(&self) -> PyS2kParams {
        self.secret_s2k.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "SecretSubkeyPacket(fingerprint='{}', key_id='{}')",
            self.data.fingerprint, self.data.key_id
        )
    }
}

pub(crate) fn public_key_packet_object(
    py: Python<'_>,
    key: &PgpPublicKeyPacket,
) -> PyResult<Py<PublicKeyPacket>> {
    Py::new(
        py,
        PublicKeyPacket {
            data: key_packet_data_from_details(key, key.packet_header_version()),
        },
    )
}

pub(crate) fn public_subkey_packet_object(
    py: Python<'_>,
    key: &PgpPublicSubkeyPacket,
) -> PyResult<Py<PublicSubkeyPacket>> {
    Py::new(
        py,
        PublicSubkeyPacket {
            data: key_packet_data_from_details(key, key.packet_header_version()),
        },
    )
}

pub(crate) fn secret_key_packet_object(
    py: Python<'_>,
    key: &PgpSecretKeyPacket,
) -> PyResult<Py<SecretKeyPacket>> {
    Py::new(
        py,
        SecretKeyPacket {
            data: key_packet_data_from_details(key, key.packet_header_version()),
            secret_s2k: s2k_params_from_secret_params(key.secret_params()),
        },
    )
}

pub(crate) fn secret_subkey_packet_object(
    py: Python<'_>,
    key: &PgpSecretSubkeyPacket,
) -> PyResult<Py<SecretSubkeyPacket>> {
    Py::new(
        py,
        SecretSubkeyPacket {
            data: key_packet_data_from_details(key, key.packet_header_version()),
            secret_s2k: s2k_params_from_secret_params(key.secret_params()),
        },
    )
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
pub(crate) struct SignedKeyDetails {
    revocation_signatures: Vec<SignatureInfo>,
    direct_signatures: Vec<SignatureInfo>,
    users: Vec<UserBindingInfo>,
    user_attributes: Vec<UserAttributeBindingInfo>,
}

#[pymethods]
impl SignedKeyDetails {
    #[getter]
    fn revocation_signatures(&self) -> Vec<SignatureInfo> {
        self.revocation_signatures.clone()
    }

    #[getter]
    fn direct_signatures(&self) -> Vec<SignatureInfo> {
        self.direct_signatures.clone()
    }

    #[getter]
    fn users(&self) -> Vec<UserBindingInfo> {
        self.users.clone()
    }

    #[getter]
    fn user_attributes(&self) -> Vec<UserAttributeBindingInfo> {
        self.user_attributes.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "SignedKeyDetails(user_count={}, user_attribute_count={})",
            self.users.len(),
            self.user_attributes.len()
        )
    }
}

pub(crate) fn signed_key_details_from_raw(details: &PgpSignedKeyDetails) -> SignedKeyDetails {
    SignedKeyDetails {
        revocation_signatures: revocation_signature_infos_from_details(details),
        direct_signatures: direct_signature_infos_from_details(details),
        users: user_binding_infos_from_details(details),
        user_attributes: user_attribute_binding_infos_from_details(details),
    }
}

#[pyclass(module = "openpgp")]
pub(crate) struct SignedPublicSubKey {
    key: Py<PublicSubkeyPacket>,
    signatures: Vec<SignatureInfo>,
}

#[pymethods]
impl SignedPublicSubKey {
    #[getter]
    fn key(&self, py: Python<'_>) -> Py<PublicSubkeyPacket> {
        self.key.clone_ref(py)
    }

    #[getter]
    fn signatures(&self) -> Vec<SignatureInfo> {
        self.signatures.clone()
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let key = self.key.bind(py).borrow();
        Ok(format!(
            "SignedPublicSubKey(fingerprint='{}', signature_count={})",
            key.fingerprint(),
            self.signatures.len()
        ))
    }
}

pub(crate) fn signed_public_subkey_from_raw(
    py: Python<'_>,
    subkey: &PgpSignedPublicSubKey,
) -> PyResult<SignedPublicSubKey> {
    Ok(SignedPublicSubKey {
        key: public_subkey_packet_object(py, &subkey.key)?,
        signatures: subkey
            .signatures
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect(),
    })
}

#[pyclass(module = "openpgp")]
pub(crate) struct SignedSecretSubKey {
    key: Py<SecretSubkeyPacket>,
    public_key: Py<PublicSubkeyPacket>,
    signatures: Vec<SignatureInfo>,
}

#[pymethods]
impl SignedSecretSubKey {
    #[getter]
    fn key(&self, py: Python<'_>) -> Py<SecretSubkeyPacket> {
        self.key.clone_ref(py)
    }

    #[getter]
    fn signatures(&self) -> Vec<SignatureInfo> {
        self.signatures.clone()
    }

    fn signed_public_key(&self, py: Python<'_>) -> SignedPublicSubKey {
        SignedPublicSubKey {
            key: self.public_key.clone_ref(py),
            signatures: self.signatures.clone(),
        }
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let key = self.key.bind(py).borrow();
        Ok(format!(
            "SignedSecretSubKey(fingerprint='{}', signature_count={})",
            key.fingerprint(),
            self.signatures.len()
        ))
    }
}

pub(crate) fn signed_secret_subkey_from_raw(
    py: Python<'_>,
    subkey: &PgpSignedSecretSubKey,
) -> PyResult<SignedSecretSubKey> {
    Ok(SignedSecretSubKey {
        key: secret_subkey_packet_object(py, &subkey.key)?,
        public_key: public_subkey_packet_object(py, subkey.key.public_key())?,
        signatures: subkey
            .signatures
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect(),
    })
}
