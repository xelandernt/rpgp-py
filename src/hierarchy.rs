use crate::conversions::{
    aead_algorithm_preference_names, compression_algorithm_names, hash_algorithm_names,
    key_version_number, normalized_algorithm_name, symmetric_algorithm_names,
};
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
        Signature as PgpSignature,
    },
    types::{
        EcdhPublicParams as PgpEcdhPublicParams, EcdsaPublicParams as PgpEcdsaPublicParams,
        EddsaLegacyPublicParams as PgpEddsaLegacyPublicParams, KeyDetails as PgpKeyDetails,
        PublicParams as PgpPublicParams, SignedUser as PgpSignedUser,
        SignedUserAttribute as PgpSignedUserAttribute,
    },
};
use pyo3::{PyClass, prelude::PyRef, types::PyAny};
use rsa::traits::PublicKeyParts;

#[pyclass(subclass, module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PublicParams {
    pub(crate) inner: PgpPublicParams,
    pub(crate) info: PublicParamsInfo,
}

macro_rules! public_params_variant {
    ($name:ident) => {
        #[pyclass(extends = PublicParams, module = "openpgp", skip_from_py_object)]
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

#[pyclass(module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct RsaPublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

#[pymethods]
impl RsaPublicKey {
    #[getter]
    fn n(&self) -> Vec<u8> {
        self.n.clone()
    }

    #[getter]
    fn e(&self) -> Vec<u8> {
        self.e.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "RsaPublicKey(n_len={}, e_len={})",
            self.n.len(),
            self.e.len()
        )
    }
}

#[pyclass(module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct DsaPublicKey {
    p: Vec<u8>,
    q: Vec<u8>,
    g: Vec<u8>,
    y: Vec<u8>,
}

#[pymethods]
impl DsaPublicKey {
    #[getter]
    fn p(&self) -> Vec<u8> {
        self.p.clone()
    }

    #[getter]
    fn q(&self) -> Vec<u8> {
        self.q.clone()
    }

    #[getter]
    fn g(&self) -> Vec<u8> {
        self.g.clone()
    }

    #[getter]
    fn y(&self) -> Vec<u8> {
        self.y.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "DsaPublicKey(p_len={}, q_len={}, g_len={}, y_len={})",
            self.p.len(),
            self.q.len(),
            self.g.len(),
            self.y.len()
        )
    }
}

fn public_params_base<'py, T>(slf: PyRef<'py, T>) -> PyRef<'py, PublicParams>
where
    T: PyClass<BaseType = PublicParams>,
{
    slf.into_super()
}

fn unsupported_public_params(kind: &str) -> PyErr {
    to_py_err(format!("public params object is not {kind} params"))
}

#[pymethods]
impl PublicParams {
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
    fn dsa_bits(&self) -> Option<u32> {
        self.info.dsa_bits
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

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        match &self.info.curve {
            Some(curve) => format!("{}(curve='{}')", self.info.kind, curve),
            None => format!("{}()", self.info.kind),
        }
    }
}

pub(crate) fn public_params_object(
    py: Python<'_>,
    params: &PgpPublicParams,
) -> PyResult<Py<PyAny>> {
    let base = PublicParams {
        inner: params.clone(),
        info: public_params_info_from_params(params),
    };

    match params {
        PgpPublicParams::RSA(_) => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(RsaPublicParams),
        )?
        .into_any()),
        PgpPublicParams::DSA(_) => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(DsaPublicParams),
        )?
        .into_any()),
        PgpPublicParams::ECDSA(_) => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(EcdsaPublicParams),
        )?
        .into_any()),
        PgpPublicParams::ECDH(_) => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(EcdhPublicParams),
        )?
        .into_any()),
        PgpPublicParams::Elgamal(_) => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(ElgamalPublicParams),
        )?
        .into_any()),
        PgpPublicParams::EdDSALegacy(_) => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(EdDsaLegacyPublicParams),
        )?
        .into_any()),
        PgpPublicParams::Ed25519(_) => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(Ed25519PublicParams),
        )?
        .into_any()),
        PgpPublicParams::X25519(_) => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(X25519PublicParams),
        )?
        .into_any()),
        PgpPublicParams::X448(_) => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(X448PublicParams),
        )?
        .into_any()),
        PgpPublicParams::Ed448(_) => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(Ed448PublicParams),
        )?
        .into_any()),
        PgpPublicParams::Unknown { .. } => Ok(Py::new(
            py,
            PyClassInitializer::from(base).add_subclass(UnknownPublicParams),
        )?
        .into_any()),
    }
}

#[pymethods]
impl RsaPublicParams {
    #[getter]
    fn key(slf: PyRef<'_, Self>) -> PyResult<RsaPublicKey> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::RSA(params) => Ok(RsaPublicKey {
                n: params.key.n().to_bytes_be(),
                e: params.key.e().to_bytes_be(),
            }),
            _ => Err(unsupported_public_params("rsa")),
        }
    }
}

#[pymethods]
impl DsaPublicParams {
    #[getter]
    fn key(slf: PyRef<'_, Self>) -> PyResult<DsaPublicKey> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::DSA(params) => {
                let components = params.key.components();
                Ok(DsaPublicKey {
                    p: components.p().to_bytes_be(),
                    q: components.q().to_bytes_be(),
                    g: components.g().to_bytes_be(),
                    y: params.key.y().to_bytes_be(),
                })
            }
            _ => Err(unsupported_public_params("dsa")),
        }
    }
}

#[pymethods]
impl EcdsaPublicParams {
    #[getter]
    fn key(slf: PyRef<'_, Self>) -> PyResult<Option<Vec<u8>>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::ECDSA(params) => match params {
                PgpEcdsaPublicParams::P256 { key } => {
                    Ok(Some(key.to_sec1_bytes().as_ref().to_vec()))
                }
                PgpEcdsaPublicParams::P384 { key } => {
                    Ok(Some(key.to_sec1_bytes().as_ref().to_vec()))
                }
                PgpEcdsaPublicParams::P521 { key } => {
                    Ok(Some(key.to_sec1_bytes().as_ref().to_vec()))
                }
                PgpEcdsaPublicParams::Secp256k1 { key } => {
                    Ok(Some(key.to_sec1_bytes().as_ref().to_vec()))
                }
                PgpEcdsaPublicParams::Unsupported { .. } => Ok(None),
            },
            _ => Err(unsupported_public_params("ecdsa")),
        }
    }

    #[getter]
    fn opaque(slf: PyRef<'_, Self>) -> PyResult<Option<Vec<u8>>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::ECDSA(PgpEcdsaPublicParams::Unsupported { opaque, .. }) => {
                Ok(Some(opaque.to_vec()))
            }
            PgpPublicParams::ECDSA(_) => Ok(None),
            _ => Err(unsupported_public_params("ecdsa")),
        }
    }
}

#[pymethods]
impl EcdhPublicParams {
    #[getter]
    fn p(slf: PyRef<'_, Self>) -> PyResult<Option<Vec<u8>>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::ECDH(params) => match params {
                PgpEcdhPublicParams::Curve25519Legacy { p, .. } => Ok(Some(p.as_bytes().to_vec())),
                PgpEcdhPublicParams::P256 { p, .. } => {
                    Ok(Some(p.to_sec1_bytes().as_ref().to_vec()))
                }
                PgpEcdhPublicParams::P384 { p, .. } => {
                    Ok(Some(p.to_sec1_bytes().as_ref().to_vec()))
                }
                PgpEcdhPublicParams::P521 { p, .. } => {
                    Ok(Some(p.to_sec1_bytes().as_ref().to_vec()))
                }
                PgpEcdhPublicParams::Brainpool256 { p, .. }
                | PgpEcdhPublicParams::Brainpool384 { p, .. }
                | PgpEcdhPublicParams::Brainpool512 { p, .. } => Ok(Some(p.as_ref().to_vec())),
                PgpEcdhPublicParams::Unsupported { .. } => Ok(None),
            },
            _ => Err(unsupported_public_params("ecdh")),
        }
    }

    #[getter]
    fn opaque(slf: PyRef<'_, Self>) -> PyResult<Option<Vec<u8>>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::ECDH(PgpEcdhPublicParams::Unsupported { opaque, .. }) => {
                Ok(Some(opaque.to_vec()))
            }
            PgpPublicParams::ECDH(_) => Ok(None),
            _ => Err(unsupported_public_params("ecdh")),
        }
    }

    #[getter]
    fn hash(slf: PyRef<'_, Self>) -> PyResult<String> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::ECDH(PgpEcdhPublicParams::Curve25519Legacy { hash, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::P256 { hash, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::P384 { hash, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::P521 { hash, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::Brainpool256 { hash, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::Brainpool384 { hash, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::Brainpool512 { hash, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::Unsupported { hash, .. }) => {
                Ok(normalized_algorithm_name(hash))
            }
            _ => Err(unsupported_public_params("ecdh")),
        }
    }

    #[getter]
    fn alg_sym(slf: PyRef<'_, Self>) -> PyResult<String> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::ECDH(PgpEcdhPublicParams::Curve25519Legacy { alg_sym, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::P256 { alg_sym, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::P384 { alg_sym, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::P521 { alg_sym, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::Brainpool256 { alg_sym, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::Brainpool384 { alg_sym, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::Brainpool512 { alg_sym, .. })
            | PgpPublicParams::ECDH(PgpEcdhPublicParams::Unsupported { alg_sym, .. }) => {
                Ok(normalized_algorithm_name(alg_sym))
            }
            _ => Err(unsupported_public_params("ecdh")),
        }
    }

    #[getter]
    fn ecdh_kdf_type(slf: PyRef<'_, Self>) -> PyResult<String> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::ECDH(PgpEcdhPublicParams::Curve25519Legacy {
                ecdh_kdf_type, ..
            }) => Ok(normalized_algorithm_name(ecdh_kdf_type)),
            PgpPublicParams::ECDH(_) => Ok("native".to_string()),
            _ => Err(unsupported_public_params("ecdh")),
        }
    }
}

#[pymethods]
impl EdDsaLegacyPublicParams {
    #[getter]
    fn key(slf: PyRef<'_, Self>) -> PyResult<Option<Vec<u8>>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::EdDSALegacy(PgpEddsaLegacyPublicParams::Ed25519 { key }) => {
                Ok(Some(key.as_bytes().to_vec()))
            }
            PgpPublicParams::EdDSALegacy(PgpEddsaLegacyPublicParams::Unsupported { .. }) => {
                Ok(None)
            }
            _ => Err(unsupported_public_params("eddsa-legacy")),
        }
    }

    #[getter]
    fn opaque(slf: PyRef<'_, Self>) -> PyResult<Option<Vec<u8>>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::EdDSALegacy(PgpEddsaLegacyPublicParams::Unsupported {
                opaque,
                ..
            }) => Ok(Some(opaque.to_vec())),
            PgpPublicParams::EdDSALegacy(_) => Ok(None),
            _ => Err(unsupported_public_params("eddsa-legacy")),
        }
    }
}

#[pymethods]
impl Ed25519PublicParams {
    #[getter]
    fn key(slf: PyRef<'_, Self>) -> PyResult<Vec<u8>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::Ed25519(params) => Ok(params.key.as_bytes().to_vec()),
            _ => Err(unsupported_public_params("ed25519")),
        }
    }
}

#[pymethods]
impl X25519PublicParams {
    #[getter]
    fn key(slf: PyRef<'_, Self>) -> PyResult<Vec<u8>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::X25519(params) => Ok(params.key.as_bytes().to_vec()),
            _ => Err(unsupported_public_params("x25519")),
        }
    }
}

#[pymethods]
impl X448PublicParams {
    #[getter]
    fn key(slf: PyRef<'_, Self>) -> PyResult<Vec<u8>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::X448(params) => Ok(params.key.as_bytes().to_vec()),
            _ => Err(unsupported_public_params("x448")),
        }
    }
}

#[pymethods]
impl Ed448PublicParams {
    #[getter]
    fn key(slf: PyRef<'_, Self>) -> PyResult<Vec<u8>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::Ed448(params) => Ok(params.key.as_bytes().to_vec()),
            _ => Err(unsupported_public_params("ed448")),
        }
    }
}

#[pymethods]
impl UnknownPublicParams {
    #[getter]
    fn data(slf: PyRef<'_, Self>) -> PyResult<Vec<u8>> {
        let base = public_params_base(slf);
        match &base.inner {
            PgpPublicParams::Unknown { data } => Ok(data.to_vec()),
            _ => Err(unsupported_public_params("unknown")),
        }
    }
}

#[derive(Clone)]
struct KeyPacketData {
    fingerprint: String,
    key_id: String,
    version: u8,
    created_at: u32,
    public_key_algorithm: String,
    public_params: PgpPublicParams,
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
        public_params: key.public_params().clone(),
        packet_version,
    }
}

#[pyclass(module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PublicKeyPacket {
    data: KeyPacketData,
}

#[pyclass(module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PublicSubkeyPacket {
    data: KeyPacketData,
}

#[pyclass(module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SecretKeyPacket {
    data: KeyPacketData,
    secret_s2k: PyS2kParams,
}

#[pyclass(module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SecretSubkeyPacket {
    data: KeyPacketData,
    secret_s2k: PyS2kParams,
}

macro_rules! key_packet_methods {
    ($ty:ty, $name:literal) => {
        #[pymethods]
        impl $ty {
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
                public_params_object(py, &self.data.public_params)
            }

            #[getter]
            fn packet_version(&self) -> PyPacketHeaderVersion {
                PyPacketHeaderVersion {
                    inner: self.data.packet_version,
                }
            }

            fn __repr__(&self) -> String {
                format!(
                    "{}(fingerprint='{}', key_id='{}')",
                    $name, self.data.fingerprint, self.data.key_id
                )
            }
        }
    };
}

macro_rules! secret_key_packet_methods {
    ($ty:ty, $name:literal) => {
        #[pymethods]
        impl $ty {
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
                public_params_object(py, &self.data.public_params)
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
                    "{}(fingerprint='{}', key_id='{}')",
                    $name, self.data.fingerprint, self.data.key_id
                )
            }
        }
    };
}

key_packet_methods!(PublicKeyPacket, "PublicKeyPacket");
key_packet_methods!(PublicSubkeyPacket, "PublicSubkeyPacket");
secret_key_packet_methods!(SecretKeyPacket, "SecretKeyPacket");
secret_key_packet_methods!(SecretSubkeyPacket, "SecretSubkeyPacket");

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

#[pyclass(module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SignaturePacket {
    inner: PgpSignature,
}

#[pymethods]
impl SignaturePacket {
    fn version(&self) -> u8 {
        signature_version_number(self.inner.version())
    }

    fn typ(&self) -> Option<String> {
        self.inner
            .typ()
            .map(|typ| signature_type_name(typ).to_string())
    }

    fn hash_alg(&self) -> Option<String> {
        self.inner.hash_alg().map(normalized_algorithm_name)
    }

    fn signed_hash_value(&self) -> Option<Vec<u8>> {
        self.inner.signed_hash_value().map(|value| value.to_vec())
    }

    fn salt(&self) -> Option<Vec<u8>> {
        signature_salt(&self.inner)
    }

    fn key_expiration_time(&self) -> Option<u32> {
        self.inner
            .key_expiration_time()
            .map(|duration| duration.as_secs())
    }

    fn signature_expiration_time(&self) -> Option<u32> {
        self.inner
            .signature_expiration_time()
            .map(|duration| duration.as_secs())
    }

    fn created(&self) -> Option<u32> {
        self.inner.created().map(|timestamp| timestamp.as_secs())
    }

    fn issuer_key_id(&self) -> Vec<String> {
        self.inner
            .issuer_key_id()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn issuer_fingerprint(&self) -> Vec<String> {
        self.inner
            .issuer_fingerprint()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn preferred_symmetric_algs(&self) -> Vec<String> {
        symmetric_algorithm_names(self.inner.preferred_symmetric_algs())
    }

    fn preferred_aead_algs(&self) -> Vec<(String, String)> {
        aead_algorithm_preference_names(self.inner.preferred_aead_algs())
    }

    fn preferred_hash_algs(&self) -> Vec<String> {
        hash_algorithm_names(self.inner.preferred_hash_algs())
    }

    fn preferred_compression_algs(&self) -> Vec<String> {
        compression_algorithm_names(self.inner.preferred_compression_algs())
    }

    fn key_flags(&self) -> KeyFlags {
        key_flags_from_key_flags(&self.inner.key_flags())
    }

    fn features(&self) -> Option<Features> {
        self.inner.features().map(features_from_features)
    }

    fn embedded_signature(&self) -> Option<SignaturePacket> {
        self.inner
            .embedded_signature()
            .map(signature_packet_from_raw)
    }

    fn preferred_key_server(&self) -> Option<String> {
        self.inner.preferred_key_server().map(str::to_owned)
    }

    fn notations(&self) -> Vec<Notation> {
        self.inner
            .notations()
            .into_iter()
            .map(notation_from_notation)
            .collect()
    }

    fn revocation_key(&self) -> Option<RevocationKey> {
        self.inner
            .revocation_key()
            .map(revocation_key_from_revocation_key)
    }

    fn signers_userid(&self) -> Option<String> {
        self.inner
            .signers_userid()
            .map(|user_id| String::from_utf8_lossy(user_id.as_ref()).into_owned())
    }

    fn policy_uri(&self) -> Option<String> {
        self.inner.policy_uri().map(str::to_owned)
    }

    fn is_revocable(&self) -> bool {
        self.inner.is_revocable()
    }

    fn exportable_certification(&self) -> bool {
        self.inner.exportable_certification()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "SignaturePacket(version={}, type={:?})",
            self.version(),
            self.typ()
        )
    }
}

pub(crate) fn signature_packet_from_raw(signature: &PgpSignature) -> SignaturePacket {
    SignaturePacket {
        inner: signature.clone(),
    }
}

#[pyclass(module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SignedUser {
    id: String,
    signatures: Vec<SignaturePacket>,
    is_primary: bool,
}

#[pymethods]
impl SignedUser {
    #[getter]
    fn id(&self) -> String {
        self.id.clone()
    }

    #[getter]
    fn user_id(&self) -> String {
        self.id.clone()
    }

    #[getter]
    fn signatures(&self) -> Vec<SignaturePacket> {
        self.signatures.clone()
    }

    #[getter]
    fn is_primary(&self) -> bool {
        self.is_primary
    }

    fn __repr__(&self) -> String {
        format!(
            "SignedUser(id={:?}, signature_count={})",
            self.id,
            self.signatures.len()
        )
    }
}

fn signed_user_from_raw(user: &PgpSignedUser) -> SignedUser {
    SignedUser {
        id: String::from_utf8_lossy(user.id.id()).into_owned(),
        signatures: user
            .signatures
            .iter()
            .map(signature_packet_from_raw)
            .collect(),
        is_primary: user.is_primary(),
    }
}

#[pyclass(module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SignedUserAttribute {
    attr: UserAttribute,
    signatures: Vec<SignaturePacket>,
}

#[pymethods]
impl SignedUserAttribute {
    #[getter]
    fn attr(&self) -> UserAttribute {
        self.attr.clone()
    }

    #[getter]
    fn user_attribute(&self) -> UserAttribute {
        self.attr.clone()
    }

    #[getter]
    fn signatures(&self) -> Vec<SignaturePacket> {
        self.signatures.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "SignedUserAttribute(kind='{}', signature_count={})",
            user_attribute_kind_name(&self.attr.inner),
            self.signatures.len()
        )
    }
}

fn signed_user_attribute_from_raw(attribute: &PgpSignedUserAttribute) -> SignedUserAttribute {
    SignedUserAttribute {
        attr: UserAttribute {
            inner: attribute.attr.clone(),
        },
        signatures: attribute
            .signatures
            .iter()
            .map(signature_packet_from_raw)
            .collect(),
    }
}

#[pyclass(module = "openpgp", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SignedKeyDetails {
    revocation_signatures: Vec<SignaturePacket>,
    direct_signatures: Vec<SignaturePacket>,
    users: Vec<SignedUser>,
    user_attributes: Vec<SignedUserAttribute>,
}

#[pymethods]
impl SignedKeyDetails {
    #[getter]
    fn revocation_signatures(&self) -> Vec<SignaturePacket> {
        self.revocation_signatures.clone()
    }

    #[getter]
    fn direct_signatures(&self) -> Vec<SignaturePacket> {
        self.direct_signatures.clone()
    }

    #[getter]
    fn users(&self) -> Vec<SignedUser> {
        self.users.clone()
    }

    #[getter]
    fn user_attributes(&self) -> Vec<SignedUserAttribute> {
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
        revocation_signatures: details
            .revocation_signatures
            .iter()
            .map(signature_packet_from_raw)
            .collect(),
        direct_signatures: details
            .direct_signatures
            .iter()
            .map(signature_packet_from_raw)
            .collect(),
        users: details.users.iter().map(signed_user_from_raw).collect(),
        user_attributes: details
            .user_attributes
            .iter()
            .map(signed_user_attribute_from_raw)
            .collect(),
    }
}

#[pyclass(module = "openpgp")]
pub(crate) struct SignedPublicSubKey {
    pub(crate) inner: PgpSignedPublicSubKey,
    key: Py<PublicSubkeyPacket>,
    signatures: Vec<SignaturePacket>,
}

#[pymethods]
impl SignedPublicSubKey {
    #[getter]
    fn key(&self, py: Python<'_>) -> Py<PublicSubkeyPacket> {
        self.key.clone_ref(py)
    }

    #[getter]
    fn signatures(&self) -> Vec<SignaturePacket> {
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
        inner: subkey.clone(),
        key: public_subkey_packet_object(py, &subkey.key)?,
        signatures: subkey
            .signatures
            .iter()
            .map(signature_packet_from_raw)
            .collect(),
    })
}

#[pyclass(module = "openpgp")]
pub(crate) struct SignedSecretSubKey {
    pub(crate) inner: PgpSignedSecretSubKey,
    key: Py<SecretSubkeyPacket>,
    public_key: Py<PublicSubkeyPacket>,
    signatures: Vec<SignaturePacket>,
}

#[pymethods]
impl SignedSecretSubKey {
    #[getter]
    fn key(&self, py: Python<'_>) -> Py<SecretSubkeyPacket> {
        self.key.clone_ref(py)
    }

    #[getter]
    fn signatures(&self) -> Vec<SignaturePacket> {
        self.signatures.clone()
    }

    fn signed_public_key(&self, py: Python<'_>) -> PyResult<SignedPublicSubKey> {
        Ok(SignedPublicSubKey {
            inner: self.inner.signed_public_key(),
            key: self.public_key.clone_ref(py),
            signatures: self.signatures.clone(),
        })
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
        inner: subkey.clone(),
        key: secret_subkey_packet_object(py, &subkey.key)?,
        public_key: public_subkey_packet_object(py, subkey.key.public_key())?,
        signatures: subkey
            .signatures
            .iter()
            .map(signature_packet_from_raw)
            .collect(),
    })
}
