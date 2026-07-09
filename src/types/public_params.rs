use crate::{conversions::normalized_algorithm_name, info::*, to_py_err};
use pgp::{
    ser::Serialize,
    types::{
        EcdhPublicParams as PgpEcdhPublicParams, EcdsaPublicParams as PgpEcdsaPublicParams,
        EddsaLegacyPublicParams as PgpEddsaLegacyPublicParams, PublicParams as PgpPublicParams,
    },
};
use pyo3::{PyClass, PyClassInitializer, prelude::*, types::PyAny};
use rsa::traits::PublicKeyParts;

#[pyclass(subclass, module = "openpgp.types", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PublicParams {
    pub(crate) inner: PgpPublicParams,
    pub(crate) info: PublicParamsInfo,
}

macro_rules! public_params_variant {
    ($name:ident) => {
        #[pyclass(extends = PublicParams, module = "openpgp.types", skip_from_py_object)]
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

#[pyclass(module = "openpgp.types", skip_from_py_object)]
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

#[pyclass(module = "openpgp.types", skip_from_py_object)]
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
