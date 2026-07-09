use crate::{
    composed::keys::SignedSecretKey,
    conversions::*,
    info::UserAttribute,
    serialization::*,
    types::{PyPacketHeaderVersion, PyS2kParams},
    *,
};
use pgp::packet::UserAttribute as PgpUserAttribute;
use std::sync::Mutex;

/// This mirrors rPGP's `EncryptionCaps` builder enum and RFC 9580 key-flags semantics for the
/// "encrypt communications" and "encrypt storage" flags.
#[pyclass(module = "openpgp.composed", from_py_object)]
#[derive(Clone, Copy)]
pub(crate) struct EncryptionCaps {
    pub(crate) inner: PgpEncryptionCaps,
}

#[pymethods]
impl EncryptionCaps {
    #[staticmethod]
    fn none() -> Self {
        Self {
            inner: PgpEncryptionCaps::None,
        }
    }

    #[staticmethod]
    fn communication() -> Self {
        Self {
            inner: PgpEncryptionCaps::Communication,
        }
    }

    #[staticmethod]
    fn storage() -> Self {
        Self {
            inner: PgpEncryptionCaps::Storage,
        }
    }

    #[staticmethod]
    fn all() -> Self {
        Self {
            inner: PgpEncryptionCaps::All,
        }
    }

    fn __repr__(&self) -> String {
        let name = match self.inner {
            PgpEncryptionCaps::None => "none",
            PgpEncryptionCaps::Communication => "communication",
            PgpEncryptionCaps::Storage => "storage",
            PgpEncryptionCaps::All => "all",
        };
        format!("EncryptionCaps.{name}()")
    }
}

/// An asymmetric algorithm configuration for OpenPGP key generation.
#[pyclass(module = "openpgp.composed", from_py_object)]
#[derive(Clone)]
pub(crate) struct KeyType {
    pub(crate) inner: PgpKeyType,
}

#[pymethods]
impl KeyType {
    #[staticmethod]
    fn rsa(bits: u32) -> Self {
        Self {
            inner: PgpKeyType::Rsa(bits),
        }
    }

    #[staticmethod]
    fn dsa(bits: u32) -> PyResult<Self> {
        Ok(Self {
            inner: PgpKeyType::Dsa(dsa_key_size_from_bits(bits)?),
        })
    }

    #[staticmethod]
    fn ed25519_legacy() -> Self {
        Self {
            inner: PgpKeyType::Ed25519Legacy,
        }
    }

    #[staticmethod]
    fn ed25519() -> Self {
        Self {
            inner: PgpKeyType::Ed25519,
        }
    }

    #[staticmethod]
    fn ed448() -> Self {
        Self {
            inner: PgpKeyType::Ed448,
        }
    }

    #[staticmethod]
    fn ecdsa(curve: &str) -> PyResult<Self> {
        Ok(Self {
            inner: PgpKeyType::ECDSA(curve_from_name(curve)?),
        })
    }

    #[staticmethod]
    fn ecdh(curve: &str) -> PyResult<Self> {
        Ok(Self {
            inner: PgpKeyType::ECDH(curve_from_name(curve)?),
        })
    }

    #[staticmethod]
    fn x25519() -> Self {
        Self {
            inner: PgpKeyType::X25519,
        }
    }

    #[staticmethod]
    fn x448() -> Self {
        Self {
            inner: PgpKeyType::X448,
        }
    }

    fn can_sign(&self) -> bool {
        self.inner.can_sign()
    }

    fn can_encrypt(&self) -> bool {
        self.inner.can_encrypt()
    }

    fn __repr__(&self) -> String {
        format!("KeyType.{}", key_type_name(&self.inner))
    }
}
#[pyclass(module = "openpgp.composed", from_py_object)]
#[derive(Clone)]
pub(crate) struct SubkeyParams {
    pub(crate) inner: PgpSubkeyParams,
    pub(crate) packet_version: PgpPacketHeaderVersion,
}

#[pymethods]
impl SubkeyParams {
    fn __repr__(&self) -> String {
        "SubkeyParams()".to_string()
    }
}

/// Builder for subkey-generation parameters.
#[pyclass(module = "openpgp.composed", from_py_object)]
#[derive(Clone)]
pub(crate) struct SubkeyParamsBuilder {
    pub(crate) inner: PgpSubkeyParamsBuilder,
    pub(crate) packet_version: PgpPacketHeaderVersion,
}

#[pymethods]
impl SubkeyParamsBuilder {
    #[new]
    fn new() -> Self {
        Self {
            inner: PgpSubkeyParamsBuilder::default(),
            packet_version: PgpPacketHeaderVersion::New,
        }
    }

    fn version<'py>(mut slf: PyRefMut<'py, Self>, value: u8) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner.version(key_version_from_number(value)?);
        Ok(slf)
    }

    fn key_type<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, KeyType>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.key_type(value.inner.clone());
        slf
    }

    fn can_sign<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.can_sign(value);
        slf
    }

    fn can_encrypt<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, EncryptionCaps>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.can_encrypt(value.inner);
        slf
    }

    fn can_authenticate<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.can_authenticate(value);
        slf
    }

    fn created_at<'py>(mut slf: PyRefMut<'py, Self>, value: u32) -> PyRefMut<'py, Self> {
        slf.inner.created_at(timestamp_from_seconds(value));
        slf
    }

    /// Select the RFC 9580 packet-header framing used when serializing this subkey packet.
    fn packet_version<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, PyPacketHeaderVersion>,
    ) -> PyRefMut<'py, Self> {
        slf.packet_version = value.inner;
        slf.inner.packet_version(value.inner);
        slf
    }

    fn passphrase<'py>(mut slf: PyRefMut<'py, Self>, value: Option<&str>) -> PyRefMut<'py, Self> {
        slf.inner.passphrase(value.map(str::to_owned));
        slf
    }

    /// Override the secret-key protection parameters for this subkey.
    fn s2k<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, PyS2kParams>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.s2k(Some(value.inner.clone()));
        slf
    }

    fn build(&self) -> PyResult<SubkeyParams> {
        let inner = self.inner.build().map_err(to_py_err)?;
        Ok(SubkeyParams {
            inner,
            packet_version: self.packet_version,
        })
    }

    fn __repr__(&self) -> String {
        "SubkeyParamsBuilder()".to_string()
    }
}

/// Built primary-key generation parameters.
#[pyclass(module = "openpgp.composed")]
pub(crate) struct SecretKeyParams {
    pub(crate) inner: Mutex<Option<PgpSecretKeyParams>>,
    pub(crate) packet_versions: KeyPacketVersions,
}

#[pymethods]
impl SecretKeyParams {
    fn generate(&self) -> PyResult<SignedSecretKey> {
        let params = self
            .inner
            .lock()
            .map_err(|_| to_py_err("key parameter state is unavailable"))?
            .take()
            .ok_or_else(|| to_py_err("key parameters have already been consumed"))?;
        let inner = params.generate(rand::thread_rng()).map_err(to_py_err)?;
        let inner = apply_generated_key_packet_versions(inner, &self.packet_versions)?;
        Ok(SignedSecretKey { inner })
    }

    fn __repr__(&self) -> String {
        let consumed = self
            .inner
            .lock()
            .map(|guard| guard.is_none())
            .unwrap_or(true);
        format!("SecretKeyParams(consumed={consumed})")
    }
}

/// Builder for primary-key generation parameters.
#[pyclass(module = "openpgp.composed", from_py_object)]
#[derive(Clone)]
pub(crate) struct SecretKeyParamsBuilder {
    pub(crate) inner: PgpSecretKeyParamsBuilder,
    pub(crate) user_attributes: Vec<PgpUserAttribute>,
    pub(crate) packet_version: PgpPacketHeaderVersion,
    pub(crate) subkey_packet_versions: Vec<PgpPacketHeaderVersion>,
}

#[pymethods]
impl SecretKeyParamsBuilder {
    #[new]
    fn new() -> Self {
        Self {
            inner: PgpSecretKeyParamsBuilder::default(),
            user_attributes: Vec::new(),
            packet_version: PgpPacketHeaderVersion::New,
            subkey_packet_versions: Vec::new(),
        }
    }

    fn version<'py>(mut slf: PyRefMut<'py, Self>, value: u8) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner.version(key_version_from_number(value)?);
        Ok(slf)
    }

    fn key_type<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, KeyType>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.key_type(value.inner.clone());
        slf
    }

    fn can_sign<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.can_sign(value);
        slf
    }

    fn can_certify<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.can_certify(value);
        slf
    }

    fn can_encrypt<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, EncryptionCaps>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.can_encrypt(value.inner);
        slf
    }

    fn can_authenticate<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.can_authenticate(value);
        slf
    }

    fn created_at<'py>(mut slf: PyRefMut<'py, Self>, value: u32) -> PyRefMut<'py, Self> {
        slf.inner.created_at(timestamp_from_seconds(value));
        slf
    }

    /// Select the RFC 9580 packet-header framing used when serializing the primary key packet.
    fn packet_version<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, PyPacketHeaderVersion>,
    ) -> PyRefMut<'py, Self> {
        slf.packet_version = value.inner;
        slf.inner.packet_version(value.inner);
        slf
    }

    fn feature_seipd_v1<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.feature_seipd_v1(value);
        slf
    }

    fn feature_seipd_v2<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.feature_seipd_v2(value);
        slf
    }

    fn preferred_symmetric_algorithms<'py>(
        mut slf: PyRefMut<'py, Self>,
        values: Vec<String>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner
            .preferred_symmetric_algorithms(symmetric_algorithms_from_names(values)?);
        Ok(slf)
    }

    fn preferred_hash_algorithms<'py>(
        mut slf: PyRefMut<'py, Self>,
        values: Vec<String>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner
            .preferred_hash_algorithms(hash_algorithms_from_names(values)?);
        Ok(slf)
    }

    fn preferred_compression_algorithms<'py>(
        mut slf: PyRefMut<'py, Self>,
        values: Vec<String>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner
            .preferred_compression_algorithms(compression_algorithms_from_names(values)?);
        Ok(slf)
    }

    fn preferred_aead_algorithms<'py>(
        mut slf: PyRefMut<'py, Self>,
        values: Vec<(String, String)>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner
            .preferred_aead_algorithms(aead_algorithm_preferences_from_names(values)?);
        Ok(slf)
    }

    fn passphrase<'py>(mut slf: PyRefMut<'py, Self>, value: Option<&str>) -> PyRefMut<'py, Self> {
        slf.inner.passphrase(value.map(str::to_owned));
        slf
    }

    /// Override the secret-key protection parameters for the primary key packet.
    fn s2k<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, PyS2kParams>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.s2k(Some(value.inner.clone()));
        slf
    }

    fn primary_user_id<'py>(mut slf: PyRefMut<'py, Self>, value: &str) -> PyRefMut<'py, Self> {
        slf.inner.primary_user_id(value.to_string());
        slf
    }

    fn user_id<'py>(mut slf: PyRefMut<'py, Self>, value: &str) -> PyRefMut<'py, Self> {
        slf.inner.user_id(value.to_string());
        slf
    }

    fn user_ids<'py>(mut slf: PyRefMut<'py, Self>, values: Vec<String>) -> PyRefMut<'py, Self> {
        slf.inner.user_ids(values);
        slf
    }

    /// Add a single RFC 9580 user attribute that will be self-certified on the certificate.
    fn user_attribute<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, UserAttribute>,
    ) -> PyRefMut<'py, Self> {
        slf.user_attributes.push(value.inner.clone());
        slf
    }

    /// Replace the builder's user-attribute list with the provided sequence.
    fn user_attributes<'py>(
        mut slf: PyRefMut<'py, Self>,
        values: Vec<PyRef<'_, UserAttribute>>,
    ) -> PyRefMut<'py, Self> {
        slf.user_attributes = values
            .into_iter()
            .map(|value| value.inner.clone())
            .collect();
        slf
    }

    fn subkey<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, SubkeyParams>,
    ) -> PyRefMut<'py, Self> {
        slf.subkey_packet_versions.push(value.packet_version);
        slf.inner.subkey(value.inner.clone());
        slf
    }

    fn build(&self) -> PyResult<SecretKeyParams> {
        let mut inner_builder = self.inner.clone();
        inner_builder.user_attributes(self.user_attributes.clone());
        let inner = inner_builder.build().map_err(to_py_err)?;
        Ok(SecretKeyParams {
            inner: Mutex::new(Some(inner)),
            packet_versions: KeyPacketVersions {
                primary: self.packet_version,
                subkeys: self.subkey_packet_versions.clone(),
            },
        })
    }

    fn generate(&self) -> PyResult<SignedSecretKey> {
        self.build()?.generate()
    }

    fn __repr__(&self) -> String {
        "SecretKeyParamsBuilder()".to_string()
    }
}
