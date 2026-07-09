use crate::conversions::*;
use crate::info::*;
use crate::keys::*;
use crate::serialization::*;
use crate::*;

/// Packet-header framing for transferable key packets.
///
/// RFC 9580 distinguishes between the legacy "old" header format and the current "new" header
/// format. rPGP exposes this via `types::PacketHeaderVersion`; the key builders use the selected
/// value when serializing primary-key and subkey packets.
#[pyclass(module = "openpgp.types", name = "PacketHeaderVersion", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyPacketHeaderVersion {
    pub(crate) inner: PgpPacketHeaderVersion,
}

#[pymethods]
impl PyPacketHeaderVersion {
    #[staticmethod]
    fn old() -> Self {
        Self {
            inner: PgpPacketHeaderVersion::Old,
        }
    }

    #[staticmethod]
    #[pyo3(name = "new")]
    fn new_() -> Self {
        Self {
            inner: PgpPacketHeaderVersion::New,
        }
    }

    /// Return the normalized RFC 9580 packet-header variant name.
    #[getter]
    fn name(&self) -> &'static str {
        packet_header_version_name(self.inner)
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }

    fn __repr__(&self) -> String {
        format!("PacketHeaderVersion.{}()", self.name())
    }
}

/// Key-flag configuration for encryption-capable OpenPGP keys.
///
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

/// A parsed or constructed RFC 9580 String-to-Key (S2K) specifier.
#[pyclass(module = "openpgp.types", name = "StringToKey", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyStringToKey {
    pub(crate) inner: PgpStringToKey,
}

#[pymethods]
impl PyStringToKey {
    /// Create an iterated-and-salted S2K specifier (type 3).
    ///
    /// ``count`` is the encoded iteration-count octet from RFC 9580 section 3.7.1.3.
    #[staticmethod]
    #[pyo3(signature = (hash_algorithm, count, salt=None))]
    fn iterated(hash_algorithm: &str, count: u8, salt: Option<&[u8]>) -> PyResult<Self> {
        Ok(Self {
            inner: PgpStringToKey::IteratedAndSalted {
                hash_alg: hash_algorithm_from_name(hash_algorithm)?,
                salt: exact_or_random_array::<8>(salt, "salt")?,
                count,
            },
        })
    }

    /// Create an Argon2 S2K specifier (type 4).
    ///
    /// The parameters correspond to RFC 9580 section 3.7.1.4 and RFC 9106 section 4.5.
    #[staticmethod]
    #[pyo3(signature = (passes, parallelism, memory_exponent, salt=None))]
    fn argon2(
        passes: u8,
        parallelism: u8,
        memory_exponent: u8,
        salt: Option<&[u8]>,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: PgpStringToKey::Argon2 {
                salt: exact_or_random_array::<16>(salt, "salt")?,
                t: passes,
                p: parallelism,
                m_enc: memory_exponent,
            },
        })
    }

    /// Return the numeric S2K type identifier from RFC 9580 section 3.7.1.
    #[getter]
    fn type_id(&self) -> u8 {
        self.inner.id()
    }

    /// Return a normalized name for the wrapped S2K variant.
    #[getter]
    fn kind(&self) -> String {
        string_to_key_kind_name(&self.inner).to_string()
    }

    /// Return the hash algorithm name for hash-based S2K variants, if present.
    #[getter]
    fn hash_algorithm(&self) -> Option<String> {
        match &self.inner {
            PgpStringToKey::Simple { hash_alg }
            | PgpStringToKey::Salted { hash_alg, .. }
            | PgpStringToKey::IteratedAndSalted { hash_alg, .. } => {
                Some(normalized_algorithm_name(hash_alg))
            }
            _ => None,
        }
    }

    /// Return the salt bytes for salted S2K variants, if present.
    #[getter]
    fn salt(&self) -> Option<Vec<u8>> {
        match &self.inner {
            PgpStringToKey::Salted { salt, .. }
            | PgpStringToKey::IteratedAndSalted { salt, .. } => Some(salt.to_vec()),
            PgpStringToKey::Argon2 { salt, .. } => Some(salt.to_vec()),
            _ => None,
        }
    }

    /// Return the encoded iteration-count octet for iterated-and-salted S2K variants.
    #[getter]
    fn count(&self) -> Option<u8> {
        match &self.inner {
            PgpStringToKey::IteratedAndSalted { count, .. } => Some(*count),
            _ => None,
        }
    }

    /// Return the Argon2 pass count ``t``, if present.
    #[getter]
    fn passes(&self) -> Option<u8> {
        match &self.inner {
            PgpStringToKey::Argon2 { t, .. } => Some(*t),
            _ => None,
        }
    }

    /// Return the Argon2 degree of parallelism ``p``, if present.
    #[getter]
    fn parallelism(&self) -> Option<u8> {
        match &self.inner {
            PgpStringToKey::Argon2 { p, .. } => Some(*p),
            _ => None,
        }
    }

    /// Return the Argon2 encoded memory exponent ``m`` , if present.
    #[getter]
    fn memory_exponent(&self) -> Option<u8> {
        match &self.inner {
            PgpStringToKey::Argon2 { m_enc, .. } => Some(*m_enc),
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "StringToKey(kind='{}', type_id={})",
            self.kind(),
            self.type_id()
        )
    }
}

/// Parsed or constructed secret-key protection parameters (RFC 9580 section 3.7.2).
#[pyclass(module = "openpgp.types", name = "S2kParams", from_py_object)]
#[derive(Clone)]
pub(crate) struct PyS2kParams {
    pub(crate) inner: PgpS2kParams,
}

#[pymethods]
impl PyS2kParams {
    /// Create CFB-based secret-key protection parameters (usage 254).
    ///
    /// RFC 9580 forbids combining Argon2 S2K with non-AEAD usage modes.
    #[staticmethod]
    #[pyo3(signature = (symmetric_algorithm, string_to_key, iv=None))]
    fn cfb(
        symmetric_algorithm: &str,
        string_to_key: PyRef<'_, PyStringToKey>,
        iv: Option<&[u8]>,
    ) -> PyResult<Self> {
        if matches!(&string_to_key.inner, PgpStringToKey::Argon2 { .. }) {
            return Err(to_py_err(
                "Argon2 String-to-Key may only be used with AEAD S2K parameters",
            ));
        }

        let sym_alg = symmetric_algorithm_from_name(symmetric_algorithm)?;
        let iv = exact_or_random_vec(iv, sym_alg.block_size(), "iv")?;
        Ok(Self {
            inner: PgpS2kParams::Cfb {
                sym_alg,
                s2k: string_to_key.inner.clone(),
                iv: iv.into(),
            },
        })
    }

    /// Create AEAD-based secret-key protection parameters (usage 253).
    #[staticmethod]
    #[pyo3(signature = (symmetric_algorithm, aead_algorithm, string_to_key, nonce=None))]
    fn aead(
        symmetric_algorithm: &str,
        aead_algorithm: &str,
        string_to_key: PyRef<'_, PyStringToKey>,
        nonce: Option<&[u8]>,
    ) -> PyResult<Self> {
        let sym_alg = symmetric_algorithm_from_name(symmetric_algorithm)?;
        let aead_mode = aead_algorithm_from_name(aead_algorithm)?;
        let nonce = exact_or_random_vec(nonce, aead_mode.nonce_size(), "nonce")?;
        Ok(Self {
            inner: PgpS2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k: string_to_key.inner.clone(),
                nonce: nonce.into(),
            },
        })
    }

    /// Return the numeric S2K-usage octet from RFC 9580 section 3.7.2.
    #[getter]
    fn usage_id(&self) -> u8 {
        (&self.inner).into()
    }

    /// Return a normalized name for the wrapped S2K usage mode.
    #[getter]
    fn usage(&self) -> String {
        s2k_usage_name(&self.inner).to_string()
    }

    /// Return the symmetric algorithm used to encrypt the secret material, if present.
    #[getter]
    fn symmetric_algorithm(&self) -> Option<String> {
        match &self.inner {
            PgpS2kParams::Unprotected => None,
            PgpS2kParams::LegacyCfb { sym_alg, .. }
            | PgpS2kParams::Aead { sym_alg, .. }
            | PgpS2kParams::Cfb { sym_alg, .. }
            | PgpS2kParams::MalleableCfb { sym_alg, .. } => {
                Some(normalized_algorithm_name(sym_alg))
            }
        }
    }

    /// Return the AEAD algorithm name for AEAD-protected secret material, if present.
    #[getter]
    fn aead_algorithm(&self) -> Option<String> {
        match &self.inner {
            PgpS2kParams::Aead { aead_mode, .. } => Some(normalized_algorithm_name(aead_mode)),
            _ => None,
        }
    }

    /// Return the wrapped String-to-Key specifier, if this usage mode carries one.
    #[getter]
    fn string_to_key(&self) -> Option<PyStringToKey> {
        match &self.inner {
            PgpS2kParams::Aead { s2k, .. }
            | PgpS2kParams::Cfb { s2k, .. }
            | PgpS2kParams::MalleableCfb { s2k, .. } => Some(PyStringToKey { inner: s2k.clone() }),
            _ => None,
        }
    }

    /// Return the initialization vector for CFB-based modes, if present.
    #[getter]
    fn iv(&self) -> Option<Vec<u8>> {
        match &self.inner {
            PgpS2kParams::LegacyCfb { iv, .. }
            | PgpS2kParams::Cfb { iv, .. }
            | PgpS2kParams::MalleableCfb { iv, .. } => Some(iv.to_vec()),
            _ => None,
        }
    }

    /// Return the AEAD nonce, if present.
    #[getter]
    fn nonce(&self) -> Option<Vec<u8>> {
        match &self.inner {
            PgpS2kParams::Aead { nonce, .. } => Some(nonce.to_vec()),
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "S2kParams(usage='{}', usage_id={})",
            self.usage(),
            self.usage_id()
        )
    }
}

/// Built subkey-generation parameters.
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
