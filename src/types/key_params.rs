use crate::conversions::*;
use crate::serialization::{exact_or_random_array, exact_or_random_vec};
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
