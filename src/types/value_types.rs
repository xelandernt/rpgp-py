use std::io::Cursor;

use pgp::{
    ser::Serialize,
    types::{
        Duration as PgpDuration, Fingerprint as PgpFingerprint, KeyId as PgpKeyId,
        KeyVersion as PgpKeyVersion, Mpi as PgpMpi, PacketLength as PgpPacketLength,
        PkeskVersion as PgpPkeskVersion, SkeskVersion as PgpSkeskVersion, Tag as PgpTag,
        Timestamp as PgpTimestamp,
    },
};
use pyo3::{basic::CompareOp, prelude::*, types::PyBytes};

use crate::to_py_err;

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// An OpenPGP duration backed by rPGP's ``Duration``.
#[pyclass(module = "openpgp.types", name = "Duration", from_py_object)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PyDuration {
    inner: PgpDuration,
}

#[pymethods]
impl PyDuration {
    #[staticmethod]
    fn from_secs(seconds: u32) -> Self {
        Self {
            inner: PgpDuration::from_secs(seconds),
        }
    }

    fn as_secs(&self) -> u32 {
        self.inner.as_secs()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    fn __int__(&self) -> u32 {
        self.as_secs()
    }

    fn __repr__(&self) -> String {
        format!("Duration.from_secs({})", self.as_secs())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            CompareOp::Lt => self.inner < other.inner,
            CompareOp::Le => self.inner <= other.inner,
            CompareOp::Gt => self.inner > other.inner,
            CompareOp::Ge => self.inner >= other.inner,
        }
    }
}

/// An OpenPGP timestamp backed by rPGP's ``Timestamp``.
#[pyclass(module = "openpgp.types", name = "Timestamp", from_py_object)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PyTimestamp {
    inner: PgpTimestamp,
}

#[pymethods]
impl PyTimestamp {
    #[staticmethod]
    fn now() -> Self {
        Self {
            inner: PgpTimestamp::now(),
        }
    }

    #[staticmethod]
    fn from_secs(seconds: u32) -> Self {
        Self {
            inner: PgpTimestamp::from_secs(seconds),
        }
    }

    fn as_secs(&self) -> u32 {
        self.inner.as_secs()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    fn __int__(&self) -> u32 {
        self.as_secs()
    }

    fn __repr__(&self) -> String {
        format!("Timestamp.from_secs({})", self.as_secs())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            CompareOp::Lt => self.inner < other.inner,
            CompareOp::Le => self.inner <= other.inner,
            CompareOp::Gt => self.inner > other.inner,
            CompareOp::Ge => self.inner >= other.inner,
        }
    }
}

/// OpenPGP key-packet version backed by rPGP's ``KeyVersion``.
#[pyclass(module = "openpgp.types", name = "KeyVersion", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyKeyVersion {
    pub(crate) inner: PgpKeyVersion,
}

#[pymethods]
impl PyKeyVersion {
    #[new]
    fn new(value: u8) -> Self {
        Self {
            inner: PgpKeyVersion::from(value),
        }
    }

    #[classattr]
    #[pyo3(name = "V2")]
    fn v2() -> Self {
        Self {
            inner: PgpKeyVersion::V2,
        }
    }

    #[classattr]
    #[pyo3(name = "V3")]
    fn v3() -> Self {
        Self {
            inner: PgpKeyVersion::V3,
        }
    }

    #[classattr]
    #[pyo3(name = "V4")]
    fn v4() -> Self {
        Self {
            inner: PgpKeyVersion::V4,
        }
    }

    #[classattr]
    #[pyo3(name = "V5")]
    fn v5() -> Self {
        Self {
            inner: PgpKeyVersion::V5,
        }
    }

    #[classattr]
    #[pyo3(name = "V6")]
    fn v6() -> Self {
        Self {
            inner: PgpKeyVersion::V6,
        }
    }

    #[getter]
    fn value(&self) -> u8 {
        self.inner.into()
    }

    fn fingerprint_len(&self) -> Option<usize> {
        self.inner.fingerprint_len()
    }

    fn __int__(&self) -> u8 {
        self.value()
    }

    fn __repr__(&self) -> String {
        format!("KeyVersion({})", self.value())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            CompareOp::Lt => self.inner < other.inner,
            CompareOp::Le => self.inner <= other.inner,
            CompareOp::Gt => self.inner > other.inner,
            CompareOp::Ge => self.inner >= other.inner,
        }
    }
}

/// PKESK packet version backed by rPGP's ``PkeskVersion``.
#[pyclass(module = "openpgp.types", name = "PkeskVersion", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyPkeskVersion {
    inner: PgpPkeskVersion,
}

#[pymethods]
impl PyPkeskVersion {
    #[new]
    fn new(value: u8) -> Self {
        Self {
            inner: PgpPkeskVersion::from(value),
        }
    }

    #[classattr]
    #[pyo3(name = "V3")]
    fn v3() -> Self {
        Self {
            inner: PgpPkeskVersion::V3,
        }
    }

    #[classattr]
    #[pyo3(name = "V6")]
    fn v6() -> Self {
        Self {
            inner: PgpPkeskVersion::V6,
        }
    }

    #[getter]
    fn value(&self) -> u8 {
        self.inner.into()
    }

    fn __int__(&self) -> u8 {
        self.value()
    }

    fn __repr__(&self) -> String {
        format!("PkeskVersion({})", self.value())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// SKESK packet version backed by rPGP's ``SkeskVersion``.
#[pyclass(module = "openpgp.types", name = "SkeskVersion", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PySkeskVersion {
    inner: PgpSkeskVersion,
}

#[pymethods]
impl PySkeskVersion {
    #[new]
    fn new(value: u8) -> Self {
        Self {
            inner: PgpSkeskVersion::from(value),
        }
    }

    #[classattr]
    #[pyo3(name = "V4")]
    fn v4() -> Self {
        Self {
            inner: PgpSkeskVersion::V4,
        }
    }

    #[classattr]
    #[pyo3(name = "V5")]
    fn v5() -> Self {
        Self {
            inner: PgpSkeskVersion::V5,
        }
    }

    #[classattr]
    #[pyo3(name = "V6")]
    fn v6() -> Self {
        Self {
            inner: PgpSkeskVersion::V6,
        }
    }

    #[getter]
    fn value(&self) -> u8 {
        self.inner.into()
    }

    fn __int__(&self) -> u8 {
        self.value()
    }

    fn __repr__(&self) -> String {
        format!("SkeskVersion({})", self.value())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// A versioned OpenPGP fingerprint backed by rPGP's ``Fingerprint``.
#[pyclass(module = "openpgp.types", name = "Fingerprint", from_py_object)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PyFingerprint {
    inner: PgpFingerprint,
}

#[pymethods]
impl PyFingerprint {
    #[new]
    fn new(version: PyRef<'_, PyKeyVersion>, value: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: PgpFingerprint::new(version.inner, value).map_err(to_py_err)?,
        })
    }

    #[getter]
    fn version(&self) -> Option<PyKeyVersion> {
        self.inner.version().map(|inner| PyKeyVersion { inner })
    }

    fn as_bytes(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, self.inner.as_bytes()).unbind()
    }

    fn __bytes__(&self, py: Python<'_>) -> Py<PyBytes> {
        self.as_bytes(py)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("Fingerprint('{}')", self.inner)
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// A legacy eight-byte OpenPGP key ID backed by rPGP's ``KeyId``.
#[pyclass(module = "openpgp.types", name = "KeyId", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyKeyId {
    inner: PgpKeyId,
}

#[pymethods]
impl PyKeyId {
    #[new]
    fn new(value: &[u8]) -> PyResult<Self> {
        let value: [u8; 8] = value
            .try_into()
            .map_err(|_| to_py_err("KeyId requires exactly 8 bytes"))?;
        Ok(Self {
            inner: PgpKeyId::new(value),
        })
    }

    #[classattr]
    #[pyo3(name = "WILDCARD")]
    fn wildcard() -> Self {
        Self {
            inner: PgpKeyId::WILDCARD,
        }
    }

    fn is_wildcard(&self) -> bool {
        self.inner.is_wildcard()
    }

    fn as_bytes(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, self.inner.as_ref()).unbind()
    }

    fn __bytes__(&self, py: Python<'_>) -> Py<PyBytes> {
        self.as_bytes(py)
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("KeyId('{}')", self.inner)
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// An OpenPGP multiprecision integer backed by rPGP's ``Mpi``.
#[pyclass(module = "openpgp.types", name = "Mpi", from_py_object)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PyMpi {
    inner: PgpMpi,
}

#[pymethods]
impl PyMpi {
    #[staticmethod]
    fn from_slice(value: &[u8]) -> Self {
        Self {
            inner: PgpMpi::from_slice(value),
        }
    }

    #[staticmethod]
    fn try_from_reader(value: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: PgpMpi::try_from_reader(Cursor::new(value)).map_err(to_py_err)?,
        })
    }

    fn as_bytes(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, self.inner.as_ref()).unbind()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __bytes__(&self, py: Python<'_>) -> Py<PyBytes> {
        self.as_bytes(py)
    }

    fn __repr__(&self) -> String {
        format!("Mpi('{}')", encode_hex(self.inner.as_ref()))
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// OpenPGP packet length backed by rPGP's ``PacketLength``.
#[pyclass(module = "openpgp.types", name = "PacketLength", from_py_object)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PyPacketLength {
    pub(crate) inner: PgpPacketLength,
}

#[pymethods]
impl PyPacketLength {
    #[staticmethod]
    fn fixed(length: u32) -> Self {
        Self {
            inner: PgpPacketLength::Fixed(length),
        }
    }

    #[staticmethod]
    fn partial(length: u32) -> PyResult<Self> {
        if !length.is_power_of_two() {
            return Err(to_py_err("partial packet length must be a power of two"));
        }
        Ok(Self {
            inner: PgpPacketLength::Partial(length),
        })
    }

    #[staticmethod]
    fn indeterminate() -> Self {
        Self {
            inner: PgpPacketLength::Indeterminate,
        }
    }

    #[staticmethod]
    fn try_from_reader(value: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: PgpPacketLength::try_from_reader(Cursor::new(value)).map_err(to_py_err)?,
        })
    }

    #[staticmethod]
    fn fixed_encoding_len(length: u32) -> usize {
        PgpPacketLength::fixed_encoding_len(length)
    }

    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            PgpPacketLength::Fixed(_) => "fixed",
            PgpPacketLength::Partial(_) => "partial",
            PgpPacketLength::Indeterminate => "indeterminate",
        }
    }

    fn maybe_len(&self) -> Option<u32> {
        self.inner.maybe_len()
    }

    fn to_bytes_new(&self) -> PyResult<Vec<u8>> {
        if matches!(self.inner, PgpPacketLength::Indeterminate) {
            return Err(to_py_err(
                "indeterminate lengths are invalid for new-format packet headers",
            ));
        }
        let mut output = Vec::new();
        self.inner.to_writer_new(&mut output).map_err(to_py_err)?;
        Ok(output)
    }

    fn __repr__(&self) -> String {
        format!(
            "PacketLength(kind='{}', length={:?})",
            self.kind(),
            self.maybe_len()
        )
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// OpenPGP packet tag backed by rPGP's ``Tag``.
#[pyclass(module = "openpgp.types", name = "Tag", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyTag {
    pub(crate) inner: PgpTag,
}

#[pymethods]
impl PyTag {
    #[new]
    fn new(value: u8) -> Self {
        Self {
            inner: PgpTag::from(value),
        }
    }

    #[classattr]
    #[pyo3(name = "PublicKeyEncryptedSessionKey")]
    fn public_key_encrypted_session_key() -> Self {
        Self::new(1)
    }

    #[classattr]
    #[pyo3(name = "Signature")]
    fn signature() -> Self {
        Self::new(2)
    }

    #[classattr]
    #[pyo3(name = "SymKeyEncryptedSessionKey")]
    fn sym_key_encrypted_session_key() -> Self {
        Self::new(3)
    }

    #[classattr]
    #[pyo3(name = "OnePassSignature")]
    fn one_pass_signature() -> Self {
        Self::new(4)
    }

    #[classattr]
    #[pyo3(name = "SecretKey")]
    fn secret_key() -> Self {
        Self::new(5)
    }

    #[classattr]
    #[pyo3(name = "PublicKey")]
    fn public_key() -> Self {
        Self::new(6)
    }

    #[classattr]
    #[pyo3(name = "SecretSubkey")]
    fn secret_subkey() -> Self {
        Self::new(7)
    }

    #[classattr]
    #[pyo3(name = "CompressedData")]
    fn compressed_data() -> Self {
        Self::new(8)
    }

    #[classattr]
    #[pyo3(name = "SymEncryptedData")]
    fn sym_encrypted_data() -> Self {
        Self::new(9)
    }

    #[classattr]
    #[pyo3(name = "Marker")]
    fn marker() -> Self {
        Self::new(10)
    }

    #[classattr]
    #[pyo3(name = "LiteralData")]
    fn literal_data() -> Self {
        Self::new(11)
    }

    #[classattr]
    #[pyo3(name = "Trust")]
    fn trust() -> Self {
        Self::new(12)
    }

    #[classattr]
    #[pyo3(name = "UserId")]
    fn user_id() -> Self {
        Self::new(13)
    }

    #[classattr]
    #[pyo3(name = "PublicSubkey")]
    fn public_subkey() -> Self {
        Self::new(14)
    }

    #[classattr]
    #[pyo3(name = "UserAttribute")]
    fn user_attribute() -> Self {
        Self::new(17)
    }

    #[classattr]
    #[pyo3(name = "SymEncryptedProtectedData")]
    fn sym_encrypted_protected_data() -> Self {
        Self::new(18)
    }

    #[classattr]
    #[pyo3(name = "ModDetectionCode")]
    fn mod_detection_code() -> Self {
        Self::new(19)
    }

    #[classattr]
    #[pyo3(name = "GnupgAeadData")]
    fn gnupg_aead_data() -> Self {
        Self::new(20)
    }

    #[classattr]
    #[pyo3(name = "Padding")]
    fn padding() -> Self {
        Self::new(21)
    }

    #[getter]
    fn value(&self) -> u8 {
        self.inner.into()
    }

    #[getter]
    fn name(&self) -> &'static str {
        match self.inner {
            PgpTag::PublicKeyEncryptedSessionKey => "public-key-encrypted-session-key",
            PgpTag::Signature => "signature",
            PgpTag::SymKeyEncryptedSessionKey => "sym-key-encrypted-session-key",
            PgpTag::OnePassSignature => "one-pass-signature",
            PgpTag::SecretKey => "secret-key",
            PgpTag::PublicKey => "public-key",
            PgpTag::SecretSubkey => "secret-subkey",
            PgpTag::CompressedData => "compressed-data",
            PgpTag::SymEncryptedData => "sym-encrypted-data",
            PgpTag::Marker => "marker",
            PgpTag::LiteralData => "literal-data",
            PgpTag::Trust => "trust",
            PgpTag::UserId => "user-id",
            PgpTag::PublicSubkey => "public-subkey",
            PgpTag::UserAttribute => "user-attribute",
            PgpTag::SymEncryptedProtectedData => "sym-encrypted-protected-data",
            PgpTag::ModDetectionCode => "mod-detection-code",
            PgpTag::GnupgAeadData => "gnupg-aead-data",
            PgpTag::Padding => "padding",
            PgpTag::UnassignedCritical(_) => "unassigned-critical",
            PgpTag::UnassignedNonCritical(_) => "unassigned-non-critical",
            PgpTag::Experimental(_) => "experimental",
            PgpTag::Invalid(_) => "invalid",
            _ => "unknown",
        }
    }

    fn encode(&self) -> u8 {
        self.inner.encode()
    }

    fn __int__(&self) -> u8 {
        self.value()
    }

    fn __repr__(&self) -> String {
        format!("Tag(name='{}', value={})", self.name(), self.value())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}
