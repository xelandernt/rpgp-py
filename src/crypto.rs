use pgp::{
    crypto::{
        aead::{AeadAlgorithm as PgpAeadAlgorithm, ChunkSize as PgpChunkSize},
        ecc_curve::{ECCCurve as PgpEccCurve, ecc_curve_from_oid},
        hash::HashAlgorithm as PgpHashAlgorithm,
        public_key::PublicKeyAlgorithm as PgpPublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm as PgpSymmetricKeyAlgorithm,
    },
    types::CompressionAlgorithm as PgpCompressionAlgorithm,
};
use pyo3::{basic::CompareOp, prelude::*};

use crate::{conversions::normalized_algorithm_name, to_py_err};

/// Hash algorithm backed by rPGP's ``HashAlgorithm``.
#[pyclass(module = "openpgp.crypto.hash", name = "HashAlgorithm", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyHashAlgorithm {
    pub(crate) inner: PgpHashAlgorithm,
}

#[pymethods]
impl PyHashAlgorithm {
    #[new]
    fn new(value: u8) -> Self {
        Self {
            inner: PgpHashAlgorithm::from(value),
        }
    }

    #[classattr]
    #[pyo3(name = "None_")]
    fn none() -> Self {
        Self::new(0)
    }

    #[classattr]
    #[pyo3(name = "Md5")]
    fn md5() -> Self {
        Self::new(1)
    }

    #[classattr]
    #[pyo3(name = "Sha1")]
    fn sha1() -> Self {
        Self::new(2)
    }

    #[classattr]
    #[pyo3(name = "Ripemd160")]
    fn ripemd160() -> Self {
        Self::new(3)
    }

    #[classattr]
    #[pyo3(name = "Sha256")]
    fn sha256() -> Self {
        Self::new(8)
    }

    #[classattr]
    #[pyo3(name = "Sha384")]
    fn sha384() -> Self {
        Self::new(9)
    }

    #[classattr]
    #[pyo3(name = "Sha512")]
    fn sha512() -> Self {
        Self::new(10)
    }

    #[classattr]
    #[pyo3(name = "Sha224")]
    fn sha224() -> Self {
        Self::new(11)
    }

    #[classattr]
    #[pyo3(name = "Sha3_256")]
    fn sha3_256() -> Self {
        Self::new(12)
    }

    #[classattr]
    #[pyo3(name = "Sha3_512")]
    fn sha3_512() -> Self {
        Self::new(14)
    }

    #[classattr]
    #[pyo3(name = "Private10")]
    fn private10() -> Self {
        Self::new(110)
    }

    #[getter]
    fn value(&self) -> String {
        match self.inner {
            PgpHashAlgorithm::Other(value) => format!("other-{value}"),
            _ => normalized_algorithm_name(self.inner),
        }
    }

    #[getter]
    fn id(&self) -> u8 {
        self.inner.into()
    }

    fn salt_len(&self) -> Option<usize> {
        self.inner.salt_len()
    }

    fn digest(&self, data: &[u8]) -> PyResult<Vec<u8>> {
        self.inner.digest(data).map_err(to_py_err)
    }

    fn digest_size(&self) -> Option<usize> {
        self.inner.digest_size()
    }

    fn __str__(&self) -> String {
        self.value()
    }

    fn __int__(&self) -> u8 {
        self.id()
    }

    fn __repr__(&self) -> String {
        format!("HashAlgorithm('{}')", self.value())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// Symmetric algorithm backed by rPGP's ``SymmetricKeyAlgorithm``.
#[pyclass(
    module = "openpgp.crypto.sym",
    name = "SymmetricKeyAlgorithm",
    from_py_object
)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PySymmetricKeyAlgorithm {
    pub(crate) inner: PgpSymmetricKeyAlgorithm,
}

#[pymethods]
impl PySymmetricKeyAlgorithm {
    #[new]
    fn new(value: u8) -> Self {
        Self {
            inner: PgpSymmetricKeyAlgorithm::from(value),
        }
    }

    #[classattr]
    #[pyo3(name = "Plaintext")]
    fn plaintext() -> Self {
        Self::new(0)
    }

    #[classattr]
    #[pyo3(name = "IDEA")]
    fn idea() -> Self {
        Self::new(1)
    }

    #[classattr]
    #[pyo3(name = "TripleDES")]
    fn triple_des() -> Self {
        Self::new(2)
    }

    #[classattr]
    #[pyo3(name = "CAST5")]
    fn cast5() -> Self {
        Self::new(3)
    }

    #[classattr]
    #[pyo3(name = "Blowfish")]
    fn blowfish() -> Self {
        Self::new(4)
    }

    #[classattr]
    #[pyo3(name = "AES128")]
    fn aes128() -> Self {
        Self::new(7)
    }

    #[classattr]
    #[pyo3(name = "Aes128")]
    fn aes128_compat() -> Self {
        Self::new(7)
    }

    #[classattr]
    #[pyo3(name = "AES192")]
    fn aes192() -> Self {
        Self::new(8)
    }

    #[classattr]
    #[pyo3(name = "Aes192")]
    fn aes192_compat() -> Self {
        Self::new(8)
    }

    #[classattr]
    #[pyo3(name = "AES256")]
    fn aes256() -> Self {
        Self::new(9)
    }

    #[classattr]
    #[pyo3(name = "Aes256")]
    fn aes256_compat() -> Self {
        Self::new(9)
    }

    #[classattr]
    #[pyo3(name = "Twofish")]
    fn twofish() -> Self {
        Self::new(10)
    }

    #[classattr]
    #[pyo3(name = "Camellia128")]
    fn camellia128() -> Self {
        Self::new(11)
    }

    #[classattr]
    #[pyo3(name = "Camellia192")]
    fn camellia192() -> Self {
        Self::new(12)
    }

    #[classattr]
    #[pyo3(name = "Camellia256")]
    fn camellia256() -> Self {
        Self::new(13)
    }

    #[classattr]
    #[pyo3(name = "Private10")]
    fn private10() -> Self {
        Self::new(110)
    }

    #[getter]
    fn value(&self) -> String {
        match self.inner {
            PgpSymmetricKeyAlgorithm::TripleDES => "triple-des".to_string(),
            PgpSymmetricKeyAlgorithm::Other(value) => format!("other-{value}"),
            _ => normalized_algorithm_name(self.inner),
        }
    }

    #[getter]
    fn id(&self) -> u8 {
        self.inner.into()
    }

    fn block_size(&self) -> usize {
        self.inner.block_size()
    }

    fn key_size(&self) -> usize {
        self.inner.key_size()
    }

    fn encrypted_protected_len(&self, plaintext_len: usize) -> usize {
        self.inner.encrypted_protected_len(plaintext_len)
    }

    fn encrypted_protected_overhead(&self) -> usize {
        self.inner.encrypted_protected_overhead()
    }

    fn __str__(&self) -> String {
        self.value()
    }

    fn __int__(&self) -> u8 {
        self.id()
    }

    fn __repr__(&self) -> String {
        format!("SymmetricKeyAlgorithm('{}')", self.value())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// AEAD algorithm backed by rPGP's ``AeadAlgorithm``.
#[pyclass(module = "openpgp.crypto.aead", name = "AeadAlgorithm", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyAeadAlgorithm {
    pub(crate) inner: PgpAeadAlgorithm,
}

#[pymethods]
impl PyAeadAlgorithm {
    #[new]
    fn new(value: u8) -> Self {
        Self {
            inner: PgpAeadAlgorithm::from(value),
        }
    }

    #[classattr]
    #[pyo3(name = "None_")]
    fn none() -> Self {
        Self::new(0)
    }

    #[classattr]
    #[pyo3(name = "Eax")]
    fn eax() -> Self {
        Self::new(1)
    }

    #[classattr]
    #[pyo3(name = "Ocb")]
    fn ocb() -> Self {
        Self::new(2)
    }

    #[classattr]
    #[pyo3(name = "Gcm")]
    fn gcm() -> Self {
        Self::new(3)
    }

    #[getter]
    fn value(&self) -> String {
        match self.inner {
            PgpAeadAlgorithm::Private100
            | PgpAeadAlgorithm::Private101
            | PgpAeadAlgorithm::Private102
            | PgpAeadAlgorithm::Private103
            | PgpAeadAlgorithm::Private104
            | PgpAeadAlgorithm::Private105
            | PgpAeadAlgorithm::Private106
            | PgpAeadAlgorithm::Private107
            | PgpAeadAlgorithm::Private108
            | PgpAeadAlgorithm::Private109
            | PgpAeadAlgorithm::Private110 => format!("private-{}", u8::from(self.inner)),
            PgpAeadAlgorithm::Other(value) => format!("other-{value}"),
            _ => normalized_algorithm_name(self.inner),
        }
    }

    #[getter]
    fn id(&self) -> u8 {
        self.inner.into()
    }

    fn nonce_size(&self) -> usize {
        self.inner.nonce_size()
    }

    fn iv_size(&self) -> usize {
        self.inner.iv_size()
    }

    fn tag_size(&self) -> Option<usize> {
        self.inner.tag_size()
    }

    fn __str__(&self) -> String {
        self.value()
    }

    fn __int__(&self) -> u8 {
        self.id()
    }

    fn __repr__(&self) -> String {
        format!("AeadAlgorithm('{}')", self.value())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// RFC 9580 AEAD chunk size backed by rPGP's ``ChunkSize``.
#[pyclass(module = "openpgp.crypto.aead", name = "ChunkSize", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyChunkSize {
    inner: PgpChunkSize,
}

#[pymethods]
impl PyChunkSize {
    #[new]
    #[pyo3(signature = (value=6))]
    fn new(value: u8) -> PyResult<Self> {
        Ok(Self {
            inner: PgpChunkSize::try_from(value)
                .map_err(|_| to_py_err("chunk-size octet must be between 0 and 16"))?,
        })
    }

    #[staticmethod]
    fn from_byte_size(size: u32) -> PyResult<Self> {
        if !(64..=4 * 1024 * 1024).contains(&size) || !size.is_power_of_two() {
            return Err(to_py_err(
                "chunk byte size must be a power of two from 64 bytes through 4 MiB",
            ));
        }
        Self::new(size.trailing_zeros() as u8 - 6)
    }

    #[classattr]
    #[pyo3(name = "C64B")]
    fn c64b() -> Self {
        Self {
            inner: PgpChunkSize::C64B,
        }
    }

    #[classattr]
    #[pyo3(name = "C4KiB")]
    fn c4_kib() -> Self {
        Self {
            inner: PgpChunkSize::C4KiB,
        }
    }

    #[classattr]
    #[pyo3(name = "C4MiB")]
    fn c4_mib() -> Self {
        Self {
            inner: PgpChunkSize::C4MiB,
        }
    }

    #[getter]
    fn value(&self) -> u8 {
        self.inner.into()
    }

    fn as_byte_size(&self) -> u32 {
        self.inner.as_byte_size()
    }

    fn __int__(&self) -> u8 {
        self.value()
    }

    fn __repr__(&self) -> String {
        format!(
            "ChunkSize({}, byte_size={})",
            self.value(),
            self.as_byte_size()
        )
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

/// Public-key algorithm backed by rPGP's ``PublicKeyAlgorithm``.
#[pyclass(
    module = "openpgp.crypto.public_key",
    name = "PublicKeyAlgorithm",
    from_py_object
)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyPublicKeyAlgorithm {
    pub(crate) inner: PgpPublicKeyAlgorithm,
}

#[pymethods]
impl PyPublicKeyAlgorithm {
    #[new]
    fn new(value: u8) -> Self {
        Self {
            inner: PgpPublicKeyAlgorithm::from(value),
        }
    }

    #[classattr]
    #[pyo3(name = "RSA")]
    fn rsa() -> Self {
        Self::new(1)
    }

    #[classattr]
    #[pyo3(name = "RSAEncrypt")]
    fn rsa_encrypt() -> Self {
        Self::new(2)
    }

    #[classattr]
    #[pyo3(name = "RSASign")]
    fn rsa_sign() -> Self {
        Self::new(3)
    }

    #[classattr]
    #[pyo3(name = "ElgamalEncrypt")]
    fn elgamal_encrypt() -> Self {
        Self::new(16)
    }

    #[classattr]
    #[pyo3(name = "DSA")]
    fn dsa() -> Self {
        Self::new(17)
    }

    #[classattr]
    #[pyo3(name = "ECDH")]
    fn ecdh() -> Self {
        Self::new(18)
    }

    #[classattr]
    #[pyo3(name = "ECDSA")]
    fn ecdsa() -> Self {
        Self::new(19)
    }

    #[classattr]
    #[pyo3(name = "Elgamal")]
    fn elgamal() -> Self {
        Self::new(20)
    }

    #[classattr]
    #[pyo3(name = "DiffieHellman")]
    fn diffie_hellman() -> Self {
        Self::new(21)
    }

    #[classattr]
    #[pyo3(name = "EdDSALegacy")]
    fn eddsa_legacy() -> Self {
        Self::new(22)
    }

    #[classattr]
    #[pyo3(name = "X25519")]
    fn x25519() -> Self {
        Self::new(25)
    }

    #[classattr]
    #[pyo3(name = "X448")]
    fn x448() -> Self {
        Self::new(26)
    }

    #[classattr]
    #[pyo3(name = "Ed25519")]
    fn ed25519() -> Self {
        Self::new(27)
    }

    #[classattr]
    #[pyo3(name = "Ed448")]
    fn ed448() -> Self {
        Self::new(28)
    }

    #[getter]
    fn value(&self) -> String {
        match self.inner {
            PgpPublicKeyAlgorithm::RSA => "rsa".to_string(),
            PgpPublicKeyAlgorithm::RSAEncrypt => "rsa-encrypt".to_string(),
            PgpPublicKeyAlgorithm::RSASign => "rsa-sign".to_string(),
            PgpPublicKeyAlgorithm::ElgamalEncrypt => "elgamal-encrypt".to_string(),
            PgpPublicKeyAlgorithm::DSA => "dsa".to_string(),
            PgpPublicKeyAlgorithm::ECDH => "ecdh".to_string(),
            PgpPublicKeyAlgorithm::ECDSA => "ecdsa".to_string(),
            PgpPublicKeyAlgorithm::Elgamal => "elgamal".to_string(),
            PgpPublicKeyAlgorithm::DiffieHellman => "diffie-hellman".to_string(),
            PgpPublicKeyAlgorithm::EdDSALegacy => "eddsa-legacy".to_string(),
            PgpPublicKeyAlgorithm::X25519 => "x25519".to_string(),
            PgpPublicKeyAlgorithm::X448 => "x448".to_string(),
            PgpPublicKeyAlgorithm::Ed25519 => "ed25519".to_string(),
            PgpPublicKeyAlgorithm::Ed448 => "ed448".to_string(),
            PgpPublicKeyAlgorithm::Private100
            | PgpPublicKeyAlgorithm::Private101
            | PgpPublicKeyAlgorithm::Private102
            | PgpPublicKeyAlgorithm::Private103
            | PgpPublicKeyAlgorithm::Private104
            | PgpPublicKeyAlgorithm::Private105
            | PgpPublicKeyAlgorithm::Private106
            | PgpPublicKeyAlgorithm::Private107
            | PgpPublicKeyAlgorithm::Private108
            | PgpPublicKeyAlgorithm::Private109
            | PgpPublicKeyAlgorithm::Private110 => format!("private-{}", u8::from(self.inner)),
            PgpPublicKeyAlgorithm::Unknown(value) => format!("unknown-{value}"),
            _ => normalized_algorithm_name(self.inner),
        }
    }

    #[getter]
    fn id(&self) -> u8 {
        self.inner.into()
    }

    fn is_pqc(&self) -> bool {
        self.inner.is_pqc()
    }

    fn can_sign(&self) -> bool {
        self.inner.can_sign()
    }

    fn can_encrypt(&self) -> bool {
        self.inner.can_encrypt()
    }

    fn __str__(&self) -> String {
        self.value()
    }

    fn __int__(&self) -> u8 {
        self.id()
    }

    fn __repr__(&self) -> String {
        format!("PublicKeyAlgorithm('{}')", self.value())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// Elliptic curve backed by rPGP's ``ECCCurve``.
#[pyclass(module = "openpgp.crypto.ecc_curve", name = "ECCCurve", from_py_object)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PyEccCurve {
    pub(crate) inner: PgpEccCurve,
}

#[pymethods]
impl PyEccCurve {
    #[classattr]
    #[pyo3(name = "Curve25519Legacy")]
    fn curve25519_legacy() -> Self {
        Self {
            inner: PgpEccCurve::Curve25519Legacy,
        }
    }

    #[classattr]
    #[pyo3(name = "Ed25519Legacy")]
    fn ed25519_legacy() -> Self {
        Self {
            inner: PgpEccCurve::Ed25519Legacy,
        }
    }

    #[classattr]
    #[pyo3(name = "P256")]
    fn p256() -> Self {
        Self {
            inner: PgpEccCurve::P256,
        }
    }

    #[classattr]
    #[pyo3(name = "P384")]
    fn p384() -> Self {
        Self {
            inner: PgpEccCurve::P384,
        }
    }

    #[classattr]
    #[pyo3(name = "P521")]
    fn p521() -> Self {
        Self {
            inner: PgpEccCurve::P521,
        }
    }

    #[classattr]
    #[pyo3(name = "BrainpoolP256r1")]
    fn brainpool_p256r1() -> Self {
        Self {
            inner: PgpEccCurve::BrainpoolP256r1,
        }
    }

    #[classattr]
    #[pyo3(name = "BrainpoolP384r1")]
    fn brainpool_p384r1() -> Self {
        Self {
            inner: PgpEccCurve::BrainpoolP384r1,
        }
    }

    #[classattr]
    #[pyo3(name = "BrainpoolP512r1")]
    fn brainpool_p512r1() -> Self {
        Self {
            inner: PgpEccCurve::BrainpoolP512r1,
        }
    }

    #[classattr]
    #[pyo3(name = "Secp256k1")]
    fn secp256k1() -> Self {
        Self {
            inner: PgpEccCurve::Secp256k1,
        }
    }

    #[staticmethod]
    fn from_oid(oid: &[u8]) -> Option<Self> {
        ecc_curve_from_oid(oid).map(|inner| Self { inner })
    }

    #[getter]
    fn value(&self) -> String {
        match self.inner {
            PgpEccCurve::Curve25519Legacy => "curve25519".to_string(),
            PgpEccCurve::Ed25519Legacy => "ed25519".to_string(),
            PgpEccCurve::P256 => "p256".to_string(),
            PgpEccCurve::P384 => "p384".to_string(),
            PgpEccCurve::P521 => "p521".to_string(),
            PgpEccCurve::BrainpoolP256r1 => "brainpoolp256r1".to_string(),
            PgpEccCurve::BrainpoolP384r1 => "brainpoolp384r1".to_string(),
            PgpEccCurve::BrainpoolP512r1 => "brainpoolp512r1".to_string(),
            PgpEccCurve::Secp256k1 => "secp256k1".to_string(),
            PgpEccCurve::Unknown(_) => "unknown".to_string(),
        }
    }

    fn name(&self) -> &str {
        self.inner.name()
    }

    fn oid_str(&self) -> String {
        self.inner.oid_str()
    }

    fn oid(&self) -> Vec<u8> {
        self.inner.oid()
    }

    fn nbits(&self) -> u16 {
        self.inner.nbits()
    }

    fn secret_key_length(&self) -> usize {
        self.inner.secret_key_length()
    }

    fn alias(&self) -> Option<&str> {
        self.inner.alias()
    }

    fn pubkey_algo(&self) -> Option<PyPublicKeyAlgorithm> {
        self.inner
            .pubkey_algo()
            .map(|inner| PyPublicKeyAlgorithm { inner })
    }

    fn hash_algo(&self) -> PyResult<PyHashAlgorithm> {
        Ok(PyHashAlgorithm {
            inner: self.inner.hash_algo().map_err(to_py_err)?,
        })
    }

    fn sym_algo(&self) -> PyResult<PySymmetricKeyAlgorithm> {
        Ok(PySymmetricKeyAlgorithm {
            inner: self.inner.sym_algo().map_err(to_py_err)?,
        })
    }

    fn __str__(&self) -> String {
        self.value()
    }

    fn __repr__(&self) -> String {
        format!("ECCCurve('{}')", self.value())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// Compression algorithm backed by rPGP's ``CompressionAlgorithm``.
#[pyclass(
    module = "openpgp.types",
    name = "CompressionAlgorithm",
    from_py_object
)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyCompressionAlgorithm {
    pub(crate) inner: PgpCompressionAlgorithm,
}

#[pymethods]
impl PyCompressionAlgorithm {
    #[new]
    fn new(value: u8) -> Self {
        Self {
            inner: PgpCompressionAlgorithm::from(value),
        }
    }

    #[classattr]
    #[pyo3(name = "Uncompressed")]
    fn uncompressed() -> Self {
        Self::new(0)
    }

    #[classattr]
    #[pyo3(name = "ZIP")]
    fn zip() -> Self {
        Self::new(1)
    }

    #[classattr]
    #[pyo3(name = "Zip")]
    fn zip_compat() -> Self {
        Self::new(1)
    }

    #[classattr]
    #[pyo3(name = "ZLIB")]
    fn zlib() -> Self {
        Self::new(2)
    }

    #[classattr]
    #[pyo3(name = "Zlib")]
    fn zlib_compat() -> Self {
        Self::new(2)
    }

    #[classattr]
    #[pyo3(name = "BZip2")]
    fn bzip2() -> Self {
        Self::new(3)
    }

    #[classattr]
    #[pyo3(name = "Bzip2")]
    fn bzip2_compat() -> Self {
        Self::new(3)
    }

    #[classattr]
    #[pyo3(name = "Private10")]
    fn private10() -> Self {
        Self::new(110)
    }

    #[getter]
    fn value(&self) -> String {
        match self.inner {
            PgpCompressionAlgorithm::ZIP => "zip".to_string(),
            PgpCompressionAlgorithm::ZLIB => "zlib".to_string(),
            PgpCompressionAlgorithm::BZip2 => "bzip2".to_string(),
            PgpCompressionAlgorithm::Other(value) => format!("other-{value}"),
            _ => normalized_algorithm_name(self.inner),
        }
    }

    #[getter]
    fn id(&self) -> u8 {
        self.inner.into()
    }

    fn __str__(&self) -> String {
        self.value()
    }

    fn __int__(&self) -> u8 {
        self.id()
    }

    fn __repr__(&self) -> String {
        format!("CompressionAlgorithm('{}')", self.value())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}
