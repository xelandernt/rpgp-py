use std::io::{Cursor, Read, Write};

use pgp::{
    armor::{
        self, ArmorCrc24Status as PgpArmorCrc24Status, BlockType as PgpBlockType,
        Dearmor as PgpDearmor, DearmorOptions as PgpDearmorOptions, PKCS1Type as PgpPkcs1Type,
    },
    ser::Serialize,
};
use pyo3::{
    basic::CompareOp,
    exceptions::PyTypeError,
    prelude::*,
    types::{PyAny, PyBytes},
};

use crate::{Headers, to_py_err};

struct ByteSource<'a>(&'a [u8]);

impl Serialize for ByteSource<'_> {
    fn to_writer<W: Write>(&self, writer: &mut W) -> pgp::errors::Result<()> {
        writer.write_all(self.0)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.0.len()
    }
}

fn source_bytes(source: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(value) = source.extract::<Vec<u8>>() {
        return Ok(value);
    }

    source.call_method0("to_bytes")?.extract()
}

fn armored_input(source: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(value) = source.extract::<String>() {
        return Ok(value.into_bytes());
    }

    source.extract()
}

/// OpenSSL PKCS#1 armor key type backed by rPGP's ``PKCS1Type``.
#[pyclass(module = "openpgp.armor", name = "PKCS1Type", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pkcs1Type {
    inner: PgpPkcs1Type,
}

#[pymethods]
impl Pkcs1Type {
    #[classattr]
    #[pyo3(name = "RSA")]
    fn rsa() -> Self {
        Self {
            inner: PgpPkcs1Type::RSA,
        }
    }

    #[classattr]
    #[pyo3(name = "DSA")]
    fn dsa() -> Self {
        Self {
            inner: PgpPkcs1Type::DSA,
        }
    }

    #[classattr]
    #[pyo3(name = "EC")]
    fn ec() -> Self {
        Self {
            inner: PgpPkcs1Type::EC,
        }
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("PKCS1Type.{}", self.inner)
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// ASCII armor block type backed by rPGP's ``BlockType``.
#[pyclass(module = "openpgp.armor", name = "BlockType", from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlockType {
    pub(crate) inner: PgpBlockType,
}

#[pymethods]
impl BlockType {
    #[classattr]
    #[pyo3(name = "PublicKey")]
    fn public_key() -> Self {
        Self {
            inner: PgpBlockType::PublicKey,
        }
    }

    #[classattr]
    #[pyo3(name = "PublicKeyPKCS8")]
    fn public_key_pkcs8() -> Self {
        Self {
            inner: PgpBlockType::PublicKeyPKCS8,
        }
    }

    #[classattr]
    #[pyo3(name = "PublicKeyOpenssh")]
    fn public_key_openssh() -> Self {
        Self {
            inner: PgpBlockType::PublicKeyOpenssh,
        }
    }

    #[classattr]
    #[pyo3(name = "PrivateKey")]
    fn private_key() -> Self {
        Self {
            inner: PgpBlockType::PrivateKey,
        }
    }

    #[classattr]
    #[pyo3(name = "PrivateKeyPKCS8")]
    fn private_key_pkcs8() -> Self {
        Self {
            inner: PgpBlockType::PrivateKeyPKCS8,
        }
    }

    #[classattr]
    #[pyo3(name = "PrivateKeyOpenssh")]
    fn private_key_openssh() -> Self {
        Self {
            inner: PgpBlockType::PrivateKeyOpenssh,
        }
    }

    #[classattr]
    #[pyo3(name = "Message")]
    fn message() -> Self {
        Self {
            inner: PgpBlockType::Message,
        }
    }

    #[classattr]
    #[pyo3(name = "Signature")]
    fn signature() -> Self {
        Self {
            inner: PgpBlockType::Signature,
        }
    }

    #[classattr]
    #[pyo3(name = "File")]
    fn file() -> Self {
        Self {
            inner: PgpBlockType::File,
        }
    }

    #[classattr]
    #[pyo3(name = "CleartextMessage")]
    fn cleartext_message() -> Self {
        Self {
            inner: PgpBlockType::CleartextMessage,
        }
    }

    #[staticmethod]
    fn public_key_pkcs1(typ: PyRef<'_, Pkcs1Type>) -> Self {
        Self {
            inner: PgpBlockType::PublicKeyPKCS1(typ.inner),
        }
    }

    #[staticmethod]
    fn private_key_pkcs1(typ: PyRef<'_, Pkcs1Type>) -> Self {
        Self {
            inner: PgpBlockType::PrivateKeyPKCS1(typ.inner),
        }
    }

    #[staticmethod]
    fn multi_part_message(part: usize, total: usize) -> Self {
        Self {
            inner: PgpBlockType::MultiPartMessage(part, total),
        }
    }

    #[getter]
    fn name(&self) -> &'static str {
        match self.inner {
            PgpBlockType::PublicKey => "public-key",
            PgpBlockType::PublicKeyPKCS1(_) => "public-key-pkcs1",
            PgpBlockType::PublicKeyPKCS8 => "public-key-pkcs8",
            PgpBlockType::PublicKeyOpenssh => "public-key-openssh",
            PgpBlockType::PrivateKey => "private-key",
            PgpBlockType::PrivateKeyPKCS1(_) => "private-key-pkcs1",
            PgpBlockType::PrivateKeyPKCS8 => "private-key-pkcs8",
            PgpBlockType::PrivateKeyOpenssh => "private-key-openssh",
            PgpBlockType::Message => "message",
            PgpBlockType::MultiPartMessage(_, _) => "multi-part-message",
            PgpBlockType::Signature => "signature",
            PgpBlockType::File => "file",
            PgpBlockType::CleartextMessage => "cleartext-message",
        }
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("BlockType(name='{}')", self.name())
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }
}

/// CRC24 result returned by rPGP's armor reader.
#[pyclass(module = "openpgp.armor", name = "ArmorCrc24Status", from_py_object)]
#[derive(Clone, Copy)]
pub(crate) struct ArmorCrc24Status {
    inner: PgpArmorCrc24Status,
}

#[pymethods]
impl ArmorCrc24Status {
    #[getter]
    fn status(&self) -> &'static str {
        match self.inner {
            PgpArmorCrc24Status::NoCrc24 => "no-crc24",
            PgpArmorCrc24Status::CheckedOk { .. } => "checked-ok",
            PgpArmorCrc24Status::CheckedInvalid { .. } => "checked-invalid",
            PgpArmorCrc24Status::Unchecked { .. } => "unchecked",
        }
    }

    #[getter]
    fn crc(&self) -> Option<u32> {
        match self.inner {
            PgpArmorCrc24Status::CheckedOk { crc } => Some(crc),
            _ => None,
        }
    }

    #[getter]
    fn footer_crc(&self) -> Option<u32> {
        match self.inner {
            PgpArmorCrc24Status::CheckedInvalid { footer_crc, .. }
            | PgpArmorCrc24Status::Unchecked { footer_crc } => Some(footer_crc),
            _ => None,
        }
    }

    #[getter]
    fn calculated_crc(&self) -> Option<u32> {
        match self.inner {
            PgpArmorCrc24Status::CheckedInvalid { calculated_crc, .. } => Some(calculated_crc),
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        format!("ArmorCrc24Status(status='{}')", self.status())
    }
}

/// Configuration for rPGP's armor reader.
#[pyclass(module = "openpgp.armor", name = "DearmorOptions", from_py_object)]
#[derive(Clone, Copy)]
pub(crate) struct DearmorOptions {
    pub(crate) inner: PgpDearmorOptions,
    limit: usize,
    crc24_check: bool,
}

#[pymethods]
impl DearmorOptions {
    #[new]
    #[pyo3(signature = (limit=1024 * 1024 * 1024, crc24_check=false))]
    fn new(limit: usize, crc24_check: bool) -> Self {
        let mut inner = PgpDearmorOptions::new().set_limit(limit);
        if crc24_check {
            inner = inner.enable_crc24_check();
        }
        Self {
            inner,
            limit,
            crc24_check,
        }
    }

    fn set_limit(&self, limit: usize) -> Self {
        Self::new(limit, self.crc24_check)
    }

    fn enable_crc24_check(&self) -> Self {
        Self::new(self.limit, true)
    }

    #[getter]
    fn limit(&self) -> usize {
        self.limit
    }

    #[getter]
    fn crc24_check(&self) -> bool {
        self.crc24_check
    }
}

/// Eager Python view over rPGP's streaming ``Dearmor`` reader.
#[pyclass(module = "openpgp.armor", name = "Dearmor")]
pub(crate) struct Dearmor {
    data: Vec<u8>,
    position: usize,
    typ: Option<PgpBlockType>,
    headers: Headers,
    checksum: Option<u64>,
    crc24_status: PgpArmorCrc24Status,
    max_buffer_limit: usize,
}

#[pymethods]
impl Dearmor {
    #[new]
    #[pyo3(signature = (source, options=None))]
    fn new(
        source: &Bound<'_, PyAny>,
        options: Option<PyRef<'_, DearmorOptions>>,
    ) -> PyResult<Self> {
        let input = armored_input(source)?;
        let options = options
            .as_ref()
            .map_or_else(PgpDearmorOptions::default, |value| value.inner);
        let mut reader = PgpDearmor::with_options(Cursor::new(input), options);
        let max_buffer_limit = reader.max_buffer_limit();
        let mut data = Vec::new();
        reader.read_to_end(&mut data).map_err(to_py_err)?;

        Ok(Self {
            data,
            position: 0,
            typ: reader.typ,
            headers: reader.headers.clone(),
            checksum: reader.checksum,
            crc24_status: reader.crc24_status(),
            max_buffer_limit,
        })
    }

    #[getter]
    fn typ(&self) -> Option<BlockType> {
        self.typ.map(|inner| BlockType { inner })
    }

    #[getter]
    fn headers(&self) -> Headers {
        self.headers.clone()
    }

    #[getter]
    fn checksum(&self) -> Option<u64> {
        self.checksum
    }

    fn crc24_status(&self) -> ArmorCrc24Status {
        ArmorCrc24Status {
            inner: self.crc24_status,
        }
    }

    fn max_buffer_limit(&self) -> usize {
        self.max_buffer_limit
    }

    #[pyo3(signature = (size=-1))]
    fn read(&mut self, py: Python<'_>, size: isize) -> Py<PyBytes> {
        let remaining = self.data.len().saturating_sub(self.position);
        let length = if size < 0 {
            remaining
        } else {
            remaining.min(size as usize)
        };
        let start = self.position;
        self.position += length;
        PyBytes::new(py, &self.data[start..self.position]).unbind()
    }

    fn readall(&mut self, py: Python<'_>) -> Py<PyBytes> {
        self.read(py, -1)
    }
}

/// Write ASCII armor using rPGP's armor writer.
#[pyfunction(name = "write")]
#[pyo3(signature = (source, typ, writer, headers=None, include_checksum=true))]
pub(crate) fn armor_write(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    typ: PyRef<'_, BlockType>,
    writer: &Bound<'_, PyAny>,
    headers: Option<Headers>,
    include_checksum: bool,
) -> PyResult<()> {
    let source = source_bytes(source)?;
    let mut output = Vec::new();
    armor::write(
        &ByteSource(&source),
        typ.inner,
        &mut output,
        headers.as_ref(),
        include_checksum,
    )
    .map_err(to_py_err)?;

    let text = std::str::from_utf8(&output).map_err(to_py_err)?;
    match writer.call_method1("write", (text,)) {
        Ok(_) => Ok(()),
        Err(error) if error.is_instance_of::<PyTypeError>(py) => {
            writer.call_method1("write", (PyBytes::new(py, &output),))?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}
