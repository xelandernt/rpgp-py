use std::io::{Cursor, Read};

use pgp::{
    packet::{
        CompressedData as PgpCompressedData, LiteralData as PgpLiteralData, Marker as PgpMarker,
        ModDetectionCode as PgpModDetectionCode, OnePassSignature as PgpOnePassSignature,
        Packet as PgpPacket, PacketHeader as PgpPacketHeader, PacketParser as PgpPacketParser,
        PacketTrait, Padding as PgpPadding, Trust as PgpTrust, UserId as PgpUserId,
    },
    ser::Serialize,
};
use pyo3::{prelude::*, types::PyAny};

use crate::{
    conversions::normalized_algorithm_name,
    crypto::{PyCompressionAlgorithm, PyHashAlgorithm, PyPublicKeyAlgorithm},
    info::UserAttribute,
    info::{public_key_algorithm_name, signature_type_name},
    packet::{
        encrypted::{
            PublicKeyEncryptedSessionKey, SymKeyEncryptedSessionKey,
            encrypted_data_packet_from_packet, encrypted_data_packet_object,
        },
        key_packets::{
            public_key_packet_object, public_subkey_packet_object, secret_key_packet_object,
            secret_subkey_packet_object,
        },
        signatures::{Signature, signature_packet_from_raw},
    },
    serialization::serialize_packet_with_header,
    to_py_err,
    types::{PyPacketLength, PyTag},
};

fn packet_kind(packet: &PgpPacket) -> &'static str {
    match packet {
        PgpPacket::CompressedData(_) => "compressed-data",
        PgpPacket::PublicKey(_) => "public-key",
        PgpPacket::PublicSubkey(_) => "public-subkey",
        PgpPacket::SecretKey(_) => "secret-key",
        PgpPacket::SecretSubkey(_) => "secret-subkey",
        PgpPacket::LiteralData(_) => "literal-data",
        PgpPacket::Marker(_) => "marker",
        PgpPacket::ModDetectionCode(_) => "mod-detection-code",
        PgpPacket::OnePassSignature(_) => "one-pass-signature",
        PgpPacket::PublicKeyEncryptedSessionKey(_) => "public-key-encrypted-session-key",
        PgpPacket::Signature(_) => "signature",
        PgpPacket::SymEncryptedData(_) => "sym-encrypted-data",
        PgpPacket::SymEncryptedProtectedData(_) => "sym-encrypted-protected-data",
        PgpPacket::SymKeyEncryptedSessionKey(_) => "sym-key-encrypted-session-key",
        PgpPacket::Trust(_) => "trust",
        PgpPacket::UserAttribute(_) => "user-attribute",
        PgpPacket::UserId(_) => "user-id",
        PgpPacket::Padding(_) => "padding",
        PgpPacket::GnupgAeadData(_) => "gnupg-aead-data",
    }
}

macro_rules! opaque_packet {
    ($name:ident, $inner:ty, $kind:literal) => {
        #[pyclass(module = "openpgp.packet", from_py_object)]
        #[derive(Clone)]
        pub(crate) struct $name {
            inner: $inner,
        }

        #[pymethods]
        impl $name {
            fn to_bytes(&self) -> PyResult<Vec<u8>> {
                serialize_packet_with_header(&self.inner)
            }

            fn __repr__(&self) -> &'static str {
                concat!(stringify!($name), "()")
            }
        }
    };
}

opaque_packet!(Marker, PgpMarker, "marker");
opaque_packet!(ModDetectionCode, PgpModDetectionCode, "mod-detection-code");
opaque_packet!(Padding, PgpPadding, "padding");
opaque_packet!(Trust, PgpTrust, "trust");

/// An rPGP compressed-data packet.
#[pyclass(module = "openpgp.packet", from_py_object)]
#[derive(Clone)]
pub(crate) struct CompressedData {
    inner: PgpCompressedData,
}

#[pymethods]
impl CompressedData {
    #[getter]
    fn compression_algorithm(&self) -> PyResult<String> {
        let body = self.inner.to_bytes().map_err(to_py_err)?;
        let algorithm = body
            .first()
            .copied()
            .ok_or_else(|| to_py_err("compressed-data packet has an empty body"))?;
        Ok(normalized_algorithm_name(
            pgp::types::CompressionAlgorithm::from(algorithm),
        ))
    }

    /// Return the native rPGP compression algorithm enum.
    #[getter]
    fn algorithm(&self) -> PyResult<PyCompressionAlgorithm> {
        let body = self.inner.to_bytes().map_err(to_py_err)?;
        let algorithm = body
            .first()
            .copied()
            .ok_or_else(|| to_py_err("compressed-data packet has an empty body"))?;
        Ok(PyCompressionAlgorithm {
            inner: pgp::types::CompressionAlgorithm::from(algorithm),
        })
    }

    #[getter]
    fn compressed_data(&self) -> Vec<u8> {
        self.inner.compressed_data().to_vec()
    }

    fn decompress(&self) -> PyResult<Vec<u8>> {
        let mut output = Vec::new();
        self.inner
            .decompress()
            .map_err(to_py_err)?
            .read_to_end(&mut output)
            .map_err(to_py_err)?;
        Ok(output)
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        serialize_packet_with_header(&self.inner)
    }
}

/// An rPGP literal-data packet.
#[pyclass(module = "openpgp.packet", from_py_object)]
#[derive(Clone)]
pub(crate) struct LiteralData {
    inner: PgpLiteralData,
}

#[pymethods]
impl LiteralData {
    #[staticmethod]
    fn from_bytes(file_name: &str, data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: PgpLiteralData::from_bytes(file_name.as_bytes().to_vec(), data.to_vec().into())
                .map_err(to_py_err)?,
        })
    }

    #[staticmethod]
    fn from_str(file_name: &str, data: &str) -> PyResult<Self> {
        Ok(Self {
            inner: PgpLiteralData::from_str(file_name.as_bytes().to_vec(), data)
                .map_err(to_py_err)?,
        })
    }

    #[getter]
    fn file_name(&self) -> Vec<u8> {
        self.inner.file_name().to_vec()
    }

    #[getter]
    fn is_binary(&self) -> bool {
        self.inner.is_binary()
    }

    #[getter]
    fn data(&self) -> Vec<u8> {
        self.inner.data().to_vec()
    }

    fn as_str(&self) -> Option<&str> {
        self.inner.as_str()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        serialize_packet_with_header(&self.inner)
    }
}

/// An rPGP one-pass-signature packet.
#[pyclass(module = "openpgp.packet", from_py_object)]
#[derive(Clone)]
pub(crate) struct OnePassSignature {
    inner: PgpOnePassSignature,
}

#[pymethods]
impl OnePassSignature {
    #[getter]
    fn version(&self) -> u8 {
        self.inner.version()
    }

    #[getter]
    fn is_nested(&self) -> bool {
        self.inner.is_nested()
    }

    #[getter]
    fn hash_algorithm(&self) -> String {
        normalized_algorithm_name(self.inner.hash_algorithm())
    }

    #[getter]
    fn hash_algorithm_type(&self) -> PyHashAlgorithm {
        PyHashAlgorithm {
            inner: self.inner.hash_algorithm(),
        }
    }

    #[getter]
    fn public_key_algorithm(&self) -> String {
        public_key_algorithm_name(self.inner.public_key_algorithm()).to_string()
    }

    #[getter]
    fn public_key_algorithm_type(&self) -> PyPublicKeyAlgorithm {
        PyPublicKeyAlgorithm {
            inner: self.inner.public_key_algorithm(),
        }
    }

    #[getter]
    fn typ(&self) -> String {
        signature_type_name(self.inner.typ())
    }

    fn matches(&self, signature: PyRef<'_, Signature>) -> bool {
        self.inner.matches(&signature.inner)
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        serialize_packet_with_header(&self.inner)
    }
}

/// An rPGP user-ID packet.
#[pyclass(module = "openpgp.packet", from_py_object)]
#[derive(Clone)]
pub(crate) struct UserId {
    inner: PgpUserId,
}

#[pymethods]
impl UserId {
    #[staticmethod]
    #[pyo3(signature = (value, packet_version=None))]
    fn from_str(value: &str, packet_version: Option<&str>) -> PyResult<Self> {
        let packet_version = match packet_version.unwrap_or("new") {
            "old" => pgp::types::PacketHeaderVersion::Old,
            "new" => pgp::types::PacketHeaderVersion::New,
            _ => return Err(to_py_err("packet_version must be 'old' or 'new'")),
        };
        Ok(Self {
            inner: PgpUserId::from_str(packet_version, value).map_err(to_py_err)?,
        })
    }

    #[getter]
    fn id(&self) -> Vec<u8> {
        self.inner.id().to_vec()
    }

    fn as_str(&self) -> Option<&str> {
        self.inner.as_str()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        serialize_packet_with_header(&self.inner)
    }
}

/// An OpenPGP packet header backed by rPGP's ``PacketHeader``.
#[pyclass(module = "openpgp.packet", from_py_object)]
#[derive(Clone)]
pub(crate) struct PacketHeader {
    inner: PgpPacketHeader,
}

#[pymethods]
impl PacketHeader {
    /// Parse one packet header from its binary representation.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = PgpPacketHeader::try_from_reader(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Return ``"old"`` or ``"new"``.
    #[getter]
    fn version(&self) -> &'static str {
        match self.inner.version() {
            pgp::types::PacketHeaderVersion::Old => "old",
            pgp::types::PacketHeaderVersion::New => "new",
        }
    }

    /// Return the numeric RFC packet tag.
    #[getter]
    fn tag(&self) -> u8 {
        self.inner.tag().into()
    }

    /// Return the rPGP-backed packet tag value.
    #[getter]
    fn tag_type(&self) -> PyTag {
        PyTag {
            inner: self.inner.tag(),
        }
    }

    /// Return ``"fixed"``, ``"partial"``, or ``"indeterminate"``.
    #[getter]
    fn length_kind(&self) -> &'static str {
        match self.inner.packet_length() {
            pgp::types::PacketLength::Fixed(_) => "fixed",
            pgp::types::PacketLength::Partial(_) => "partial",
            pgp::types::PacketLength::Indeterminate => "indeterminate",
        }
    }

    /// Return the encoded body length when the header carries one.
    #[getter]
    fn length(&self) -> Option<u32> {
        self.inner.packet_length().maybe_len()
    }

    /// Return the rPGP-backed packet-length value.
    #[getter]
    fn packet_length(&self) -> PyPacketLength {
        PyPacketLength {
            inner: self.inner.packet_length(),
        }
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "PacketHeader(version='{}', tag={}, length={:?})",
            self.version(),
            self.tag(),
            self.length()
        )
    }
}

/// A parsed OpenPGP packet backed by rPGP's packet sum type.
#[pyclass(module = "openpgp.packet", from_py_object)]
#[derive(Clone)]
pub(crate) struct Packet {
    pub(crate) inner: PgpPacket,
}

#[pymethods]
impl Packet {
    /// Parse exactly one packet.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let mut packets = PgpPacketParser::new(Cursor::new(data));
        let inner = packets
            .next()
            .ok_or_else(|| to_py_err("input contains no packet"))?
            .map_err(to_py_err)?;
        if packets.next().is_some() {
            return Err(to_py_err("input contains more than one packet"));
        }
        Ok(Self { inner })
    }

    /// Parse all packets in one byte stream.
    #[staticmethod]
    fn from_bytes_many(data: &[u8]) -> PyResult<Vec<Self>> {
        PgpPacketParser::new(Cursor::new(data))
            .map(|packet| packet.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    #[getter]
    fn kind(&self) -> &'static str {
        packet_kind(&self.inner)
    }

    #[getter]
    fn header(&self) -> PacketHeader {
        PacketHeader {
            inner: *self.inner.packet_header(),
        }
    }

    /// Return the concrete packet wrapper when one is available.
    #[getter]
    fn value(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.inner {
            PgpPacket::PublicKey(packet) => Ok(public_key_packet_object(py, packet)?.into_any()),
            PgpPacket::PublicSubkey(packet) => {
                Ok(public_subkey_packet_object(py, packet)?.into_any())
            }
            PgpPacket::SecretKey(packet) => Ok(secret_key_packet_object(py, packet)?.into_any()),
            PgpPacket::SecretSubkey(packet) => {
                Ok(secret_subkey_packet_object(py, packet)?.into_any())
            }
            PgpPacket::Signature(packet) => {
                Ok(Py::new(py, signature_packet_from_raw(packet))?.into_any())
            }
            PgpPacket::PublicKeyEncryptedSessionKey(packet) => Ok(Py::new(
                py,
                PublicKeyEncryptedSessionKey {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
            PgpPacket::SymKeyEncryptedSessionKey(packet) => Ok(Py::new(
                py,
                SymKeyEncryptedSessionKey {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
            PgpPacket::SymEncryptedData(_)
            | PgpPacket::SymEncryptedProtectedData(_)
            | PgpPacket::GnupgAeadData(_) => encrypted_data_packet_object(
                py,
                encrypted_data_packet_from_packet(self.inner.clone())?,
            ),
            PgpPacket::UserAttribute(packet) => Ok(Py::new(
                py,
                UserAttribute {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
            PgpPacket::CompressedData(packet) => Ok(Py::new(
                py,
                CompressedData {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
            PgpPacket::LiteralData(packet) => Ok(Py::new(
                py,
                LiteralData {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
            PgpPacket::Marker(packet) => Ok(Py::new(
                py,
                Marker {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
            PgpPacket::ModDetectionCode(packet) => Ok(Py::new(
                py,
                ModDetectionCode {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
            PgpPacket::OnePassSignature(packet) => Ok(Py::new(
                py,
                OnePassSignature {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
            PgpPacket::Padding(packet) => Ok(Py::new(
                py,
                Padding {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
            PgpPacket::Trust(packet) => Ok(Py::new(
                py,
                Trust {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
            PgpPacket::UserId(packet) => Ok(Py::new(
                py,
                UserId {
                    inner: packet.clone(),
                },
            )?
            .into_any()),
        }
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!("Packet(kind='{}')", self.kind())
    }
}

/// An iterator over rPGP's streaming packet parser.
#[pyclass(module = "openpgp.packet")]
pub(crate) struct PacketParser {
    packets: std::vec::IntoIter<PgpPacket>,
}

#[pymethods]
impl PacketParser {
    #[new]
    fn new(data: &[u8]) -> PyResult<Self> {
        let packets = PgpPacketParser::new(Cursor::new(data))
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_py_err)?;
        Ok(Self {
            packets: packets.into_iter(),
        })
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> Option<Packet> {
        self.packets.next().map(|inner| Packet { inner })
    }
}
