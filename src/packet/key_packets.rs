use crate::{
    conversions::key_version_number,
    info::public_key_algorithm_name,
    serialization::s2k_params_from_secret_params,
    types::{PyPacketHeaderVersion, PyS2kParams, public_params::public_params_object},
};
use pgp::{
    packet::{
        PacketTrait, PublicKey as PgpPublicKey, PublicSubkey as PgpPublicSubkey,
        SecretKey as PgpSecretKey, SecretSubkey as PgpSecretSubkey,
    },
    types::{
        KeyDetails as PgpKeyDetails, PacketHeaderVersion as PgpPacketHeaderVersion,
        PublicParams as PgpPublicParams,
    },
};
use pyo3::prelude::*;

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

#[pyclass(module = "openpgp.packet", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PublicKey {
    data: KeyPacketData,
}

#[pyclass(module = "openpgp.packet", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PublicSubkey {
    data: KeyPacketData,
}

#[pyclass(module = "openpgp.packet", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SecretKey {
    data: KeyPacketData,
    secret_s2k: PyS2kParams,
}

#[pyclass(module = "openpgp.packet", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SecretSubkey {
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

key_packet_methods!(PublicKey, "PublicKey");
key_packet_methods!(PublicSubkey, "PublicSubkey");
secret_key_packet_methods!(SecretKey, "SecretKey");
secret_key_packet_methods!(SecretSubkey, "SecretSubkey");

impl PublicSubkey {
    pub(crate) fn fingerprint_value(&self) -> String {
        self.data.fingerprint.clone()
    }
}

impl SecretSubkey {
    pub(crate) fn fingerprint_value(&self) -> String {
        self.data.fingerprint.clone()
    }
}

pub(crate) fn public_key_packet_object(
    py: Python<'_>,
    key: &PgpPublicKey,
) -> PyResult<Py<PublicKey>> {
    Py::new(
        py,
        PublicKey {
            data: key_packet_data_from_details(key, key.packet_header_version()),
        },
    )
}

pub(crate) fn public_subkey_packet_object(
    py: Python<'_>,
    key: &PgpPublicSubkey,
) -> PyResult<Py<PublicSubkey>> {
    Py::new(
        py,
        PublicSubkey {
            data: key_packet_data_from_details(key, key.packet_header_version()),
        },
    )
}

pub(crate) fn secret_key_packet_object(
    py: Python<'_>,
    key: &PgpSecretKey,
) -> PyResult<Py<SecretKey>> {
    Py::new(
        py,
        SecretKey {
            data: key_packet_data_from_details(key, key.packet_header_version()),
            secret_s2k: s2k_params_from_secret_params(key.secret_params()),
        },
    )
}

pub(crate) fn secret_subkey_packet_object(
    py: Python<'_>,
    key: &PgpSecretSubkey,
) -> PyResult<Py<SecretSubkey>> {
    Py::new(
        py,
        SecretSubkey {
            data: key_packet_data_from_details(key, key.packet_header_version()),
            secret_s2k: s2k_params_from_secret_params(key.secret_params()),
        },
    )
}
