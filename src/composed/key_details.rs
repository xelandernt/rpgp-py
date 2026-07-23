use crate::{
    info::{UserAttribute, user_attribute_kind_name},
    packet::{
        PublicSubkey, SecretSubkey, Signature, key_packets::public_subkey_packet_object,
        key_packets::secret_subkey_packet_object, signatures::signature_packet_from_raw,
    },
};
use pgp::{
    composed::{
        SignedKeyDetails as PgpSignedKeyDetails, SignedPublicSubKey as PgpSignedPublicSubKey,
        SignedSecretSubKey as PgpSignedSecretSubKey,
    },
    types::{SignedUser as PgpSignedUser, SignedUserAttribute as PgpSignedUserAttribute},
};
use pyo3::prelude::*;

#[pyclass(module = "openpgp.types", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SignedUser {
    id: String,
    signatures: Vec<Signature>,
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
    fn signatures(&self) -> Vec<Signature> {
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

#[pyclass(module = "openpgp.types", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SignedUserAttribute {
    attr: UserAttribute,
    signatures: Vec<Signature>,
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
    fn signatures(&self) -> Vec<Signature> {
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

#[pyclass(module = "openpgp.composed", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct SignedKeyDetails {
    revocation_signatures: Vec<Signature>,
    direct_signatures: Vec<Signature>,
    users: Vec<SignedUser>,
    user_attributes: Vec<SignedUserAttribute>,
}

#[pymethods]
impl SignedKeyDetails {
    #[getter]
    fn revocation_signatures(&self) -> Vec<Signature> {
        self.revocation_signatures.clone()
    }

    #[getter]
    fn direct_signatures(&self) -> Vec<Signature> {
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

#[pyclass(module = "openpgp.composed")]
pub(crate) struct SignedPublicSubKey {
    pub(crate) inner: PgpSignedPublicSubKey,
    key: Py<PublicSubkey>,
    signatures: Vec<Signature>,
}

#[pymethods]
impl SignedPublicSubKey {
    #[getter]
    fn key(&self, py: Python<'_>) -> Py<PublicSubkey> {
        self.key.clone_ref(py)
    }

    #[getter]
    fn signatures(&self) -> Vec<Signature> {
        self.signatures.clone()
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let key = self.key.bind(py).borrow();
        Ok(format!(
            "SignedPublicSubKey(fingerprint='{}', signature_count={})",
            key.fingerprint_value(),
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

#[pyclass(module = "openpgp.composed")]
pub(crate) struct SignedSecretSubKey {
    pub(crate) inner: PgpSignedSecretSubKey,
    key: Py<SecretSubkey>,
    public_key: Py<PublicSubkey>,
    signatures: Vec<Signature>,
}

#[pymethods]
impl SignedSecretSubKey {
    #[getter]
    fn key(&self, py: Python<'_>) -> Py<SecretSubkey> {
        self.key.clone_ref(py)
    }

    #[getter]
    fn signatures(&self) -> Vec<Signature> {
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
            key.fingerprint_value(),
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
