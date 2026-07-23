use crate::{
    conversions::*,
    crypto::PyHashAlgorithm,
    info::*,
    packet::key_packets::{PublicKey, PublicSubkey},
    to_py_err,
};
use pgp::{packet::Signature as PgpSignature, ser::Serialize};
use pyo3::prelude::*;

#[pyclass(module = "openpgp.packet", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct Signature {
    pub(crate) inner: PgpSignature,
}

#[pymethods]
impl Signature {
    /// Verify a data signature with a public key packet.
    fn verify(&self, key: PyRef<'_, PublicKey>, content: &[u8]) -> PyResult<()> {
        self.inner.verify(&key.inner, content).map_err(to_py_err)
    }

    /// Verify a direct-key self-signature or key-revocation signature.
    fn verify_key(&self, key: PyRef<'_, PublicKey>) -> PyResult<()> {
        self.inner.verify_key(&key.inner).map_err(to_py_err)
    }

    /// Verify a third-party direct-key or key-revocation signature.
    fn verify_key_third_party(
        &self,
        signee: PyRef<'_, PublicKey>,
        signer: PyRef<'_, PublicKey>,
    ) -> PyResult<()> {
        self.inner
            .verify_key_third_party(&signee.inner, &signer.inner)
            .map_err(to_py_err)
    }

    /// Verify a subkey-binding or subkey-revocation signature.
    fn verify_subkey_binding(
        &self,
        signer: PyRef<'_, PublicKey>,
        signee: PyRef<'_, PublicSubkey>,
    ) -> PyResult<()> {
        self.inner
            .verify_subkey_binding(&signer.inner, &signee.inner)
            .map_err(to_py_err)
    }

    /// Verify a primary-key-binding signature made by a signing subkey.
    fn verify_primary_key_binding(
        &self,
        signer: PyRef<'_, PublicSubkey>,
        signee: PyRef<'_, PublicKey>,
    ) -> PyResult<()> {
        self.inner
            .verify_primary_key_binding(&signer.inner, &signee.inner)
            .map_err(to_py_err)
    }

    fn version(&self) -> u8 {
        signature_version_number(self.inner.version())
    }

    fn typ(&self) -> Option<String> {
        self.inner
            .typ()
            .map(|typ| signature_type_name(typ).to_string())
    }

    fn hash_alg(&self) -> Option<String> {
        self.inner.hash_alg().map(normalized_algorithm_name)
    }

    /// Return the native rPGP hash algorithm enum.
    fn hash_algorithm(&self) -> Option<PyHashAlgorithm> {
        self.inner.hash_alg().map(|inner| PyHashAlgorithm { inner })
    }

    fn signed_hash_value(&self) -> Option<Vec<u8>> {
        self.inner.signed_hash_value().map(|value| value.to_vec())
    }

    fn salt(&self) -> Option<Vec<u8>> {
        signature_salt(&self.inner)
    }

    fn key_expiration_time(&self) -> Option<u32> {
        self.inner
            .key_expiration_time()
            .map(|duration| duration.as_secs())
    }

    fn signature_expiration_time(&self) -> Option<u32> {
        self.inner
            .signature_expiration_time()
            .map(|duration| duration.as_secs())
    }

    fn created(&self) -> Option<u32> {
        self.inner.created().map(|timestamp| timestamp.as_secs())
    }

    fn issuer_key_id(&self) -> Vec<String> {
        self.inner
            .issuer_key_id()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn issuer_fingerprint(&self) -> Vec<String> {
        self.inner
            .issuer_fingerprint()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn preferred_symmetric_algs(&self) -> Vec<String> {
        symmetric_algorithm_names(self.inner.preferred_symmetric_algs())
    }

    fn preferred_aead_algs(&self) -> Vec<(String, String)> {
        aead_algorithm_preference_names(self.inner.preferred_aead_algs())
    }

    fn preferred_hash_algs(&self) -> Vec<String> {
        hash_algorithm_names(self.inner.preferred_hash_algs())
    }

    fn preferred_compression_algs(&self) -> Vec<String> {
        compression_algorithm_names(self.inner.preferred_compression_algs())
    }

    fn key_flags(&self) -> KeyFlags {
        key_flags_from_key_flags(&self.inner.key_flags())
    }

    fn features(&self) -> Option<Features> {
        self.inner.features().map(features_from_features)
    }

    fn embedded_signature(&self) -> Option<Signature> {
        self.inner
            .embedded_signature()
            .map(signature_packet_from_raw)
    }

    fn preferred_key_server(&self) -> Option<String> {
        self.inner.preferred_key_server().map(str::to_owned)
    }

    fn notations(&self) -> Vec<Notation> {
        self.inner
            .notations()
            .into_iter()
            .map(notation_from_notation)
            .collect()
    }

    fn revocation_key(&self) -> Option<RevocationKey> {
        self.inner
            .revocation_key()
            .map(revocation_key_from_revocation_key)
    }

    fn signers_userid(&self) -> Option<String> {
        self.inner
            .signers_userid()
            .map(|user_id| String::from_utf8_lossy(user_id.as_ref()).into_owned())
    }

    fn policy_uri(&self) -> Option<String> {
        self.inner.policy_uri().map(str::to_owned)
    }

    fn is_revocable(&self) -> bool {
        self.inner.is_revocable()
    }

    fn exportable_certification(&self) -> bool {
        self.inner.exportable_certification()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "Signature(version={}, type={:?})",
            self.version(),
            self.typ()
        )
    }
}

pub(crate) fn signature_packet_from_raw(signature: &PgpSignature) -> Signature {
    Signature {
        inner: signature.clone(),
    }
}
