use crate::conversions::*;
use crate::info::*;
use crate::key_params::*;
use crate::serialization::*;
use crate::*;
use std::path::PathBuf;

/// A transferable OpenPGP public key (certificate) as defined by RFC 9580.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct PublicKey {
    pub(crate) inner: SignedPublicKey,
}

#[pymethods]
impl PublicKey {
    /// Parse an ASCII-armored transferable public key.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedPublicKey::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse multiple ASCII-armored transferable public keys from one armored input.
    #[staticmethod]
    fn from_armor_many(data: &str) -> PyResult<(Vec<Self>, Headers)> {
        let (iter, headers) = SignedPublicKey::from_string_many(data).map_err(to_py_err)?;
        let keys = iter
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((keys, headers))
    }

    /// Parse a binary transferable public key.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = SignedPublicKey::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse multiple binary transferable public keys from concatenated packet bytes.
    #[staticmethod]
    fn from_bytes_many(data: &[u8]) -> PyResult<Vec<Self>> {
        SignedPublicKey::from_bytes_many(Cursor::new(data))
            .map_err(to_py_err)?
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    /// Parse a single binary transferable public key from a file.
    #[staticmethod]
    fn from_file(path: PathBuf) -> PyResult<Self> {
        let inner = SignedPublicKey::from_file(&path).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse multiple binary transferable public keys from a file of concatenated packet bytes.
    #[staticmethod]
    fn from_file_many(path: PathBuf) -> PyResult<Vec<Self>> {
        SignedPublicKey::from_file_many(&path)
            .map_err(to_py_err)?
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    /// Parse a single ASCII-armored transferable public key from a file.
    #[staticmethod]
    fn from_armor_file(path: PathBuf) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedPublicKey::from_armor_file(&path).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse multiple ASCII-armored transferable public keys from one armored file.
    #[staticmethod]
    fn from_armor_file_many(path: PathBuf) -> PyResult<(Vec<Self>, Headers)> {
        let (iter, headers) = SignedPublicKey::from_armor_file_many(&path).map_err(to_py_err)?;
        let keys = iter
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((keys, headers))
    }

    /// The RFC 9580 fingerprint of the primary key.
    #[getter]
    fn fingerprint(&self) -> String {
        self.inner.fingerprint().to_string()
    }

    /// The legacy key identifier of the primary key.
    #[getter]
    fn key_id(&self) -> String {
        self.inner.legacy_key_id().to_string()
    }

    /// The OpenPGP key-packet version number of the primary key.
    #[getter]
    fn version(&self) -> u8 {
        key_version_number(self.inner.primary_key.version())
    }

    /// The primary key packet's creation time as seconds since the Unix epoch.
    #[getter]
    fn created_at(&self) -> u32 {
        self.inner.primary_key.created_at().as_secs()
    }

    /// The primary key packet's public-key algorithm.
    #[getter]
    fn public_key_algorithm(&self) -> String {
        public_key_algorithm_name(self.inner.primary_key.algorithm()).to_string()
    }

    /// Structured algorithm-specific public-key metadata from `KeyDetails.public_params()`.
    #[getter]
    fn public_params(&self) -> PublicParamsInfo {
        public_params_info_from_params(self.inner.primary_key.public_params())
    }

    /// The RFC 9580 packet-header framing used by the primary key packet.
    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.inner.primary_key.packet_header_version(),
        }
    }

    /// The number of public subkeys attached to the certificate.
    #[getter]
    fn public_subkey_count(&self) -> usize {
        self.inner.public_subkeys.len()
    }

    /// UTF-8 decoded user IDs, with invalid octets replaced lossily.
    #[getter]
    fn user_ids(&self) -> Vec<String> {
        lossy_user_ids(&self.inner.details)
    }

    /// Return direct-key self-signature metadata attached to the certificate.
    ///
    /// RFC 9580 version-6 certificates place certificate-wide preferences, key flags, and
    /// feature advertisements on these direct-key signatures.
    fn direct_signature_infos(&self) -> Vec<SignatureInfo> {
        direct_signature_infos_from_details(&self.inner.details)
    }

    /// Return key-revocation signatures attached directly to the certificate.
    ///
    /// These signatures are separate from direct-key signatures and from user or subkey bindings.
    fn revocation_signature_infos(&self) -> Vec<SignatureInfo> {
        revocation_signature_infos_from_details(&self.inner.details)
    }

    /// Return user IDs together with their certification self-signatures.
    ///
    /// Version-4 certificates carry certificate metadata such as key flags and preferred
    /// algorithms on the primary user-ID binding signature.
    fn user_bindings(&self) -> Vec<UserBindingInfo> {
        user_binding_infos_from_details(&self.inner.details)
    }

    /// Return user attributes together with their certification self-signatures.
    fn user_attribute_bindings(&self) -> Vec<UserAttributeBindingInfo> {
        user_attribute_binding_infos_from_details(&self.inner.details)
    }

    /// Return public subkeys together with their binding-signature metadata.
    fn subkey_bindings(&self) -> Vec<SubkeyBindingInfo> {
        self.inner
            .public_subkeys
            .iter()
            .map(subkey_binding_info_from_signed_public_subkey)
            .collect::<Vec<_>>()
    }

    /// Verify the certificate's self-signatures and subkey binding signatures.
    fn verify_bindings(&self) -> PyResult<()> {
        self.inner.verify_bindings().map_err(to_py_err)
    }

    /// Serialize the transferable public key to binary packet bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Serialize the transferable public key as ASCII armor.
    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "PublicKey(fingerprint='{}', key_id='{}')",
            self.fingerprint(),
            self.key_id()
        )
    }
}

/// A transferable OpenPGP secret key, including any secret subkeys.
#[pyclass(module = "openpgp", from_py_object)]
#[derive(Clone)]
pub(crate) struct SecretKey {
    pub(crate) inner: SignedSecretKey,
}

#[pymethods]
impl SecretKey {
    /// Parse an ASCII-armored transferable secret key.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedSecretKey::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse multiple ASCII-armored transferable secret keys from one armored input.
    #[staticmethod]
    fn from_armor_many(data: &str) -> PyResult<(Vec<Self>, Headers)> {
        let (iter, headers) = SignedSecretKey::from_string_many(data).map_err(to_py_err)?;
        let keys = iter
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((keys, headers))
    }

    /// Parse a binary transferable secret key.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = SignedSecretKey::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse multiple binary transferable secret keys from concatenated packet bytes.
    #[staticmethod]
    fn from_bytes_many(data: &[u8]) -> PyResult<Vec<Self>> {
        SignedSecretKey::from_bytes_many(Cursor::new(data))
            .map_err(to_py_err)?
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    /// Parse a single binary transferable secret key from a file.
    #[staticmethod]
    fn from_file(path: PathBuf) -> PyResult<Self> {
        let inner = SignedSecretKey::from_file(&path).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Parse multiple binary transferable secret keys from a file of concatenated packet bytes.
    #[staticmethod]
    fn from_file_many(path: PathBuf) -> PyResult<Vec<Self>> {
        SignedSecretKey::from_file_many(&path)
            .map_err(to_py_err)?
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect()
    }

    /// Parse a single ASCII-armored transferable secret key from a file.
    #[staticmethod]
    fn from_armor_file(path: PathBuf) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedSecretKey::from_armor_file(&path).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse multiple ASCII-armored transferable secret keys from one armored file.
    #[staticmethod]
    fn from_armor_file_many(path: PathBuf) -> PyResult<(Vec<Self>, Headers)> {
        let (iter, headers) = SignedSecretKey::from_armor_file_many(&path).map_err(to_py_err)?;
        let keys = iter
            .map(|inner| inner.map(|inner| Self { inner }).map_err(to_py_err))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((keys, headers))
    }

    /// The RFC 9580 fingerprint of the primary key.
    #[getter]
    fn fingerprint(&self) -> String {
        self.inner
            .primary_key
            .public_key()
            .fingerprint()
            .to_string()
    }

    /// The legacy key identifier of the primary key.
    #[getter]
    fn key_id(&self) -> String {
        self.inner
            .primary_key
            .public_key()
            .legacy_key_id()
            .to_string()
    }

    /// The OpenPGP key-packet version number of the primary key.
    #[getter]
    fn version(&self) -> u8 {
        key_version_number(self.inner.primary_key.version())
    }

    /// The primary key packet's creation time as seconds since the Unix epoch.
    #[getter]
    fn created_at(&self) -> u32 {
        self.inner.primary_key.created_at().as_secs()
    }

    /// The primary key packet's public-key algorithm.
    #[getter]
    fn public_key_algorithm(&self) -> String {
        public_key_algorithm_name(self.inner.primary_key.algorithm()).to_string()
    }

    /// Structured algorithm-specific public-key metadata from `KeyDetails.public_params()`.
    #[getter]
    fn public_params(&self) -> PublicParamsInfo {
        public_params_info_from_params(self.inner.primary_key.public_params())
    }

    /// The RFC 9580 packet-header framing used by the primary secret-key packet.
    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.inner.primary_key.packet_header_version(),
        }
    }

    /// The number of public subkeys attached to the secret key.
    #[getter]
    fn public_subkey_count(&self) -> usize {
        self.inner.public_subkeys.len()
    }

    /// The number of secret subkeys attached to the secret key.
    #[getter]
    fn secret_subkey_count(&self) -> usize {
        self.inner.secret_subkeys.len()
    }

    /// UTF-8 decoded user IDs, with invalid octets replaced lossily.
    #[getter]
    fn user_ids(&self) -> Vec<String> {
        lossy_user_ids(&self.inner.details)
    }

    /// Return direct-key self-signature metadata attached to the secret certificate.
    ///
    /// RFC 9580 version-6 certificates place certificate-wide preferences, key flags, and
    /// feature advertisements on these direct-key signatures.
    fn direct_signature_infos(&self) -> Vec<SignatureInfo> {
        direct_signature_infos_from_details(&self.inner.details)
    }

    /// Return key-revocation signatures attached directly to the secret certificate.
    ///
    /// These signatures are separate from direct-key signatures and from user or subkey bindings.
    fn revocation_signature_infos(&self) -> Vec<SignatureInfo> {
        revocation_signature_infos_from_details(&self.inner.details)
    }

    /// Return user IDs together with their certification self-signatures.
    ///
    /// Version-4 certificates carry certificate metadata such as key flags and preferred
    /// algorithms on the primary user-ID binding signature.
    fn user_bindings(&self) -> Vec<UserBindingInfo> {
        user_binding_infos_from_details(&self.inner.details)
    }

    /// Return user attributes together with their certification self-signatures.
    fn user_attribute_bindings(&self) -> Vec<UserAttributeBindingInfo> {
        user_attribute_binding_infos_from_details(&self.inner.details)
    }

    /// Return secret subkeys together with their binding-signature metadata.
    fn subkey_bindings(&self) -> Vec<SubkeyBindingInfo> {
        self.inner
            .secret_subkeys
            .iter()
            .map(subkey_binding_info_from_signed_secret_subkey)
            .collect::<Vec<_>>()
    }

    /// Return the primary secret key packet's RFC 9580 S2K protection parameters.
    ///
    /// Unprotected keys return an ``S2kParams`` instance with usage ``"unprotected"``.
    fn primary_secret_s2k(&self) -> PyS2kParams {
        s2k_params_from_secret_params(self.inner.primary_key.secret_params())
    }

    /// Return RFC 9580 S2K protection parameters for each secret subkey packet.
    fn secret_subkey_s2ks(&self) -> Vec<PyS2kParams> {
        self.inner
            .secret_subkeys
            .iter()
            .map(|subkey| s2k_params_from_secret_params(subkey.key.secret_params()))
            .collect()
    }

    /// Verify the secret key's self-signatures and subkey binding signatures.
    fn verify_bindings(&self) -> PyResult<()> {
        self.inner.verify_bindings().map_err(to_py_err)
    }

    /// Drop the secret key material and return the corresponding public certificate.
    fn to_public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.to_public_key(),
        }
    }

    /// Serialize the transferable secret key to binary packet bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Serialize the transferable secret key as ASCII armor.
    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "SecretKey(fingerprint='{}', key_id='{}')",
            self.fingerprint(),
            self.key_id()
        )
    }
}
