use crate::conversions::*;
use crate::info::*;
use crate::keys::*;
use crate::messages::*;
use crate::packets::*;
use crate::serialization::*;
use crate::*;

macro_rules! encrypt_to_recipient {
    ($builder:expr, $recipient:expr, $anonymous_recipient:expr) => {{
        let recipient = $recipient;
        if let Some(subkey) = recipient
            .public_subkeys
            .iter()
            .find(|subkey| subkey.algorithm().can_encrypt())
        {
            if $anonymous_recipient {
                $builder
                    .encrypt_to_key_anonymous(rand::thread_rng(), subkey)
                    .map_err(to_py_err)?;
            } else {
                $builder
                    .encrypt_to_key(rand::thread_rng(), subkey)
                    .map_err(to_py_err)?;
            }
        } else if recipient.algorithm().can_encrypt() {
            if $anonymous_recipient {
                $builder
                    .encrypt_to_key_anonymous(rand::thread_rng(), recipient)
                    .map_err(to_py_err)?;
            } else {
                $builder
                    .encrypt_to_key(rand::thread_rng(), recipient)
                    .map_err(to_py_err)?;
            }
        } else {
            return Err(to_py_err(
                "public key does not contain an encryption-capable primary key or subkey",
            ));
        }
    }};
}

macro_rules! configure_message_builder {
    ($builder:expr, $compression:expr, $session_key:expr, $symmetric_algorithm:expr) => {{
        if let Some(compression) = $compression {
            $builder.compression(compression);
        }
        if let Some(session_key) = $session_key {
            $builder
                .set_session_key(raw_session_key_from_bytes(
                    session_key,
                    $symmetric_algorithm,
                )?)
                .map_err(to_py_err)?;
        }
    }};
}

fn signer_entries_from_python(
    py: Python<'_>,
    signers: Vec<Py<SecretKey>>,
    passwords: Option<Vec<Option<String>>>,
) -> PyResult<(Vec<SignedSecretKey>, Vec<Password>)> {
    if signers.is_empty() {
        return Err(to_py_err("at least one signer is required"));
    }

    let passwords = passwords.unwrap_or_else(|| vec![None; signers.len()]);
    if passwords.len() != signers.len() {
        return Err(to_py_err("password count must match signer count"));
    }

    let signers = signers
        .into_iter()
        .map(|signer| signer.borrow(py).inner.clone())
        .collect::<Vec<_>>();
    let passwords = passwords
        .into_iter()
        .map(|password| password_from_option(password.as_deref()))
        .collect::<Vec<_>>();
    Ok((signers, passwords))
}

fn recipients_from_python(
    py: Python<'_>,
    recipients: Vec<Py<PublicKey>>,
) -> PyResult<Vec<SignedPublicKey>> {
    if recipients.is_empty() {
        return Err(to_py_err("at least one recipient is required"));
    }

    Ok(recipients
        .into_iter()
        .map(|recipient| recipient.borrow(py).inner.clone())
        .collect())
}

fn sign_message_with_signers(
    data: &[u8],
    signers: &[SignedSecretKey],
    passwords: Vec<Password>,
    file_name: &str,
    hash_algorithm: HashAlgorithm,
) -> PyResult<String> {
    let mut builder =
        MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()));
    for (signer, password) in signers.iter().zip(passwords) {
        builder.sign(&signer.primary_key, password, hash_algorithm);
    }
    builder
        .to_armored_string(&mut rand::thread_rng(), ArmorOptions::default())
        .map_err(to_py_err)
}

fn sign_cleartext_with_signers(
    text: &str,
    signers: &[SignedSecretKey],
    passwords: Vec<Password>,
    hash_algorithm: HashAlgorithm,
) -> PyResult<String> {
    let signers = signers.iter().cloned().zip(passwords).collect::<Vec<_>>();
    let message = cleartext_signed_message_from_signers(text, &signers, hash_algorithm)?;
    message
        .to_armored_string(ArmorOptions::default())
        .map_err(to_py_err)
}

fn anonymize_public_key_encrypted_session_key(
    mut packet: PgpPublicKeyEncryptedSessionKey,
) -> PgpPublicKeyEncryptedSessionKey {
    match &mut packet {
        PgpPublicKeyEncryptedSessionKey::V3 { id, .. } => *id = KeyId::WILDCARD,
        PgpPublicKeyEncryptedSessionKey::V6 { fingerprint, .. } => *fingerprint = None,
        PgpPublicKeyEncryptedSessionKey::Other { .. } => {}
    }
    packet
}

/// Inspect an ASCII-armored or binary OpenPGP message without exposing its payload.
#[pyfunction]
pub(crate) fn inspect_message(data: &str) -> PyResult<MessageInfo> {
    parse_message_info_from_reader(Cursor::new(data.as_bytes())).map_err(to_py_err)
}

/// Inspect a binary OpenPGP message without exposing its payload.
#[pyfunction]
pub(crate) fn inspect_message_bytes(data: &[u8]) -> PyResult<MessageInfo> {
    parse_message_info_from_reader(Cursor::new(data)).map_err(to_py_err)
}

/// Create a binary signed message and return it as ASCII armor.
///
/// ``hash_algorithm`` controls the digest used for the signature packet.
#[pyfunction]
#[pyo3(signature = (data, signer, password=None, file_name="", hash_algorithm="sha256"))]
pub(crate) fn sign_message(
    data: &[u8],
    signer: PyRef<'_, SecretKey>,
    password: Option<&str>,
    file_name: &str,
    hash_algorithm: &str,
) -> PyResult<String> {
    let password = password_from_option(password);
    let hash_algorithm = hash_algorithm_from_name(hash_algorithm)?;
    sign_message_with_signers(
        data,
        &[signer.inner.clone()],
        vec![password],
        file_name,
        hash_algorithm,
    )
}

/// Create a multi-signed binary message and return it as ASCII armor.
///
/// ``signers`` must contain at least one secret key. When ``passwords`` is provided, it must have
/// the same length as ``signers`` and each entry unlocks the corresponding key.
#[pyfunction]
#[pyo3(signature = (data, signers, passwords=None, file_name="", hash_algorithm="sha256"))]
pub(crate) fn sign_message_many(
    py: Python<'_>,
    data: &[u8],
    signers: Vec<Py<SecretKey>>,
    passwords: Option<Vec<Option<String>>>,
    file_name: &str,
    hash_algorithm: &str,
) -> PyResult<String> {
    let hash_algorithm = hash_algorithm_from_name(hash_algorithm)?;
    let (signers, passwords) = signer_entries_from_python(py, signers, passwords)?;
    sign_message_with_signers(data, &signers, passwords, file_name, hash_algorithm)
}

/// Create a cleartext signed message and return it as ASCII armor.
///
/// ``hash_algorithm`` controls the digest used for every signature packet.
#[pyfunction]
#[pyo3(signature = (text, signer, password=None, hash_algorithm="sha256"))]
pub(crate) fn sign_cleartext_message(
    text: &str,
    signer: PyRef<'_, SecretKey>,
    password: Option<&str>,
    hash_algorithm: &str,
) -> PyResult<String> {
    let password = password_from_option(password);
    let hash_algorithm = hash_algorithm_from_name(hash_algorithm)?;
    sign_cleartext_with_signers(
        text,
        &[signer.inner.clone()],
        vec![password],
        hash_algorithm,
    )
}

/// Create a multi-signed cleartext signed message and return it as ASCII armor.
///
/// ``signers`` must contain at least one secret key. When ``passwords`` is provided, it must have
/// the same length as ``signers`` and each entry unlocks the corresponding key.
#[pyfunction]
#[pyo3(signature = (text, signers, passwords=None, hash_algorithm="sha256"))]
pub(crate) fn sign_cleartext_message_many(
    py: Python<'_>,
    text: &str,
    signers: Vec<Py<SecretKey>>,
    passwords: Option<Vec<Option<String>>>,
    hash_algorithm: &str,
) -> PyResult<String> {
    let hash_algorithm = hash_algorithm_from_name(hash_algorithm)?;
    let (signers, passwords) = signer_entries_from_python(py, signers, passwords)?;
    sign_cleartext_with_signers(text, &signers, passwords, hash_algorithm)
}

pub(crate) fn encrypt_session_key_to_recipient_inner(
    session_key: &[u8],
    recipient: &SignedPublicKey,
    version: EncryptionVersion,
    symmetric_algorithm: SymmetricKeyAlgorithm,
    anonymous_recipient: bool,
) -> PyResult<PgpPublicKeyEncryptedSessionKey> {
    let session_key = raw_session_key_from_bytes(session_key, symmetric_algorithm)?;
    let packet = if let Some(subkey) = recipient
        .public_subkeys
        .iter()
        .find(|subkey| subkey.algorithm().can_encrypt())
    {
        match version {
            EncryptionVersion::SeipdV1 => PgpPublicKeyEncryptedSessionKey::from_session_key_v3(
                rand::thread_rng(),
                &session_key,
                symmetric_algorithm,
                subkey,
            )
            .map_err(to_py_err),
            EncryptionVersion::SeipdV2 => PgpPublicKeyEncryptedSessionKey::from_session_key_v6(
                rand::thread_rng(),
                &session_key,
                subkey,
            )
            .map_err(to_py_err),
        }
    } else if recipient.algorithm().can_encrypt() {
        match version {
            EncryptionVersion::SeipdV1 => PgpPublicKeyEncryptedSessionKey::from_session_key_v3(
                rand::thread_rng(),
                &session_key,
                symmetric_algorithm,
                recipient,
            )
            .map_err(to_py_err),
            EncryptionVersion::SeipdV2 => PgpPublicKeyEncryptedSessionKey::from_session_key_v6(
                rand::thread_rng(),
                &session_key,
                recipient,
            )
            .map_err(to_py_err),
        }
    } else {
        return Err(to_py_err(
            "public key does not contain an encryption-capable primary key or subkey",
        ));
    }?;

    if anonymous_recipient {
        Ok(anonymize_public_key_encrypted_session_key(packet))
    } else {
        Ok(packet)
    }
}

pub(crate) fn encrypt_session_key_with_password_inner(
    session_key: &[u8],
    password: &str,
    version: EncryptionVersion,
    symmetric_algorithm: SymmetricKeyAlgorithm,
    aead_algorithm: AeadAlgorithm,
) -> PyResult<PgpSymKeyEncryptedSessionKey> {
    let session_key = raw_session_key_from_bytes(session_key, symmetric_algorithm)?;
    let password = Password::from(password);
    match version {
        EncryptionVersion::SeipdV1 => PgpSymKeyEncryptedSessionKey::encrypt_v4(
            &password,
            &session_key,
            PgpStringToKey::new_default(rand::thread_rng()),
            symmetric_algorithm,
        )
        .map_err(to_py_err),
        EncryptionVersion::SeipdV2 => PgpSymKeyEncryptedSessionKey::encrypt_v6(
            rand::thread_rng(),
            &password,
            &session_key,
            PgpStringToKey::new_default(rand::thread_rng()),
            symmetric_algorithm,
            aead_algorithm,
        )
        .map_err(to_py_err),
    }
}

/// Encrypt a raw session key to a public-key recipient and expose the PKESK packet.
#[pyfunction]
#[pyo3(signature = (
    session_key,
    recipient,
    version="seipd-v2",
    symmetric_algorithm="aes256",
    anonymous_recipient=false,
))]
pub(crate) fn encrypt_session_key_to_recipient(
    session_key: &[u8],
    recipient: PyRef<'_, PublicKey>,
    version: &str,
    symmetric_algorithm: &str,
    anonymous_recipient: bool,
) -> PyResult<PublicKeyEncryptedSessionKeyPacket> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let inner = encrypt_session_key_to_recipient_inner(
        session_key,
        &recipient.inner,
        version,
        symmetric_algorithm,
        anonymous_recipient,
    )?;
    Ok(PublicKeyEncryptedSessionKeyPacket { inner })
}

/// Encrypt a raw session key to a password and expose the SKESK packet.
#[pyfunction]
#[pyo3(signature = (
    session_key,
    password,
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
))]
pub(crate) fn encrypt_session_key_with_password(
    session_key: &[u8],
    password: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
) -> PyResult<SymKeyEncryptedSessionKeyPacket> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let inner = encrypt_session_key_with_password_inner(
        session_key,
        password,
        version,
        symmetric_algorithm,
        aead_algorithm,
    )?;
    Ok(SymKeyEncryptedSessionKeyPacket { inner })
}

/// Encrypt a message to a public-key recipient and return the result as binary packets.
#[pyfunction]
#[pyo3(signature = (
    data,
    recipient,
    file_name="",
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
    compression=None,
    session_key=None,
    anonymous_recipient=false,
))]
pub(crate) fn encrypt_message_to_recipient_bytes(
    data: &[u8],
    recipient: PyRef<'_, PublicKey>,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
    session_key: Option<&[u8]>,
    anonymous_recipient: bool,
) -> PyResult<Vec<u8>> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let compression = compression_algorithm_from_name(compression)?;

    match version {
        EncryptionVersion::SeipdV1 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            encrypt_to_recipient!(builder, &recipient.inner, anonymous_recipient);
            builder.to_vec(rand::thread_rng()).map_err(to_py_err)
        }
        EncryptionVersion::SeipdV2 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v2(
                        rand::thread_rng(),
                        symmetric_algorithm,
                        aead_algorithm,
                        ChunkSize::default(),
                    );
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            encrypt_to_recipient!(builder, &recipient.inner, anonymous_recipient);
            builder.to_vec(rand::thread_rng()).map_err(to_py_err)
        }
    }
}

/// Encrypt a message to a public-key recipient and return the result as ASCII armor.
#[pyfunction]
#[pyo3(signature = (
    data,
    recipient,
    file_name="",
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
    compression=None,
    session_key=None,
    anonymous_recipient=false,
))]
pub(crate) fn encrypt_message_to_recipient(
    data: &[u8],
    recipient: PyRef<'_, PublicKey>,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
    session_key: Option<&[u8]>,
    anonymous_recipient: bool,
) -> PyResult<String> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let compression = compression_algorithm_from_name(compression)?;

    match version {
        EncryptionVersion::SeipdV1 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            encrypt_to_recipient!(builder, &recipient.inner, anonymous_recipient);
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
        }
        EncryptionVersion::SeipdV2 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v2(
                        rand::thread_rng(),
                        symmetric_algorithm,
                        aead_algorithm,
                        ChunkSize::default(),
                    );
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            encrypt_to_recipient!(builder, &recipient.inner, anonymous_recipient);
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
        }
    }
}

/// Encrypt a message to one or more public-key recipients and return the result as binary packets.
///
/// ``recipients`` must contain at least one public key. When ``anonymous_recipient`` is true, the
/// generated PKESK packets omit recipient identifiers for every recipient.
#[pyfunction]
#[pyo3(signature = (
    data,
    recipients,
    file_name="",
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
    compression=None,
    session_key=None,
    anonymous_recipient=false,
))]
pub(crate) fn encrypt_message_to_recipients_bytes(
    py: Python<'_>,
    data: &[u8],
    recipients: Vec<Py<PublicKey>>,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
    session_key: Option<&[u8]>,
    anonymous_recipient: bool,
) -> PyResult<Vec<u8>> {
    let recipients = recipients_from_python(py, recipients)?;
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let compression = compression_algorithm_from_name(compression)?;

    match version {
        EncryptionVersion::SeipdV1 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            for recipient in &recipients {
                encrypt_to_recipient!(builder, recipient, anonymous_recipient);
            }
            builder.to_vec(rand::thread_rng()).map_err(to_py_err)
        }
        EncryptionVersion::SeipdV2 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v2(
                        rand::thread_rng(),
                        symmetric_algorithm,
                        aead_algorithm,
                        ChunkSize::default(),
                    );
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            for recipient in &recipients {
                encrypt_to_recipient!(builder, recipient, anonymous_recipient);
            }
            builder.to_vec(rand::thread_rng()).map_err(to_py_err)
        }
    }
}

/// Encrypt a message to one or more public-key recipients and return the result as ASCII armor.
///
/// ``recipients`` must contain at least one public key. When ``anonymous_recipient`` is true, the
/// generated PKESK packets omit recipient identifiers for every recipient.
#[pyfunction]
#[pyo3(signature = (
    data,
    recipients,
    file_name="",
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
    compression=None,
    session_key=None,
    anonymous_recipient=false,
))]
pub(crate) fn encrypt_message_to_recipients(
    py: Python<'_>,
    data: &[u8],
    recipients: Vec<Py<PublicKey>>,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
    session_key: Option<&[u8]>,
    anonymous_recipient: bool,
) -> PyResult<String> {
    let recipients = recipients_from_python(py, recipients)?;
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let compression = compression_algorithm_from_name(compression)?;

    match version {
        EncryptionVersion::SeipdV1 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            for recipient in &recipients {
                encrypt_to_recipient!(builder, recipient, anonymous_recipient);
            }
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
        }
        EncryptionVersion::SeipdV2 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v2(
                        rand::thread_rng(),
                        symmetric_algorithm,
                        aead_algorithm,
                        ChunkSize::default(),
                    );
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            for recipient in &recipients {
                encrypt_to_recipient!(builder, recipient, anonymous_recipient);
            }
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
        }
    }
}

/// Encrypt a message with a password and return the result as binary packets.
#[pyfunction]
#[pyo3(signature = (
    data,
    password,
    file_name="",
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
    compression=None,
    session_key=None,
))]
pub(crate) fn encrypt_message_with_password_bytes(
    data: &[u8],
    password: &str,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
    session_key: Option<&[u8]>,
) -> PyResult<Vec<u8>> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let compression = compression_algorithm_from_name(compression)?;
    let password = Password::from(password);

    match version {
        EncryptionVersion::SeipdV1 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            builder
                .encrypt_with_password(PgpStringToKey::new_default(rand::thread_rng()), &password)
                .map_err(to_py_err)?;
            builder.to_vec(rand::thread_rng()).map_err(to_py_err)
        }
        EncryptionVersion::SeipdV2 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v2(
                        rand::thread_rng(),
                        symmetric_algorithm,
                        aead_algorithm,
                        ChunkSize::default(),
                    );
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            builder
                .encrypt_with_password(
                    rand::thread_rng(),
                    PgpStringToKey::new_default(rand::thread_rng()),
                    &password,
                )
                .map_err(to_py_err)?;
            builder.to_vec(rand::thread_rng()).map_err(to_py_err)
        }
    }
}

/// Encrypt a message with a password and return the result as ASCII armor.
#[pyfunction]
#[pyo3(signature = (
    data,
    password,
    file_name="",
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
    compression=None,
    session_key=None,
))]
pub(crate) fn encrypt_message_with_password(
    data: &[u8],
    password: &str,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
    session_key: Option<&[u8]>,
) -> PyResult<String> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let compression = compression_algorithm_from_name(compression)?;
    let password = Password::from(password);

    match version {
        EncryptionVersion::SeipdV1 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            builder
                .encrypt_with_password(PgpStringToKey::new_default(rand::thread_rng()), &password)
                .map_err(to_py_err)?;
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
        }
        EncryptionVersion::SeipdV2 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v2(
                        rand::thread_rng(),
                        symmetric_algorithm,
                        aead_algorithm,
                        ChunkSize::default(),
                    );
            configure_message_builder!(builder, compression, session_key, symmetric_algorithm);
            builder
                .encrypt_with_password(
                    rand::thread_rng(),
                    PgpStringToKey::new_default(rand::thread_rng()),
                    &password,
                )
                .map_err(to_py_err)?;
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
        }
    }
}
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(pyo3::wrap_pyfunction!(inspect_message, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(inspect_message_bytes, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(sign_message, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(sign_message_many, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(sign_cleartext_message, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(sign_cleartext_message_many, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(
        encrypt_session_key_to_recipient,
        module
    )?)?;
    module.add_function(pyo3::wrap_pyfunction!(
        encrypt_session_key_with_password,
        module
    )?)?;
    module.add_function(pyo3::wrap_pyfunction!(
        encrypt_message_to_recipient_bytes,
        module
    )?)?;
    module.add_function(pyo3::wrap_pyfunction!(
        encrypt_message_to_recipients_bytes,
        module
    )?)?;
    module.add_function(pyo3::wrap_pyfunction!(
        encrypt_message_to_recipient,
        module
    )?)?;
    module.add_function(pyo3::wrap_pyfunction!(
        encrypt_message_to_recipients,
        module
    )?)?;
    module.add_function(pyo3::wrap_pyfunction!(
        encrypt_message_with_password_bytes,
        module
    )?)?;
    module.add_function(pyo3::wrap_pyfunction!(
        encrypt_message_with_password,
        module
    )?)?;
    Ok(())
}
