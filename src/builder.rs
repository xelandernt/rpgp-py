use std::{
    convert::TryFrom,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use pgp::{
    composed::{
        ArmorOptions as PgpArmorOptions, DEFAULT_PARTIAL_CHUNK_SIZE, Encryption as PgpEncryption,
        EncryptionSeipdV1, EncryptionSeipdV2, MessageBuilder as PgpMessageBuilder,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::DataMode,
    types::{CompressionAlgorithm, Password, StringToKey as PgpStringToKey},
};
use pyo3::{
    prelude::*,
    types::{PyAny, PyBytes},
};

use crate::conversions::{
    aead_algorithm_from_name, compression_algorithm_from_name, symmetric_algorithm_from_name,
};
use crate::{
    Headers,
    key_params::PyStringToKey,
    keys::{
        PublicRecipient, SecretSigner, public_recipient_from_python, secret_signer_from_python,
    },
    serialization::raw_session_key_from_bytes,
    to_py_err,
};

#[pyclass(module = "openpgp", name = "ArmorOptions", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PyArmorOptions {
    pub(crate) headers: Option<Headers>,
    pub(crate) include_checksum: bool,
}

#[pymethods]
impl PyArmorOptions {
    #[new]
    #[pyo3(signature = (headers=None, include_checksum=true))]
    fn new(headers: Option<Headers>, include_checksum: bool) -> Self {
        Self {
            headers,
            include_checksum,
        }
    }

    #[getter]
    fn headers(&self) -> Option<Headers> {
        self.headers.clone()
    }

    #[getter]
    fn include_checksum(&self) -> bool {
        self.include_checksum
    }

    fn __repr__(&self) -> String {
        format!(
            "ArmorOptions(headers={}, include_checksum={})",
            if self.headers.is_some() {
                "..."
            } else {
                "None"
            },
            self.include_checksum
        )
    }
}

#[derive(Clone)]
struct PasswordEncryptionConfig {
    s2k: PgpStringToKey,
    password: String,
}

#[derive(Clone)]
struct RecipientEncryptionConfig {
    recipient: PublicRecipient,
    anonymous: bool,
}

#[derive(Clone)]
struct SignatureConfig {
    signer: SecretSigner,
    password: String,
    hash_algorithm: HashAlgorithm,
}

#[derive(Clone)]
enum MessageBuilderSource {
    Bytes { name: String, data: Vec<u8> },
    File(PathBuf),
    Reader { name: String, data: Vec<u8> },
}

#[derive(Clone)]
enum EncryptionConfig {
    Plaintext,
    SeipdV1 {
        symmetric_algorithm: SymmetricKeyAlgorithm,
        session_key: Vec<u8>,
        recipients: Vec<RecipientEncryptionConfig>,
        passwords: Vec<PasswordEncryptionConfig>,
    },
    SeipdV2 {
        symmetric_algorithm: SymmetricKeyAlgorithm,
        aead_algorithm: AeadAlgorithm,
        chunk_size: ChunkSize,
        session_key: Vec<u8>,
        recipients: Vec<RecipientEncryptionConfig>,
        passwords: Vec<PasswordEncryptionConfig>,
    },
}

#[derive(Clone, Copy)]
enum MessageBuilderDataMode {
    Binary,
    Utf8,
}

#[derive(Clone, Copy)]
enum MessageBuilderSignatureType {
    Binary,
    Text,
}

#[derive(Clone)]
struct MessageBuilderConfig {
    source: MessageBuilderSource,
    compression: Option<CompressionAlgorithm>,
    partial_chunk_size: u32,
    data_mode: MessageBuilderDataMode,
    signature_type: MessageBuilderSignatureType,
    signatures: Vec<SignatureConfig>,
    encryption: EncryptionConfig,
}

impl MessageBuilderConfig {
    fn new(source: MessageBuilderSource) -> Self {
        Self {
            source,
            compression: None,
            partial_chunk_size: DEFAULT_PARTIAL_CHUNK_SIZE,
            data_mode: MessageBuilderDataMode::Binary,
            signature_type: MessageBuilderSignatureType::Binary,
            signatures: Vec::new(),
            encryption: EncryptionConfig::Plaintext,
        }
    }

    fn source_name(&self) -> &'static str {
        match &self.source {
            MessageBuilderSource::Bytes { .. } => "bytes",
            MessageBuilderSource::File(_) => "file",
            MessageBuilderSource::Reader { .. } => "reader",
        }
    }

    fn encryption_name(&self) -> &'static str {
        match &self.encryption {
            EncryptionConfig::Plaintext => "plaintext",
            EncryptionConfig::SeipdV1 { .. } => "seipd-v1",
            EncryptionConfig::SeipdV2 { .. } => "seipd-v2",
        }
    }
}

fn message_builder_data_mode_from_name(value: &str) -> PyResult<MessageBuilderDataMode> {
    match value.to_ascii_lowercase().as_str() {
        "binary" => Ok(MessageBuilderDataMode::Binary),
        "utf8" | "utf-8" => Ok(MessageBuilderDataMode::Utf8),
        _ => Err(to_py_err(
            "unsupported data mode; expected 'binary' or 'utf8'",
        )),
    }
}

fn chunk_size_from_number(value: u8) -> PyResult<ChunkSize> {
    ChunkSize::try_from(value)
        .map_err(|_| to_py_err("unsupported chunk size; expected an integer between 0 and 16"))
}

fn apply_common_builder_options<R: Read, E: PgpEncryption>(
    builder: &mut PgpMessageBuilder<'_, R, E>,
    partial_chunk_size: u32,
    compression: &Option<CompressionAlgorithm>,
    data_mode: MessageBuilderDataMode,
    signature_type: MessageBuilderSignatureType,
) -> PyResult<()> {
    builder
        .partial_chunk_size(partial_chunk_size)
        .map_err(to_py_err)?;
    if let Some(compression) = compression.clone() {
        builder.compression(compression);
    }
    builder
        .data_mode(match data_mode {
            MessageBuilderDataMode::Binary => DataMode::Binary,
            MessageBuilderDataMode::Utf8 => DataMode::Utf8,
        })
        .map_err(to_py_err)?;
    match signature_type {
        MessageBuilderSignatureType::Binary => {
            builder.sign_binary();
        }
        MessageBuilderSignatureType::Text => {
            builder.sign_text();
        }
    }
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> PyResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(to_py_err)?;
    }
    Ok(())
}

fn read_bytes_from_python_reader(py: Python<'_>, reader: Py<PyAny>) -> PyResult<Vec<u8>> {
    let reader = reader.bind(py);
    reader.call_method0("read")?.extract::<Vec<u8>>()
}

fn write_bytes_to_python_writer(py: Python<'_>, writer: Py<PyAny>, data: &[u8]) -> PyResult<()> {
    let writer = writer.bind(py);
    let payload = PyBytes::new(py, data);
    writer.call_method1("write", (payload,))?;
    if writer.hasattr("flush")? {
        writer.call_method0("flush")?;
    }
    Ok(())
}

fn write_text_to_python_writer(py: Python<'_>, writer: Py<PyAny>, data: &str) -> PyResult<()> {
    let writer = writer.bind(py);
    writer.call_method1("write", (data,))?;
    if writer.hasattr("flush")? {
        writer.call_method0("flush")?;
    }
    Ok(())
}

fn apply_signatures<'a, R: Read, E: PgpEncryption>(
    builder: &mut PgpMessageBuilder<'a, R, E>,
    signatures: &'a [SignatureConfig],
) {
    for signature in signatures {
        signature.signer.apply_message_signature(
            builder,
            Password::from(signature.password.as_str()),
            signature.hash_algorithm,
        );
    }
}

fn apply_passwords_v1<R: Read>(
    builder: &mut PgpMessageBuilder<'_, R, EncryptionSeipdV1>,
    passwords: &[PasswordEncryptionConfig],
) -> PyResult<()> {
    for password_config in passwords {
        let password = Password::from(password_config.password.as_str());
        builder
            .encrypt_with_password(password_config.s2k.clone(), &password)
            .map_err(to_py_err)?;
    }
    Ok(())
}

fn apply_recipients_v1<'a, R: Read>(
    builder: &mut PgpMessageBuilder<'a, R, EncryptionSeipdV1>,
    recipients: &'a [RecipientEncryptionConfig],
) -> PyResult<()> {
    for recipient in recipients {
        recipient
            .recipient
            .encrypt_to_message_builder_v1(builder, recipient.anonymous)?;
    }
    Ok(())
}

fn apply_passwords_v2<R: Read>(
    builder: &mut PgpMessageBuilder<'_, R, EncryptionSeipdV2>,
    passwords: &[PasswordEncryptionConfig],
) -> PyResult<()> {
    for password_config in passwords {
        let password = Password::from(password_config.password.as_str());
        builder
            .encrypt_with_password(rand::thread_rng(), password_config.s2k.clone(), &password)
            .map_err(to_py_err)?;
    }
    Ok(())
}

fn apply_recipients_v2<'a, R: Read>(
    builder: &mut PgpMessageBuilder<'a, R, EncryptionSeipdV2>,
    recipients: &'a [RecipientEncryptionConfig],
) -> PyResult<()> {
    for recipient in recipients {
        recipient
            .recipient
            .encrypt_to_message_builder_v2(builder, recipient.anonymous)?;
    }
    Ok(())
}

fn build_binary_message(config: MessageBuilderConfig) -> PyResult<Vec<u8>> {
    let MessageBuilderConfig {
        source,
        compression,
        partial_chunk_size,
        data_mode,
        signature_type,
        signatures,
        encryption,
    } = config;

    match source {
        MessageBuilderSource::Bytes { name, data }
        | MessageBuilderSource::Reader { name, data } => match encryption {
            EncryptionConfig::Plaintext => {
                let mut builder = PgpMessageBuilder::from_bytes(name, data);
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder.to_vec(rand::thread_rng()).map_err(to_py_err)
            }
            EncryptionConfig::SeipdV1 {
                symmetric_algorithm,
                session_key,
                recipients,
                passwords,
            } => {
                let mut builder = PgpMessageBuilder::from_bytes(name, data)
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder
                    .set_session_key(raw_session_key_from_bytes(
                        &session_key,
                        symmetric_algorithm,
                    )?)
                    .map_err(to_py_err)?;
                apply_recipients_v1(&mut builder, &recipients)?;
                apply_passwords_v1(&mut builder, &passwords)?;
                builder.to_vec(rand::thread_rng()).map_err(to_py_err)
            }
            EncryptionConfig::SeipdV2 {
                symmetric_algorithm,
                aead_algorithm,
                chunk_size,
                session_key,
                recipients,
                passwords,
            } => {
                let mut builder = PgpMessageBuilder::from_bytes(name, data).seipd_v2(
                    rand::thread_rng(),
                    symmetric_algorithm,
                    aead_algorithm,
                    chunk_size,
                );
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder
                    .set_session_key(raw_session_key_from_bytes(
                        &session_key,
                        symmetric_algorithm,
                    )?)
                    .map_err(to_py_err)?;
                apply_recipients_v2(&mut builder, &recipients)?;
                apply_passwords_v2(&mut builder, &passwords)?;
                builder.to_vec(rand::thread_rng()).map_err(to_py_err)
            }
        },
        MessageBuilderSource::File(path) => match encryption {
            EncryptionConfig::Plaintext => {
                let mut builder = PgpMessageBuilder::from_file(path);
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder.to_vec(rand::thread_rng()).map_err(to_py_err)
            }
            EncryptionConfig::SeipdV1 {
                symmetric_algorithm,
                session_key,
                recipients,
                passwords,
            } => {
                let mut builder = PgpMessageBuilder::from_file(path)
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder
                    .set_session_key(raw_session_key_from_bytes(
                        &session_key,
                        symmetric_algorithm,
                    )?)
                    .map_err(to_py_err)?;
                apply_recipients_v1(&mut builder, &recipients)?;
                apply_passwords_v1(&mut builder, &passwords)?;
                builder.to_vec(rand::thread_rng()).map_err(to_py_err)
            }
            EncryptionConfig::SeipdV2 {
                symmetric_algorithm,
                aead_algorithm,
                chunk_size,
                session_key,
                recipients,
                passwords,
            } => {
                let mut builder = PgpMessageBuilder::from_file(path).seipd_v2(
                    rand::thread_rng(),
                    symmetric_algorithm,
                    aead_algorithm,
                    chunk_size,
                );
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder
                    .set_session_key(raw_session_key_from_bytes(
                        &session_key,
                        symmetric_algorithm,
                    )?)
                    .map_err(to_py_err)?;
                apply_recipients_v2(&mut builder, &recipients)?;
                apply_passwords_v2(&mut builder, &passwords)?;
                builder.to_vec(rand::thread_rng()).map_err(to_py_err)
            }
        },
    }
}

fn build_armored_message(
    config: MessageBuilderConfig,
    armor_options: PgpArmorOptions<'_>,
) -> PyResult<String> {
    let MessageBuilderConfig {
        source,
        compression,
        partial_chunk_size,
        data_mode,
        signature_type,
        signatures,
        encryption,
    } = config;

    match source {
        MessageBuilderSource::Bytes { name, data }
        | MessageBuilderSource::Reader { name, data } => match encryption {
            EncryptionConfig::Plaintext => {
                let mut builder = PgpMessageBuilder::from_bytes(name, data);
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder
                    .to_armored_string(rand::thread_rng(), armor_options)
                    .map_err(to_py_err)
            }
            EncryptionConfig::SeipdV1 {
                symmetric_algorithm,
                session_key,
                recipients,
                passwords,
            } => {
                let mut builder = PgpMessageBuilder::from_bytes(name, data)
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder
                    .set_session_key(raw_session_key_from_bytes(
                        &session_key,
                        symmetric_algorithm,
                    )?)
                    .map_err(to_py_err)?;
                apply_recipients_v1(&mut builder, &recipients)?;
                apply_passwords_v1(&mut builder, &passwords)?;
                builder
                    .to_armored_string(rand::thread_rng(), armor_options)
                    .map_err(to_py_err)
            }
            EncryptionConfig::SeipdV2 {
                symmetric_algorithm,
                aead_algorithm,
                chunk_size,
                session_key,
                recipients,
                passwords,
            } => {
                let mut builder = PgpMessageBuilder::from_bytes(name, data).seipd_v2(
                    rand::thread_rng(),
                    symmetric_algorithm,
                    aead_algorithm,
                    chunk_size,
                );
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder
                    .set_session_key(raw_session_key_from_bytes(
                        &session_key,
                        symmetric_algorithm,
                    )?)
                    .map_err(to_py_err)?;
                apply_recipients_v2(&mut builder, &recipients)?;
                apply_passwords_v2(&mut builder, &passwords)?;
                builder
                    .to_armored_string(rand::thread_rng(), armor_options)
                    .map_err(to_py_err)
            }
        },
        MessageBuilderSource::File(path) => match encryption {
            EncryptionConfig::Plaintext => {
                let mut builder = PgpMessageBuilder::from_file(path);
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder
                    .to_armored_string(rand::thread_rng(), armor_options)
                    .map_err(to_py_err)
            }
            EncryptionConfig::SeipdV1 {
                symmetric_algorithm,
                session_key,
                recipients,
                passwords,
            } => {
                let mut builder = PgpMessageBuilder::from_file(path)
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder
                    .set_session_key(raw_session_key_from_bytes(
                        &session_key,
                        symmetric_algorithm,
                    )?)
                    .map_err(to_py_err)?;
                apply_recipients_v1(&mut builder, &recipients)?;
                apply_passwords_v1(&mut builder, &passwords)?;
                builder
                    .to_armored_string(rand::thread_rng(), armor_options)
                    .map_err(to_py_err)
            }
            EncryptionConfig::SeipdV2 {
                symmetric_algorithm,
                aead_algorithm,
                chunk_size,
                session_key,
                recipients,
                passwords,
            } => {
                let mut builder = PgpMessageBuilder::from_file(path).seipd_v2(
                    rand::thread_rng(),
                    symmetric_algorithm,
                    aead_algorithm,
                    chunk_size,
                );
                apply_common_builder_options(
                    &mut builder,
                    partial_chunk_size,
                    &compression,
                    data_mode,
                    signature_type,
                )?;
                apply_signatures(&mut builder, &signatures);
                builder
                    .set_session_key(raw_session_key_from_bytes(
                        &session_key,
                        symmetric_algorithm,
                    )?)
                    .map_err(to_py_err)?;
                apply_recipients_v2(&mut builder, &recipients)?;
                apply_passwords_v2(&mut builder, &passwords)?;
                builder
                    .to_armored_string(rand::thread_rng(), armor_options)
                    .map_err(to_py_err)
            }
        },
    }
}

#[pyclass(module = "openpgp", name = "MessageBuilder")]
pub(crate) struct PyMessageBuilder {
    state: Option<MessageBuilderConfig>,
}

impl PyMessageBuilder {
    fn config_mut(&mut self) -> PyResult<&mut MessageBuilderConfig> {
        self.state
            .as_mut()
            .ok_or_else(|| to_py_err("message builder has already been consumed"))
    }

    fn take_config(&mut self) -> PyResult<MessageBuilderConfig> {
        self.state
            .take()
            .ok_or_else(|| to_py_err("message builder has already been consumed"))
    }
}

#[pymethods]
impl PyMessageBuilder {
    #[staticmethod]
    fn from_bytes(name: &str, data: &[u8]) -> Self {
        Self {
            state: Some(MessageBuilderConfig::new(MessageBuilderSource::Bytes {
                name: name.to_string(),
                data: data.to_vec(),
            })),
        }
    }

    #[staticmethod]
    fn from_file(path: PathBuf) -> Self {
        Self {
            state: Some(MessageBuilderConfig::new(MessageBuilderSource::File(path))),
        }
    }

    #[staticmethod]
    fn from_reader(py: Python<'_>, file_name: &str, reader: Py<PyAny>) -> PyResult<Self> {
        Ok(Self {
            state: Some(MessageBuilderConfig::new(MessageBuilderSource::Reader {
                name: file_name.to_string(),
                data: read_bytes_from_python_reader(py, reader)?,
            })),
        })
    }

    fn data_mode<'py>(mut slf: PyRefMut<'py, Self>, mode: &str) -> PyResult<PyRefMut<'py, Self>> {
        slf.config_mut()?.data_mode = message_builder_data_mode_from_name(mode)?;
        Ok(slf)
    }

    fn sign_binary<'py>(mut slf: PyRefMut<'py, Self>) -> PyResult<PyRefMut<'py, Self>> {
        slf.config_mut()?.signature_type = MessageBuilderSignatureType::Binary;
        Ok(slf)
    }

    fn sign_text<'py>(mut slf: PyRefMut<'py, Self>) -> PyResult<PyRefMut<'py, Self>> {
        slf.config_mut()?.signature_type = MessageBuilderSignatureType::Text;
        Ok(slf)
    }

    fn compression<'py>(
        mut slf: PyRefMut<'py, Self>,
        compression: &str,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.config_mut()?.compression = compression_algorithm_from_name(Some(compression))?;
        Ok(slf)
    }

    fn partial_chunk_size<'py>(
        mut slf: PyRefMut<'py, Self>,
        size: u32,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let mut builder = PgpMessageBuilder::from_bytes("", Vec::<u8>::new());
        builder.partial_chunk_size(size).map_err(to_py_err)?;
        slf.config_mut()?.partial_chunk_size = size;
        Ok(slf)
    }

    fn seipd_v1<'py>(
        mut slf: PyRefMut<'py, Self>,
        symmetric_algorithm: &str,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let config = slf.config_mut()?;
        if !matches!(config.encryption, EncryptionConfig::Plaintext) {
            return Err(to_py_err(
                "message builder is already configured for encryption",
            ));
        }
        let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
        config.encryption = EncryptionConfig::SeipdV1 {
            symmetric_algorithm,
            session_key: symmetric_algorithm
                .new_session_key(&mut rand::thread_rng())
                .as_ref()
                .to_vec(),
            recipients: Vec::new(),
            passwords: Vec::new(),
        };
        Ok(slf)
    }

    #[pyo3(signature = (symmetric_algorithm, aead_algorithm, chunk_size=None))]
    fn seipd_v2<'py>(
        mut slf: PyRefMut<'py, Self>,
        symmetric_algorithm: &str,
        aead_algorithm: &str,
        chunk_size: Option<u8>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let config = slf.config_mut()?;
        if !matches!(config.encryption, EncryptionConfig::Plaintext) {
            return Err(to_py_err(
                "message builder is already configured for encryption",
            ));
        }
        let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
        config.encryption = EncryptionConfig::SeipdV2 {
            symmetric_algorithm,
            aead_algorithm: aead_algorithm_from_name(aead_algorithm)?,
            chunk_size: match chunk_size {
                Some(chunk_size) => chunk_size_from_number(chunk_size)?,
                None => ChunkSize::default(),
            },
            session_key: symmetric_algorithm
                .new_session_key(&mut rand::thread_rng())
                .as_ref()
                .to_vec(),
            recipients: Vec::new(),
            passwords: Vec::new(),
        };
        Ok(slf)
    }

    fn set_session_key<'py>(
        mut slf: PyRefMut<'py, Self>,
        session_key: &[u8],
    ) -> PyResult<PyRefMut<'py, Self>> {
        match &mut slf.config_mut()?.encryption {
            EncryptionConfig::Plaintext => Err(to_py_err(
                "set_session_key requires seipd_v1() or seipd_v2() to be called first",
            )),
            EncryptionConfig::SeipdV1 {
                symmetric_algorithm,
                session_key: configured_session_key,
                ..
            }
            | EncryptionConfig::SeipdV2 {
                symmetric_algorithm,
                session_key: configured_session_key,
                ..
            } => {
                raw_session_key_from_bytes(session_key, *symmetric_algorithm)?;
                *configured_session_key = session_key.to_vec();
                Ok(slf)
            }
        }
    }

    fn session_key(&self) -> PyResult<Vec<u8>> {
        match &self
            .state
            .as_ref()
            .ok_or_else(|| to_py_err("message builder has already been consumed"))?
            .encryption
        {
            EncryptionConfig::Plaintext => Err(to_py_err(
                "session_key requires seipd_v1() or seipd_v2() to be called first",
            )),
            EncryptionConfig::SeipdV1 { session_key, .. }
            | EncryptionConfig::SeipdV2 { session_key, .. } => Ok(session_key.clone()),
        }
    }

    #[pyo3(signature = (key, password=None, hash_algorithm="sha256"))]
    fn sign<'py>(
        mut slf: PyRefMut<'py, Self>,
        py: Python<'_>,
        key: Py<PyAny>,
        password: Option<&str>,
        hash_algorithm: &str,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let signature = SignatureConfig {
            signer: secret_signer_from_python(py, key)?,
            password: password.unwrap_or_default().to_string(),
            hash_algorithm: crate::conversions::hash_algorithm_from_name(hash_algorithm)?,
        };
        slf.config_mut()?.signatures.push(signature);
        Ok(slf)
    }

    fn encrypt_to_key<'py>(
        mut slf: PyRefMut<'py, Self>,
        py: Python<'_>,
        key: Py<PyAny>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let recipient = RecipientEncryptionConfig {
            recipient: public_recipient_from_python(py, key)?,
            anonymous: false,
        };
        match &mut slf.config_mut()?.encryption {
            EncryptionConfig::Plaintext => Err(to_py_err(
                "encrypt_to_key requires seipd_v1() or seipd_v2() to be called first",
            )),
            EncryptionConfig::SeipdV1 { recipients, .. }
            | EncryptionConfig::SeipdV2 { recipients, .. } => {
                recipients.push(recipient);
                Ok(slf)
            }
        }
    }

    fn encrypt_to_key_anonymous<'py>(
        mut slf: PyRefMut<'py, Self>,
        py: Python<'_>,
        key: Py<PyAny>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let recipient = RecipientEncryptionConfig {
            recipient: public_recipient_from_python(py, key)?,
            anonymous: true,
        };
        match &mut slf.config_mut()?.encryption {
            EncryptionConfig::Plaintext => Err(to_py_err(
                "encrypt_to_key_anonymous requires seipd_v1() or seipd_v2() to be called first",
            )),
            EncryptionConfig::SeipdV1 { recipients, .. }
            | EncryptionConfig::SeipdV2 { recipients, .. } => {
                recipients.push(recipient);
                Ok(slf)
            }
        }
    }

    fn encrypt_with_password<'py>(
        mut slf: PyRefMut<'py, Self>,
        string_to_key: PyRef<'_, PyStringToKey>,
        password: &str,
    ) -> PyResult<PyRefMut<'py, Self>> {
        let password_config = PasswordEncryptionConfig {
            s2k: string_to_key.inner.clone(),
            password: password.to_string(),
        };
        match &mut slf.config_mut()?.encryption {
            EncryptionConfig::Plaintext => Err(to_py_err(
                "encrypt_with_password requires seipd_v1() or seipd_v2() to be called first",
            )),
            EncryptionConfig::SeipdV1 { passwords, .. }
            | EncryptionConfig::SeipdV2 { passwords, .. } => {
                passwords.push(password_config);
                Ok(slf)
            }
        }
    }

    fn to_vec(mut slf: PyRefMut<'_, Self>) -> PyResult<Vec<u8>> {
        let config = slf.take_config()?;
        build_binary_message(config)
    }

    fn to_writer(mut slf: PyRefMut<'_, Self>, py: Python<'_>, writer: Py<PyAny>) -> PyResult<()> {
        let config = slf.take_config()?;
        let data = build_binary_message(config)?;
        write_bytes_to_python_writer(py, writer, &data)
    }

    #[pyo3(signature = (opts=None))]
    fn to_armored_string(
        mut slf: PyRefMut<'_, Self>,
        opts: Option<PyRef<'_, PyArmorOptions>>,
    ) -> PyResult<String> {
        let config = slf.take_config()?;
        let (headers, include_checksum) = match opts {
            Some(opts) => (opts.headers.clone(), opts.include_checksum),
            None => (None, true),
        };
        build_armored_message(
            config,
            PgpArmorOptions {
                headers: headers.as_ref(),
                include_checksum,
            },
        )
    }

    #[pyo3(signature = (writer, opts=None))]
    fn to_armored_writer(
        mut slf: PyRefMut<'_, Self>,
        py: Python<'_>,
        writer: Py<PyAny>,
        opts: Option<PyRef<'_, PyArmorOptions>>,
    ) -> PyResult<()> {
        let config = slf.take_config()?;
        let (headers, include_checksum) = match opts {
            Some(opts) => (opts.headers.clone(), opts.include_checksum),
            None => (None, true),
        };
        let armored = build_armored_message(
            config,
            PgpArmorOptions {
                headers: headers.as_ref(),
                include_checksum,
            },
        )?;
        write_text_to_python_writer(py, writer, &armored)
    }

    fn to_file(mut slf: PyRefMut<'_, Self>, path: PathBuf) -> PyResult<()> {
        let data = build_binary_message(slf.take_config()?)?;
        ensure_parent_dir(&path)?;
        fs::write(path, data).map_err(to_py_err)
    }

    #[pyo3(signature = (path, opts=None))]
    fn to_armored_file(
        mut slf: PyRefMut<'_, Self>,
        path: PathBuf,
        opts: Option<PyRef<'_, PyArmorOptions>>,
    ) -> PyResult<()> {
        let config = slf.take_config()?;
        let (headers, include_checksum) = match opts {
            Some(opts) => (opts.headers.clone(), opts.include_checksum),
            None => (None, true),
        };
        let armored = build_armored_message(
            config,
            PgpArmorOptions {
                headers: headers.as_ref(),
                include_checksum,
            },
        )?;
        ensure_parent_dir(&path)?;
        fs::write(path, armored).map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        match &self.state {
            Some(config) => format!(
                "MessageBuilder(source='{}', encryption='{}', consumed=false)",
                config.source_name(),
                config.encryption_name()
            ),
            None => "MessageBuilder(consumed=true)".to_string(),
        }
    }
}
