use crate::types::*;
use crate::*;

pub(crate) fn exact_or_random_array<const N: usize>(
    value: Option<&[u8]>,
    field_name: &str,
) -> PyResult<[u8; N]> {
    match value {
        Some(value) => value
            .try_into()
            .map_err(|_| to_py_err(format!("{field_name} must be exactly {N} bytes"))),
        None => {
            let mut generated = [0u8; N];
            rand::thread_rng().fill(&mut generated[..]);
            Ok(generated)
        }
    }
}

pub(crate) fn exact_or_random_vec(
    value: Option<&[u8]>,
    expected_len: usize,
    field_name: &str,
) -> PyResult<Vec<u8>> {
    match value {
        Some(value) if value.len() == expected_len => Ok(value.to_vec()),
        Some(_) => Err(to_py_err(format!(
            "{field_name} must be exactly {expected_len} bytes"
        ))),
        None => {
            let mut generated = vec![0u8; expected_len];
            rand::thread_rng().fill(generated.as_mut_slice());
            Ok(generated)
        }
    }
}

pub(crate) fn packet_header_from_body_len(
    version: PgpPacketHeaderVersion,
    tag: Tag,
    body_len: usize,
) -> PyResult<PacketHeader> {
    let length = u32::try_from(body_len).map_err(to_py_err)?;
    PacketHeader::from_parts(version, tag, PacketLength::Fixed(length)).map_err(to_py_err)
}

pub(crate) fn serialize_packet_body<T: Serialize>(packet: &T) -> PyResult<Vec<u8>> {
    let mut body = Vec::new();
    packet.to_writer(&mut body).map_err(to_py_err)?;
    Ok(body)
}

pub(crate) fn serialize_packet_with_header<T: PacketTrait>(packet: &T) -> PyResult<Vec<u8>> {
    let mut bytes = Vec::new();
    packet
        .to_writer_with_header(&mut bytes)
        .map_err(to_py_err)?;
    Ok(bytes)
}

pub(crate) fn binary_message_source(source: &[u8], headers: &Option<Headers>) -> PyResult<Vec<u8>> {
    if headers.is_some() {
        let mut bytes = Vec::new();
        let mut dearmor = Dearmor::new(Cursor::new(source));
        dearmor.read_to_end(&mut bytes).map_err(to_py_err)?;
        Ok(bytes)
    } else {
        Ok(source.to_vec())
    }
}

pub(crate) fn parse_top_level_packets(
    source: &[u8],
    headers: &Option<Headers>,
) -> PyResult<Vec<PgpPacket>> {
    let binary = binary_message_source(source, headers)?;
    PacketParser::new(Cursor::new(binary.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(to_py_err)
}

pub(crate) fn raw_session_key_from_bytes(
    session_key: &[u8],
    symmetric_algorithm: SymmetricKeyAlgorithm,
) -> PyResult<PgpRawSessionKey> {
    let expected_len = symmetric_algorithm.key_size();
    if session_key.len() != expected_len {
        return Err(to_py_err(format!(
            "session_key must be exactly {expected_len} bytes for {symmetric_algorithm:?}"
        )));
    }
    Ok(session_key.to_vec().into())
}

pub(crate) fn reframe_secret_key_packet(
    packet: pgp::packet::SecretKey,
    version: PgpPacketHeaderVersion,
) -> PyResult<pgp::packet::SecretKey> {
    if packet.packet_header_version() == version {
        return Ok(packet);
    }

    let body = serialize_packet_body(&packet)?;
    let header = packet_header_from_body_len(version, Tag::SecretKey, body.len())?;
    pgp::packet::SecretKey::try_from_reader(header, Cursor::new(body.as_slice())).map_err(to_py_err)
}

pub(crate) fn reframe_secret_subkey_packet(
    packet: pgp::packet::SecretSubkey,
    version: PgpPacketHeaderVersion,
) -> PyResult<pgp::packet::SecretSubkey> {
    if packet.packet_header_version() == version {
        return Ok(packet);
    }

    let body = serialize_packet_body(&packet)?;
    let header = packet_header_from_body_len(version, Tag::SecretSubkey, body.len())?;
    pgp::packet::SecretSubkey::try_from_reader(header, Cursor::new(body.as_slice()))
        .map_err(to_py_err)
}

#[derive(Clone)]
pub(crate) struct KeyPacketVersions {
    pub(crate) primary: PgpPacketHeaderVersion,
    pub(crate) subkeys: Vec<PgpPacketHeaderVersion>,
}

pub(crate) fn apply_generated_key_packet_versions(
    key: PgpSignedSecretKey,
    packet_versions: &KeyPacketVersions,
) -> PyResult<PgpSignedSecretKey> {
    let PgpSignedSecretKey {
        primary_key,
        details,
        public_subkeys,
        secret_subkeys,
    } = key;

    if secret_subkeys.len() != packet_versions.subkeys.len() {
        return Err(to_py_err(format!(
            "generated subkey count mismatch: expected {}, got {}",
            packet_versions.subkeys.len(),
            secret_subkeys.len(),
        )));
    }

    let primary_key = reframe_secret_key_packet(primary_key, packet_versions.primary)?;
    let secret_subkeys = secret_subkeys
        .into_iter()
        .zip(packet_versions.subkeys.iter().copied())
        .map(|(mut subkey, version)| {
            subkey.key = reframe_secret_subkey_packet(subkey.key, version)?;
            Ok(subkey)
        })
        .collect::<PyResult<Vec<_>>>()?;

    Ok(PgpSignedSecretKey {
        primary_key,
        details,
        public_subkeys,
        secret_subkeys,
    })
}

pub(crate) fn s2k_params_from_secret_params(secret_params: &PgpSecretParams) -> PyS2kParams {
    let inner = match secret_params {
        PgpSecretParams::Plain(_) => PgpS2kParams::Unprotected,
        PgpSecretParams::Encrypted(params) => params.string_to_key_params().clone(),
    };
    PyS2kParams { inner }
}
