use std::{any::Any, fmt::Display};

use pyo3::{exceptions::PyValueError, prelude::*};

pyo3::create_exception!(
    openpgp.errors,
    Error,
    PyValueError,
    "Base exception raised by the rPGP Python bindings."
);

fn pgp_error_code(error: &pgp::errors::Error) -> &'static str {
    use pgp::errors::Error as PgpError;

    match error {
        PgpError::IO { .. } => "IO",
        PgpError::Unimplemented { .. } => "UNIMPLEMENTED",
        PgpError::Unsupported { .. } => "UNSUPPORTED",
        PgpError::Message { .. } => "MESSAGE",
        PgpError::PacketParsing { .. } | PgpError::PacketIncomplete { .. } => "PARSING",
        PgpError::RSAError { .. }
        | PgpError::EllipticCurve { .. }
        | PgpError::InvalidKeyLength
        | PgpError::BlockMode
        | PgpError::MissingKey
        | PgpError::CfbInvalidKeyIvLength
        | PgpError::UnpadError
        | PgpError::PadError
        | PgpError::SignatureError { .. }
        | PgpError::MdcError
        | PgpError::Aead { .. }
        | PgpError::AesKw { .. }
        | PgpError::ChecksumMissmatch { .. }
        | PgpError::Sha1HashCollision { .. }
        | PgpError::AesKek { .. }
        | PgpError::Argon2 { .. }
        | PgpError::SigningError { .. } => "CRYPTO",
        PgpError::InvalidInput { .. }
        | PgpError::InvalidArmorWrappers
        | PgpError::InvalidChecksum
        | PgpError::Base64Decode { .. }
        | PgpError::RequestedSizeTooLarge
        | PgpError::NoMatchingPacket { .. }
        | PgpError::TooManyPackets
        | PgpError::PacketTooLarge { .. }
        | PgpError::Utf8Error { .. }
        | PgpError::ParseIntError { .. }
        | PgpError::InvalidPacketContent { .. }
        | PgpError::PacketError { .. }
        | PgpError::TryFromInt { .. } => "INVALID_INPUT",
        _ => "RPGP",
    }
}

pub(crate) fn to_py_err<E>(error: E) -> PyErr
where
    E: Any + Display,
{
    let code = if let Some(error) = (&error as &dyn Any).downcast_ref::<pgp::errors::Error>() {
        pgp_error_code(error)
    } else if (&error as &dyn Any).is::<std::io::Error>() {
        "IO"
    } else {
        "BINDING"
    };
    let error = Error::new_err(error.to_string());

    Python::attach(|py| match error.value(py).setattr("code", code) {
        Ok(()) => error,
        Err(metadata_error) => metadata_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorizes_representative_rpgp_errors() {
        assert_eq!(
            pgp_error_code(&pgp::errors::Error::InvalidChecksum),
            "INVALID_INPUT"
        );
        assert_eq!(pgp_error_code(&pgp::errors::Error::MissingKey), "CRYPTO");
        assert_eq!(
            pgp_error_code(&pgp::errors::Error::TooManyPackets),
            "INVALID_INPUT"
        );
    }
}
