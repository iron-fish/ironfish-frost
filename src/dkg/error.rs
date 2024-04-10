use crate::checksum::ChecksumError;
use crate::frost;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    InvalidInput(&'static str),
    FrostError(frost::Error),
    EncryptionError(io::Error),
    ChecksumError(ChecksumError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::InvalidInput(e) => {
                write!(f, "invalid input: ")?;
                e.fmt(f)
            }
            Self::FrostError(e) => {
                write!(f, "frost error: ")?;
                e.fmt(f)
            }
            Self::EncryptionError(e) => {
                write!(f, "encryption error: ")?;
                e.fmt(f)
            }
            Self::ChecksumError(e) => {
                write!(f, "checksum error: ")?;
                e.fmt(f)
            }
        }
    }
}

impl std::error::Error for Error {}
