/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use ironfish_reddsa::frost::redjubjub::frost::Error as FrostError;
use ironfish_reddsa::frost::redjubjub::JubjubBlake2b512;

use crate::io;

use crate::checksum::ChecksumError;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String;

#[derive(Debug)]
pub enum IronfishFrostError {
    InvalidInput(String),
    StdError,
    IoError(io::Error),
    DecryptionError(io::Error),
    EncryptionError(io::Error),
    FrostError(FrostError<JubjubBlake2b512>),
    SignatureError(ed25519_dalek::SignatureError),
    ChecksumError(ChecksumError),
}

impl From<FrostError<JubjubBlake2b512>> for IronfishFrostError {
    fn from(error: FrostError<JubjubBlake2b512>) -> Self {
        IronfishFrostError::FrostError(error)
    }
}

impl From<io::Error> for IronfishFrostError {
    fn from(error: io::Error) -> Self {
        IronfishFrostError::IoError(error)
    }
}

impl From<ed25519_dalek::SignatureError> for IronfishFrostError {
    fn from(error: ed25519_dalek::SignatureError) -> Self {
        IronfishFrostError::SignatureError(error)
    }
}

#[cfg(feature = "std")]
use std::fmt;

#[cfg(feature = "std")]
impl fmt::Display for IronfishFrostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::InvalidInput(e) => {
                write!(f, "invalid input: ")?;
                e.fmt(f)
            }
            Self::StdError => {
                write!(f, "std error")?;
                Ok(())
            }
            Self::IoError(e) => {
                write!(f, "io error: ")?;
                e.fmt(f)
            }
            Self::DecryptionError(e) => {
                write!(f, "decryption error: ")?;
                e.fmt(f)
            }
            Self::EncryptionError(e) => {
                write!(f, "encryption error: ")?;
                e.fmt(f)
            }
            Self::FrostError(e) => {
                write!(f, "frost error: ")?;
                e.fmt(f)
            }
            Self::SignatureError(e) => {
                write!(f, "signature rror: ")?;
                e.fmt(f)
            }
            Self::ChecksumError(e) => {
                write!(f, "checksum error: ")?;
                e.fmt(f)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IronfishFrostError {}
