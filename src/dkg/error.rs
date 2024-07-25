/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::checksum::ChecksumError;
use crate::frost;
use crate::io;
use core::fmt;
use core::fmt::Debug;

#[derive(Debug)]
pub enum Error {
    // TODO(jwp): potentially remove these to reduce binary size
    InvalidInput(&'static str),
    FrostError(frost::Error),
    EncryptionError(io::Error),
    DecryptionError(io::Error),
    ChecksumError(ChecksumError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::InvalidInput(e) => {
                write!(f, "invalid input: ")?;
                Debug::fmt(&e, f)
            }
            Self::FrostError(e) => {
                write!(f, "frost error: ")?;
                Debug::fmt(&e, f)
            }
            Self::EncryptionError(e) => {
                write!(f, "encryption error: ")?;
                Debug::fmt(&e, f)
            }
            Self::DecryptionError(e) => {
                write!(f, "decryption error: ")?;
                Debug::fmt(&e, f)
            }
            Self::ChecksumError(e) => {
                write!(f, "checksum error: ")?;
                Debug::fmt(&e, f)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
