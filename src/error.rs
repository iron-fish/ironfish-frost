/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use reddsa::frost::redjubjub::frost::Error as FrostError;
use reddsa::frost::redjubjub::JubjubBlake2b512;

use crate::io;

use crate::checksum::ChecksumError;

#[derive(Debug)]
pub enum IronfishFrostError {
    InvalidInput,
    StdError,
    IoError(io::Error),
    FrostError(FrostError<JubjubBlake2b512>),
    SignatureError(ed25519_dalek::SignatureError),
    ChecksumError(ChecksumError),
    InvalidScenario(&'static str),
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
