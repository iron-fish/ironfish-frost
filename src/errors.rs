/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
use reddsa::frost::redjubjub::Error as FrostError;
use std::backtrace::Backtrace;
use std::backtrace::BacktraceStatus;
use std::error::Error;
use std::fmt;
use std::io;

#[derive(Debug)]
pub struct IronfishError {
    pub kind: IronfishErrorKind,
    pub source: Option<Box<dyn Error>>,
    pub backtrace: Backtrace,
}

#[derive(Debug, PartialEq)]
pub enum IronfishErrorKind {
    InvalidFrostIdentifier,
    InvalidFrostSignatureShare,
    Io,
    FrostLibError,
}

impl Error for IronfishError {}

impl fmt::Display for IronfishError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let has_backtrace = self.backtrace.status() == BacktraceStatus::Captured;
        write!(f, "{:?}", self.kind)?;
        if let Some(source) = &self.source {
            write!(f, "\nCaused by: \n{}", source)?;
        }
        if has_backtrace {
            write!(f, "\nBacktrace:\n{:2}", self.backtrace)
        } else {
            write!(f, "\nTo enable Rust backtraces, use RUST_BACKTRACE=1")
        }
    }
}

impl IronfishError {
    pub fn new(kind: IronfishErrorKind) -> Self {
        Self {
            kind,
            source: None,
            backtrace: Backtrace::capture(),
        }
    }

    pub fn new_with_source<E>(kind: IronfishErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn Error>>,
    {
        Self {
            kind,
            source: Some(source.into()),
            backtrace: Backtrace::capture(),
        }
    }
}

impl From<io::Error> for IronfishError {
    fn from(e: io::Error) -> IronfishError {
        IronfishError::new_with_source(IronfishErrorKind::Io, e)
    }
}

impl From<FrostError> for IronfishError {
    fn from(e: FrostError) -> IronfishError {
        IronfishError::new_with_source(IronfishErrorKind::FrostLibError, e)
    }
}
