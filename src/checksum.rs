/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use core::fmt;

#[cfg(feature = "std")]
use siphasher::sip::SipHasher24;
#[cfg(feature = "std")]
pub(crate) type ChecksumHasher = SipHasher24;

#[cfg(not(feature = "std"))]
use core::hash::SipHasher;
#[cfg(not(feature = "std"))]
pub(crate) type ChecksumHasher = SipHasher;


pub(crate) const CHECKSUM_LEN: usize = 8;

pub(crate) type Checksum = u64;



#[derive(Clone, Debug)]
pub enum ChecksumError {
    SigningCommitmentError,
    DkgPublicPackageError,
}

impl fmt::Display for ChecksumError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningCommitmentError => {
                fmt::Display::fmt("SigningCommitment checksum doesn't match", f)
            }
            Self::DkgPublicPackageError => {
                fmt::Display::fmt("PublicPackage checksum doesn't match", f)
            }
        }
    }
}

#[cfg(feature = "std")]
use std::error;
#[cfg(feature = "std")]
impl error::Error for ChecksumError {}
