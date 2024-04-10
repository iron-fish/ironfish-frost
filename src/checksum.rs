/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::error;
use std::fmt;

use siphasher::sip::SipHasher24;

pub(crate) const CHECKSUM_LEN: usize = 8;

pub(crate) type Checksum = u64;

pub(crate) type ChecksumHasher = SipHasher24;

#[derive(Clone, Debug)]
pub struct ChecksumError;

impl fmt::Display for ChecksumError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt("checksum doesn't match", f)
    }
}

impl error::Error for ChecksumError {}
