/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::participant::Identity;
use siphasher::sip::SipHasher24;
use std::borrow::Borrow;
use std::error;
use std::fmt;
use std::hash::Hasher;

pub const CHECKSUM_LEN: usize = 8;

pub type Checksum = u64;

#[derive(Clone, Debug)]
pub struct ChecksumError;

impl fmt::Display for ChecksumError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt("checksum doesn't match", f)
    }
}

impl error::Error for ChecksumError {}

#[must_use]
pub fn input_checksum<I>(input_data: &[u8], signing_participants: &[I]) -> Checksum
where
    I: Borrow<Identity>,
{
    let mut signing_participants = signing_participants
        .iter()
        .map(Borrow::borrow)
        .collect::<Vec<_>>();
    signing_participants.sort_unstable();
    signing_participants.dedup();

    let mut hasher = SipHasher24::new();
    hasher.write(input_data);

    for id in signing_participants {
        hasher.write(&id.serialize());
    }

    hasher.finish()
}
