/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::io;

use reddsa::frost::redjubjub::round2::SignatureShare as FrostSignatureShare;

use crate::participant::{Identity, IDENTITY_LEN};

const FROST_SIGNATURE_SHARE_LEN: usize = 32;
pub const SIGNATURE_SHARE_SERIALIZATION_LEN: usize = IDENTITY_LEN + FROST_SIGNATURE_SHARE_LEN;

pub type SignatureShareSerialization = [u8; SIGNATURE_SHARE_SERIALIZATION_LEN];

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SignatureShare {
    identity: Identity,
    frost_signature_share: FrostSignatureShare,
}

impl SignatureShare {
    #[must_use]
    pub fn from_frost(frost_signature_share: FrostSignatureShare, identity: Identity) -> Self {
        Self {
            frost_signature_share,
            identity,
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn frost_signature_share(&self) -> &FrostSignatureShare {
        &self.frost_signature_share
    }

    pub fn serialize(&self) -> SignatureShareSerialization {
        let mut s = [0u8; SIGNATURE_SHARE_SERIALIZATION_LEN];
        self.serialize_into(&mut s[..])
            .expect("array too small to contain serialization");
        s
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.identity.serialize_into(&mut writer)?;

        let signature_share_bytes = self.frost_signature_share.serialize();
        writer.write_all(&signature_share_bytes)
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let identity = Identity::deserialize_from(&mut reader)?;

        let mut signature_share_bytes = [0u8; FROST_SIGNATURE_SHARE_LEN];
        reader.read_exact(&mut signature_share_bytes)?;
        let frost_signature_share =
            FrostSignatureShare::deserialize(signature_share_bytes).map_err(io::Error::other)?;

        Ok(SignatureShare {
            identity,
            frost_signature_share,
        })
    }
}
