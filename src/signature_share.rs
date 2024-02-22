/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::io;

use reddsa::frost::redjubjub::round2::SignatureShare as FrostSignatureShare;

use crate::participant::{Identity, IDENTITY_LEN};

const FROST_SIGNATURE_SHARE_LEN: usize = 32;

pub struct SignatureShare {
    identity: Identity,
    frost_signature_share: FrostSignatureShare,
}

impl SignatureShare {
    #[must_use]
    pub fn from_frost<I>(frost_signature_share: FrostSignatureShare, identity: Identity) -> Self {
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

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        let identity_bytes = self.identity.serialize();
        let signature_share_bytes = self.frost_signature_share.serialize();
        writer.write_all(&identity_bytes)?;
        writer.write_all(&signature_share_bytes)?;

        Ok(())
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut identity_bytes = [0u8; IDENTITY_LEN];
        let mut signature_share_bytes = [0u8; FROST_SIGNATURE_SHARE_LEN];
        reader.read_exact(&mut identity_bytes)?;
        reader.read_exact(&mut signature_share_bytes)?;

        let identity = Identity::deserialize_from(&identity_bytes[..])?;

        let frost_signature_share = FrostSignatureShare::deserialize(signature_share_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(SignatureShare {
            identity,
            frost_signature_share,
        })
    }
}
