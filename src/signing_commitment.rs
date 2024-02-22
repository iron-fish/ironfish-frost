/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::io;

use reddsa::frost::redjubjub::round1::NonceCommitment;

use crate::participant::{Identity, IDENTITY_LEN};

const NONCE_COMMITMENT_LENGTH: usize = 32;
const SIGNING_COMMITMENT_LENGTH: usize = IDENTITY_LEN + NONCE_COMMITMENT_LENGTH * 2;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigningCommitment {
    identity: Identity,
    hiding: NonceCommitment,
    binding: NonceCommitment,
}

impl SigningCommitment {
    #[must_use]
    pub fn from_frost(
        identity: Identity,
        hiding: NonceCommitment,
        binding: NonceCommitment,
    ) -> Self {
        Self {
            identity,
            hiding,
            binding,
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.identity.serialize())?;
        writer.write_all(&self.hiding.serialize())?;
        writer.write_all(&self.binding.serialize())?;
        Ok(())
    }

    pub fn serialize(&self) -> io::Result<[u8; SIGNING_COMMITMENT_LENGTH]> {
        let mut bytes = [0u8; SIGNING_COMMITMENT_LENGTH];
        self.serialize_into(&mut bytes[..])?;
        Ok(bytes)
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let identity = Identity::deserialize_from(&mut reader)?;

        let mut hiding = [0u8; 32];
        reader.read_exact(&mut hiding)?;
        let hiding = NonceCommitment::deserialize(hiding)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut binding = [0u8; 32];
        reader.read_exact(&mut binding)?;
        let binding = NonceCommitment::deserialize(binding)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(SigningCommitment {
            identity,
            hiding,
            binding,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::participant::Secret;

    use super::SigningCommitment;
    use rand::thread_rng;
    use reddsa::frost::redjubjub::{keys::SigningShare, round1::SigningNonces};

    #[test]
    fn serialization_round_trip() {
        let mut rng = thread_rng();

        let signing_share = SigningShare::default();
        let identity = Secret::random(&mut rng).to_identity();
        let nonces = SigningNonces::new(&signing_share, &mut rng);

        let signing_commitment = SigningCommitment {
            identity,
            hiding: nonces.hiding().into(),
            binding: nonces.binding().into(),
        };
        let serialized = signing_commitment
            .serialize()
            .expect("serialization failed");

        let deserialized =
            SigningCommitment::deserialize_from(&serialized[..]).expect("deserialization failed");

        assert_eq!(deserialized, signing_commitment);
    }
}
