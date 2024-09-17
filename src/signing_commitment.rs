/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::checksum::Checksum;
use crate::checksum::ChecksumError;
use crate::checksum::ChecksumHasher;
use crate::checksum::CHECKSUM_LEN;
use crate::error::IronfishFrostError;
use crate::frost::keys::SigningShare;
use crate::frost::round1::NonceCommitment;
use crate::frost::round1::SigningCommitments;
use crate::io;
use crate::nonces::deterministic_signing_nonces;
use crate::participant::Identity;
use crate::participant::Secret;
use crate::participant::IDENTITY_LEN;
use core::borrow::Borrow;
use core::hash::Hasher;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

const NONCE_COMMITMENT_LEN: usize = 32;
pub const SIGNING_COMMITMENT_LEN: usize = IDENTITY_LEN + NONCE_COMMITMENT_LEN * 2 + CHECKSUM_LEN;

#[must_use]
fn input_checksum<I>(transaction_hash: &[u8], signing_participants: &[I]) -> Checksum
where
    I: Borrow<Identity>,
{
    let mut signing_participants = signing_participants
        .iter()
        .map(Borrow::borrow)
        .collect::<Vec<_>>();
    signing_participants.sort_unstable();
    signing_participants.dedup();

    let mut hasher = ChecksumHasher::new();
    hasher.write(transaction_hash);

    for id in signing_participants {
        hasher.write(&id.serialize());
    }

    hasher.finish()
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigningCommitment {
    identity: Identity,
    raw_commitments: SigningCommitments,
    /// A checksum of the transaction hash and the signers for a signing operation. Used to quickly
    /// tell if a set of commitments were all generated from the same inputs.
    checksum: Checksum,
}

impl SigningCommitment {
    pub fn from_raw<I>(
        raw_commitments: SigningCommitments,
        identity: Identity,
        transaction_hash: &[u8],
        signing_participants: &[I],
    ) -> Result<SigningCommitment, IronfishFrostError>
    where
        I: Borrow<Identity>,
    {
        let checksum = input_checksum(transaction_hash, signing_participants);

        Ok(SigningCommitment {
            identity,
            raw_commitments,
            checksum,
        })
    }

    pub fn from_secrets<I>(
        participant_secret: &Secret,
        secret_share: &SigningShare,
        transaction_hash: &[u8],
        signing_participants: &[I],
    ) -> Result<SigningCommitment, IronfishFrostError>
    where
        I: Borrow<Identity>,
    {
        let identity = participant_secret.to_identity();
        let nonces =
            deterministic_signing_nonces(secret_share, transaction_hash, signing_participants);
        let raw_commitments = *nonces.commitments();
        let checksum = input_checksum(transaction_hash, signing_participants);
        Ok(SigningCommitment {
            identity,
            raw_commitments,
            checksum,
        })
    }

    pub fn verify_checksum<I>(
        &self,
        transaction_hash: &[u8],
        signing_participants: &[I],
    ) -> Result<(), ChecksumError>
    where
        I: Borrow<Identity>,
    {
        let computed_checksum = input_checksum(transaction_hash, signing_participants);
        if self.checksum == computed_checksum {
            Ok(())
        } else {
            Err(ChecksumError::SigningCommitmentError)
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn raw_commitments(&self) -> &SigningCommitments {
        &self.raw_commitments
    }

    pub fn hiding(&self) -> &NonceCommitment {
        self.raw_commitments.hiding()
    }

    pub fn binding(&self) -> &NonceCommitment {
        self.raw_commitments.binding()
    }

    pub fn checksum(&self) -> Checksum {
        self.checksum
    }

    pub fn serialize(&self) -> [u8; SIGNING_COMMITMENT_LEN] {
        let mut bytes = [0u8; SIGNING_COMMITMENT_LEN];
        self.serialize_into(&mut bytes[..])
            .expect("serialization failed");
        bytes
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> Result<(), IronfishFrostError> {
        writer.write_all(&self.identity.serialize())?;
        writer.write_all(&self.hiding().serialize()?)?;
        writer.write_all(&self.binding().serialize()?)?;
        writer.write_all(&self.checksum.to_le_bytes())?;
        Ok(())
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> Result<Self, IronfishFrostError> {
        let identity = Identity::deserialize_from(&mut reader)?;

        let mut hiding = [0u8; 32];
        reader.read_exact(&mut hiding)?;
        let hiding = NonceCommitment::deserialize(&hiding[..])?;

        let mut binding = [0u8; 32];
        reader.read_exact(&mut binding)?;
        let binding = NonceCommitment::deserialize(&binding[..])?;

        let raw_commitments = SigningCommitments::new(hiding, binding);

        let mut checksum = [0u8; 8];
        reader.read_exact(&mut checksum)?;
        let checksum = Checksum::from_le_bytes(checksum);

        Ok(SigningCommitment {
            identity,
            raw_commitments,
            checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SigningCommitment;
    use crate::frost::keys::SigningShare;
    use crate::participant::Secret;
    use rand::thread_rng;

    #[test]
    fn serialization_round_trip() {
        let mut rng = thread_rng();

        let secret = Secret::random(&mut rng);
        let signing_share = SigningShare::default();
        let signing_participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let commitment = SigningCommitment::from_secrets(
            &secret,
            &signing_share,
            b"transaction hash",
            &signing_participants,
        )
        .expect("commitment creation failed");

        let serialized = commitment.serialize();

        let deserialized =
            SigningCommitment::deserialize_from(&serialized[..]).expect("deserialization failed");

        assert_eq!(deserialized, commitment);
    }

    #[test]
    fn test_checksum_stability() {
        let mut rng = thread_rng();

        let secret1 = Secret::random(&mut rng);
        let secret2 = Secret::random(&mut rng);
        let signing_share1 = SigningShare::default();
        let signing_share2 = SigningShare::default();
        let transaction_hash = b"something";
        let signing_participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let commitment1 = SigningCommitment::from_secrets(
            &secret1,
            &signing_share1,
            transaction_hash,
            &signing_participants,
        )
        .expect("commitment creation failed");

        let commitment2 = SigningCommitment::from_secrets(
            &secret2,
            &signing_share2,
            transaction_hash,
            &signing_participants,
        )
        .expect("commitment creation failed");

        assert_ne!(commitment1, commitment2);
        assert_eq!(commitment1.checksum(), commitment2.checksum());
    }

    #[test]
    fn test_checksum_variation_with_transaction_hash() {
        let mut rng = thread_rng();

        let secret = Secret::random(&mut rng);
        let signing_share = SigningShare::default();
        let signing_participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let commitment1 = SigningCommitment::from_secrets(
            &secret,
            &signing_share,
            b"something",
            &signing_participants,
        )
        .expect("commitment creation failed");

        let commitment2 = SigningCommitment::from_secrets(
            &secret,
            &signing_share,
            b"something else",
            &signing_participants,
        )
        .expect("commitment creation failed");

        assert_ne!(commitment1.checksum(), commitment2.checksum());
    }

    #[test]
    fn test_checksum_variation_with_signers_list() {
        let mut rng = thread_rng();

        let secret = Secret::random(&mut rng);
        let signing_share = SigningShare::default();
        let transaction_hash = b"something";
        let signing_participants1 = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];
        let signing_participants2 = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let commitment1 = SigningCommitment::from_secrets(
            &secret,
            &signing_share,
            transaction_hash,
            &signing_participants1,
        )
        .expect("commitment creation failed");

        let commitment2 = SigningCommitment::from_secrets(
            &secret,
            &signing_share,
            transaction_hash,
            &signing_participants2,
        )
        .expect("commitment creation failed");

        assert_ne!(commitment1.checksum(), commitment2.checksum());
    }
}
