/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::io;

use reddsa::frost::redjubjub::round1::NonceCommitment;

use crate::participant::{Identity, Secret, Signature, SignatureError, IDENTITY_LEN};

const NONCE_COMMITMENT_LENGTH: usize = 32;
pub const SIGNATURE_DATA_LENGTH: usize = IDENTITY_LEN + NONCE_COMMITMENT_LENGTH * 2;
pub const SIGNING_COMMITMENT_LENGTH: usize = SIGNATURE_DATA_LENGTH + Signature::BYTE_SIZE;

fn signature_data(
    identity: &Identity,
    hiding: &NonceCommitment,
    binding: &NonceCommitment,
) -> [u8; SIGNATURE_DATA_LENGTH] {
    let mut data = [0u8; SIGNATURE_DATA_LENGTH];
    let parts = [
        &identity.serialize()[..],
        &hiding.serialize(),
        &binding.serialize(),
    ];
    let mut slice = &mut data[..];
    for part in parts {
        slice[..part.len()].copy_from_slice(part);
        slice = &mut slice[part.len()..];
    }
    assert_eq!(slice.len(), 0);
    data
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SigningCommitment {
    identity: Identity,
    hiding: NonceCommitment,
    binding: NonceCommitment,
    signature: Signature,
}

impl SigningCommitment {
    pub fn new(
        identity: Identity,
        hiding: NonceCommitment,
        binding: NonceCommitment,
        signature: Signature,
    ) -> Result<Self, SignatureError> {
        let signing_commitment = Self {
            identity,
            hiding,
            binding,
            signature,
        };

        signing_commitment.verify().map(|_| signing_commitment)
    }

    pub fn from_frost(
        secret: Secret,
        hiding: NonceCommitment,
        binding: NonceCommitment,
    ) -> SigningCommitment {
        let identity = secret.to_identity();
        let signature_data = signature_data(&identity, &hiding, &binding);

        SigningCommitment {
            hiding,
            binding,
            identity,
            signature: secret.sign(&signature_data),
        }
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        let signature_data = signature_data(&self.identity, &self.hiding, &self.binding);

        self.identity.verify_data(&signature_data, &self.signature)
    }

    pub fn hiding(&self) -> &NonceCommitment {
        &self.hiding
    }

    pub fn binding(&self) -> &NonceCommitment {
        &self.binding
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.signature.to_bytes())?;
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
        let mut signature_bytes = [0u8; Signature::BYTE_SIZE];
        reader.read_exact(&mut signature_bytes)?;
        let signature = Signature::from_bytes(&signature_bytes);

        let identity = Identity::deserialize_from(&mut reader)?;

        let mut hiding = [0u8; 32];
        reader.read_exact(&mut hiding)?;
        let hiding = NonceCommitment::deserialize(hiding)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut binding = [0u8; 32];
        reader.read_exact(&mut binding)?;
        let binding = NonceCommitment::deserialize(binding)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Self::new(identity, hiding, binding, signature)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

#[cfg(test)]
mod tests {
    use crate::{participant::Secret, signing_commitment::signature_data};

    use super::SigningCommitment;
    use rand::thread_rng;
    use reddsa::frost::redjubjub::{keys::SigningShare, round1::SigningNonces};

    #[test]
    fn serialization_round_trip() {
        let mut rng = thread_rng();

        let signing_share = SigningShare::default();
        let secret = Secret::random(&mut rng);
        let nonces = SigningNonces::new(&signing_share, &mut rng);
        let hiding = nonces.hiding().into();
        let binding = nonces.binding().into();
        let signature = secret.sign(&signature_data(&secret.to_identity(), &hiding, &binding));

        let signing_commitment = SigningCommitment {
            hiding,
            binding,
            signature,
            identity: secret.to_identity(),
        };
        let serialized = signing_commitment
            .serialize()
            .expect("serialization failed");

        let deserialized =
            SigningCommitment::deserialize_from(&serialized[..]).expect("deserialization failed");

        assert_eq!(deserialized, signing_commitment);
    }

    #[test]
    fn test_valid_signature() {
        let mut rng = thread_rng();

        let signing_share = SigningShare::default();
        let secret = Secret::random(&mut rng);
        let nonces = SigningNonces::new(&signing_share, &mut rng);
        let hiding = nonces.hiding().into();
        let binding = nonces.binding().into();

        assert!(SigningCommitment::from_frost(secret, hiding, binding)
            .verify()
            .is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let mut rng = thread_rng();

        let signing_share = SigningShare::default();
        let secret = Secret::random(&mut rng);
        let nonces = SigningNonces::new(&signing_share, &mut rng);
        let hiding = nonces.hiding().into();
        let binding = nonces.binding().into();
        let signature = secret.sign(&signature_data(&secret.to_identity(), &hiding, &binding));

        let signing_commitment = SigningCommitment {
            hiding,
            binding,
            signature,
            identity: Secret::random(&mut rng).to_identity(),
        };

        assert!(signing_commitment.verify().is_err());
    }

    #[test]
    fn test_invalid_deserialization() {
        let mut rng = thread_rng();

        let signing_share = SigningShare::default();
        let secret = Secret::random(&mut rng);
        let nonces = SigningNonces::new(&signing_share, &mut rng);
        let hiding = nonces.hiding().into();
        let binding = nonces.binding().into();
        let signature = secret.sign(&signature_data(&secret.to_identity(), &hiding, &binding));

        let signing_commitment = SigningCommitment {
            hiding,
            binding,
            signature,
            identity: Secret::random(&mut rng).to_identity(),
        };

        let serialized = signing_commitment
            .serialize()
            .expect("serialization failed");

        assert!(SigningCommitment::deserialize_from(&serialized[..]).is_err());
    }
}
