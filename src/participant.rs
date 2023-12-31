/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::frost;
use ed25519_dalek::Signature;
use ed25519_dalek::SignatureError;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use once_cell::sync::OnceCell;
use rand_core::CryptoRng;
use rand_core::RngCore;
use std::io;
use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

const VERIFICATION_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
const ENCRYPTION_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = Signature::BYTE_SIZE;
const VERSION_LEN: usize = 1;
const VERSION: [u8; VERSION_LEN] = [0x72];

pub const IDENTITY_LEN: usize =
    VERSION_LEN + VERIFICATION_KEY_LEN + ENCRYPTION_KEY_LEN + SIGNATURE_LEN;

pub type IdentitySerialization = [u8; IDENTITY_LEN];

/// Returns the portion of identifier data that is signed by [`Secret::signing_key`]
fn authenticated_data(
    verification_key: &VerifyingKey,
    encryption_key: &PublicKey,
) -> [u8; VERSION_LEN + VERIFICATION_KEY_LEN + ENCRYPTION_KEY_LEN] {
    let mut data = [0u8; VERSION_LEN + VERIFICATION_KEY_LEN + ENCRYPTION_KEY_LEN];
    let parts = [
        &VERSION[..],
        verification_key.as_bytes(),
        encryption_key.as_bytes(),
    ];
    let mut slice = &mut data[..];
    for part in parts {
        slice[..part.len()].copy_from_slice(part);
        slice = &mut slice[part.len()..];
    }
    assert_eq!(slice.len(), 0);
    data
}

/// Secret keys of a participant.
#[derive(Clone)]
pub struct Secret {
    signing_key: SigningKey,
    decryption_key: StaticSecret,
    // Use a cell to lazily compute (and cache) the `Identity` corresponding to this `Secret`, to
    // avoid computing public keys and signatures multiple times. This makes `Secret` not `Sync`,
    // but this can be revisited if it turns out to be a problem.
    identity: OnceCell<Identity>,
}

impl Secret {
    #[must_use]
    pub fn random<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        Self {
            signing_key: SigningKey::generate(&mut csprng),
            decryption_key: StaticSecret::random_from_rng(&mut csprng),
            identity: OnceCell::new(),
        }
    }

    #[inline]
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    #[inline]
    #[must_use]
    pub fn decryption_key(&self) -> &StaticSecret {
        &self.decryption_key
    }

    #[must_use]
    pub fn to_identity(&self) -> Identity {
        self.identity
            .get_or_init(|| {
                let verification_key = self.signing_key.verifying_key();
                let encryption_key = PublicKey::from(&self.decryption_key);
                let authenticated_data = authenticated_data(&verification_key, &encryption_key);
                let signature = self.signing_key.sign(&authenticated_data);

                Identity::new_unchecked(verification_key, encryption_key, signature)
            })
            .clone()
    }
}

/// Public identity of a participant.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Identity {
    verification_key: VerifyingKey,
    encryption_key: PublicKey,
    signature: Signature,
}

impl Identity {
    pub fn new(
        verification_key: VerifyingKey,
        encryption_key: PublicKey,
        signature: Signature,
    ) -> Result<Self, SignatureError> {
        let id = Self {
            verification_key,
            encryption_key,
            signature,
        };
        id.verify().map(|_| id)
    }

    fn new_unchecked(
        verification_key: VerifyingKey,
        encryption_key: PublicKey,
        signature: Signature,
    ) -> Self {
        let id = Self {
            verification_key,
            encryption_key,
            signature,
        };
        if cfg!(debug) {
            id.verify().expect("signature did not verify");
        }
        id
    }

    #[inline]
    #[must_use]
    pub fn verification_key(&self) -> &VerifyingKey {
        &self.verification_key
    }

    #[inline]
    #[must_use]
    pub fn encryption_key(&self) -> &PublicKey {
        &self.encryption_key
    }

    pub fn verify(&self) -> Result<(), SignatureError> {
        let authenticated_data = authenticated_data(&self.verification_key, &self.encryption_key);
        self.verification_key
            .verify(&authenticated_data, &self.signature)
    }

    #[must_use]
    pub fn to_frost_identifier(&self) -> frost::Identifier {
        frost::Identifier::derive(&self.serialize())
            .expect("deriving an identifier with FROST-RedJubJub should never fail")
    }

    #[must_use]
    pub fn serialize(&self) -> IdentitySerialization {
        let mut s = [0u8; IDENTITY_LEN];
        self.serialize_into(&mut s[..])
            .expect("array too small to contain serialization");
        s
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&VERSION)?;
        writer.write_all(self.verification_key.as_bytes())?;
        writer.write_all(self.encryption_key.as_bytes())?;
        writer.write_all(self.signature.r_bytes())?;
        writer.write_all(self.signature.s_bytes())?;
        Ok(())
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut version = [0u8; VERSION_LEN];
        reader.read_exact(&mut version)?;
        if version != VERSION {
            return Err(io::Error::new(io::ErrorKind::Other, "unsupported serialization version number"));
        }

        let mut verification_key = [0u8; VERIFICATION_KEY_LEN];
        reader.read_exact(&mut verification_key)?;
        let verification_key =
            VerifyingKey::from_bytes(&verification_key).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let mut encryption_key = [0u8; ENCRYPTION_KEY_LEN];
        reader.read_exact(&mut encryption_key)?;
        let encryption_key = PublicKey::from(encryption_key);

        let mut signature = [0u8; SIGNATURE_LEN];
        reader.read_exact(&mut signature)?;
        let signature = Signature::from(signature);

        Self::new(verification_key, encryption_key, signature).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }
}

impl From<Secret> for Identity {
    #[inline]
    fn from(secret: Secret) -> Identity {
        secret.to_identity()
    }
}

impl<'a> From<&'a Secret> for Identity {
    #[inline]
    fn from(secret: &Secret) -> Identity {
        secret.to_identity()
    }
}

impl From<Identity> for frost::Identifier {
    #[inline]
    fn from(identity: Identity) -> frost::Identifier {
        identity.to_frost_identifier()
    }
}

impl<'a> From<&'a Identity> for frost::Identifier {
    #[inline]
    fn from(identity: &Identity) -> frost::Identifier {
        identity.to_frost_identifier()
    }
}

#[cfg(test)]
mod tests {
    use super::Identity;
    use super::Secret;
    use rand::thread_rng;

    #[test]
    fn secret_to_identity() {
        let secret = Secret::random(thread_rng());
        let id = secret.to_identity();
        id.verify().expect("verification failed");
    }

    #[test]
    fn identity_serialization_stability() {
        let secret = Secret::random(thread_rng());
        let id = secret.to_identity();
        let serialization1 = id.serialize();
        let serialization2 = id.serialize();
        assert_eq!(serialization1, serialization2);
    }

    #[test]
    fn identity_deserialization() {
        let secret = Secret::random(thread_rng());
        let id = secret.to_identity();
        let serialization = id.serialize();
        let deserialized =
            Identity::deserialize_from(&serialization[..]).expect("deserialization failed");
        deserialized.verify().expect("verification failed");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn identity_integrity_check() {
        let secret = Secret::random(thread_rng());
        let serialization = secret.to_identity().serialize();
        assert!(Identity::deserialize_from(&serialization[..]).is_ok());
        for i in 0..serialization.len() {
            let mut broken_serialization = serialization;
            broken_serialization[i] ^= 0xff;
            assert!(
                Identity::deserialize_from(&broken_serialization[..]).is_err(),
                "deserialization did not fail after mutating byte {}",
                i
            );
        }
    }

    #[test]
    fn frost_identity() {
        let secret = Secret::random(thread_rng());
        let id = secret.to_identity();
        let frost_id1 = id.to_frost_identifier();
        let frost_id2 = id.to_frost_identifier();
        assert_eq!(frost_id1, frost_id2);
    }
}
