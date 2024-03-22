/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use reddsa::frost::redjubjub::VerifyingKey;

use crate::frost::keys::PublicKeyPackage as FrostPublicKeyPackage;
use crate::participant::Identity;
use std::io;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PublicKeyPackage {
    frost_public_key_package: FrostPublicKeyPackage,
    identities: Vec<Identity>,
    min_signers: u16,
}

impl PublicKeyPackage {
    #[must_use]
    pub fn from_frost<I>(
        frost_public_key_package: FrostPublicKeyPackage,
        identities: I,
        min_signers: u16,
    ) -> Self
    where
        I: IntoIterator<Item = Identity>,
    {
        Self {
            frost_public_key_package,
            identities: identities.into_iter().collect(),
            min_signers,
        }
    }

    pub fn identities(&self) -> &[Identity] {
        &self.identities[..]
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        self.frost_public_key_package.verifying_key()
    }

    pub fn frost_public_key_package(&self) -> &FrostPublicKeyPackage {
        &self.frost_public_key_package
    }

    pub fn min_signers(&self) -> u16 {
        self.min_signers
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.serialize_into(&mut bytes)
            .expect("serialization failed");
        bytes
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        let public_key_package = self
            .frost_public_key_package
            .serialize()
            .map_err(io::Error::other)?;
        let public_key_package_len = u32::try_from(public_key_package.len())
            .map_err(io::Error::other)?
            .to_le_bytes();
        writer.write_all(&public_key_package_len)?;
        writer.write_all(&public_key_package)?;

        let identities_len = u32::try_from(self.identities.len())
            .map_err(io::Error::other)?
            .to_le_bytes();
        writer.write_all(&identities_len)?;
        for identity in &self.identities {
            let identity_bytes = identity.serialize();
            writer.write_all(&identity_bytes)?
        }
        writer.write_all(&self.min_signers.to_le_bytes())?;

        Ok(())
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut public_key_package_len = [0u8; 4];
        reader.read_exact(&mut public_key_package_len)?;
        let public_key_package_len = u32::from_le_bytes(public_key_package_len) as usize;

        let mut frost_public_key_package = vec![0u8; public_key_package_len];
        reader.read_exact(&mut frost_public_key_package)?;
        let frost_public_key_package =
            FrostPublicKeyPackage::deserialize(&frost_public_key_package)
                .map_err(io::Error::other)?;

        let mut identities_len = [0u8; 4];
        reader.read_exact(&mut identities_len)?;
        let identities_len = u32::from_le_bytes(identities_len) as usize;

        let mut identities = Vec::with_capacity(identities_len);
        for _ in 0..identities_len {
            identities.push(Identity::deserialize_from(&mut reader)?);
        }

        let mut min_signers = [0u8; 2];
        reader.read_exact(&mut min_signers)?;
        let min_signers = u16::from_le_bytes(min_signers);

        Ok(PublicKeyPackage {
            frost_public_key_package,
            identities,
            min_signers,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use reddsa::frost::{
        redjubjub::{keys::split, SigningKey},
        redpallas::frost::keys::IdentifierList,
    };

    use crate::participant::Secret;

    use super::PublicKeyPackage;

    #[test]
    fn serialization_roundtrip() {
        let secret1 = Secret::random(thread_rng());
        let secret2 = Secret::random(thread_rng());
        let id1 = secret1.to_identity();
        let id2 = secret2.to_identity();

        let mut rng = thread_rng();
        let signing_key = SigningKey::new(&mut rng);

        let (_, frost_public_key_package) = split(
            &signing_key,
            2,
            2,
            IdentifierList::Custom(&[id1.to_frost_identifier(), id2.to_frost_identifier()]),
            &mut rng,
        )
        .expect("signing key split failed");

        let public_key_package =
            PublicKeyPackage::from_frost(frost_public_key_package, [id1, id2], 2);

        let serialized = public_key_package.serialize();

        let deserialized = PublicKeyPackage::deserialize_from(&serialized[..])
            .expect("public key package deserialization failed");

        assert_eq!(public_key_package, deserialized)
    }
}
