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
    use super::PublicKeyPackage;
    use crate::participant::Secret;
    use hex_literal::hex;
    use rand::thread_rng;
    use reddsa::frost::{
        redjubjub::{keys::split, SigningKey},
        redpallas::frost::keys::IdentifierList,
    };

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

    #[test]
    fn deserialization_regression() {
        let serialization = hex!(
            "
            a600000000c3d2051e02b62709a88950f3a75eb0d03a9510123a72947eb083b5822
            e874793e8f40f6b0ba381109571a24f9f87421f0393f45cee913ef891bd75eb7ba7
            a5611858a80305cf631451a7d94604cb32d11285ebd4b6ee797eceaa464b2dfcd09
            7295cacf90c579265130e9e37225a23dfd51da2c4b8db499cb0e7aa6b03a15cde2d
            b678e99c94974b2a766f83b134c5c782803f5f5a65bc4a6392f6a81062ad8292e84
            4f3c00200000072cf6be086f2453ec7ce6f7b76fbb35c4dcf6fac1737dbcc2a2467
            b3f0c8453574ad36e9dd2b092aa0870930ed6be8d9ba40c146c5b2110fbb03f7e3b
            60e5d63347f47bd69c418630d0c4d3301f0a910c3d127c9d7064cedf26c0c2f0cea
            9486a8993eea77744ead60ea210bc43a4c56be4933762dddaba145fb215c5dbaebc
            a0272586e451ceb90d00fde8fa96f7eba99845066803aef4073ca39f3af9050b9f0
            bc63deb3652c1455090070a8dd3376128e093726a055bab2e2d2325cb5c978b62eb
            a97c6b42325cf4fc106321b7c8979fc123dc77a5da91ace3b3245405d680b9bcc13
            5828ac28415305d74abe2ca084639dd1ab7bb8c69930cf0a55a1151022020200
        "
        );
        let deserialized =
            PublicKeyPackage::deserialize_from(&serialization[..]).expect("deserialization failed");
        assert_eq!(&serialization[..], deserialized.serialize());
    }
}
