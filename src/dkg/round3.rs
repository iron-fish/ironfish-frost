/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::checksum::ChecksumError;
use crate::dkg::group_key::GroupSecretKey;
use crate::dkg::group_key::GroupSecretKeyShard;
use crate::dkg::round1;
use crate::dkg::round2;
use crate::dkg::round2::import_secret_package;
use crate::error::IronfishFrostError;
use crate::frost::keys::dkg::part3;
use crate::frost::keys::KeyPackage;
use crate::frost::keys::PublicKeyPackage as FrostPublicKeyPackage;
use crate::io;
use crate::participant::Identity;
use crate::participant::Secret;
use crate::serde::read_u16;
use crate::serde::read_variable_length;
use crate::serde::read_variable_length_bytes;
use crate::serde::write_u16;
use crate::serde::write_variable_length;
use crate::serde::write_variable_length_bytes;
use core::borrow::Borrow;
use ironfish_reddsa::frost::redjubjub::keys::dkg::round1::Package as Round1Package;
use ironfish_reddsa::frost::redjubjub::keys::dkg::round2::Package as Round2Package;
use ironfish_reddsa::frost::redjubjub::VerifyingKey;

#[cfg(feature = "std")]
use std::collections::BTreeMap;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

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
        let frost_public_key_package = self
            .frost_public_key_package
            .serialize()
            .map_err(|_| io::Error::other("public key package serialization failed"))?;
        write_variable_length_bytes(&mut writer, &frost_public_key_package)?;
        write_variable_length(&mut writer, &self.identities, |writer, identity| {
            identity.serialize_into(writer)
        })?;
        write_u16(&mut writer, self.min_signers)?;

        Ok(())
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> Result<Self, IronfishFrostError> {
        let frost_public_key_package = read_variable_length_bytes(&mut reader)?;
        let frost_public_key_package =
            FrostPublicKeyPackage::deserialize(&frost_public_key_package)?;
        let identities =
            read_variable_length(&mut reader, |reader| Identity::deserialize_from(reader))?;
        let min_signers = read_u16(&mut reader)?;

        Ok(PublicKeyPackage {
            frost_public_key_package,
            identities,
            min_signers,
        })
    }
}

pub fn round3<'a, P, Q>(
    secret: &Secret,
    round2_secret_package: &[u8],
    round1_public_packages: P,
    round2_public_packages: Q,
) -> Result<(KeyPackage, PublicKeyPackage, GroupSecretKey), IronfishFrostError>
where
    P: IntoIterator<Item = &'a round1::PublicPackage>,
    Q: IntoIterator<Item = &'a round2::CombinedPublicPackage>,
{
    let identity = secret.to_identity();
    let round2_secret_package = import_secret_package(round2_secret_package, secret)?;
    let round1_public_packages = round1_public_packages.into_iter().collect::<Vec<_>>();
    let round2_public_packages = round2_public_packages
        .into_iter()
        .flat_map(|combo| combo.packages_for(&identity))
        .collect::<Vec<_>>();

    let (min_signers, max_signers) = round2::get_secret_package_signers(&round2_secret_package);

    // Ensure that the number of public packages provided matches max_signers
    let expected_round1_packages = max_signers as usize;
    if round1_public_packages.len() != expected_round1_packages {
        #[cfg(feature = "std")]
        return Err(IronfishFrostError::InvalidInput(format!(
            "expected {} round 1 public packages, got {}",
            expected_round1_packages,
            round1_public_packages.len()
        )));

        #[cfg(not(feature = "std"))]
        return Err(IronfishFrostError::InvalidInput(
            "incorrect number of round 1 public packages".to_string(),
        ));
    }

    let expected_round2_packages = expected_round1_packages.saturating_sub(1);
    if round2_public_packages.len() != expected_round2_packages {
        #[cfg(feature = "std")]
        return Err(IronfishFrostError::InvalidInput(format!(
            "expected {} round 2 public packages, got {}",
            expected_round2_packages,
            round2_public_packages.len()
        )));

        #[cfg(not(feature = "std"))]
        return Err(IronfishFrostError::InvalidInput(
            "incorrect number of round 2 public packages".to_string(),
        ));
    }

    let expected_round1_checksum = round1::input_checksum(
        min_signers,
        round1_public_packages.iter().map(|pkg| pkg.identity()),
    );

    let mut gsk_shards = Vec::new();
    let mut round1_frost_packages = BTreeMap::new();
    let mut identities = Vec::new();

    for public_package in round1_public_packages.iter() {
        if public_package.checksum() != expected_round1_checksum {
            return Err(IronfishFrostError::ChecksumError(
                ChecksumError::DkgPublicPackageError,
            ));
        }

        let identity = public_package.identity();
        let frost_identifier = identity.to_frost_identifier();
        let frost_package = public_package.frost_package().clone();

        if round1_frost_packages
            .insert(frost_identifier, frost_package)
            .is_some()
        {
            #[cfg(feature = "std")]
            return Err(IronfishFrostError::InvalidInput(format!(
                "multiple round 1 public packages provided for identity {}",
                public_package.identity()
            )));

            #[cfg(not(feature = "std"))]
            return Err(IronfishFrostError::InvalidInput(
                "multiple round 1 public packages provided for an identity".to_string(),
            ));
        }

        let gsk_shard = public_package
            .group_secret_key_shard(secret)
            .map_err(IronfishFrostError::DecryptionError)?;
        gsk_shards.push(gsk_shard);
        identities.push(identity.clone());
    }

    // Sanity check
    if round1_public_packages.len() != round1_frost_packages.len() {
        return Err(IronfishFrostError::InvalidInput(
            "incorrect number of round 1 packages provided".to_string(),
        ));
    }

    // The public package for `identity` must be excluded from `frost::keys::dkg::part3`
    // inputs
    round1_frost_packages
        .remove(&identity.to_frost_identifier())
        .ok_or(IronfishFrostError::InvalidInput(
            "missing round 1 public package for own identity".to_string(),
        ))?;

    let expected_round2_checksum =
        round2::input_checksum(round1_public_packages.iter().map(Borrow::borrow));

    let mut round2_frost_packages = BTreeMap::new();
    for public_package in round2_public_packages.iter() {
        if public_package.checksum() != expected_round2_checksum {
            return Err(IronfishFrostError::ChecksumError(
                ChecksumError::DkgPublicPackageError,
            ));
        }

        if !identity.eq(public_package.recipient_identity()) {
            #[cfg(feature = "std")]
            return Err(IronfishFrostError::InvalidInput(format!(
                "round 2 public package does not have the correct recipient identity {:?}",
                public_package.recipient_identity().serialize()
            )));

            #[cfg(not(feature = "std"))]
            return Err(IronfishFrostError::InvalidInput(
                "round 2 public package does not have the correct recipient identity".to_string(),
            ));
        }

        let frost_identifier = public_package.sender_identity().to_frost_identifier();
        let frost_package = public_package.frost_package().clone();

        if round2_frost_packages
            .insert(frost_identifier, frost_package)
            .is_some()
        {
            #[cfg(feature = "std")]
            return Err(IronfishFrostError::InvalidInput(format!(
                "multiple round 2 public packages provided for identity {}",
                public_package.sender_identity(),
            )));

            #[cfg(not(feature = "std"))]
            return Err(IronfishFrostError::InvalidInput(
                "multiple round 2 public packages provided for an identity".to_string(),
            ));
        }
    }

    if round2_public_packages.len() != round2_frost_packages.len() {
        return Err(IronfishFrostError::InvalidInput(
            "incorrect number of round 2 packages provided".to_string(),
        ));
    }

    let (key_package, public_key_package) = part3(
        &round2_secret_package,
        &round1_frost_packages,
        &round2_frost_packages,
    )?;

    let public_key_package =
        PublicKeyPackage::from_frost(public_key_package, identities, min_signers);

    Ok((
        key_package,
        public_key_package,
        GroupSecretKeyShard::combine(&gsk_shards),
    ))
}

pub fn round3_min(
    secret: &Secret,
    participants: Vec<&[u8]>,
    round2_secret_package: &[u8],
    round1_frost_packages: Vec<&[u8]>,
    round2_frost_packages: Vec<&[u8]>,
    gsk_bytes: Vec<&[u8]>,
) -> Result<(KeyPackage, FrostPublicKeyPackage, GroupSecretKey), IronfishFrostError> {
    let round2_secret_package = import_secret_package(round2_secret_package, secret)?;

    let mut round1_packages = BTreeMap::new();
    let mut round2_packages = BTreeMap::new();

    for i in 0..participants.len() {
        let identity = Identity::deserialize_from(participants[i])?;

        let identifier = identity.to_frost_identifier();

        let round1_package = Round1Package::deserialize(round1_frost_packages[i])?;
        round1_packages.insert(identifier, round1_package);

        let round2_package = Round2Package::deserialize(round2_frost_packages[i])?;
        round2_packages.insert(identifier, round2_package);
    }

    let (key_package, public_key_package) =
        part3(&round2_secret_package, &round1_packages, &round2_packages)?;

    let mut gsk_shards: Vec<GroupSecretKeyShard> = Vec::with_capacity(participants.len() + 1);
    for g in gsk_bytes {
        gsk_shards.push(GroupSecretKeyShard::import(secret, g)?);
    }

    Ok((
        key_package,
        public_key_package,
        GroupSecretKeyShard::combine(&gsk_shards),
    ))
}

#[cfg(test)]
mod tests {
    use super::round3;
    use super::round3_min;
    use super::PublicKeyPackage;
    use crate::dkg::round1;
    use crate::dkg::round2;
    use crate::error::IronfishFrostError;
    use crate::participant::Secret;
    extern crate alloc;
    use alloc::vec::Vec;
    use hex_literal::hex;
    use ironfish_reddsa::frost::redjubjub::keys::split;
    use ironfish_reddsa::frost::redjubjub::SigningKey;
    use ironfish_reddsa::frost::redpallas::frost::keys::IdentifierList;
    use rand::thread_rng;

    #[test]
    fn public_pkg_serialization_roundtrip() {
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
    fn public_pkg_deserialization_regression() {
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

    #[test]
    fn test_round3_missing_round1_packages() {
        let secret1 = Secret::random(thread_rng());
        let secret2 = Secret::random(thread_rng());
        let identity1 = secret1.to_identity();
        let identity2 = secret2.to_identity();

        let (round1_secret_package_1, package1) =
            round1::round1(&identity1, 2, [&identity1, &identity2], thread_rng())
                .expect("round 1 failed");

        let (round1_secret_package_2, package2) =
            round1::round1(&identity2, 2, [&identity1, &identity2], thread_rng())
                .expect("round 1 failed");

        let (encrypted_secret_package, _) = round2::round2(
            &secret1,
            &round1_secret_package_1,
            [&package1, &package2],
            thread_rng(),
        )
        .expect("round 2 failed");

        let (_, round2_public_packages) = round2::round2(
            &secret2,
            &round1_secret_package_2,
            [&package1, &package2],
            thread_rng(),
        )
        .expect("round 2 failed");

        let result = round3(
            &secret1,
            &encrypted_secret_package,
            [&package2],
            [&round2_public_packages],
        );

        match result {
            Err(IronfishFrostError::InvalidInput(_)) => (),
            _ => panic!("dkg round3 should have failed with InvalidInput"),
        }
    }

    #[test]
    fn test_round3_invalid_round1_checksum() {
        let secret1 = Secret::random(thread_rng());
        let secret2 = Secret::random(thread_rng());
        let identity1 = secret1.to_identity();
        let identity2 = secret2.to_identity();

        let (round1_secret_package_1, package1) =
            round1::round1(&identity1, 2, [&identity1, &identity2], thread_rng())
                .expect("round 1 failed");

        let (round1_secret_package_2, package2) =
            round1::round1(&identity2, 2, [&identity1, &identity2], thread_rng())
                .expect("round 1 failed");

        let (encrypted_secret_package, _) = round2::round2(
            &secret1,
            &round1_secret_package_1,
            [&package1, &package2],
            thread_rng(),
        )
        .expect("round 2 failed");

        let (_, round2_public_packages) = round2::round2(
            &secret2,
            &round1_secret_package_2,
            [&package1, &package2],
            thread_rng(),
        )
        .expect("round 2 failed");

        let result = round3(
            &secret1,
            &encrypted_secret_package,
            [&package1, &package1],
            [&round2_public_packages],
        );

        match result {
            Err(IronfishFrostError::ChecksumError(_)) => (),
            _ => panic!("dkg round3 should have failed with ChecksumError"),
        }
    }

    #[test]
    fn test_round3() {
        let secret1 = Secret::random(thread_rng());
        let secret2 = Secret::random(thread_rng());
        let secret3 = Secret::random(thread_rng());
        let identity1 = secret1.to_identity();
        let identity2 = secret2.to_identity();
        let identity3 = secret3.to_identity();

        let (round1_secret_package_1, package1) = round1::round1(
            &identity1,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        let (round1_secret_package_2, package2) = round1::round1(
            &identity2,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        let (round1_secret_package_3, package3) = round1::round1(
            &identity3,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        let (encrypted_secret_package, _) = round2::round2(
            &secret1,
            &round1_secret_package_1,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        let (_, round2_public_packages_2) = round2::round2(
            &secret2,
            &round1_secret_package_2,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        let (_, round2_public_packages_3) = round2::round2(
            &secret3,
            &round1_secret_package_3,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        round3(
            &secret1,
            &encrypted_secret_package,
            [&package1, &package2, &package3],
            [&round2_public_packages_2, &round2_public_packages_3],
        )
        .expect("round 3 failed");
    }

    #[test]
    fn test_round3_min() {
        let secret1 = Secret::random(thread_rng());
        let secret2 = Secret::random(thread_rng());
        let secret3 = Secret::random(thread_rng());
        let identity1 = secret1.to_identity();
        let identity2 = secret2.to_identity();
        let identity3 = secret3.to_identity();

        let (round1_secret_package_1, package1) = round1::round1(
            &identity1,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        let (round1_secret_package_2, package2) = round1::round1(
            &identity2,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        let (round1_secret_package_3, package3) = round1::round1(
            &identity3,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        let (encrypted_secret_package, _) = round2::round2(
            &secret1,
            &round1_secret_package_1,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        let (_, round2_public_packages_2) = round2::round2(
            &secret2,
            &round1_secret_package_2,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        let (_, round2_public_packages_3) = round2::round2(
            &secret3,
            &round1_secret_package_3,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        let id2_ser: &[u8] = &identity2.serialize();
        let id3_ser: &[u8] = &identity3.serialize();
        let participants = vec![id2_ser, id3_ser];

        let pkg2_ser = package2
            .frost_package()
            .serialize()
            .expect("serialization failed");
        let pkg3_ser = package3
            .frost_package()
            .serialize()
            .expect("serialization failed");

        let round1_frost_packages: Vec<&[u8]> = vec![&pkg2_ser[..], &pkg3_ser[..]];

        let pkg2_2 = round2_public_packages_2
            .package_for(&identity1)
            .expect("missing round2 public package for identity")
            .frost_package()
            .serialize()
            .expect("round2 public package serialization failed");
        let pkg2_3 = round2_public_packages_3
            .package_for(&identity1)
            .expect("missing round2 public package for identity")
            .frost_package()
            .serialize()
            .expect("round2 public package serialization failed");

        let round2_frost_packages: Vec<&[u8]> = vec![&pkg2_2[..], &pkg2_3[..]];

        let gsk_bytes: Vec<&[u8]> = vec![
            package1.group_secret_key_shard_encrypted(),
            package2.group_secret_key_shard_encrypted(),
            package3.group_secret_key_shard_encrypted(),
        ];

        round3_min(
            &secret1,
            participants,
            &encrypted_secret_package,
            round1_frost_packages,
            round2_frost_packages,
            gsk_bytes,
        )
        .expect("round 3 failed");
    }
}
