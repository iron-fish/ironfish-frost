/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::checksum::Checksum;
use crate::checksum::ChecksumHasher;
use crate::checksum::CHECKSUM_LEN;
use crate::frost::keys::dkg::round2::Package;
use crate::frost::keys::dkg::round2::SecretPackage;
use crate::frost::keys::VerifiableSecretSharingCommitment;
use crate::frost::Field;
use crate::frost::Identifier;
use crate::frost::JubjubScalarField;
use crate::multienc;
use crate::multienc::MultiRecipientBlob;
use crate::participant;
use crate::participant::Identity;
use crate::serde::read_u16;
use crate::serde::read_variable_length;
use crate::serde::read_variable_length_bytes;
use crate::serde::write_u16;
use crate::serde::write_variable_length;
use crate::serde::write_variable_length_bytes;
use rand_core::CryptoRng;
use rand_core::RngCore;
use std::borrow::Borrow;
use std::hash::Hasher;
use std::io;
use std::mem;

use super::group_key::GroupSecretKey;
use super::group_key::GROUP_SECRET_KEY_LEN;
use super::round1;

type Scalar = <JubjubScalarField as Field>::Scalar;

/// Copy of the [`frost_core::dkg::round2::SecretPackage`] struct. Necessary to implement
/// serialization for this struct. This must be kept in sync with the upstream version.
struct SerializableSecretPackage {
    identifier: Identifier,
    commitment: VerifiableSecretSharingCommitment,
    secret_share: Scalar,
    min_signers: u16,
    max_signers: u16,
}

impl From<SecretPackage> for SerializableSecretPackage {
    #[inline]
    fn from(pkg: SecretPackage) -> Self {
        // SAFETY: The fields of `SecretPackage` and `SerializableSecretPackage` have the same
        // size, alignment, and semantics
        unsafe { mem::transmute(pkg) }
    }
}

impl From<SerializableSecretPackage> for SecretPackage {
    #[inline]
    fn from(pkg: SerializableSecretPackage) -> Self {
        // SAFETY: The fields of `SecretPackage` and `SerializableSecretPackage` have the same
        // size, alignment, and semantics
        unsafe { mem::transmute(pkg) }
    }
}

impl SerializableSecretPackage {
    fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.identifier.serialize())?;
        write_variable_length(&mut writer, self.commitment.serialize(), |writer, array| {
            writer.write_all(&array)
        })?;
        writer.write_all(&self.secret_share.to_bytes())?;
        write_u16(&mut writer, self.min_signers)?;
        write_u16(&mut writer, self.max_signers)?;
        Ok(())
    }

    fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut identifier = [0u8; 32];
        reader.read_exact(&mut identifier)?;
        let identifier = Identifier::deserialize(&identifier).map_err(io::Error::other)?;

        let commitment = VerifiableSecretSharingCommitment::deserialize(read_variable_length(
            &mut reader,
            |reader| {
                let mut array = [0u8; 32];
                reader.read_exact(&mut array)?;
                Ok(array)
            },
        )?)
        .map_err(io::Error::other)?;

        let mut scalar = [0u8; 32];
        reader.read_exact(&mut scalar)?;
        let scalar: Option<Scalar> = Scalar::from_bytes(&scalar).into();
        let secret_share =
            scalar.ok_or_else(|| io::Error::other("secret_share deserialization failed"))?;

        let min_signers = read_u16(&mut reader)?;
        let max_signers = read_u16(&mut reader)?;

        Ok(Self {
            identifier,
            commitment,
            secret_share,
            min_signers,
            max_signers,
        })
    }
}

pub fn export_secret_package<R: RngCore + CryptoRng>(
    pkg: &SecretPackage,
    identity: &Identity,
    csrng: R,
) -> io::Result<Vec<u8>> {
    let serializable = SerializableSecretPackage::from(pkg.clone());
    if serializable.identifier != identity.to_frost_identifier() {
        return Err(io::Error::other("identity mismatch"));
    }
    let mut serialized = Vec::new();
    serializable.serialize_into(&mut serialized)?;
    multienc::encrypt(&serialized, [identity], csrng).serialize()
}

pub fn import_secret_package(
    exported: &[u8],
    secret: &participant::Secret,
) -> io::Result<SecretPackage> {
    let exported = MultiRecipientBlob::deserialize_from(exported)?;
    let serialized = multienc::decrypt(secret, &exported).map_err(io::Error::other)?;
    SerializableSecretPackage::deserialize_from(&serialized[..]).map(|pkg| pkg.into())
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicPackage {
    identity: Identity,
    frost_package: Package,
    group_secret_key: GroupSecretKey,
    checksum: Checksum,
}

#[allow(dead_code)]
fn input_checksum(
    round1_packages: &[round1::PublicPackage],
    group_secret_key: GroupSecretKey,
) -> Checksum {
    let mut hasher = ChecksumHasher::new();

    let mut packages = round1_packages
        .iter()
        .map(Borrow::borrow)
        .collect::<Vec<_>>();
    packages.sort_unstable();
    packages.dedup();

    for package in packages {
        hasher.write(&package.serialize());
    }
    hasher.write(&group_secret_key);

    hasher.finish()
}

impl PublicPackage {
    #[allow(dead_code)]
    pub(crate) fn new(
        identity: Identity,
        round1_packages: &[round1::PublicPackage],
        frost_package: Package,
        group_secret_key: GroupSecretKey,
    ) -> Self {
        let checksum = input_checksum(round1_packages, group_secret_key);

        PublicPackage {
            identity,
            frost_package,
            group_secret_key,
            checksum,
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn frost_package(&self) -> &Package {
        &self.frost_package
    }

    pub fn group_secret_key(&self) -> &GroupSecretKey {
        &self.group_secret_key
    }

    pub fn checksum(&self) -> Checksum {
        self.checksum
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize_into(&mut buf).expect("serialization failed");
        buf
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.identity.serialize_into(&mut writer)?;
        let frost_package = self.frost_package.serialize().map_err(io::Error::other)?;
        write_variable_length_bytes(&mut writer, &frost_package)?;
        writer.write_all(self.group_secret_key())?;
        writer.write_all(&self.checksum.to_le_bytes())?;
        Ok(())
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let identity = Identity::deserialize_from(&mut reader).expect("reading identity failed");

        let frost_package = read_variable_length_bytes(&mut reader)?;
        let frost_package = Package::deserialize(&frost_package).map_err(io::Error::other)?;

        let mut group_secret_key = [0u8; GROUP_SECRET_KEY_LEN];
        reader.read_exact(&mut group_secret_key)?;

        let mut checksum = [0u8; CHECKSUM_LEN];
        reader.read_exact(&mut checksum)?;
        let checksum = u64::from_le_bytes(checksum);

        Ok(Self {
            identity,
            frost_package,
            group_secret_key,
            checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost;
    use rand::{random, thread_rng};
    use std::collections::BTreeMap;

    fn create_round1_packages() -> (
        participant::Secret,
        frost::keys::dkg::round1::SecretPackage,
        Vec<round1::PublicPackage>,
    ) {
        let min_signers = 5;
        let max_signers = 10;
        let mut secrets = Vec::new();
        let mut participants = Vec::new();

        for _ in 0..max_signers {
            let secret = participant::Secret::random(thread_rng());
            secrets.push(secret.clone());
            participants.push(secret.to_identity());
        }

        let mut secret_packages = Vec::new();
        let mut public_packages = Vec::new();

        for secret in secrets.iter() {
            let participant = &secret.to_identity();

            let (encrypted_secret_pkg, public_pkg) =
                round1::round1(participant, min_signers, &participants[..], thread_rng())
                    .expect("dkg round 1 failed");

            let secret_pkg = round1::import_secret_package(&encrypted_secret_pkg, secret)
                .expect("secret package decryption failed");
            secret_packages.push(secret_pkg);
            public_packages.push(public_pkg);
        }

        let secret = secrets[0].clone();
        let _id = secret.to_identity().to_frost_identifier();
        let round1_secret_pkg = secret_packages[0].clone();

        (secret, round1_secret_pkg, public_packages)
    }

    fn create_round2_packages(
        secret: participant::Secret,
        round1_secret_pkg: frost::keys::dkg::round1::SecretPackage,
        round1_packages: Vec<round1::PublicPackage>,
    ) -> (SecretPackage, BTreeMap<Identifier, Package>) {
        let mut packages = BTreeMap::new();
        for package in round1_packages {
            packages.insert(
                package.identity().to_frost_identifier(),
                package.frost_package().clone(),
            );
        }
        packages.remove(&secret.to_identity().to_frost_identifier());

        let (round2_secret_pkg, round2_pkgs) =
            frost::keys::dkg::part2(round1_secret_pkg, &packages).expect("dkg round 2 failed");

        (round2_secret_pkg, round2_pkgs)
    }

    #[test]
    fn serialize_deserialize() {
        let (secret, round1_secret_pkg, round1_packages) = create_round1_packages();
        let (secret_pkg, _) = create_round2_packages(secret, round1_secret_pkg, round1_packages);

        let mut serialized = Vec::new();
        SerializableSecretPackage::from(secret_pkg.clone())
            .serialize_into(&mut serialized)
            .expect("serialization failed");

        let deserialized: SecretPackage =
            SerializableSecretPackage::deserialize_from(&serialized[..])
                .expect("deserialization failed")
                .into();

        assert_eq!(secret_pkg, deserialized);
    }

    #[test]
    fn export_import() {
        let (secret, round1_secret_pkg, round1_packages) = create_round1_packages();
        let (secret_pkg, _) =
            create_round2_packages(secret.clone(), round1_secret_pkg, round1_packages);

        let exported =
            export_secret_package(&secret_pkg, &secret.clone().to_identity(), thread_rng())
                .expect("export failed");
        let imported = import_secret_package(&exported, &secret).expect("import failed");

        assert_eq!(secret_pkg, imported);
    }

    #[test]
    fn test_round2_checksum_stability() {
        let group_secret_key: [u8; 32] = random();
        let (_, _, round1_packages) = create_round1_packages();

        let checksum_1 = input_checksum(&round1_packages, group_secret_key);
        let checksum_2 = input_checksum(&round1_packages, group_secret_key);

        assert_eq!(checksum_1, checksum_2);
    }

    #[test]
    fn test_round2_checksum_variation_with_round1_packages() {
        let group_secret_key: [u8; 32] = random();
        let (_, _, round1_packages1) = create_round1_packages();
        let (_, _, round1_packages2) = create_round1_packages();

        let checksum_1 = input_checksum(&round1_packages1, group_secret_key);
        let checksum_2 = input_checksum(&round1_packages2, group_secret_key);

        assert_ne!(checksum_1, checksum_2);
    }

    #[test]
    fn test_round2_checksum_variation_with_group_secret_key() {
        let group_secret_key1: [u8; 32] = random();
        let group_secret_key2: [u8; 32] = random();
        let (_, _, round1_packages) = create_round1_packages();

        let checksum_1 = input_checksum(&round1_packages, group_secret_key1);
        let checksum_2 = input_checksum(&round1_packages, group_secret_key2);

        assert_ne!(checksum_1, checksum_2);
    }

    #[test]
    fn test_round2_package_checksum() {
        let group_secret_key: [u8; 32] = random();
        let (secret, round1_secret_pkg, round1_packages) = create_round1_packages();
        let (_, round2_packages) =
            create_round2_packages(secret.clone(), round1_secret_pkg, round1_packages.clone());

        let round2_package = round2_packages.values().last().unwrap();
        let package = PublicPackage::new(
            secret.to_identity(),
            &round1_packages[..],
            round2_package.clone(),
            group_secret_key,
        );
        let checksum = input_checksum(&round1_packages[..], group_secret_key);

        assert_eq!(checksum, package.checksum());
    }

    #[test]
    fn test_round2_package_serialization() {
        let group_secret_key: [u8; 32] = random();
        let (secret, round1_secret_pkg, round1_packages) = create_round1_packages();
        let (_, round2_packages) =
            create_round2_packages(secret.clone(), round1_secret_pkg, round1_packages.clone());

        let round2_package = round2_packages.values().last().unwrap();
        let package = PublicPackage::new(
            secret.to_identity(),
            &round1_packages[..],
            round2_package.clone(),
            group_secret_key,
        );

        let serialized = package.serialize();

        let deserialized = PublicPackage::deserialize_from(&serialized[..])
            .expect("package deserialization failed");

        assert_eq!(package, deserialized);
    }
}
