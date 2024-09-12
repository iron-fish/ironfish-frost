/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::checksum::Checksum;
use crate::checksum::ChecksumError;
use crate::checksum::ChecksumHasher;
use crate::checksum::CHECKSUM_LEN;
use crate::dkg::round1;
use crate::error::IronfishFrostError;
use crate::frost;
use crate::frost::keys::dkg::round1::Package as Round1Package;
use crate::frost::keys::dkg::round2::Package;
use crate::frost::keys::dkg::round2::SecretPackage;
use crate::frost::keys::VerifiableSecretSharingCommitment;
use crate::frost::Field;
use crate::frost::Identifier;
use crate::frost::JubjubScalarField;
use crate::io;
use crate::multienc;
use crate::participant;
use crate::participant::Identity;
use crate::serde::read_u16;
use crate::serde::read_variable_length;
use crate::serde::read_variable_length_bytes;
use crate::serde::write_u16;
use crate::serde::write_variable_length;
use crate::serde::write_variable_length_bytes;
use core::borrow::Borrow;
use core::hash::Hasher;
use core::mem;
use rand_core::CryptoRng;
use rand_core::RngCore;
// use log::info;

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

impl<'a> From<&'a SecretPackage> for &'a SerializableSecretPackage {
    #[inline]
    fn from(pkg: &'a SecretPackage) -> Self {
        // SAFETY: The fields of `SecretPackage` and `SerializableSecretPackage` have the same
        // size, alignment, and semantics
        unsafe { mem::transmute(pkg) }
    }
}

impl<'a> From<&'a SerializableSecretPackage> for &'a SecretPackage {
    #[inline]
    fn from(pkg: &'a SerializableSecretPackage) -> Self {
        // SAFETY: The fields of `SecretPackage` and `SerializableSecretPackage` have the same
        // size, alignment, and semantics
        unsafe { mem::transmute(pkg) }
    }
}

impl SerializableSecretPackage {
    fn serialize_into<W: io::Write>(&self, mut writer: W) -> Result<(), IronfishFrostError> {
        writer.write_all(&self.identifier.serialize())?;
        let serialized = self.commitment.serialize()?;
        write_variable_length(&mut writer, serialized, |writer, array| {
            writer.write_all(&array)
        })?;
        writer.write_all(&self.secret_share.to_bytes())?;
        write_u16(&mut writer, self.min_signers)?;
        write_u16(&mut writer, self.max_signers)?;
        Ok(())
    }

    fn deserialize_from<R: io::Read>(mut reader: R) -> Result<Self, IronfishFrostError> {
        let mut identifier = [0u8; 32];
        reader.read_exact(&mut identifier)?;
        let identifier = Identifier::deserialize(&identifier)?;

        let commitment = VerifiableSecretSharingCommitment::deserialize(read_variable_length(
            &mut reader,
            |reader| {
                let mut array = [0u8; 32];
                reader.read_exact(&mut array)?;
                Ok(array)
            },
        )?)?;

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

pub(super) fn get_secret_package_signers(pkg: &SecretPackage) -> (u16, u16) {
    let serializable = <&SerializableSecretPackage>::from(pkg);
    (serializable.min_signers, serializable.max_signers)
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
    serializable
        .serialize_into(&mut serialized)
        .expect("serialization failed");
    Ok(multienc::encrypt(&serialized, [identity], csrng))
}

pub fn import_secret_package(
    exported: &[u8],
    secret: &participant::Secret,
) -> Result<SecretPackage, IronfishFrostError> {
    let serialized =
        multienc::decrypt(secret, exported).map_err(IronfishFrostError::DecryptionError)?;
    SerializableSecretPackage::deserialize_from(&serialized[..]).map(|pkg| pkg.into())
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicPackage {
    sender_identity: Identity,
    recipient_identity: Identity,
    frost_package: Package,
    checksum: Checksum,
}

#[must_use]
pub(super) fn input_checksum<'a, P>(round1_packages: P) -> Checksum
where
    P: IntoIterator<Item = &'a round1::PublicPackage>,
{
    let mut hasher = ChecksumHasher::new();

    let mut round1_packages = round1_packages.into_iter().collect::<Vec<_>>();
    round1_packages.sort_unstable_by_key(|&p| p.identity());
    round1_packages.dedup();
    let round1_packages = round1_packages;

    for package in round1_packages {
        hasher.write(&package.serialize());
    }

    hasher.finish()
}

impl PublicPackage {
    pub(crate) fn new<P>(
        sender_identity: Identity,
        recipient_identity: Identity,
        round1_packages: &[P],
        frost_package: Package,
    ) -> Self
    where
        P: Borrow<round1::PublicPackage>,
    {
        let checksum = input_checksum(round1_packages.iter().map(Borrow::borrow));

        PublicPackage {
            sender_identity,
            recipient_identity,
            frost_package,
            checksum,
        }
    }

    pub fn sender_identity(&self) -> &Identity {
        &self.sender_identity
    }

    pub fn recipient_identity(&self) -> &Identity {
        &self.recipient_identity
    }

    pub fn frost_package(&self) -> &Package {
        &self.frost_package
    }

    pub fn checksum(&self) -> Checksum {
        self.checksum
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize_into(&mut buf).expect("serialization failed");
        buf
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> Result<(), IronfishFrostError> {
        self.sender_identity.serialize_into(&mut writer)?;
        self.serialize_without_sender_into(writer)
    }

    fn serialize_without_sender_into<W: io::Write>(
        &self,
        mut writer: W,
    ) -> Result<(), IronfishFrostError> {
        self.recipient_identity.serialize_into(&mut writer)?;
        let frost_package = self.frost_package.serialize()?;
        write_variable_length_bytes(&mut writer, &frost_package)?;
        Ok(writer.write_all(&self.checksum.to_le_bytes())?)
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> Result<Self, IronfishFrostError> {
        let sender_identity = Identity::deserialize_from(&mut reader)?;
        Self::deserialize_without_sender_from(reader, sender_identity)
    }

    fn deserialize_without_sender_from<R: io::Read>(
        mut reader: R,
        sender_identity: Identity,
    ) -> Result<Self, IronfishFrostError> {
        let recipient_identity = Identity::deserialize_from(&mut reader)?;

        let frost_package = read_variable_length_bytes(&mut reader)?;
        let frost_package = Package::deserialize(&frost_package)?;

        let mut checksum = [0u8; CHECKSUM_LEN];
        reader.read_exact(&mut checksum)?;
        let checksum = u64::from_le_bytes(checksum);

        Ok(Self {
            sender_identity,
            recipient_identity,
            frost_package,
            checksum,
        })
    }
}

/// A collection of [`PublicPackage`] structs, all from the same sender.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct CombinedPublicPackage {
    packages: Vec<PublicPackage>,
}

impl CombinedPublicPackage {
    // This struct should not be constructed directly, hence `new` does not need to be `pub`.
    // Keeping `new` private has the advantage that the implementation does not need to strictly
    // enforce the same `sender_identity`, but it can omit this check (here we still check in debug
    // builds just to catch bugs).
    fn new(packages: Vec<PublicPackage>) -> Self {
        // The serialization expects at least 1 package to be present
        debug_assert!(!packages.is_empty());

        let first_identity = &packages[0].sender_identity;
        for pkg in &packages {
            debug_assert_eq!(&pkg.sender_identity, first_identity);
        }

        Self { packages }
    }

    #[inline]
    #[must_use]
    pub fn packages(&self) -> &[PublicPackage] {
        &self.packages
    }

    #[inline]
    pub fn packages_for<'a>(
        &'a self,
        recipient_identity: &'a Identity,
    ) -> impl Iterator<Item = &'a PublicPackage> + 'a {
        self.packages
            .iter()
            .filter(move |pkg| &pkg.recipient_identity == recipient_identity)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize_into(&mut buf).expect("serialization failed");
        buf
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> Result<(), IronfishFrostError> {
        let sender_identity = &self.packages[0].sender_identity;
        sender_identity.serialize_into(&mut writer)?;
        Ok(write_variable_length(
            writer,
            &self.packages,
            |writer, pkg| {
                pkg.serialize_without_sender_into(writer)
                    .map_err(|_| io::Error::other("serialize_into failed"))
            },
        )?)
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> Result<Self, IronfishFrostError> {
        let sender_identity = Identity::deserialize_from(&mut reader)?;

        let packages = read_variable_length(reader, move |reader| {
            PublicPackage::deserialize_without_sender_from(reader, sender_identity.clone())
                .map_err(|_| io::Error::other("deserialization failed"))
        })?;

        Ok(Self { packages })
    }
}

impl IntoIterator for CombinedPublicPackage {
    type Item = PublicPackage;
    type IntoIter = <Vec<PublicPackage> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.packages.into_iter()
    }
}

pub fn round2<'a, P, R>(
    secret: &participant::Secret,
    round1_secret_package: &[u8],
    round1_public_packages: P,
    mut csrng: R,
) -> Result<(Vec<u8>, CombinedPublicPackage), IronfishFrostError>
where
    P: IntoIterator<Item = &'a round1::PublicPackage>,
    R: RngCore + CryptoRng,
{
    let self_identity = secret.to_identity();
    let round1_secret_package = round1::import_secret_package(round1_secret_package, secret)?;

    // Extract the min/max signers from the secret package
    let (min_signers, max_signers) = round1::get_secret_package_signers(&round1_secret_package);

    let round1_public_packages = round1_public_packages.into_iter().collect::<Vec<_>>();

    // Ensure that the number of public packages provided matches max_signers
    if round1_public_packages.len() != max_signers as usize {
        #[cfg(feature = "std")]
        return Err(IronfishFrostError::InvalidInput(format!(
            "expected {} public packages, got {}",
            max_signers,
            round1_public_packages.len()
        )));

        #[cfg(not(feature = "std"))]
        return Err(IronfishFrostError::InvalidInput(
            "incorrect number of round 1 public packages".to_string(),
        ));
    }

    let expected_round1_checksum = round1::input_checksum(
        min_signers,
        round1_public_packages.iter().map(|pkg| pkg.identity()),
    );

    let mut identities = BTreeMap::new();
    let mut round1_frost_packages: BTreeMap<Identifier, Round1Package> = BTreeMap::new();
    for public_package in round1_public_packages.clone() {
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
                "multiple public packages provided for identity {}",
                public_package.identity()
            )));

            #[cfg(not(feature = "std"))]
            return Err(IronfishFrostError::InvalidInput(
                "multiple public packages provided for an identity".to_string(),
            ));
        }

        identities.insert(frost_identifier, identity);
        round1_frost_packages.insert(
            public_package.identity().to_frost_identifier(),
            public_package.frost_package().clone(),
        );
    }

    // Sanity check
    assert_eq!(round1_public_packages.len(), identities.len());
    assert_eq!(round1_public_packages.len(), round1_frost_packages.len());

    // The public package for `self_identity` must be excluded from `frost::keys::dkg::part2`
    // inputs
    round1_frost_packages
        .remove(&self_identity.to_frost_identifier())
        .expect("missing public package for self_identity");

    // Run the FROST DKG round 2
    let (round2_secret_package, round2_packages) =
        frost::keys::dkg::part2(round1_secret_package.clone(), &round1_frost_packages)?;

    // Encrypt the secret package
    let encrypted_secret_package =
        export_secret_package(&round2_secret_package, &self_identity, &mut csrng)
            .map_err(IronfishFrostError::EncryptionError)?;

    // Convert the Identifier->Package map to an Identity->PublicPackage map
    let mut round2_public_packages = Vec::new();
    for (identifier, package) in round2_packages {
        let identity = *identities
            .get(&identifier)
            .expect("round2 generated package for unknown identifier");

        let public_package = PublicPackage::new(
            self_identity.clone(),
            identity.clone(),
            &round1_public_packages[..],
            package,
        );

        round2_public_packages.push(public_package);
    }

    Ok((
        encrypted_secret_package,
        CombinedPublicPackage::new(round2_public_packages),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

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
        let (_, _, round1_packages) = create_round1_packages();

        let checksum_1 = input_checksum(&round1_packages);
        let checksum_2 = input_checksum(&round1_packages);

        assert_eq!(checksum_1, checksum_2);
    }

    #[test]
    fn test_round2_checksum_variation_with_round1_packages() {
        let (_, _, round1_packages1) = create_round1_packages();
        let (_, _, round1_packages2) = create_round1_packages();

        let checksum_1 = input_checksum(&round1_packages1);
        let checksum_2 = input_checksum(&round1_packages2);

        assert_ne!(checksum_1, checksum_2);
    }

    #[test]
    fn test_round2_package_checksum() {
        let (secret, round1_secret_pkg, round1_packages) = create_round1_packages();
        let (_, round2_packages) =
            create_round2_packages(secret.clone(), round1_secret_pkg, round1_packages.clone());

        let round2_package = round2_packages.values().last().unwrap();
        let package = PublicPackage::new(
            secret.to_identity(),
            // reuses identity for convenience; does not affect checksum
            secret.to_identity(),
            &round1_packages[..],
            round2_package.clone(),
        );
        let checksum = input_checksum(&round1_packages[..]);

        assert_eq!(checksum, package.checksum());
    }

    #[test]
    fn test_round2_package_serialization() {
        let (secret, round1_secret_pkg, round1_packages) = create_round1_packages();
        let (_, round2_packages) =
            create_round2_packages(secret.clone(), round1_secret_pkg, round1_packages.clone());

        let round2_package = round2_packages.values().last().unwrap();
        let package = PublicPackage::new(
            secret.to_identity(),
            // reuses identity for convenience
            secret.to_identity(),
            &round1_packages[..],
            round2_package.clone(),
        );

        let serialized = package.serialize();

        let deserialized = PublicPackage::deserialize_from(&serialized[..])
            .expect("package deserialization failed");

        assert_eq!(package, deserialized);
    }

    #[test]
    fn round2() {
        let secret = participant::Secret::random(thread_rng());
        let identity1 = secret.to_identity();
        let identity2 = participant::Secret::random(thread_rng()).to_identity();
        let identity3 = participant::Secret::random(thread_rng()).to_identity();

        let (round1_secret_package, package1) = round1::round1(
            &identity1,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        let (_, package2) = round1::round1(
            &identity2,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        let (_, package3) = round1::round1(
            &identity3,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        let (secret_package, round2_public_packages) = super::round2(
            &secret,
            &round1_secret_package,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        import_secret_package(&secret_package, &secret)
            .expect("round 2 secret package import failed");

        round2_public_packages
            .packages_for(&identity2)
            .next()
            .expect("round 2 public packages missing package for identity2");
        round2_public_packages
            .packages_for(&identity3)
            .next()
            .expect("round 2 public packages missing package for identity3");
    }

    #[test]
    fn round2_duplicate_packages() {
        let secret = participant::Secret::random(thread_rng());
        let identities = [
            secret.to_identity(),
            participant::Secret::random(thread_rng()).to_identity(),
            participant::Secret::random(thread_rng()).to_identity(),
        ];

        let round1_packages = identities
            .iter()
            .map(|id| round1::round1(id, 2, &identities, thread_rng()).expect("dkg round 1 failed"))
            .collect::<Vec<_>>();

        let result = super::round2(
            &secret,
            &round1_packages[0].0,
            [
                &round1_packages[0].1,
                &round1_packages[0].1,
                &round1_packages[1].1,
                &round1_packages[2].1,
            ],
            thread_rng(),
        );

        match result {
            Err(IronfishFrostError::InvalidInput(_)) => (),
            _ => panic!("dkg round2 should have failed with InvalidInput"),
        }
    }

    #[test]
    fn round2_missing_packages() {
        let secret = participant::Secret::random(thread_rng());
        let identities = [
            secret.to_identity(),
            participant::Secret::random(thread_rng()).to_identity(),
            participant::Secret::random(thread_rng()).to_identity(),
        ];

        let round1_packages = identities
            .iter()
            .map(|id| round1::round1(id, 2, &identities, thread_rng()).expect("dkg round 1 failed"))
            .collect::<Vec<_>>();

        let result = super::round2(
            &secret,
            &round1_packages[0].0,
            [&round1_packages[0].1, &round1_packages[1].1],
            thread_rng(),
        );

        // We can use `assert_matches` once it's stabilized
        match result {
            Err(IronfishFrostError::InvalidInput(_)) => (),
            _ => panic!("dkg round2 should have failed with InvalidInput"),
        }
    }
}
