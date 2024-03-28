/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::collections::BTreeMap;
use std::error;
use std::fmt;

use crate::checksum::ChecksumError;
use crate::frost::keys::dkg::part1 as frost_part1;
use crate::frost::keys::dkg::part2 as frost_part2;
use crate::frost::keys::dkg::part3 as frost_part3;
use crate::frost::keys::dkg::round1 as frost_round1;
use crate::frost::keys::dkg::round2 as frost_round2;
use crate::participant::Identity;
use rand_core::CryptoRng;
use rand_core::RngCore;
use reddsa::frost::redjubjub::keys::KeyPackage;
use reddsa::frost::redjubjub::keys::PublicKeyPackage;
use reddsa::frost::redjubjub::Error as FrostError;
use reddsa::frost::redjubjub::Identifier;

#[derive(Clone, Debug)]
pub enum DkgError {
    Checksum(ChecksumError),
    Frost(FrostError),
}

impl fmt::Display for DkgError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DkgError::Checksum(ref e) => e.fmt(f),
            DkgError::Frost(ref e) => e.fmt(f),
        }
    }
}

impl error::Error for DkgError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            DkgError::Checksum(ref e) => Some(e),
            DkgError::Frost(ref e) => Some(e),
        }
    }
}

impl From<FrostError> for DkgError {
    fn from(e: FrostError) -> DkgError {
        DkgError::Frost(e)
    }
}

impl From<ChecksumError> for DkgError {
    fn from(e: ChecksumError) -> DkgError {
        DkgError::Checksum(e)
    }
}

mod round1 {
    use std::borrow::Borrow;
    use std::cmp;
    use std::hash::Hasher;

    use siphasher::sip::SipHasher24;

    use crate::checksum::Checksum;
    use crate::checksum::ChecksumError;
    use crate::frost::keys::dkg::round1 as frost_round1;
    use crate::participant::Identity;

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Package {
        identity: Identity,
        frost_package: frost_round1::Package,
        group_key_part: [u8; 32],
        checksum: Checksum,
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct SecretPackage {
        frost_secret_package: frost_round1::SecretPackage,
        group_key_part: [u8; 32],
        checksum: Checksum,
    }

    #[must_use]
    fn input_checksum<I>(min_signers: u16, signing_participants: &[I]) -> Checksum
    where
        I: Borrow<Identity>,
    {
        let mut signing_participants = signing_participants
            .iter()
            .map(Borrow::borrow)
            .collect::<Vec<_>>();
        signing_participants.sort_unstable();
        signing_participants.dedup();

        let mut hasher = SipHasher24::new();
        hasher.write(&min_signers.to_le_bytes());

        for id in signing_participants {
            hasher.write(&id.serialize());
        }

        hasher.finish()
    }

    impl Package {
        pub(crate) fn new(
            identity: Identity,
            signing_participants: &[Identity],
            min_signers: u16,
            group_key_part: [u8; 32],
            frost_package: frost_round1::Package,
        ) -> Self {
            let checksum = input_checksum(min_signers, signing_participants);

            Package {
                identity,
                frost_package,
                group_key_part,
                checksum,
            }
        }

        pub fn identity(&self) -> &Identity {
            &self.identity
        }

        pub fn frost_package(&self) -> &frost_round1::Package {
            &self.frost_package
        }

        pub fn checksum(&self) -> Checksum {
            self.checksum
        }
    }

    impl Ord for Package {
        #[inline]
        fn cmp(&self, other: &Self) -> cmp::Ordering {
            Ord::cmp(&self.identity(), &other.identity())
        }
    }

    impl PartialOrd<Self> for Package {
        #[inline]
        fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl SecretPackage {
        pub(crate) fn new(
            signing_participants: &[Identity],
            min_signers: u16,
            group_key_part: [u8; 32],
            frost_secret_package: frost_round1::SecretPackage,
        ) -> Self {
            let checksum = input_checksum(min_signers, signing_participants);

            SecretPackage {
                group_key_part,
                frost_secret_package,
                checksum,
            }
        }

        pub(crate) fn frost_secret_package(&self) -> &frost_round1::SecretPackage {
            &self.frost_secret_package
        }

        pub fn verify_package_checksum(&self, package: &Package) -> Result<(), ChecksumError> {
            if self.checksum != package.checksum() {
                Err(ChecksumError)
            } else {
                Ok(())
            }
        }
    }
}

pub fn part1<T: RngCore + CryptoRng>(
    identity: Identity,
    signing_participants: &[Identity],
    min_signers: u16,
    group_key_part: [u8; 32],
    rng: T,
) -> Result<(round1::SecretPackage, round1::Package), DkgError> {
    let max_signers = signing_participants.len() as u16;

    let (frost_secret_package, frost_package) = frost_part1(
        identity.to_frost_identifier(),
        max_signers,
        min_signers,
        rng,
    )?;

    Ok((
        round1::SecretPackage::new(
            signing_participants,
            min_signers,
            group_key_part,
            frost_secret_package,
        ),
        round1::Package::new(
            identity,
            signing_participants,
            min_signers,
            group_key_part,
            frost_package,
        ),
    ))
}

mod round2 {
    use std::borrow::Borrow;
    use std::hash::Hasher;

    use reddsa::frost::redjubjub::Error;
    use siphasher::sip::SipHasher24;

    use crate::checksum::{Checksum, ChecksumError};
    use crate::frost::keys::dkg::round2 as frost_round2;
    use crate::participant::Identity;

    use super::round1;

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Package {
        identity: Identity,
        frost_package: frost_round2::Package,
        group_secret_key: [u8; 32],
        checksum: Checksum,
    }
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct SecretPackage {
        frost_secret_package: frost_round2::SecretPackage,
        group_secret_key: [u8; 32],
        checksum: Checksum,
    }

    fn input_checksum<P>(packages: &[P], group_secret_key: [u8; 32]) -> Result<Checksum, Error>
    where
        P: Borrow<round1::Package>,
    {
        let mut packages = packages.iter().map(Borrow::borrow).collect::<Vec<_>>();
        packages.sort_unstable();
        packages.dedup();

        let mut hasher = SipHasher24::new();

        for package in packages {
            hasher.write(&package.frost_package().serialize()?);
        }

        hasher.write(&group_secret_key);

        Ok(hasher.finish())
    }

    impl Package {
        pub(crate) fn new(
            identity: Identity,
            round1_packages: &[round1::Package],
            group_secret_key: [u8; 32],
            frost_package: frost_round2::Package,
        ) -> Result<Self, Error> {
            let checksum = input_checksum(round1_packages, group_secret_key)?;

            Ok(Package {
                identity,
                frost_package,
                group_secret_key,
                checksum,
            })
        }

        pub fn checksum(&self) -> Checksum {
            self.checksum
        }

        pub fn identity(&self) -> &Identity {
            &self.identity
        }

        pub fn frost_package(&self) -> &frost_round2::Package {
            &self.frost_package
        }
    }

    impl SecretPackage {
        pub(crate) fn new(
            round1_packages: &[round1::Package],
            group_secret_key: [u8; 32],
            frost_secret_package: frost_round2::SecretPackage,
        ) -> Result<Self, Error> {
            let checksum = input_checksum(round1_packages, group_secret_key)?;

            Ok(SecretPackage {
                frost_secret_package,
                group_secret_key,
                checksum,
            })
        }

        pub(crate) fn frost_secret_package(&self) -> &frost_round2::SecretPackage {
            &self.frost_secret_package
        }

        pub fn verify_package_checksum(&self, package: &Package) -> Result<(), ChecksumError> {
            if self.checksum != package.checksum() {
                Err(ChecksumError)
            } else {
                Ok(())
            }
        }
    }
}

pub fn part2(
    identity: Identity,
    secret_package: &round1::SecretPackage,
    round1_packages: &[round1::Package],
    group_secret_key: [u8; 32],
) -> Result<(round2::SecretPackage, Vec<round2::Package>), DkgError> {
    let mut round1_frost_packages_map: BTreeMap<Identifier, frost_round1::Package> =
        BTreeMap::new();

    let mut identity_map: BTreeMap<Identifier, Identity> = BTreeMap::new();

    for package in round1_packages {
        if package.identity() == &identity {
            continue;
        }

        secret_package.verify_package_checksum(package)?;

        round1_frost_packages_map.insert(
            package.identity().to_frost_identifier(),
            package.frost_package().clone(),
        );

        identity_map.insert(
            package.identity().to_frost_identifier(),
            package.identity().clone(),
        );
    }

    let (frost_secret_package, round2_frost_packages_map) = frost_part2(
        secret_package.frost_secret_package().clone(),
        &round1_frost_packages_map,
    )?;

    let secret_package: round2::SecretPackage =
        round2::SecretPackage::new(round1_packages, group_secret_key, frost_secret_package)?;

    let mut round2_packages: Vec<round2::Package> = Vec::new();

    for (identifier, round2_frost_package) in round2_frost_packages_map.iter() {
        let identity = identity_map
            .remove(identifier)
            .expect("part2 generated package for unknown identity");

        let round2_package = round2::Package::new(
            identity.clone(),
            round1_packages,
            group_secret_key,
            round2_frost_package.clone(),
        )?;

        round2_packages.push(round2_package);
    }

    Ok((secret_package, round2_packages))
}

pub fn part3(
    identity: Identity,
    secret_package: &round2::SecretPackage,
    round1_packages: &[round1::Package],
    round2_packages: &[round2::Package],
) -> Result<(KeyPackage, PublicKeyPackage), DkgError> {
    let mut round1_frost_packages_map: BTreeMap<Identifier, frost_round1::Package> =
        BTreeMap::new();
    let mut round2_frost_packages_map: BTreeMap<Identifier, frost_round2::Package> =
        BTreeMap::new();

    for package in round1_packages {
        if package.identity() == &identity {
            continue;
        }

        round1_frost_packages_map.insert(
            package.identity().to_frost_identifier(),
            package.frost_package().clone(),
        );
    }

    for package in round2_packages {
        if package.identity() == &identity {
            continue;
        }

        secret_package.verify_package_checksum(package)?;

        round2_frost_packages_map.insert(
            package.identity().to_frost_identifier(),
            package.frost_package().clone(),
        );
    }

    let (key_package, public_key_package) = frost_part3(
        secret_package.frost_secret_package(),
        &round1_frost_packages_map,
        &round2_frost_packages_map,
    )?;

    Ok((key_package, public_key_package))
}

#[cfg(test)]
mod tests {
    use rand::random;
    use rand::thread_rng;

    use crate::dkg::part1;
    use crate::dkg::part2;
    use crate::participant::Secret;

    use super::part3;

    #[test]
    fn test_round1_checksum_stability() {
        let mut rng = thread_rng();

        let group_key_part: [u8; 32] = random();

        let signing_participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let min_signers1: u16 = 2;

        let identity = &signing_participants[0];

        let (_, package_1) = part1(
            identity.clone(),
            &signing_participants,
            min_signers1,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let (_, package_2) = part1(
            identity.clone(),
            &signing_participants,
            min_signers1,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        assert_eq!(package_1.checksum(), package_2.checksum());
    }

    #[test]
    fn test_round1_checksum_variation_with_min_signers() {
        let mut rng = thread_rng();

        let group_key_part: [u8; 32] = random();

        let signing_participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let min_signers1: u16 = 2;
        let min_signers2: u16 = 3;

        let identity = &signing_participants[0];

        let (_, package_1) = part1(
            identity.clone(),
            &signing_participants,
            min_signers1,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let (_, package_2) = part1(
            identity.clone(),
            &signing_participants,
            min_signers2,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        assert_ne!(package_1.checksum(), package_2.checksum());
    }

    #[test]
    fn test_round1_checksum_variation_with_signing_participants() {
        let mut rng = thread_rng();

        let group_key_part: [u8; 32] = random();

        let identity = Secret::random(&mut rng).to_identity();

        let signing_participants1 = [
            identity.clone(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let signing_participants2 = [
            identity.clone(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let min_signers: u16 = 2;

        let (_, package1) = part1(
            identity.clone(),
            &signing_participants1,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let (_, package2) = part1(
            identity.clone(),
            &signing_participants2,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        assert_ne!(package1.checksum(), package2.checksum());
    }

    #[test]
    fn test_part1_checksum_verification() {
        let mut rng = thread_rng();

        let group_key_part: [u8; 32] = random();

        let signing_participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let min_signers1: u16 = 2;
        let min_signers2: u16 = 3;

        let identity = &signing_participants[0];

        let (secret_package, package_1) = part1(
            identity.clone(),
            &signing_participants,
            min_signers1,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let (_, package_2) = part1(
            identity.clone(),
            &signing_participants,
            min_signers2,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let group_secret_key: [u8; 32] = random();

        part2(
            identity.clone(),
            &secret_package,
            &[package_1, package_2],
            group_secret_key,
        )
        .expect_err("checksum verification should fail for mismatched package checksums");
    }

    #[test]
    fn test_round2_checksum_stability() {
        let mut rng = thread_rng();

        let group_key_part: [u8; 32] = random();

        let identity1 = Secret::random(&mut rng).to_identity();
        let identity2 = Secret::random(&mut rng).to_identity();

        let signing_participants = [identity1.clone(), identity2.clone()];

        let min_signers: u16 = 2;

        let (secret_package1, package1) = part1(
            identity1.clone(),
            &signing_participants,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let (secret_package2, package2) = part1(
            identity2.clone(),
            &signing_participants,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let group_secret_key: [u8; 32] = random();

        let (_, round2_packages1) = part2(
            identity1,
            &secret_package1,
            &[package1.clone(), package2.clone()],
            group_secret_key,
        )
        .expect("creating round2 packages should not fail");

        assert_eq!(round2_packages1.len(), 1);

        let (_, round2_packages2) = part2(
            identity2,
            &secret_package2,
            &[package1.clone(), package2.clone()],
            group_secret_key,
        )
        .expect("creating round2 packages should not fail");

        assert_eq!(round2_packages2.len(), 1);

        assert_eq!(
            round2_packages1[0].checksum(),
            round2_packages2[0].checksum()
        )
    }

    #[test]
    fn test_round2_checksum_variation_with_packages() {
        let mut rng = thread_rng();

        let group_key_part: [u8; 32] = random();

        let identity1 = Secret::random(&mut rng).to_identity();
        let identity2 = Secret::random(&mut rng).to_identity();

        let signing_participants = [identity1.clone(), identity2.clone()];

        let min_signers: u16 = 2;

        let (secret_package1, package1) = part1(
            identity1.clone(),
            &signing_participants,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let (secret_package2a, package2a) = part1(
            identity2.clone(),
            &signing_participants,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let (_, package2b) = part1(
            identity2.clone(),
            &signing_participants,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let group_secret_key: [u8; 32] = random();

        let (_, round2_packages1) = part2(
            identity1,
            &secret_package1,
            &[package1.clone(), package2a],
            group_secret_key,
        )
        .expect("creating round2 packages should not fail");

        assert_eq!(round2_packages1.len(), 1);

        let (_, round2_packages2) = part2(
            identity2,
            &secret_package2a,
            &[package1.clone(), package2b],
            group_secret_key,
        )
        .expect("creating round2 packages should not fail");

        assert_eq!(round2_packages2.len(), 1);

        assert_ne!(
            round2_packages1[0].checksum(),
            round2_packages2[0].checksum()
        )
    }

    #[test]
    fn test_round2_checksum_variation_with_group_secret_key() {
        let mut rng = thread_rng();

        let group_key_part: [u8; 32] = random();

        let identity1 = Secret::random(&mut rng).to_identity();
        let identity2 = Secret::random(&mut rng).to_identity();

        let signing_participants = [identity1.clone(), identity2.clone()];

        let min_signers: u16 = 2;

        let (secret_package1, package1) = part1(
            identity1.clone(),
            &signing_participants,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let (secret_package2, package2) = part1(
            identity2.clone(),
            &signing_participants,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let group_secret_key1: [u8; 32] = random();
        let group_secret_key2: [u8; 32] = random();

        let (_, round2_packages1) = part2(
            identity1,
            &secret_package1,
            &[package1.clone(), package2.clone()],
            group_secret_key1,
        )
        .expect("creating round2 packages should not fail");

        assert_eq!(round2_packages1.len(), 1);

        let (_, round2_packages2) = part2(
            identity2,
            &secret_package2,
            &[package1.clone(), package2.clone()],
            group_secret_key2,
        )
        .expect("creating round2 packages should not fail");

        assert_eq!(round2_packages2.len(), 1);

        assert_ne!(
            round2_packages1[0].checksum(),
            round2_packages2[0].checksum()
        )
    }

    #[test]
    fn test_part3_checksum_verification() {
        let mut rng = thread_rng();

        let group_key_part: [u8; 32] = random();

        let identity1 = Secret::random(&mut rng).to_identity();
        let identity2 = Secret::random(&mut rng).to_identity();

        let signing_participants = [identity1.clone(), identity2.clone()];

        let min_signers: u16 = 2;

        let (secret_package1, package1) = part1(
            identity1.clone(),
            &signing_participants,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let (secret_package2, package2) = part1(
            identity2.clone(),
            &signing_participants,
            min_signers,
            group_key_part,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let group_secret_key1: [u8; 32] = random();
        let group_secret_key2: [u8; 32] = random();

        let (round2_secret_package, _) = part2(
            identity1.clone(),
            &secret_package1,
            &[package1.clone(), package2.clone()],
            group_secret_key1,
        )
        .expect("creating round2 packages should not fail");

        let (_, round2_packages2) = part2(
            identity2,
            &secret_package2,
            &[package1.clone(), package2.clone()],
            group_secret_key2,
        )
        .expect("creating round2 packages should not fail");

        part3(
            identity1.clone(),
            &round2_secret_package,
            &[package1.clone(), package2.clone()],
            &round2_packages2,
        )
        .expect_err("should fail checksum validation if group secret keys do not match");
    }
}
