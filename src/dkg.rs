/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::collections::BTreeMap;

use crate::frost::keys::dkg::part1 as frost_part1;
use crate::frost::keys::dkg::part2 as frost_part2;
use crate::frost::keys::dkg::round1 as frost_round1;
use crate::participant::Identity;
use rand_core::CryptoRng;
use rand_core::RngCore;
use reddsa::frost::redjubjub::Error;
use reddsa::frost::redjubjub::Identifier;

mod round1 {
    use std::borrow::Borrow;
    use std::cmp;
    use std::hash::Hasher;

    use siphasher::sip::SipHasher24;

    use crate::checksum::{Checksum, ChecksumError};
    use crate::frost::keys::dkg::round1 as frost_round1;
    use crate::participant::Identity;

    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Package {
        identity: Identity,
        frost_package: frost_round1::Package,
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

        pub fn verify_checksum<I>(
            &self,
            min_signers: u16,
            signing_participants: &[I],
        ) -> Result<(), ChecksumError>
        where
            I: Borrow<Identity>,
        {
            let computed_checksum = input_checksum(min_signers, signing_participants);
            if self.checksum == computed_checksum {
                Ok(())
            } else {
                Err(ChecksumError)
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
}

pub fn part1<T: RngCore + CryptoRng>(
    identity: Identity,
    signing_participants: &[Identity],
    min_signers: u16,
    group_key_part: [u8; 32],
    rng: T,
) -> Result<(frost_round1::SecretPackage, round1::Package), Error> {
    let max_signers = signing_participants.len() as u16;

    let (secret_package, frost_package) = frost_part1(
        identity.to_frost_identifier(),
        max_signers,
        min_signers,
        rng,
    )?;

    Ok((
        secret_package,
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

        pub fn verify_checksum<P>(
            &self,
            packages: &[P],
            group_secret_key: [u8; 32],
        ) -> Result<(), ChecksumError>
        where
            P: Borrow<round1::Package>,
        {
            let computed_checksum =
                input_checksum(packages, group_secret_key).map_err(|_| ChecksumError)?;
            if self.checksum == computed_checksum {
                Ok(())
            } else {
                Err(ChecksumError)
            }
        }

        pub fn checksum(&self) -> Checksum {
            self.checksum
        }
    }
}

pub fn part2(
    identity: Identity,
    secret_package: frost_round1::SecretPackage,
    round1_packages: &[round1::Package],
    group_secret_key: [u8; 32],
) -> Result<Vec<round2::Package>, Error> {
    let mut round1_frost_packages_map: BTreeMap<Identifier, frost_round1::Package> =
        BTreeMap::new();

    let mut identity_map: BTreeMap<Identifier, Identity> = BTreeMap::new();

    for package in round1_packages {
        if package.identity() == &identity {
            continue;
        }

        round1_frost_packages_map.insert(
            package.identity().to_frost_identifier(),
            package.frost_package().clone(),
        );

        identity_map.insert(
            package.identity().to_frost_identifier(),
            package.identity().clone(),
        );
    }

    let (_, round2_frost_packages_map) = frost_part2(secret_package, &round1_frost_packages_map)?;

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

    Ok(round2_packages)
}

#[cfg(test)]
mod tests {
    use rand::random;
    use rand::thread_rng;

    use crate::dkg::part1;
    use crate::dkg::part2;
    use crate::participant::Secret;

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

        let round2_packages1 = part2(
            identity1,
            secret_package1,
            &[package1.clone(), package2.clone()],
            group_secret_key,
        )
        .expect("creating round2 packages should not fail");

        assert_eq!(round2_packages1.len(), 1);

        let round2_packages2 = part2(
            identity2,
            secret_package2,
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

        let round2_packages1 = part2(
            identity1,
            secret_package1,
            &[package1.clone(), package2a],
            group_secret_key,
        )
        .expect("creating round2 packages should not fail");

        assert_eq!(round2_packages1.len(), 1);

        let round2_packages2 = part2(
            identity2,
            secret_package2a,
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

        let round2_packages1 = part2(
            identity1,
            secret_package1,
            &[package1.clone(), package2.clone()],
            group_secret_key1,
        )
        .expect("creating round2 packages should not fail");

        assert_eq!(round2_packages1.len(), 1);

        let round2_packages2 = part2(
            identity2,
            secret_package2,
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
}
