/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::error;
use std::fmt;

use crate::checksum::ChecksumError;
use reddsa::frost::redjubjub::Error as FrostError;

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

#[cfg(test)]
mod tests {
    use rand::random;
    use rand::thread_rng;

    use crate::dkg::part1;
    use crate::dkg::part2;
    use crate::participant::Secret;

    use crate::dkg::part3;

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
