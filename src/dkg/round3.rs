/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::checksum::ChecksumError;
use crate::dkg::error::Error;
use crate::dkg::group_key::GroupSecretKey;
use crate::dkg::group_key::GroupSecretKeyShard;
use crate::dkg::round1;
use crate::dkg::round2;
use crate::frost::keys::dkg::round2::SecretPackage as Round2SecretPackage;
use crate::participant::Secret;
use reddsa::frost::redjubjub::keys::dkg::part3;
use reddsa::frost::redjubjub::keys::KeyPackage;
use reddsa::frost::redjubjub::keys::PublicKeyPackage;
use std::borrow::Borrow;
use std::collections::BTreeMap;

pub fn round3<'a, P, Q>(
    secret: &Secret,
    round2_secret_package: &Round2SecretPackage,
    round1_public_packages: P,
    round2_public_packages: Q,
) -> Result<(KeyPackage, PublicKeyPackage, GroupSecretKey), Error>
where
    P: IntoIterator<Item = &'a round1::PublicPackage>,
    Q: IntoIterator<Item = &'a round2::PublicPackage>,
{
    let identity = secret.to_identity();
    let round1_public_packages = round1_public_packages.into_iter().collect::<Vec<_>>();
    let round2_public_packages = round2_public_packages.into_iter().collect::<Vec<_>>();

    let (min_signers, max_signers) = round2::get_secret_package_signers(round2_secret_package);

    // Ensure that the number of public packages provided matches max_signers
    let expected_round1_packages = max_signers as usize;
    if round1_public_packages.len() != expected_round1_packages {
        return Err(Error::InvalidInput(format!(
            "expected {} round 1 public packages, got {}",
            expected_round1_packages,
            round1_public_packages.len()
        )));
    }

    let expected_round2_packages = expected_round1_packages.saturating_sub(1);
    if round2_public_packages.len() != expected_round2_packages {
        return Err(Error::InvalidInput(format!(
            "expected {} round 2 public packages, got {}",
            expected_round2_packages,
            round2_public_packages.len()
        )));
    }

    let expected_round1_checksum = round1::input_checksum(
        min_signers,
        round1_public_packages.iter().map(|pkg| pkg.identity()),
    );

    let mut gsk_shards = Vec::new();
    let mut round1_frost_packages = BTreeMap::new();
    for public_package in round1_public_packages.iter() {
        if public_package.checksum() != expected_round1_checksum {
            return Err(Error::ChecksumError(ChecksumError::DkgPublicPackageError));
        }

        let identity = public_package.identity();
        let frost_identifier = identity.to_frost_identifier();
        let frost_package = public_package.frost_package().clone();

        if round1_frost_packages
            .insert(frost_identifier, frost_package)
            .is_some()
        {
            return Err(Error::InvalidInput(format!(
                "multiple public packages provided for identity {}",
                public_package.identity()
            )));
        }

        let gsk_shard = public_package
            .group_secret_key_shard(secret)
            .map_err(Error::DecryptionError)?;
        gsk_shards.push(gsk_shard);
    }

    // Sanity check
    assert_eq!(round1_public_packages.len(), round1_frost_packages.len());

    // The public package for `identity` must be excluded from `frost::keys::dkg::part3`
    // inputs
    round1_frost_packages
        .remove(&identity.to_frost_identifier())
        .expect("missing public package for identity");

    let expected_round2_checksum =
        round2::input_checksum(round1_public_packages.iter().map(Borrow::borrow));

    let mut round2_frost_packages = BTreeMap::new();
    for public_package in round2_public_packages.iter() {
        if public_package.checksum() != expected_round2_checksum {
            return Err(Error::ChecksumError(ChecksumError::DkgPublicPackageError));
        }

        if !identity.eq(public_package.recipient_identity()) {
            return Err(Error::InvalidInput(format!(
                "public package does not have the correct recipient identity {:?}",
                public_package.recipient_identity().serialize()
            )));
        }

        let frost_identifier = public_package.sender_identity().to_frost_identifier();
        let frost_package = public_package.frost_package().clone();

        if round2_frost_packages
            .insert(frost_identifier, frost_package)
            .is_some()
        {
            return Err(Error::InvalidInput(format!(
                "multiple public packages provided for identity {}",
                public_package.sender_identity()
            )));
        }
    }

    assert_eq!(round2_public_packages.len(), round2_frost_packages.len());

    let (key_package, public_key_package) = part3(
        round2_secret_package,
        &round1_frost_packages,
        &round2_frost_packages,
    )
    .map_err(Error::FrostError)?;

    Ok((
        key_package,
        public_key_package,
        GroupSecretKeyShard::combine(&gsk_shards),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::round1;
    use crate::dkg::round2::import_secret_package;
    use crate::participant::Secret;
    use rand::thread_rng;

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

        let round1_secret_package_1 =
            round1::import_secret_package(&round1_secret_package_1, &secret1)
                .expect("secret package import failed");
        let (encrypted_secret_package, _) = round2::round2(
            &identity1,
            &round1_secret_package_1,
            [&package1, &package2],
            thread_rng(),
        )
        .expect("round 2 failed");

        let round1_secret_package_2 =
            round1::import_secret_package(&round1_secret_package_2, &secret2)
                .expect("secret package import failed");
        let (_, round2_public_packages_2) = round2::round2(
            &identity2,
            &round1_secret_package_2,
            [&package1, &package2],
            thread_rng(),
        )
        .expect("round 2 failed");

        let round2_public_packages = [round2_public_packages_2
            .iter()
            .find(|p| p.recipient_identity().eq(&identity1))
            .expect("should have package for identity1")];

        let secret_package = import_secret_package(&encrypted_secret_package, &secret1)
            .expect("round 2 secret package import failed");

        let result = round3(
            &secret1,
            &secret_package,
            [&package2],
            round2_public_packages,
        );

        match result {
            Err(Error::InvalidInput(_)) => (),
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

        let round1_secret_package_1 =
            round1::import_secret_package(&round1_secret_package_1, &secret1)
                .expect("secret package import failed");
        let (encrypted_secret_package, _) = round2::round2(
            &identity1,
            &round1_secret_package_1,
            [&package1, &package2],
            thread_rng(),
        )
        .expect("round 2 failed");

        let round1_secret_package_2 =
            round1::import_secret_package(&round1_secret_package_2, &secret2)
                .expect("secret package import failed");
        let (_, round2_public_packages_2) = round2::round2(
            &identity2,
            &round1_secret_package_2,
            [&package1, &package2],
            thread_rng(),
        )
        .expect("round 2 failed");

        let round2_public_packages = [round2_public_packages_2
            .iter()
            .find(|p| p.recipient_identity().eq(&identity1))
            .expect("should have package for identity1")];

        let secret_package = import_secret_package(&encrypted_secret_package, &secret1)
            .expect("round 2 secret package import failed");

        let result = round3(
            &secret1,
            &secret_package,
            [&package1, &package1],
            round2_public_packages,
        );

        match result {
            Err(Error::ChecksumError(_)) => (),
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

        let round1_secret_package_1 =
            round1::import_secret_package(&round1_secret_package_1, &secret1)
                .expect("secret package import failed");
        let (encrypted_secret_package, _) = round2::round2(
            &identity1,
            &round1_secret_package_1,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        let round1_secret_package_2 =
            round1::import_secret_package(&round1_secret_package_2, &secret2)
                .expect("secret package import failed");
        let (_, round2_public_packages_2) = round2::round2(
            &identity2,
            &round1_secret_package_2,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        let round1_secret_package_3 =
            round1::import_secret_package(&round1_secret_package_3, &secret3)
                .expect("secret package import failed");
        let (_, round2_public_packages_3) = round2::round2(
            &identity3,
            &round1_secret_package_3,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        let round2_public_packages = [
            round2_public_packages_2
                .iter()
                .find(|p| p.recipient_identity().eq(&identity1))
                .expect("should have package for identity1"),
            round2_public_packages_3
                .iter()
                .find(|p| p.recipient_identity().eq(&identity1))
                .expect("should have package for identity1"),
        ];

        let secret_package = import_secret_package(&encrypted_secret_package, &secret1)
            .expect("round 2 secret package import failed");

        round3(
            &secret1,
            &secret_package,
            [&package1, &package2, &package3],
            round2_public_packages,
        )
        .expect("round 3 failed");
    }
}
