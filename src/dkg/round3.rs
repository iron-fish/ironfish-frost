use std::collections::BTreeMap;

use crate::checksum::ChecksumError;
use crate::frost::keys::dkg::round1::Package as Round1Package;
use crate::frost::keys::dkg::round2::Package as Round2Package;
use crate::frost::keys::dkg::round2::SecretPackage as Round2SecretPackage;
use crate::participant::Identity;
use reddsa::frost::redjubjub::keys::dkg::part3;
use reddsa::frost::redjubjub::keys::KeyPackage;
use reddsa::frost::redjubjub::keys::PublicKeyPackage;
use reddsa::frost::redjubjub::Identifier;

use super::error::Error;
use super::round1;
use super::round2;

pub fn round3<'a, P, Q>(
    identity: &Identity,
    secret_package: &Round2SecretPackage,
    round1_public_packages: P,
    round2_public_packages: Q,
) -> Result<(KeyPackage, PublicKeyPackage), Error>
where
    P: IntoIterator<Item = &'a round1::PublicPackage>,
    Q: IntoIterator<Item = &'a round2::PublicPackage>,
{
    let mut round1_public_packages = round1_public_packages.into_iter().collect::<Vec<_>>();
    round1_public_packages.sort_unstable_by_key(|&p| p.identity());
    round1_public_packages.dedup();
    let round1_public_packages = round1_public_packages;

    let self_round1_public_package = *round1_public_packages
        .iter()
        .find(|&p| p.identity() == identity)
        .expect("missing public package for identity");

    let mut round1_frost_packages: BTreeMap<Identifier, Round1Package> = BTreeMap::new();
    for package in round1_public_packages {
        if package.checksum() != self_round1_public_package.checksum() {
            return Err(Error::ChecksumError(ChecksumError));
        }

        if package.identity() == identity {
            continue;
        }

        round1_frost_packages.insert(
            package.identity().to_frost_identifier(),
            package.frost_package().clone(),
        );
    }

    let mut round2_public_packages = round2_public_packages.into_iter().collect::<Vec<_>>();
    round2_public_packages.sort_unstable_by_key(|&p| p.identity());
    round2_public_packages.dedup();
    let round2_public_packages = round2_public_packages;

    let self_round2_public_package = *round2_public_packages
        .iter()
        .find(|&p| p.identity() == identity)
        .expect("missing public package for identity");

    let mut round2_frost_packages: BTreeMap<Identifier, Round2Package> = BTreeMap::new();
    for package in round2_public_packages {
        if package.checksum() != self_round2_public_package.checksum() {
            return Err(Error::ChecksumError(ChecksumError));
        }

        if package.identity() == identity {
            continue;
        }

        round2_frost_packages.insert(
            package.identity().to_frost_identifier(),
            package.frost_package().clone(),
        );
    }

    let (key_package, public_key_package) = part3(
        secret_package,
        &round1_frost_packages,
        &round2_frost_packages,
    )
    .map_err(Error::FrostError)?;

    Ok((key_package, public_key_package))
}

#[cfg(test)]
mod tests {
    use self::round2::import_secret_package;

    use super::*;
    use crate::dkg::round1;
    use crate::participant::Secret;
    use rand::thread_rng;

    #[test]
    fn test_round3() {
        let secret = Secret::random(thread_rng());
        let identity1 = secret.to_identity();
        let identity2 = Secret::random(thread_rng()).to_identity();
        let identity3 = Secret::random(thread_rng()).to_identity();

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

        let round1_secret_package = round1::import_secret_package(&round1_secret_package, &secret)
            .expect("secret package import failed");

        let (encrypted_secret_package, round2_public_packages) = round2::round2(
            &identity1,
            &round1_secret_package,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        let secret_package = import_secret_package(&encrypted_secret_package, &secret)
            .expect("round 2 secret package import failed");

        let (key_package, public_key_package) = round3(
            &identity1,
            &secret_package,
            [&package1, &package2, &package3],
            round2_public_packages.values(),
        )
        .expect("round 3 failed");
    }
}
