/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

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
use reddsa::frost::redjubjub::Identifier;
use std::collections::BTreeMap;

pub mod round1;
pub mod round2;
pub mod round3;
pub mod utils;

pub fn part1<T: RngCore + CryptoRng>(
    identity: Identity,
    signing_participants: &[Identity],
    min_signers: u16,
    group_key_part: [u8; 32],
    rng: T,
) -> Result<(round1::SecretPackage, round1::round1::Package), utils::DkgError> {
    let max_signers = signing_participants.len() as u16;

    let (frost_secret_package, frost_package) = frost_part1(
        identity.to_frost_identifier(),
        max_signers,
        min_signers,
        rng,
    )?;

    Ok((
        frost_secret_package,
        round1::round1::Package::new(
            identity,
            signing_participants,
            min_signers,
            group_key_part,
            frost_package,
        ),
    ))
}

pub fn part2(
    identity: Identity,
    secret_package: &round1::SecretPackage,
    round1_packages: &[round1::round1::Package],
    group_secret_key: [u8; 32],
) -> Result<(round2::round2::SecretPackage, Vec<round2::round2::Package>), utils::DkgError> {
    let mut round1_frost_packages_map: BTreeMap<Identifier, frost_round1::Package> =
        BTreeMap::new();

    let mut identity_map: BTreeMap<Identifier, Identity> = BTreeMap::new();

    for package in round1_packages {
        if package.identity() == &identity {
            continue;
        }

        // TODO: Verify where this should be checked
        // secret_package.verify_package_checksum(package)?;

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
        secret_package.clone(),
        &round1_frost_packages_map,
    )?;

    let secret_package: round2::round2::SecretPackage = round2::round2::SecretPackage::new(
        round1_packages,
        group_secret_key,
        frost_secret_package,
    )?;

    let mut round2_packages: Vec<round2::round2::Package> = Vec::new();

    for (identifier, round2_frost_package) in round2_frost_packages_map.iter() {
        let identity = identity_map
            .remove(identifier)
            .expect("part2 generated package for unknown identity");

        let round2_package = round2::round2::Package::new(
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
    secret_package: &round2::round2::SecretPackage,
    round1_packages: &[round1::round1::Package],
    round2_packages: &[round2::round2::Package],
) -> Result<(KeyPackage, PublicKeyPackage), utils::DkgError> {
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
