/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */
use std::collections::BTreeMap;

use crate::checksum::ChecksumError;
use crate::frost::keys::dkg::round1::Package as Round1Package;
use crate::participant::Identity;
use reddsa::frost::redjubjub::Identifier;

use super::error::Error;
use super::round1;

pub fn build_round1_frost_packages<'a, P>(
    round1_public_packages: P,
    min_signers: u16,
    max_signers: u16,
) -> Result<
    (
        BTreeMap<Identifier, &'a Identity>,
        BTreeMap<Identifier, Round1Package>,
    ),
    Error,
>
where
    P: IntoIterator<Item = &'a round1::PublicPackage>,
{
    let round1_public_packages = round1_public_packages.into_iter().collect::<Vec<_>>();

    // Ensure that the number of public packages provided matches max_signers
    if round1_public_packages.len() != max_signers as usize {
        return Err(Error::InvalidInput(format!(
            "expected {} public packages, got {}",
            max_signers,
            round1_public_packages.len()
        )));
    }

    let expected_round1_checksum = round1::input_checksum(
        min_signers,
        round1_public_packages.iter().map(|pkg| pkg.identity()),
    );

    let mut identities = BTreeMap::new();
    let mut round1_frost_packages: BTreeMap<Identifier, Round1Package> = BTreeMap::new();
    for public_package in round1_public_packages.clone() {
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

        identities.insert(frost_identifier, identity);
        round1_frost_packages.insert(
            public_package.identity().to_frost_identifier(),
            public_package.frost_package().clone(),
        );
    }

    assert_eq!(round1_public_packages.len(), round1_frost_packages.len());

    Ok((identities, round1_frost_packages))
}
