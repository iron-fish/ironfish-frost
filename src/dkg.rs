/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use std::borrow::Borrow;

use rand_core::CryptoRng;
use rand_core::RngCore;
use reddsa::frost::redjubjub::Error;

use crate::checksum::input_checksum;
use crate::checksum::Checksum;
use crate::checksum::ChecksumError;
use crate::frost::keys::dkg::part1 as frost_part1;
use crate::frost::keys::dkg::round1;
use crate::participant::Identity;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Package {
    identity: Identity,
    frost_package: round1::Package,
    checksum: Checksum,
}

impl Package {
    pub(crate) fn new(
        identity: Identity,
        signing_participants: &[Identity],
        min_signers: u16,
        frost_package: round1::Package,
    ) -> Self {
        let checksum = input_checksum(&min_signers.to_le_bytes(), signing_participants);

        Package {
            identity,
            frost_package,
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
        let computed_checksum = input_checksum(&min_signers.to_le_bytes(), signing_participants);
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

pub fn part1<T: RngCore + CryptoRng>(
    identity: Identity,
    signing_participants: &[Identity],
    min_signers: u16,
    rng: T,
) -> Result<Package, Error> {
    let max_signers = signing_participants.len() as u16;

    let (_, frost_package) = frost_part1(
        identity.to_frost_identifier(),
        max_signers,
        min_signers,
        rng,
    )?;

    Ok(Package::new(
        identity,
        signing_participants,
        min_signers,
        frost_package,
    ))
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use crate::{dkg::part1, participant::Secret};

    #[test]
    fn test_checksum_variation_with_min_signers() {
        let mut rng = thread_rng();

        let signing_participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let min_signers1: u16 = 2;
        let min_signers2: u16 = 3;

        let identity = &signing_participants[0];

        let package_1 = part1(
            identity.clone(),
            &signing_participants,
            min_signers1,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let package_2 = part1(
            identity.clone(),
            &signing_participants,
            min_signers2,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        assert_ne!(package_1.checksum(), package_2.checksum());
    }

    #[test]
    fn test_checksum_variation_with_signing_participants() {
        let mut rng = thread_rng();

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

        let package_1 = part1(
            identity.clone(),
            &signing_participants1,
            min_signers,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        let package_2 = part1(
            identity.clone(),
            &signing_participants2,
            min_signers,
            thread_rng(),
        )
        .expect("creating frost round1 package should not fail");

        assert_ne!(package_1.checksum(), package_2.checksum());
    }
}
