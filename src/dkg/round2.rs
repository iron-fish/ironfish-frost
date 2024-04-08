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

use super::round1;
use super::utils::DkgError;

pub mod round2 {
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
        P: Borrow<round1::round1::Package>,
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
            round1_packages: &[round1::round1::Package],
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
            round1_packages: &[round1::round1::Package],
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
