use crate::frost::keys::dkg::round2 as frost_round2;

use super::round1;

pub type SecretPackage = frost_round2::SecretPackage;

pub mod round2 {
    use std::borrow::Borrow;
    use std::hash::Hasher;

    use reddsa::frost::redjubjub::Error;
    use siphasher::sip::SipHasher24;

    use crate::checksum::Checksum;
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
}
