/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::frost::keys::dkg::part1 as frost_part1;
use crate::frost::keys::dkg::round1::SecretPackage as RoundOneSecretPackage;
use crate::frost::keys::VerifiableSecretSharingCommitment;
use crate::frost::Field;
use crate::frost::Identifier;
use crate::frost::JubjubScalarField;
use crate::multienc;
use crate::multienc::MultiRecipientBlob;
use crate::participant;
use crate::participant::Identity;
use crate::serde::read_u16;
use crate::serde::read_variable_length;
use crate::serde::write_u16;
use crate::serde::write_variable_length;
use rand_core::CryptoRng;
use rand_core::RngCore;
use std::io;
use std::mem;

use super::utils::DkgError;

type Scalar = <JubjubScalarField as Field>::Scalar;

pub type SecretPackage = RoundOneSecretPackage;

/// Copy of the [`frost_core::dkg::round1::SecretPackage`] struct. Necessary to implement
/// serialization for this struct. This must be kept in sync with the upstream version.
pub struct SerializableSecretPackage {
    identifier: Identifier,
    coefficients: Vec<Scalar>,
    commitment: VerifiableSecretSharingCommitment,
    min_signers: u16,
    max_signers: u16,
}

impl From<SecretPackage> for SerializableSecretPackage {
    #[inline]
    fn from(pkg: SecretPackage) -> Self {
        // SAFETY: The fields of `SecretPackage` and `SerializableSecretPackage` have the same
        // size, alignment, and semantics
        unsafe { mem::transmute(pkg) }
    }
}

impl From<SerializableSecretPackage> for SecretPackage {
    #[inline]
    fn from(pkg: SerializableSecretPackage) -> Self {
        // SAFETY: The fields of `SecretPackage` and `SerializableSecretPackage` have the same
        // size, alignment, and semantics
        unsafe { mem::transmute(pkg) }
    }
}

impl SerializableSecretPackage {
    fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.identifier.serialize())?;
        write_variable_length(&mut writer, &self.coefficients, |writer, scalar| {
            writer.write_all(&scalar.to_bytes())
        })?;
        write_variable_length(&mut writer, self.commitment.serialize(), |writer, array| {
            writer.write_all(&array)
        })?;
        write_u16(&mut writer, self.min_signers)?;
        write_u16(&mut writer, self.max_signers)?;
        Ok(())
    }

    fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut identifier = [0u8; 32];
        reader.read_exact(&mut identifier)?;
        let identifier = Identifier::deserialize(&identifier).map_err(io::Error::other)?;

        let coefficients = read_variable_length(&mut reader, |reader| {
            let mut scalar = [0u8; 32];
            reader.read_exact(&mut scalar)?;
            let scalar: Option<Scalar> = Scalar::from_bytes(&scalar).into();
            scalar.ok_or_else(|| io::Error::other("coefficients deserialization failed"))
        })?;

        let commitment = VerifiableSecretSharingCommitment::deserialize(read_variable_length(
            &mut reader,
            |reader| {
                let mut array = [0u8; 32];
                reader.read_exact(&mut array)?;
                Ok(array)
            },
        )?)
        .map_err(io::Error::other)?;

        let min_signers = read_u16(&mut reader)?;
        let max_signers = read_u16(&mut reader)?;

        Ok(Self {
            identifier,
            coefficients,
            commitment,
            min_signers,
            max_signers,
        })
    }
}

pub fn export_secret_package<R: RngCore + CryptoRng>(
    identity: &participant::Identity,
    pkg: &SecretPackage,
    csrng: R,
) -> io::Result<Vec<u8>> {
    let serializable = SerializableSecretPackage::from(pkg.clone());
    if serializable.identifier != identity.to_frost_identifier() {
        return Err(io::Error::other("identity mismatch"));
    }
    let mut serialized = Vec::new();
    serializable.serialize_into(&mut serialized)?;
    multienc::encrypt(&serialized, [identity], csrng).serialize()
}

pub fn import_secret_package(
    secret: &participant::Secret,
    exported: &[u8],
) -> io::Result<SecretPackage> {
    let exported = MultiRecipientBlob::deserialize_from(exported)?;
    let serialized = multienc::decrypt(secret, &exported).map_err(io::Error::other)?;
    SerializableSecretPackage::deserialize_from(&serialized[..]).map(|pkg| pkg.into())
}

pub mod round1 {
    use std::borrow::Borrow;
    use std::cmp;
    use std::hash::Hasher;
    use std::io;

    use reddsa::frost;
    use siphasher::sip::SipHasher24;

    use crate::checksum;
    use crate::checksum::Checksum;
    use crate::checksum::ChecksumError;
    use crate::checksum::CHECKSUM_LEN;
    use crate::frost::keys::dkg::round1 as frost_round1;
    use crate::participant::Identity;
    use crate::serde::read_variable_length_bytes;

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

        pub fn identity(&self) -> &Identity {
            &self.identity
        }

        pub fn frost_package(&self) -> &frost_round1::Package {
            &self.frost_package
        }

        pub fn checksum(&self) -> Checksum {
            self.checksum
        }

        pub fn serialize(&self) -> io::Result<Vec<u8>> {
            let mut buf = Vec::new();
            self.serialize_into(&mut buf)?;
            Ok(buf)
        }

        pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
            self.identity.serialize_into(&mut writer)?;
            writer.write_all(&self.frost_package.serialize().map_err(io::Error::other)?)?;
            writer.write_all(&self.group_key_part)?;
            writer.write_all(&self.checksum.to_le_bytes())?;
            Ok(())
        }

        fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
            let identity = Identity::deserialize_from(&mut reader).map_err(io::Error::other)?;

            let frost_package = read_variable_length_bytes(&mut reader)?;
            let frost_package =
                frost_round1::Package::deserialize(&frost_package).map_err(io::Error::other)?;

            let mut group_key_part = [0u8; 32];
            reader.read_exact(&mut group_key_part)?;

            let mut checksum = [0u8; CHECKSUM_LEN];
            reader.read_exact(&mut checksum)?;
            let checksum = u64::from_le_bytes(checksum);

            Ok(Self {
                identity,
                frost_package,
                group_key_part,
                checksum,
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost;
    use crate::frost::keys::dkg::round1::SecretPackage;
    use rand::thread_rng;

    #[test]
    fn serialize_deserialize() {
        let id = Identifier::try_from(123u16).expect("failed to construct identifier");
        let (secret_pkg, _pkg) =
            frost::keys::dkg::part1(id, 20, 5, thread_rng()).expect("dkg round 1 failed");

        let mut serialized = Vec::new();
        SerializableSecretPackage::from(secret_pkg.clone())
            .serialize_into(&mut serialized)
            .expect("serialization failed");

        let deserialized: SecretPackage =
            SerializableSecretPackage::deserialize_from(&serialized[..])
                .expect("deserialization failed")
                .into();

        assert_eq!(secret_pkg, deserialized);
    }

    #[test]
    fn export_import() {
        let secret = participant::Secret::random(thread_rng());
        let (secret_pkg, _pkg) = frost::keys::dkg::part1(
            secret.to_identity().to_frost_identifier(),
            20,
            5,
            thread_rng(),
        )
        .expect("dkg round 1 failed");

        let exported = export_secret_package(&secret.to_identity(), &secret_pkg, thread_rng())
            .expect("export failed");
        let imported = import_secret_package(&secret, &exported).expect("import failed");

        assert_eq!(secret_pkg, imported);
    }
}
