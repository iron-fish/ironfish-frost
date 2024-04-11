/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::checksum::Checksum;
use crate::checksum::ChecksumHasher;
use crate::checksum::CHECKSUM_LEN;
use crate::frost;
use crate::frost::keys::dkg::round1::Package;
use crate::frost::keys::dkg::round1::SecretPackage;
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
use crate::serde::read_variable_length_bytes;
use crate::serde::write_u16;
use crate::serde::write_variable_length;
use crate::serde::write_variable_length_bytes;
use rand_core::CryptoRng;
use rand_core::RngCore;
use std::borrow::Borrow;
use std::cmp;
use std::hash::Hasher;
use std::io;
use std::mem;

use super::error::Error;
use super::group_key::GroupSecretKeyShard;

type Scalar = <JubjubScalarField as Field>::Scalar;

/// Copy of the [`frost_core::dkg::round1::SecretPackage`] struct. Necessary to implement
/// serialization for this struct. This must be kept in sync with the upstream version.
struct SerializableSecretPackage {
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
    pkg: &SecretPackage,
    identity: &Identity,
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
    exported: &[u8],
    secret: &participant::Secret,
) -> io::Result<SecretPackage> {
    let exported = MultiRecipientBlob::deserialize_from(exported)?;
    let serialized = multienc::decrypt(secret, &exported).map_err(io::Error::other)?;
    SerializableSecretPackage::deserialize_from(&serialized[..]).map(|pkg| pkg.into())
}

#[must_use]
fn input_checksum<I>(min_signers: u16, participants: &[I]) -> Checksum
where
    I: Borrow<Identity>,
{
    // This function is only used in `PublicPackage::new()`, which in turn is only used in
    // `round1()`. `round1()` already takes care of sorting and deduping the participants, hence we
    // can assume that our input does not need any further processing. The following checks that
    // it's indeed the case, but only for debug builds.
    #[cfg(debug_assertions)]
    {
        let input_participants = participants.iter().map(Borrow::borrow).collect::<Vec<_>>();
        let mut deduped_participants = input_participants.clone();
        deduped_participants.sort_unstable();
        deduped_participants.dedup();
        debug_assert_eq!(
            input_participants, deduped_participants,
            "participants is expected to be sorted and to contain no duplicates"
        );
    }

    let mut hasher = ChecksumHasher::new();

    hasher.write(&min_signers.to_le_bytes());

    for id in participants {
        hasher.write(&id.borrow().serialize());
    }

    hasher.finish()
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicPackage {
    identity: Identity,
    frost_package: Package,
    group_secret_key_shard: GroupSecretKeyShard,
    checksum: Checksum,
}

impl PublicPackage {
    pub(crate) fn new<I>(
        identity: Identity,
        min_signers: u16,
        signing_participants: &[I],
        frost_package: Package,
        group_secret_key_shard: GroupSecretKeyShard,
    ) -> Self
    where
        I: Borrow<Identity>,
    {
        let checksum = input_checksum(min_signers, signing_participants);

        PublicPackage {
            identity,
            frost_package,
            group_secret_key_shard,
            checksum,
        }
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn frost_package(&self) -> &Package {
        &self.frost_package
    }

    pub fn group_secret_key_shard(&self) -> &GroupSecretKeyShard {
        &self.group_secret_key_shard
    }

    pub fn checksum(&self) -> Checksum {
        self.checksum
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize_into(&mut buf).expect("serialization failed");
        buf
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        self.identity.serialize_into(&mut writer)?;
        let frost_package = self.frost_package.serialize().map_err(io::Error::other)?;
        write_variable_length_bytes(&mut writer, &frost_package)?;
        writer.write_all(&self.group_secret_key_shard.serialize())?;
        writer.write_all(&self.checksum.to_le_bytes())?;
        Ok(())
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let identity = Identity::deserialize_from(&mut reader).expect("reading identity failed");

        let frost_package = read_variable_length_bytes(&mut reader)?;
        let frost_package = Package::deserialize(&frost_package).map_err(io::Error::other)?;

        let group_secret_key_shard =
            GroupSecretKeyShard::deserialize_from(&mut reader).map_err(io::Error::other)?;

        let mut checksum = [0u8; CHECKSUM_LEN];
        reader.read_exact(&mut checksum)?;
        let checksum = u64::from_le_bytes(checksum);

        Ok(Self {
            identity,
            frost_package,
            group_secret_key_shard,
            checksum,
        })
    }
}

impl Ord for PublicPackage {
    #[inline]
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        Ord::cmp(&self.identity(), &other.identity())
    }
}

impl PartialOrd<Self> for PublicPackage {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub fn round1<'a, I, R: RngCore + CryptoRng>(
    self_identity: &Identity,
    min_signers: u16,
    participants: I,
    mut csrng: R,
) -> Result<(Vec<u8>, PublicPackage), Error>
where
    I: IntoIterator<Item = &'a Identity>,
    R: RngCore + CryptoRng,
{
    // Remove duplicates from `participants` to ensure that `max_signers` is calculated correctly.
    // `Package::new()` also expects `participants` to be deduped and sorted.
    let mut participants = participants.into_iter().collect::<Vec<_>>();
    participants.sort_unstable();
    participants.dedup();
    let participants = participants;

    if !participants.contains(&self_identity) {
        return Err(Error::InvalidInput(
            "participants must include self_identity",
        ));
    }

    let max_signers = u16::try_from(participants.len())
        .map_err(|_| Error::InvalidInput("too many participants"))?;

    let (secret_package, public_package) = frost::keys::dkg::part1(
        self_identity.to_frost_identifier(),
        max_signers,
        min_signers,
        &mut csrng,
    )
    .map_err(Error::FrostError)?;

    let encrypted_secret_package =
        export_secret_package(&secret_package, self_identity, &mut csrng)
            .map_err(Error::EncryptionError)?;

    let group_secret_key_shard = GroupSecretKeyShard::random(&mut csrng);

    let public_package = PublicPackage::new(
        self_identity.clone(),
        min_signers,
        &participants,
        public_package,
        group_secret_key_shard,
    );

    Ok((encrypted_secret_package, public_package))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost;
    use crate::participant::Secret;
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
        let secret = Secret::random(thread_rng());
        let (secret_pkg, _pkg) = frost::keys::dkg::part1(
            secret.to_identity().to_frost_identifier(),
            20,
            5,
            thread_rng(),
        )
        .expect("dkg round 1 failed");

        let exported = export_secret_package(&secret_pkg, &secret.to_identity(), thread_rng())
            .expect("export failed");
        let imported = import_secret_package(&exported, &secret).expect("import failed");

        assert_eq!(secret_pkg, imported);
    }

    #[test]
    fn test_round1_checksum_stability() {
        let mut rng = thread_rng();

        let min_signers = 2;
        let participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let checksum_1 = super::round1(&participants[0], min_signers, &participants, &mut rng)
            .expect("dkg round 1 failed")
            .1
            .checksum();
        let checksum_2 = super::round1(&participants[1], min_signers, &participants, &mut rng)
            .expect("dkg round 1 failed")
            .1
            .checksum();

        assert_eq!(checksum_1, checksum_2);
    }

    #[test]
    fn test_round1_checksum_variation_with_min_signers() {
        let mut rng = thread_rng();

        let participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let min_signers1 = 2;
        let min_signers2 = 3;

        let checksum_1 = super::round1(&participants[0], min_signers1, &participants, &mut rng)
            .expect("dkg round 1 failed")
            .1
            .checksum();
        let checksum_2 = super::round1(&participants[0], min_signers2, &participants, &mut rng)
            .expect("dkg round 1 failed")
            .1
            .checksum();

        assert_ne!(checksum_1, checksum_2);
    }

    #[test]
    fn test_round1_checksum_variation_with_signing_participants() {
        let mut rng = thread_rng();

        let min_signers = 2;

        let participants1 = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let participants2 = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let checksum_1 = super::round1(&participants1[0], min_signers, &participants1, &mut rng)
            .expect("dkg round 1 failed")
            .1
            .checksum();
        let checksum_2 = super::round1(&participants2[0], min_signers, &participants2, &mut rng)
            .expect("dkg round 1 failed")
            .1
            .checksum();

        assert_ne!(checksum_1, checksum_2);
    }

    #[test]
    fn test_round1_package_checksum() {
        let mut rng = thread_rng();

        let min_signers = 2;

        let participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let identity = &participants[0];

        let (_, public_package) = super::round1(identity, min_signers, &participants, &mut rng)
            .expect("dkg round 1 failed");

        let mut participants = participants.to_vec();
        participants.sort();
        participants.dedup();
        let expected_checksum = input_checksum(min_signers, &participants);

        assert_eq!(expected_checksum, public_package.checksum());
    }

    #[test]
    fn test_round1_package_serialization() {
        let mut rng = thread_rng();

        let min_signers = 2;

        let participants = [
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
            Secret::random(&mut rng).to_identity(),
        ];

        let identity = &participants[0];

        let (_, public_package) = super::round1(identity, min_signers, &participants, &mut rng)
            .expect("dkg round 1 failed");

        let serialized = public_package.serialize();

        let deserialized = PublicPackage::deserialize_from(&serialized[..])
            .expect("package deserialization failed");

        assert_eq!(public_package, deserialized);
    }

    #[test]
    fn round1() {
        let secret = participant::Secret::random(thread_rng());
        let identity1 = secret.to_identity();
        let identity2 = participant::Secret::random(thread_rng()).to_identity();
        let identity3 = participant::Secret::random(thread_rng()).to_identity();

        let (secret_package, _) = super::round1(
            &identity1,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        import_secret_package(&secret_package, &secret).expect("secret package import failed");
    }
}
