/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::checksum::ChecksumError;
use crate::frost;
use crate::frost::keys::dkg::round1;
use crate::frost::keys::dkg::round2::Package;
use crate::frost::keys::dkg::round2::SecretPackage;
use crate::frost::keys::VerifiableSecretSharingCommitment;
use crate::frost::Field;
use crate::frost::Identifier;
use crate::frost::JubjubScalarField;
use crate::multienc;
use crate::multienc::MultiRecipientBlob;
use crate::participant;
use crate::serde::read_u16;
use crate::serde::read_variable_length;
use crate::serde::write_u16;
use crate::serde::write_variable_length;
use rand_core::CryptoRng;
use rand_core::RngCore;
use std::collections::BTreeMap;
use std::io;
use std::mem;

use super::error::Error;
use super::group_key::GroupSecretKeyShard;
use super::round1::PublicPackage;

type Scalar = <JubjubScalarField as Field>::Scalar;

/// Copy of the [`frost_core::dkg::round2::SecretPackage`] struct. Necessary to implement
/// serialization for this struct. This must be kept in sync with the upstream version.
struct SerializableSecretPackage {
    identifier: Identifier,
    commitment: VerifiableSecretSharingCommitment,
    secret_share: Scalar,
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
        write_variable_length(&mut writer, self.commitment.serialize(), |writer, array| {
            writer.write_all(&array)
        })?;
        writer.write_all(&self.secret_share.to_bytes())?;
        write_u16(&mut writer, self.min_signers)?;
        write_u16(&mut writer, self.max_signers)?;
        Ok(())
    }

    fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut identifier = [0u8; 32];
        reader.read_exact(&mut identifier)?;
        let identifier = Identifier::deserialize(&identifier).map_err(io::Error::other)?;

        let commitment = VerifiableSecretSharingCommitment::deserialize(read_variable_length(
            &mut reader,
            |reader| {
                let mut array = [0u8; 32];
                reader.read_exact(&mut array)?;
                Ok(array)
            },
        )?)
        .map_err(io::Error::other)?;

        let mut scalar = [0u8; 32];
        reader.read_exact(&mut scalar)?;
        let scalar: Option<Scalar> = Scalar::from_bytes(&scalar).into();
        let secret_share =
            scalar.ok_or_else(|| io::Error::other("secret_share deserialization failed"))?;

        let min_signers = read_u16(&mut reader)?;
        let max_signers = read_u16(&mut reader)?;

        Ok(Self {
            identifier,
            commitment,
            secret_share,
            min_signers,
            max_signers,
        })
    }
}

pub fn export_secret_package<R: RngCore + CryptoRng>(
    pkg: &SecretPackage,
    identity: &participant::Identity,
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

pub fn round2<'a, P, R: RngCore + CryptoRng>(
    self_identity: &participant::Identity,
    round1_secret_package: round1::SecretPackage,
    round1_public_packages: P,
    mut csrng: R,
) -> Result<(Vec<u8>, BTreeMap<Identifier, Package>), Error>
where
    P: IntoIterator<Item = &'a PublicPackage>,
    R: RngCore + CryptoRng,
{
    let mut round1_public_packages = round1_public_packages.into_iter().collect::<Vec<_>>();
    round1_public_packages.sort_unstable_by(|a, b| a.identity().cmp(b.identity()));
    round1_public_packages.dedup();
    let round1_public_packages = round1_public_packages;

    let self_public_package = *round1_public_packages
        .iter()
        .find(|&p| p.identity() == self_identity)
        .expect("missing public package for self_identity");

    let mut frost_packages: BTreeMap<Identifier, round1::Package> = BTreeMap::new();
    let mut group_secret_key_shards: Vec<&GroupSecretKeyShard> = Vec::new();

    for public_package in round1_public_packages {
        if public_package.checksum() != self_public_package.checksum() {
            return Err(Error::ChecksumError(ChecksumError));
        }

        group_secret_key_shards.push(public_package.group_secret_key_shard());

        // self_public_package must be excluded from frost::keys::dkg::part2 inputs
        if public_package.identity() == self_identity {
            continue;
        }

        frost_packages.insert(
            public_package.identity().to_frost_identifier(),
            public_package.frost_package().clone(),
        );
    }

    let (round2_secret_package, round2_packages) =
        frost::keys::dkg::part2(round1_secret_package, &frost_packages)
            .map_err(Error::FrostError)?;

    let encrypted_secret_package =
        export_secret_package(&round2_secret_package, self_identity, &mut csrng)
            .map_err(Error::EncryptionError)?;

    // TODO add group_secret_key to PublicPackage structs
    // let group_secret_key = GroupSecretKeyShard::combine(group_secret_key_shards);

    // TODO return round2::PublicPackage structs
    Ok((encrypted_secret_package, round2_packages))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::round1;
    use crate::frost;
    use rand::thread_rng;
    use std::collections::BTreeMap;

    fn create_round2_packages() -> (participant::Secret, SecretPackage) {
        let mut secrets = Vec::new();
        let mut secret_packages = Vec::new();
        let mut public_packages = BTreeMap::new();

        let min_signers = 5;
        let max_signers = 10;

        for _ in 0..max_signers {
            let secret = participant::Secret::random(thread_rng());
            let id = secret.to_identity().to_frost_identifier();
            let (secret_pkg, public_pkg) =
                frost::keys::dkg::part1(id, max_signers, min_signers, thread_rng())
                    .expect("dkg round 1 failed");

            secrets.push(secret);
            secret_packages.push(secret_pkg);
            public_packages.insert(id, public_pkg);
        }

        let secret = secrets[0].clone();
        let id = secret.to_identity().to_frost_identifier();
        let round1_secret_pkg = secret_packages[0].clone();
        public_packages.remove(&id);

        let (round2_secret_pkg, _round2_pkgs) =
            frost::keys::dkg::part2(round1_secret_pkg, &public_packages)
                .expect("dkg round 2 failed");

        (secret, round2_secret_pkg)
    }

    #[test]
    fn serialize_deserialize() {
        let (_secret, secret_pkg) = create_round2_packages();

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
        let (secret, secret_pkg) = create_round2_packages();

        let exported = export_secret_package(&secret_pkg, &secret.to_identity(), thread_rng())
            .expect("export failed");
        let imported = import_secret_package(&exported, &secret).expect("import failed");

        assert_eq!(secret_pkg, imported);
    }

    #[test]
    fn round2() {
        let secret = participant::Secret::random(thread_rng());
        let identity1 = secret.to_identity();
        let identity2 = participant::Secret::random(thread_rng()).to_identity();
        let identity3 = participant::Secret::random(thread_rng()).to_identity();

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

        let (secret_package, _) = super::round2(
            &identity1,
            round1_secret_package,
            [&package1, &package2, &package3],
            thread_rng(),
        )
        .expect("round 2 failed");

        import_secret_package(&secret_package, &secret)
            .expect("round 2 secret package import failed");
    }
}
