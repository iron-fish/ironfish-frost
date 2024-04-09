/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::frost;
use crate::frost::keys::dkg::round1::SecretPackage;
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
use std::fmt;
use std::io;
use std::mem;

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

pub fn round1<'a, I, R: RngCore + CryptoRng>(
    self_identity: &participant::Identity,
    min_signers: u16,
    participants: I,
    mut csrng: R,
) -> Result<(Vec<u8>, Vec<u8>), Error>
where
    I: IntoIterator<Item = &'a participant::Identity>,
    R: RngCore + CryptoRng,
{
    // Remove duplicates from `participants` to ensure that `max_signers` is calculated correctly
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
    let public_package = public_package.serialize().map_err(Error::FrostError)?;

    // TODO bind the min/max signers and the list of participants to the packages through
    // checksumming
    Ok((encrypted_secret_package, public_package))
}

#[derive(Debug)]
pub enum Error {
    InvalidInput(&'static str),
    FrostError(frost::Error),
    EncryptionError(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::InvalidInput(e) => {
                write!(f, "invalid input: ")?;
                e.fmt(f)
            }
            Self::FrostError(e) => {
                write!(f, "frost error: ")?;
                e.fmt(f)
            }
            Self::EncryptionError(e) => {
                write!(f, "encryption error: ")?;
                e.fmt(f)
            }
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost;
    use crate::frost::keys::dkg::round1::Package;
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

        let exported = export_secret_package(&secret_pkg, &secret.to_identity(), thread_rng())
            .expect("export failed");
        let imported = import_secret_package(&exported, &secret).expect("import failed");

        assert_eq!(secret_pkg, imported);
    }

    #[test]
    fn round1() {
        let secret = participant::Secret::random(thread_rng());
        let identity1 = secret.to_identity();
        let identity2 = participant::Secret::random(thread_rng()).to_identity();
        let identity3 = participant::Secret::random(thread_rng()).to_identity();

        let (secret_package, public_package) = super::round1(
            &identity1,
            2,
            [&identity1, &identity2, &identity3],
            thread_rng(),
        )
        .expect("round 1 failed");

        import_secret_package(&secret_package, &secret).expect("secret package import failed");
        Package::deserialize(&public_package).expect("public package deserialization failed");
    }
}
