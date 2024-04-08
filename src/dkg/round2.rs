use crate::frost::keys::dkg::round2 as frost_round2;
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
use std::io;
use std::mem;

use super::round1;

type Scalar = <JubjubScalarField as Field>::Scalar;

pub type SecretPackage = frost_round2::SecretPackage;

/// Copy of the [`frost_core::dkg::round2::SecretPackage`] struct. Necessary to implement
/// serialization for this struct. This must be kept in sync with the upstream version.
pub struct SerializableSecretPackage {
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

        let mut secret_share = [0u8; 32];
        reader.read_exact(&mut secret_share)?;
        let secret_share: Scalar = Scalar::from_bytes(&secret_share).unwrap();

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

pub mod round2 {
    use std::borrow::Borrow;
    use std::hash::Hasher;
    use std::io;

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

        pub fn serialize(&self) -> io::Result<Vec<u8>> {
            let mut buf = Vec::new();
            self.serialize_into(&mut buf)?;
            Ok(buf)
        }

        pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
            self.identity.serialize_into(&mut writer)?;
            writer.write_all(&self.frost_package.serialize().map_err(io::Error::other)?)?;
            writer.write_all(&self.group_secret_key)?;
            writer.write_all(&self.checksum.to_le_bytes())?;
            Ok(())
        }
    }
}
