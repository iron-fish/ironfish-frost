use crate::frost::keys::PublicKeyPackage as FrostPublicKeyPackage;
use crate::frost::VerifyingKey;
use crate::participant::Identity;
use std::io;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PublicKeyPackage {
    frost_public_key_package: FrostPublicKeyPackage,
    identities: Vec<Identity>,
}

impl PublicKeyPackage {
    #[must_use]
    pub fn from_frost<I>(frost_public_key_package: FrostPublicKeyPackage, identities: I) -> Self
    where
        I: IntoIterator<Item = Identity>,
    {
        Self {
            frost_public_key_package,
            identities: identities.into_iter().collect(),
        }
    }

    pub fn identities(&self) -> &[Identity] {
        &self.identities[..]
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        self.frost_public_key_package.verifying_key()
    }

    pub fn frost_public_key_package(&self) -> &FrostPublicKeyPackage {
        &self.frost_public_key_package
    }

    pub fn serialize(&self) -> io::Result<Vec<u8>> {
        let mut s = Vec::new();
        self.serialize_into(&mut s)?;
        Ok(s)
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        let public_key_package = self
            .frost_public_key_package
            .serialize()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let public_key_package_len = u32::try_from(public_key_package.len())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            .to_le_bytes();
        writer.write_all(&public_key_package_len)?;
        writer.write_all(&public_key_package)?;

        let identities_len = u32::try_from(self.identities.len())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            .to_le_bytes();
        writer.write_all(&identities_len)?;
        for identity in &self.identities {
            let identity_bytes = identity.serialize();
            writer.write_all(&identity_bytes)?
        }

        Ok(())
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut public_key_package_len = [0u8; 4];
        reader.read_exact(&mut public_key_package_len)?;
        let public_key_package_len = u32::from_le_bytes(public_key_package_len) as usize;

        let mut frost_public_key_package = vec![0u8; public_key_package_len];
        reader.read_exact(&mut frost_public_key_package)?;
        let frost_public_key_package =
            FrostPublicKeyPackage::deserialize(&frost_public_key_package)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut identities_len = [0u8; 4];
        reader.read_exact(&mut identities_len)?;
        let identities_len = u32::from_le_bytes(identities_len) as usize;

        let mut identities = Vec::with_capacity(identities_len);
        for _ in 0..identities_len {
            identities.push(Identity::deserialize_from(&mut reader)?);
        }

        Ok(PublicKeyPackage {
            frost_public_key_package,
            identities,
        })
    }
}
