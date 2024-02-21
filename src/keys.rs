use crate::frost::keys::PublicKeyPackage as FrostPublicKeyPackage;
use crate::participant::Identity;
use std::io;

#[derive(Debug, Clone)]
pub struct PublicKeyPackage {
    pub frost_public_key_package: FrostPublicKeyPackage,
    pub identities: Vec<Identity>,
}

impl PublicKeyPackage {
    pub fn write<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        let public_key_package = self
            .frost_public_key_package
            .serialize()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let public_key_package_len = u32::try_from(public_key_package.len())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .to_le_bytes();
        writer.write_all(&public_key_package_len)?;
        writer.write_all(&public_key_package)?;

        let identities_len = u32::try_from(self.identities.len())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            .to_le_bytes();
        writer.write_all(&identities_len)?;
        for identity in &self.identities {
            let identity_bytes = identity.serialize();
            writer.write_all(&identity_bytes)?
        }
        Ok(())
    }

    pub fn read<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut public_key_package_len = [0u8; 4];
        reader.read_exact(&mut public_key_package_len)?;
        let public_key_package_len = u32::from_le_bytes(public_key_package_len) as usize;

        let mut public_key_package_vec = vec![0u8; public_key_package_len];
        reader.read_exact(&mut public_key_package_vec)?;

        let public_key_package = FrostPublicKeyPackage::deserialize(&public_key_package_vec)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let mut identities_len = [0u8; 4];
        reader.read_exact(&mut identities_len)?;
        let identities_len = u32::from_le_bytes(identities_len) as usize;

        let mut identities = Vec::with_capacity(identities_len);
        for _ in 0..identities_len {
            identities.push(Identity::deserialize_from(&mut reader)?);
        }

        Ok(PublicKeyPackage {
            frost_public_key_package: public_key_package,
            identities,
        })
    }
}

#[cfg(test)]
mod test {
    use std::vec;

    use crate::samples::frost_public_key_package;

    use super::*;

    #[test]
    fn serde() {
        let frost_public_key_package = frost_public_key_package();

        let pkg = PublicKeyPackage {
            frost_public_key_package,
            identities: vec![],
        };

        let mut vec = vec![];
        pkg.write(&mut vec).expect("correctly serialized");

        let pkg2 = PublicKeyPackage::read(&vec[..]).expect("correctly deserialized");

        assert_eq!(pkg.frost_public_key_package, pkg2.frost_public_key_package);

        pkg.frost_public_key_package
            .verifying_shares()
            .iter()
            .zip(pkg2.frost_public_key_package.verifying_shares().iter())
            .for_each(|(v1, v2)| {
                assert_eq!(v1, v2);
            });
    }
}
