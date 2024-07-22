/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::multienc;
use crate::participant::Identity;
use crate::participant::Secret;
use rand_core::CryptoRng;
use rand_core::RngCore;
use crate::io;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;


pub const GROUP_SECRET_KEY_LEN: usize = 32;

pub type GroupSecretKey = [u8; GROUP_SECRET_KEY_LEN];
pub type GroupSecretKeyShardSerialization = [u8; GROUP_SECRET_KEY_LEN];

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct GroupSecretKeyShard {
    shard: [u8; GROUP_SECRET_KEY_LEN],
}

impl GroupSecretKeyShard {
    #[must_use]
    pub fn random<R: RngCore + CryptoRng>(mut csrng: R) -> Self {
        let mut shard = [0u8; 32];
        csrng.fill_bytes(&mut shard);
        Self { shard }
    }

    #[must_use]
    pub fn combine<'a, I: IntoIterator<Item = &'a Self>>(shards: I) -> GroupSecretKey {
        let mut shards = shards.into_iter();
        let mut key = shards
            .next()
            .expect("shards must contain at least 1 item")
            .shard;

        #[inline]
        fn bytes_xor(left: &mut [u8], right: &[u8]) {
            debug_assert_eq!(left.len(), right.len());
            for (left_byte, right_byte) in left.iter_mut().zip(right.iter()) {
                *left_byte ^= *right_byte;
            }
        }

        for shard in shards {
            bytes_xor(&mut key, &shard.shard);
        }

        key
    }

    #[must_use]
    pub fn serialize(&self) -> GroupSecretKeyShardSerialization {
        let mut s = [0u8; GROUP_SECRET_KEY_LEN];
        self.serialize_into(&mut s[..])
            .expect("array too small to contain serialization");
        s
    }

    pub fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.shard)
    }

    pub fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut shard = [0u8; GROUP_SECRET_KEY_LEN];
        reader.read_exact(&mut shard)?;
        Ok(Self { shard })
    }

    pub fn export<'a, I, R>(&self, recipients: I, csrng: R) -> Vec<u8>
    where
        I: IntoIterator<Item = &'a Identity>,
        I::IntoIter: ExactSizeIterator,
        R: RngCore + CryptoRng,
    {
        multienc::encrypt(&self.shard, recipients, csrng)
    }

    pub fn import(secret: &Secret, exported: &[u8]) -> io::Result<Self> {
        let bytes = multienc::decrypt(secret, &exported).map_err(io::Error::other)?;

        if bytes.len() != GROUP_SECRET_KEY_LEN {
            return Err(io::Error::other(
                "encrypted blob does not contain a valid grpush secret key shard",
            ));
        }

        let mut shard = [0u8; GROUP_SECRET_KEY_LEN];
        shard.copy_from_slice(&bytes);

        Ok(Self { shard })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rand::thread_rng;

    #[test]
    #[should_panic]
    fn combine_zero() {
        let _ = GroupSecretKeyShard::combine([]);
    }

    #[test]
    fn combine_one() {
        let shard = GroupSecretKeyShard::random(thread_rng());
        let key = GroupSecretKeyShard::combine([&shard]);
        assert_eq!(key, shard.serialize());
    }

    #[test]
    fn combine_two() {
        let shard1 = GroupSecretKeyShard::random(thread_rng());
        let shard2 = GroupSecretKeyShard::random(thread_rng());

        let key = GroupSecretKeyShard::combine([&shard1, &shard2]);

        assert_ne!(&key, &shard1.serialize());
        assert_ne!(&key, &shard2.serialize());
    }

    #[test]
    fn combine_commutativity() {
        let shards = [
            GroupSecretKeyShard::random(thread_rng()),
            GroupSecretKeyShard::random(thread_rng()),
            GroupSecretKeyShard::random(thread_rng()),
        ];

        let keys = [
            GroupSecretKeyShard::combine([&shards[0], &shards[1], &shards[2]]),
            GroupSecretKeyShard::combine([&shards[1], &shards[2], &shards[0]]),
            GroupSecretKeyShard::combine([&shards[2], &shards[0], &shards[1]]),
        ];

        for key in keys {
            assert_eq!(keys[0], key);
        }
    }

    #[test]
    fn combine_compatibility() {
        // Shards were generated at random
        let shards = [
            GroupSecretKeyShard::deserialize_from(
                &hex!("ced183a1b7581e01846bc22dfbce8a87ec3a5b22ff30c4c53e630e5cafde582d")[..],
            )
            .unwrap(),
            GroupSecretKeyShard::deserialize_from(
                &hex!("5a47fe2a5e1855b5c43afe66e5c187bd81a2f99bf5451d36184a6b455eaae3bb")[..],
            )
            .unwrap(),
            GroupSecretKeyShard::deserialize_from(
                &hex!("aa8bbfe9c277a8352c7f18fce6585da9d841e3f4ebf8642b31597461c7549541")[..],
            )
            .unwrap(),
        ];

        let key = GroupSecretKeyShard::combine(&shards);
        assert_eq!(
            key,
            hex!("3e1dc2622b37e3816c2e24b7f8575093b5d9414de18dbdd81770117836202ed7")
        );
    }

    #[test]
    fn export_import() {
        let secrets = [
            Secret::random(thread_rng()),
            Secret::random(thread_rng()),
            Secret::random(thread_rng()),
        ];
        let identities = secrets
            .iter()
            .map(|secret| secret.to_identity())
            .collect::<Vec<_>>();

        let shard = GroupSecretKeyShard::random(thread_rng());

        // Encrypt the shard with all the identities at once
        let exported = shard.export(&identities, thread_rng());

        // Ensure that the exported blob does not contain the shard in cleartext
        let shard_cleartext = shard.serialize();
        for slice in exported.windows(shard_cleartext.len()) {
            assert_ne!(slice, shard_cleartext);
        }

        // Ensure that the exported blob can be decrypted with any secret
        for secret in secrets {
            let imported = GroupSecretKeyShard::import(&secret, &exported).expect("import failed");
            assert_eq!(shard.serialize(), imported.serialize());
        }
    }
}
