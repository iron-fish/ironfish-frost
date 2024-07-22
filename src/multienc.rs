/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::io;
use crate::participant::Identity;
use crate::participant::Secret;
use crate::serde::read_usize;
use crate::serde::write_usize;
use chacha20::cipher::KeyIvInit;
use chacha20::cipher::StreamCipher;
use chacha20::ChaCha20;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use chacha20poly1305::Nonce;
use chacha20poly1305::Tag;
use rand_core::CryptoRng;
use rand_core::RngCore;
use x25519_dalek::PublicKey;
use x25519_dalek::ReusableSecret;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub const HEADER_SIZE: usize = 56;
pub const KEY_SIZE: usize = 32;

#[inline]
#[must_use]
pub const fn metadata_size(num_recipients: usize) -> usize {
    HEADER_SIZE + KEY_SIZE * num_recipients
}

pub fn read_encrypted_blob<R>(mut reader: R) -> io::Result<Vec<u8>>
where
    R: io::Read,
{
    #[cfg(feature = "std")]
    use std::io::Read;

    let mut result = Vec::new();
    let reader = reader.by_ref();

    reader.take(HEADER_SIZE as u64).read_to_end(&mut result)?;

    let header = Header::deserialize_from(&result[..])?;
    for _ in 0..header.num_recipients {
        reader.take(KEY_SIZE as u64).read_to_end(&mut result)?;
    }
    reader
        .take(header.data_len as u64)
        .read_to_end(&mut result)?;

    Ok(result)
}

#[must_use]
pub fn encrypt<'a, I, R>(data: &[u8], recipients: I, csrng: R) -> Vec<u8>
where
    I: IntoIterator<Item = &'a Identity>,
    I::IntoIter: ExactSizeIterator,
    R: RngCore + CryptoRng,
{
    let recipients = recipients.into_iter();
    let metadata_len = metadata_size(recipients.len());
    let mut result = Vec::with_capacity(metadata_len + data.len());
    let (metadata, ciphertext) = result.split_at_mut(metadata_len);

    ciphertext.copy_from_slice(data);
    encrypt_in_place(ciphertext, metadata, recipients, csrng).expect("failed to encrypt data");

    result
}

/// Encrypt arbitrary `data` once for multiple participants.
///
/// The cleartext `data` is overwritten with the ciphertext in place. Additional metadata necessary
/// for decrypting the ciphertext is stored in `metadata`, which must have size `56 + 32 *
/// recipients.len()` (this size can also be obtained through [`metadata_size`]).
///
/// The data can be decrypted by each participant using [`decrypt`] or [`decrypt_in_place`].
pub fn encrypt_in_place<'a, W, I, R>(
    data: &mut [u8],
    mut metadata: W,
    recipients: I,
    mut csrng: R,
) -> io::Result<()>
where
    W: io::Write,
    I: IntoIterator<Item = &'a Identity>,
    I::IntoIter: ExactSizeIterator,
    R: RngCore + CryptoRng,
{
    let recipients = recipients.into_iter();

    // Use a zero nonce for all encryptions below. This is safe because each encryption key is
    // ephemeral and used exactly once, so no (key, nonce) reuse ever happens.
    let nonce = Nonce::default();

    // Generate a random encryption key and encrypt the data with it using ChaCha20Poly1305
    let encryption_key = ChaCha20Poly1305::generate_key(&mut csrng);
    let cipher = ChaCha20Poly1305::new(&encryption_key);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, &[], data)
        .expect("encryption failed");

    // Encrypt the encryption key for each recipient using X25519 + ChaCha20.
    //
    // Here we are using an unauthenticated cipher because we rely on the integrity provided by
    // ChaCha20Poly1305 on the data. If an encrypted key is tampered, the recipient won't be able
    // to correctly recover the data using ChaCha20Poly1305, and so they can detect the tampering.
    //
    // We write the number of recipients and the length of the ciphertext in the metadata for
    // convenience, to make decryption easier for the caller. Both numbers are unauthenticated,
    // again for the reason outline above: we rely on the ChaCha20Poly1305 tag for integrity.
    let agreement_secret = ReusableSecret::random_from_rng(csrng);
    let agreement_key = PublicKey::from(&agreement_secret);

    let header = Header {
        agreement_key,
        tag,
        num_recipients: recipients.len(),
        data_len: data.len(),
    };
    header.serialize_into(&mut metadata)?;

    for id in recipients {
        let recipient_key = id.encryption_key();
        let shared_secret = agreement_secret.diffie_hellman(recipient_key).to_bytes();
        let mut cipher = ChaCha20::new((&shared_secret).into(), &nonce);
        let mut encrypted_key = encryption_key;

        cipher.apply_keystream(&mut encrypted_key);
        metadata.write_all(&encrypted_key)?;
    }

    Ok(())
}

/// Decrypts data produced by [`encrypt`] or [`encrypt_in_place`] using one participant secret.
///
/// This method expects the ciphertext and the metadata to be concatenated in one slice. Use
/// [`decrypt_in_place`] if you have two separate slices.
pub fn decrypt(secret: &Secret, data: &[u8]) -> io::Result<Vec<u8>> {
    let header = Header::deserialize_from(data)?;
    let metadata_len = metadata_size(header.num_recipients);
    let total_len = metadata_len
        .checked_add(header.data_len)
        .ok_or_else(|| io::Error::other("overflow when calculating data size"))?;
    if data.len() < total_len {
        #[cfg(feature = "std")]
        {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        #[cfg(not(feature = "std"))]
        {
            return Err(io::Error());
        }
    }

    let (metadata, ciphertext) = data.split_at(metadata_len);
    let mut cleartext = ciphertext.to_owned();
    decrypt_in_place(secret, &mut cleartext, metadata)?;

    Ok(cleartext)
}

/// Decrypts data produced by [`encrypt`] or [`encrypt_in_place`] using one participant secret.
///
/// This method expects the ciphertext and the metadata to be passed as two distinct slices. Use
/// [`decrypt`] if you have a contiguous slice, like a vector produced by [`encrypt`].
pub fn decrypt_in_place<R>(
    secret: &Secret,
    ciphertext: &mut [u8],
    mut metadata: R,
) -> io::Result<()>
where
    R: io::Read,
{
    // Read all metadata
    let mut agreement_key = [0u8; 32];
    metadata.read_exact(&mut agreement_key)?;
    let agreement_key = PublicKey::from(agreement_key);

    let mut tag = [0u8; 16];
    metadata.read_exact(&mut tag)?;
    let tag = tag.into();

    let encrypted_keys_len = read_usize(&mut metadata)?;
    let ciphertext_len = read_usize(&mut metadata)?;

    if ciphertext.len() != ciphertext_len {
        return Err(io::Error::other(
            "ciphertext size does not match size recorded in the metadata",
        ));
    }

    // Reconstruct the shared secret
    let nonce = Nonce::default();
    let shared_secret = secret
        .decryption_key()
        .diffie_hellman(&agreement_key)
        .to_bytes();

    // Try to decrypt each encryption key one by one, and use them to attempt to decrypt the data,
    // until the data is recovered.
    for _ in 0..encrypted_keys_len {
        let mut encryption_key = [0u8; KEY_SIZE];
        metadata.read_exact(&mut encryption_key)?;

        // Decrypt the encryption key with X25519 + ChaCha20. This will always succeed, even if
        // the encryption key was not for this participant (in which case, it will result in
        // random bytes).
        let mut cipher = ChaCha20::new((&shared_secret).into(), &nonce);
        cipher.apply_keystream(&mut encryption_key);

        // Decrypt the data with ChaCha20Poly1305. This will fail if the encryption key was not
        // for this participant (or if the encryption key was tampered).
        let cipher = ChaCha20Poly1305::new((&encryption_key).into());
        match cipher.decrypt_in_place_detached(&nonce, &[], ciphertext, &tag) {
            Ok(()) => return Ok(()),
            Err(_) => {
                // `decrypt_in_place_detached` garbled the `ciphertext` and replaced it with random
                // data. We need to restore it to its original state. Because chacha20 is a stream
                // cipher, we can simply re-run the decryption to restore it. This may not be very
                // CPU-efficient, but it's a solution that does not require any additional memory.
                let _ = cipher.decrypt_in_place_detached(&nonce, &[], ciphertext, &tag);
            }
        }
    }

    Err(io::Error::other("ciphertext could not be decrypted"))
}

#[derive(Debug)]
struct Header {
    agreement_key: PublicKey,
    tag: Tag,
    num_recipients: usize,
    data_len: usize,
}

impl Header {
    fn serialize_into<W: io::Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.agreement_key.as_bytes())?;
        writer.write_all(&self.tag)?;
        write_usize(&mut writer, self.num_recipients)?;
        write_usize(&mut writer, self.data_len)
    }

    #[cfg(feature = "std")]
    fn deserialize_from<R: io::Read>(mut reader: R) -> io::Result<Self> {
        let mut agreement_key = [0u8; 32];
        reader.read_exact(&mut agreement_key)?;
        let agreement_key = PublicKey::from(agreement_key);

        let mut tag = [0u8; 16];
        reader.read_exact(&mut tag)?;
        let tag = tag.into();

        let num_recipients = read_usize(&mut reader)?;
        let data_len = read_usize(&mut reader)?;

        Ok(Self {
            agreement_key,
            tag,
            num_recipients,
            data_len,
        })
    }
}

#[cfg(test)]
mod tests {
    mod detached {
        use crate::multienc::decrypt;
        use crate::multienc::encrypt;
        use crate::multienc::HEADER_SIZE;
        use crate::multienc::KEY_SIZE;
        use crate::participant::Secret;
        use rand::thread_rng;

        #[test]
        fn round_trip() {
            let plaintext = b"hello";

            let secret1 = Secret::random(thread_rng());
            let secret2 = Secret::random(thread_rng());
            let secret3 = Secret::random(thread_rng());
            let id1 = secret1.to_identity();
            let id2 = secret2.to_identity();

            let blob = encrypt(plaintext, &[id1, id2], thread_rng());

            assert_eq!(decrypt(&secret1, &blob).unwrap(), plaintext);
            assert_eq!(decrypt(&secret2, &blob).unwrap(), plaintext);
            assert!(decrypt(&secret3, &blob).is_err());
        }

        #[test]
        fn tampering() {
            let plaintext = b"hello";

            let secret1 = Secret::random(thread_rng());
            let secret2 = Secret::random(thread_rng());
            let id1 = secret1.to_identity();
            let id2 = secret2.to_identity();

            let blob = encrypt(plaintext, &[id1, id2], thread_rng());

            assert_eq!(decrypt(&secret1, &blob).unwrap(), plaintext);
            assert_eq!(decrypt(&secret2, &blob).unwrap(), plaintext);

            // Altering the first encrypted key should be detected using `secret1`
            for i in 0..KEY_SIZE {
                let mut tampered_blob = blob.clone();
                tampered_blob[HEADER_SIZE + i] ^= 0xff;
                assert!(decrypt(&secret1, &tampered_blob).is_err());
                assert_eq!(decrypt(&secret2, &tampered_blob).unwrap(), plaintext);
            }

            // Altering the second encrypted key should be detected using `secret2`
            for i in 0..KEY_SIZE {
                let mut tampered_blob = blob.clone();
                tampered_blob[HEADER_SIZE + KEY_SIZE + i] ^= 0xff;
                assert_eq!(decrypt(&secret1, &tampered_blob).unwrap(), plaintext);
                assert!(decrypt(&secret2, &tampered_blob).is_err());
            }

            // Altering the ciphertext should be detected using either `secret1` or `secret2`
            for i in 0..plaintext.len() {
                let mut tampered_blob = blob.clone();
                tampered_blob[HEADER_SIZE + 2 * KEY_SIZE + i] ^= 0xff;
                assert!(decrypt(&secret1, &tampered_blob).is_err());
                assert!(decrypt(&secret2, &tampered_blob).is_err());
            }
        }
    }

    mod in_place {
        use crate::multienc::decrypt_in_place;
        use crate::multienc::encrypt_in_place;
        use crate::multienc::metadata_size;
        use crate::multienc::HEADER_SIZE;
        use crate::multienc::KEY_SIZE;
        use crate::participant::Secret;
        use rand::thread_rng;

        #[test]
        fn round_trip() {
            let plaintext = b"hello";
            let mut data = *plaintext;
            let mut metadata = [0u8; metadata_size(2)];

            let secret1 = Secret::random(thread_rng());
            let secret2 = Secret::random(thread_rng());
            let secret3 = Secret::random(thread_rng());
            let id1 = secret1.to_identity();
            let id2 = secret2.to_identity();

            assert!(
                encrypt_in_place(&mut data[..], &mut metadata[..], &[id1, id2], thread_rng())
                    .is_ok()
            );
            assert_ne!(&data, plaintext);

            let mut decrypted_data = data;
            assert!(decrypt_in_place(&secret1, &mut decrypted_data[..], &metadata[..]).is_ok());
            assert_eq!(&decrypted_data, plaintext);

            let mut decrypted_data = data;
            assert!(decrypt_in_place(&secret2, &mut decrypted_data[..], &metadata[..]).is_ok());
            assert_eq!(&decrypted_data, plaintext);

            let mut decrypted_data = data;
            assert!(decrypt_in_place(&secret3, &mut decrypted_data[..], &metadata[..]).is_err());
        }

        #[test]
        fn tampering() {
            let plaintext = b"hello";
            let mut data = *plaintext;
            let mut metadata = [0u8; metadata_size(2)];

            let secret1 = Secret::random(thread_rng());
            let secret2 = Secret::random(thread_rng());
            let id1 = secret1.to_identity();
            let id2 = secret2.to_identity();

            assert!(
                encrypt_in_place(&mut data[..], &mut metadata[..], &[id1, id2], thread_rng())
                    .is_ok()
            );
            assert_ne!(&data, plaintext);

            let mut decrypted_data = data;
            assert!(decrypt_in_place(&secret1, &mut decrypted_data[..], &metadata[..]).is_ok());
            assert_eq!(&decrypted_data, plaintext);

            let mut decrypted_data = data;
            assert!(decrypt_in_place(&secret2, &mut decrypted_data[..], &metadata[..]).is_ok());
            assert_eq!(&decrypted_data, plaintext);

            // Altering the first encrypted key should be detected using `secret1`
            for i in 0..KEY_SIZE {
                let mut tampered_metadata = metadata;
                tampered_metadata[HEADER_SIZE + i] ^= 0xff;

                let mut decrypted_data = data;
                assert!(decrypt_in_place(
                    &secret1,
                    &mut decrypted_data[..],
                    &tampered_metadata[..]
                )
                .is_err());

                let mut decrypted_data = data;
                assert!(decrypt_in_place(
                    &secret2,
                    &mut decrypted_data[..],
                    &tampered_metadata[..]
                )
                .is_ok());
                assert_eq!(&decrypted_data, plaintext);
            }

            // Altering the second encrypted key should be detected using `secret2`
            for i in 0..KEY_SIZE {
                let mut tampered_metadata = metadata;
                tampered_metadata[HEADER_SIZE + KEY_SIZE + i] ^= 0xff;

                let mut decrypted_data = data;
                assert!(decrypt_in_place(
                    &secret1,
                    &mut decrypted_data[..],
                    &tampered_metadata[..]
                )
                .is_ok());
                assert_eq!(&decrypted_data, plaintext);

                let mut decrypted_data = data;
                assert!(decrypt_in_place(
                    &secret2,
                    &mut decrypted_data[..],
                    &tampered_metadata[..]
                )
                .is_err());
            }

            // Altering the ciphertext should be detected using either `secret1` or `secret2`
            for i in 0..plaintext.len() {
                let mut tampered_data = data;
                tampered_data[i] ^= 0xff;

                let mut decrypted_data = tampered_data;
                assert!(
                    decrypt_in_place(&secret1, &mut decrypted_data[..], &metadata[..]).is_err()
                );

                let mut decrypted_data = tampered_data;
                assert!(
                    decrypt_in_place(&secret2, &mut decrypted_data[..], &metadata[..]).is_err()
                );
            }
        }
    }
}
