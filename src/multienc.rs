/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::participant::Identity;
use crate::participant::Secret;
use chacha20::cipher::KeyIvInit;
use chacha20::cipher::StreamCipher;
use chacha20::ChaCha20;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::Error;
use chacha20poly1305::KeyInit;
use chacha20poly1305::Nonce;
use rand_core::CryptoRng;
use rand_core::RngCore;
use std::borrow::Borrow;
use x25519_dalek::PublicKey;
use x25519_dalek::ReusableSecret;

pub const KEY_SIZE: usize = 32;
pub type EncryptedKey = [u8; KEY_SIZE];

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct MultiRecipientBlob<Keys, Cipher>
where
    Keys: AsRef<[EncryptedKey]>,
    Cipher: AsRef<[u8]>,
{
    pub agreement_key: PublicKey,
    pub encrypted_keys: Keys,
    pub ciphertext: Cipher,
}

/// Encrypt arbitrary `data` once for multiple participants.
///
/// The data can be decrypted by each participant using [`decrypt`].
pub fn encrypt<I, R>(
    data: &[u8],
    recipients: &[I],
    mut csrng: R,
) -> MultiRecipientBlob<Vec<EncryptedKey>, Vec<u8>>
where
    I: Borrow<Identity>,
    R: RngCore + CryptoRng,
{
    // Use a zero nonce for all encryptions below. This is safe because each encryption key is
    // ephemeral and used exactly once, so no (key, nonce) reuse ever happens.
    let nonce = Nonce::default();

    // Generate a random encryption key and encrypt the data with it using ChaCha20Poly1305
    let encryption_key = ChaCha20Poly1305::generate_key(&mut csrng);
    let cipher = ChaCha20Poly1305::new(&encryption_key);
    let ciphertext = cipher.encrypt(&nonce, data).expect("encryption failed");

    // Encrypt the encryption key for each recipient using X25519 + ChaCha20.
    //
    // Here we are using an unauthenticated cipher because we rely on the integrity provided by
    // ChaCha20Poly1305 on the data. If an encrypted key is tampered, the recipient won't be able
    // to correctly recover the data using ChaCha20Poly1305, and so they can detect the tampering.
    let agreement_secret = ReusableSecret::random_from_rng(csrng);
    let agreement_key = PublicKey::from(&agreement_secret);
    let encrypted_keys = recipients
        .iter()
        .map(|id| {
            let recipient_key = id.borrow().encryption_key();
            let shared_secret = agreement_secret.diffie_hellman(recipient_key).to_bytes();
            let mut cipher = ChaCha20::new((&shared_secret).into(), &nonce);
            let mut encrypted_key = encryption_key;

            cipher.apply_keystream(&mut encrypted_key);
            encrypted_key.into()
        })
        .collect();

    MultiRecipientBlob {
        agreement_key,
        encrypted_keys,
        ciphertext,
    }
}

/// Decrypt data produced by [`encrypt`] using one participant secret.
pub fn decrypt<Keys, Cipher>(
    secret: &Secret,
    blob: &MultiRecipientBlob<Keys, Cipher>,
) -> Result<Vec<u8>, Error>
where
    Keys: AsRef<[EncryptedKey]>,
    Cipher: AsRef<[u8]>,
{
    let nonce = Nonce::default();
    let shared_secret = secret
        .decryption_key()
        .diffie_hellman(&blob.agreement_key)
        .to_bytes();

    // Try to decrypt each encryption key one by one, and use them to attempt to decrypt the data,
    // until the data is recovered.
    blob.encrypted_keys
        .as_ref()
        .iter()
        .filter_map(|encrypted_key| {
            // Decrypt the encryption key with X25519 + ChaCha20. This will always succeed, even if
            // the encryption key was not for this participant (in which case, it will result in
            // random bytes).
            let mut encryption_key = *encrypted_key;
            let mut cipher = ChaCha20::new((&shared_secret).into(), &nonce);
            cipher.apply_keystream(&mut encryption_key);

            // Decrypt the data with ChaCha20Poly1305. This will fail if the encryption key was not
            // for this participant (or if the encryption key was tampered).
            let cipher = ChaCha20Poly1305::new((&encryption_key).into());
            cipher.decrypt(&nonce, blob.ciphertext.as_ref()).ok()
        })
        .next()
        .ok_or(Error)
}

#[cfg(test)]
mod tests {
    use super::decrypt;
    use super::encrypt;
    use super::KEY_SIZE;
    use crate::participant::Secret;
    use chacha20poly1305::Error;
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

        assert_eq!(decrypt(&secret1, &blob), Ok(plaintext.to_vec()));
        assert_eq!(decrypt(&secret2, &blob), Ok(plaintext.to_vec()));
        assert_eq!(decrypt(&secret3, &blob), Err(Error));
    }

    #[test]
    fn tampering() {
        let plaintext = b"hello";

        let secret1 = Secret::random(thread_rng());
        let secret2 = Secret::random(thread_rng());
        let id1 = secret1.to_identity();
        let id2 = secret2.to_identity();

        let blob = encrypt(plaintext, &[id1, id2], thread_rng());

        assert_eq!(decrypt(&secret1, &blob), Ok(plaintext.to_vec()));
        assert_eq!(decrypt(&secret2, &blob), Ok(plaintext.to_vec()));

        // Altering the first encrypted key should be detected using `secret1`
        for i in 0..KEY_SIZE {
            let mut tampered_blob = blob.clone();
            tampered_blob.encrypted_keys[0][i] ^= 0xff;
            assert_eq!(decrypt(&secret1, &tampered_blob), Err(Error));
            assert_eq!(decrypt(&secret2, &tampered_blob), Ok(plaintext.to_vec()));
        }

        // Altering the second encrypted key should be detected using `secret2`
        for i in 0..KEY_SIZE {
            let mut tampered_blob = blob.clone();
            tampered_blob.encrypted_keys[1][i] ^= 0xff;
            assert_eq!(decrypt(&secret1, &tampered_blob), Ok(plaintext.to_vec()));
            assert_eq!(decrypt(&secret2, &tampered_blob), Err(Error));
        }

        // Altering the ciphertext should be detected using either `secret1` or `secret2`
        for i in 0..plaintext.len() {
            let mut tampered_blob = blob.clone();
            tampered_blob.ciphertext[i] ^= 0xff;
            assert_eq!(decrypt(&secret1, &tampered_blob), Err(Error));
            assert_eq!(decrypt(&secret2, &tampered_blob), Err(Error));
        }
    }
}
