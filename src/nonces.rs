/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use crate::frost::keys::SigningShare;
use crate::frost::round1::SigningNonces;
use crate::participant::Identity;
use crate::participant::IdentitySerialization;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::borrow::Borrow;

type ParticipantCount = u32;

fn nonces_seed<I>(
    secret: &SigningShare,
    transaction_hash: &[u8],
    signing_participants: &[I],
) -> <ChaCha20Rng as SeedableRng>::Seed
where
    I: Borrow<Identity>,
{
    let mut identifiers: Vec<IdentitySerialization> = signing_participants
        .iter()
        .map(|id| id.borrow().serialize())
        .collect();
    identifiers.sort_unstable();
    identifiers.dedup();

    let count: ParticipantCount = identifiers
        .len()
        .try_into()
        .expect("too many signing_participants");

    let mut hasher = blake3::Hasher::new();

    hasher.update(&secret.serialize());
    hasher.update(transaction_hash);
    hasher.update(&count.to_le_bytes());
    identifiers.into_iter().for_each(|id| {
        hasher.update(&id);
    });

    hasher.finalize().into()
}

/// Generate [`SigningNonces`] for a signer participant.
///
/// The nonces generated are *deterministic*: given the same `secret`, `transaction_hash`, and list
/// of `signing_participants`, the nonces returned are the same. The order of
/// `signing_participants` can be changed without influencing the output.
pub fn deterministic_signing_nonces<I>(
    secret: &SigningShare,
    transaction_hash: &[u8],
    signing_participants: &[I],
) -> SigningNonces
where
    I: Borrow<Identity>,
{
    let seed = nonces_seed(secret, transaction_hash, signing_participants);
    let mut csrng = ChaCha20Rng::from_seed(seed);
    SigningNonces::new(secret, &mut csrng)
}

#[cfg(test)]
mod tests {
    use super::deterministic_signing_nonces;
    use crate::nonces::SigningShare;
    use crate::participant::Secret;
    use rand::thread_rng;

    macro_rules! assert_nonces_eq {
        ( $left:expr , $right:expr ) => {
            let left = $left;
            let right = $right;
            // Cannot use `assert_eq` because the types do not implement `Debug`. Also cannot use
            // `left == right` because `SigningNonces` does not implement `PartialEq`
            assert!(
                left.hiding() == right.hiding(),
                "hiding nonces do not match"
            );
            assert!(
                left.binding() == right.binding(),
                "binding nonces do not match"
            );
        };
    }

    macro_rules! assert_nonces_ne {
        ( $left:expr , $right:expr ) => {
            let left = $left;
            let right = $right;
            // Cannot use `assert_ne` because the types do not implement `Debug`. Also cannot use
            // `left != right` because `SigningNonces` does not implement `PartialEq`
            assert!(
                left.hiding() != right.hiding(),
                "hiding nonces should not be equal"
            );
            assert!(
                left.binding() != right.binding(),
                "binding nonces should not be equal"
            );
        };
    }

    #[test]
    fn same_input() {
        let secret = SigningShare::deserialize(b"some signing share.............\0").unwrap();
        let transaction_hash = b"some hash";
        let p1 = Secret::random(thread_rng()).to_identity();
        let p2 = Secret::random(thread_rng()).to_identity();
        let p3 = Secret::random(thread_rng()).to_identity();
        let signing_participants = [p1, p2, p3];

        let nonces1 =
            deterministic_signing_nonces(&secret, transaction_hash, &signing_participants);
        let nonces2 =
            deterministic_signing_nonces(&secret, transaction_hash, &signing_participants);

        assert_nonces_eq!(nonces1, nonces2);
    }

    #[test]
    fn different_participants_order() {
        let secret = SigningShare::deserialize(b"some signing share.............\0").unwrap();
        let transaction_hash = b"some hash";
        let p1 = Secret::random(thread_rng()).to_identity();
        let p2 = Secret::random(thread_rng()).to_identity();
        let p3 = Secret::random(thread_rng()).to_identity();
        let signing_participants1 = [&p1, &p2, &p3];
        let signing_participants2 = [&p3, &p2, &p1];

        let nonces1 =
            deterministic_signing_nonces(&secret, transaction_hash, &signing_participants1);
        let nonces2 =
            deterministic_signing_nonces(&secret, transaction_hash, &signing_participants2);

        assert_nonces_eq!(nonces1, nonces2);
    }

    #[test]
    fn repeated_participants() {
        let secret = SigningShare::deserialize(b"some signing share.............\0").unwrap();
        let transaction_hash = b"some hash";
        let p1 = Secret::random(thread_rng()).to_identity();
        let p2 = Secret::random(thread_rng()).to_identity();
        let p3 = Secret::random(thread_rng()).to_identity();
        let signing_participants1 = [&p1, &p2, &p3];
        let signing_participants2 = [&p1, &p2, &p3, &p1, &p2, &p3];

        let nonces1 =
            deterministic_signing_nonces(&secret, transaction_hash, &signing_participants1);
        let nonces2 =
            deterministic_signing_nonces(&secret, transaction_hash, &signing_participants2);

        assert_nonces_eq!(nonces1, nonces2);
    }

    #[test]
    fn different_shares() {
        let secret1 = SigningShare::deserialize(b"some signing share.............\0").unwrap();
        let secret2 = SigningShare::deserialize(b"some other signing share.......\0").unwrap();
        let transaction_hash = b"some hash";
        let p1 = Secret::random(thread_rng()).to_identity();
        let p2 = Secret::random(thread_rng()).to_identity();
        let p3 = Secret::random(thread_rng()).to_identity();
        let signing_participants = [p1, p2, p3];

        let nonces1 =
            deterministic_signing_nonces(&secret1, transaction_hash, &signing_participants);
        let nonces2 =
            deterministic_signing_nonces(&secret2, transaction_hash, &signing_participants);

        assert_nonces_ne!(nonces1, nonces2);
    }

    #[test]
    fn different_transactions() {
        let secret = SigningShare::deserialize(b"some signing share.............\0").unwrap();
        let transaction_hash1 = b"some hash";
        let transaction_hash2 = b"some other hash";
        let p1 = Secret::random(thread_rng()).to_identity();
        let p2 = Secret::random(thread_rng()).to_identity();
        let p3 = Secret::random(thread_rng()).to_identity();
        let signing_participants = [p1, p2, p3];

        let nonces1 =
            deterministic_signing_nonces(&secret, transaction_hash1, &signing_participants);
        let nonces2 =
            deterministic_signing_nonces(&secret, transaction_hash2, &signing_participants);

        assert_nonces_ne!(nonces1, nonces2);
    }

    #[test]
    fn different_participants() {
        let secret = SigningShare::deserialize(b"some signing share.............\0").unwrap();
        let transaction_hash = b"some hash";
        let p1 = Secret::random(thread_rng()).to_identity();
        let p2 = Secret::random(thread_rng()).to_identity();
        let p3 = Secret::random(thread_rng()).to_identity();
        let p4 = Secret::random(thread_rng()).to_identity();
        let signing_participants1 = [&p1, &p2, &p3];
        let signing_participants2 = [&p1, &p2, &p4];

        let nonces1 =
            deterministic_signing_nonces(&secret, transaction_hash, &signing_participants1);
        let nonces2 =
            deterministic_signing_nonces(&secret, transaction_hash, &signing_participants2);

        assert_nonces_ne!(nonces1, nonces2);
    }
}
