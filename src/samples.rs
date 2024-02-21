use std::collections::BTreeMap;

use reddsa::frost::{
    redjubjub::{
        keys::{
            KeyPackage, PublicKeyPackage, SecretShare, SigningShare,
            VerifiableSecretSharingCommitment, VerifyingShare,
        },
        round1::{NonceCommitment, SigningCommitments},
        round2::SignatureShare,
        Identifier, SigningPackage, VerifyingKey,
    },
    redpallas::{
        frost::{Element, Scalar},
        Ciphersuite, Field, Group,
    },
};

use reddsa::frost::redjubjub::JubjubBlake2b512;

type C = JubjubBlake2b512;

fn element1() -> Element<C> {
    <C as Ciphersuite>::Group::generator()
}

fn element2() -> Element<C> {
    element1() + element1()
}

fn scalar1() -> Scalar<C> {
    let one = <<C as Ciphersuite>::Group as Group>::Field::one();
    let three = one + one + one;
    // To return a fixed non-small number, get the inverse of 3
    <<C as Ciphersuite>::Group as Group>::Field::invert(&three)
        .expect("nonzero elements have inverses")
}

pub fn signing_commitments() -> SigningCommitments {
    let serialized_element1 = <C as Ciphersuite>::Group::serialize(&element1());
    let serialized_element2 = <C as Ciphersuite>::Group::serialize(&element2());
    let hiding_nonce_commitment = NonceCommitment::deserialize(serialized_element1).unwrap();
    let binding_nonce_commitment = NonceCommitment::deserialize(serialized_element2).unwrap();

    SigningCommitments::new(hiding_nonce_commitment, binding_nonce_commitment)
}

pub fn signing_package() -> SigningPackage {
    let identifier = 42u16.try_into().unwrap();
    let commitments = BTreeMap::from([(identifier, signing_commitments())]);
    let message = "hello world".as_bytes();

    SigningPackage::new(commitments, message)
}

pub fn signature_share() -> SignatureShare {
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1());

    SignatureShare::deserialize(serialized_scalar).unwrap()
}

pub fn secret_share() -> SecretShare {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1());
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1());
    let signing_share = SigningShare::deserialize(serialized_scalar).unwrap();
    let vss_commitment =
        VerifiableSecretSharingCommitment::deserialize(vec![serialized_element]).unwrap();

    SecretShare::new(identifier, signing_share, vss_commitment)
}

pub fn key_package() -> KeyPackage {
    let identifier = 42u16.try_into().unwrap();
    let serialized_scalar = <<C as Ciphersuite>::Group as Group>::Field::serialize(&scalar1());
    let serialized_element: [u8; 32] = <C as Ciphersuite>::Group::serialize(&element1());
    let signing_share = SigningShare::deserialize(serialized_scalar).unwrap();
    let verifying_share = VerifyingShare::deserialize(serialized_element).unwrap();
    let serialized_element = <C as Ciphersuite>::Group::serialize(&element1());
    let verifying_key = VerifyingKey::deserialize(serialized_element).unwrap();

    KeyPackage::new(identifier, signing_share, verifying_share, verifying_key, 2)
}

pub fn frost_public_key_package() -> PublicKeyPackage {
    let serialized_element: [u8; 32] = <C as Ciphersuite>::Group::serialize(&element1());
    let verifying_key = VerifyingKey::deserialize(serialized_element).unwrap();

    let verifying_shares: BTreeMap<Identifier, VerifyingShare> = BTreeMap::new();
    PublicKeyPackage::new(verifying_shares, verifying_key)
}
