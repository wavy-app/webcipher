//! A semi-incomplete representations of `JWK`'s, as according to [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517).
//!
//! `JWK`'s are used to validate `JWT`'s that are sent by some client.
//!
//! If the data contained in the `JWK` can successfully validate the `JWT` sent
//! by the client, you can be assured that the according `OAuth2` provider did,
//! indeed, sign that token. This means that the data contained inside can be
//! trusted as having being provisioned by the `OAuth2` provider.
//!
//! Note that [`Key`] is not a *COMPLETE* representation of a `JWK` as according
//! to the RFC. Namely, we expect the fetched keys to have the fields `e` and
//! `n`, which specifically correspond to the `RS256` encryption/decryption
//! algorithms.
//!
//! This means that the [`super::RemoteCache`] does not support other algorithms
//! for `OAuth2`.

use jsonwebtoken::Algorithm;
use serde::Deserialize;

/// A representation of a [`Key`] struct.
///
/// This representation is incomplete, and furthermore, requires that certain
/// fields be present whereas the RFC does not. This is because this
/// representation of [`Key`] has been fine-tuned to specifically work for
/// `OAuth2` `JWT`s.
///
/// Other forms are accepted.
/// This is a reasonable restriction since most `OAuth2` service providers use
/// `RSA` encryption using an exponent (i.e., the `e` field) and a modulus
/// (i.e., the `n` field) in the [`Key`].
#[derive(Hash, Debug, Deserialize, PartialEq, Eq)]
pub struct Key {
    #[serde(default)]
    pub e: String,
    pub kty: KeyType,
    pub alg: Option<Algorithm>,
    #[serde(default)]
    pub n: String,
    pub kid: String,
    pub r#use: Use,
}

/// All possible key-types as stated by the RFC.
///
/// This enumeration is fully complete.
/// Namely, all variants declared in this enum are mentioned in the RFC and all
/// variants mentioned in the RFC are declared in this enum.
///
/// Note that [`super::RemoteCache`] still expects [`KeyType::RSA`] only.
#[derive(Hash, Debug, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    RSA,
    EC,
}

#[allow(non_camel_case_types)]
#[derive(Hash, Debug, Deserialize, PartialEq, Eq)]
pub enum Use {
    enc,
    sig,
}
