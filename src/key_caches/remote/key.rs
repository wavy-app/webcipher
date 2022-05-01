//! An incomplete representations of `JWK`'s, as according to [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517).
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
//!
//! An example `JWK` key-set being returned by `Google` is:
//! ```no_run
//! {
//!     "keys": [
//!         {
//!             "alg": "RS256",
//!             "n": "qR7fa5Gb2rhy-RJCJwSFn7J2KiKs_WgMXVR-23Z6OfX89_utHGkM-Qk27abDGPXa0u9OKzwOU2JZx7yNye7LH4kKX1PEAEz0p9XGbfF3yFyiD5JkziOfQyYj9ERKWfxKatpk-oi9D_p2leQKzTfEZWIfLVZkgNXFkUdhzCG68j5kFhZ1Ys9bRRDo3Q1BkLXmP_Y6PW1g74_rvAYCiQ6hJVvyyXYnqHcoawedgO6_MQihaSeAW25AhY8MXVo4-MdNvboahOlJg280YuxkCZiRqxyQEqd5HKCPzP49TDQbdAxDa900ewCQK9gkbHiNKFbOBv_b94YfMh93NUoEa-jCnw==",
//!             "kid": "861649e450315383f6b9d510b7cd4e9226c3cd88",
//!             "use": "sig",
//!             "e": "AQAB",
//!             "kty": "RSA"
//!         },
//!         {
//!             "use": "sig",
//!             "alg": "RS256",
//!             "n": "oz7Gb9oYt_sq8Z37LDAcfSqQBuTtD669-tjg-_hTVyXPRslIg6qPPLlVthRkXZYjhwnc85CXO9TW1C1ItJjX70vSQPvQ1wALWMOd306BPIYRkkKSa3APtidaM6ZmR2HosWRUf_03luhfkk9QUyVaCP2WJTFxENuJi5yyggE0cDT7MJGqn9VvYCv_-LUjiQ4v8jvc-dH881HeBDtwpsucXGCmx4ZcjEBcrNXqJiQHPo1I3OIXxxtsLxujU8f0QVRjdSQDr8KgeSdic8kk4iJp8DISWSU1hQSCbXUCG465L6I1iytO6iNQp-rfjpBt9jx0TA6VqIteglWhu5gfcKb9YQ==",
//!             "kty": "RSA",
//!             "kid": "fcbd7f481a825d113e0d03dd94e60b69ff1665a2",
//!             "e": "AQAB"
//!         }
//!     ]
//! }
//! ```
//!
//! Serializing the first key in the array into a [`Key`] instance would result
//! in:
//! ```
//! let key = Key {
//!     alg: Some(jsonwebtoken::Algorithm::RS256),
//!     n: "qR7fa5Gb2rhy-RJCJwSFn7J2KiKs_WgMXVR-23Z6OfX89_utHGkM-Qk27abDGPXa0u9OKzwOU2JZx7yNye7LH4kKX1PEAEz0p9XGbfF3yFyiD5JkziOfQyYj9ERKWfxKatpk-oi9D_p2leQKzTfEZWIfLVZkgNXFkUdhzCG68j5kFhZ1Ys9bRRDo3Q1BkLXmP_Y6PW1g74_rvAYCiQ6hJVvyyXYnqHcoawedgO6_MQihaSeAW25AhY8MXVo4-MdNvboahOlJg280YuxkCZiRqxyQEqd5HKCPzP49TDQbdAxDa900ewCQK9gkbHiNKFbOBv_b94YfMh93NUoEa-jCnw==".into(),
//!     kid: "861649e450315383f6b9d510b7cd4e9226c3cd88".into(),
//!     r#use: Use::sig,
//!     e: "AQAB".into(),
//!     kty: KeyType::RSA,
//! };
//! ```
//!
//! You can take a look for yourself by visiting
//! <https://www.googleapis.com/oauth2/v2/certs>.

use jsonwebtoken::Algorithm;
use serde::Deserialize;

/// An incomplete representation of a `JWK`.
///
/// This representation is incomplete.
/// Namely, there exist fields in the RFC which are not present in [`Key`].
/// Furthermore, [`Key`] requires that certain fields be mandatory whereas the
/// RFC requires them to be optional.
/// This is because this representation of [`Key`] has been fine-tuned to
/// specifically work for `OAuth2` `JWT`s.
///
/// However, with that being said, all the fields in [`Key`] are as stated by
/// the RFC.
///
/// This is a reasonable restriction since most `OAuth2` service providers use
/// `RSA` encryption using an exponent (i.e., the `e` field) and a modulus
/// (i.e., the `n` field).
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
///
/// Namely, all variants declared in this enum are mentioned in the RFC and all
/// variants mentioned in the RFC are declared in this enum.
///
/// Note that [`super::RemoteCache`] still expects [`KeyType::RSA`] only.
///
/// Taken from [RFC7517, Section 4.1](https://datatracker.ietf.org/doc/html/rfc7517#section-4.1).
///
/// >> The "kty" (key type) parameter identifies the cryptographic algorithm
/// family used with the key, such as "RSA" or "EC". "kty" values should either
/// be registered in the IANA "JSON Web Key Types" registry established by
/// [JWA](https://datatracker.ietf.org/doc/html/rfc7518) or be a value that
/// contains a Collision- Resistant Name.
/// The "kty" value is a case-sensitive string.
/// This member MUST be present in a JWK.
///
/// >> A list of defined "kty" values can be found in the IANA "JSON Web Key
/// Types" registry established by [JWA](https://datatracker.ietf.org/doc/html/rfc7518);
/// the initial contents of this registry are the values defined in Section 6.1
/// of [JWA](https://datatracker.ietf.org/doc/html/rfc7518).
/// The key type definitions include specification of the members to be used for
/// those key types. Members used with specific "kty" values can be found in the
/// IANA "JSON Web Key Parameters" registry established by
/// [Section 8.1](https://datatracker.ietf.org/doc/html/rfc7517#section-8.1).
#[derive(Hash, Debug, Deserialize, PartialEq, Eq)]
pub enum KeyType {
    /// Indicates to use the `RSA` cryptographic family of algorithms.
    RSA,

    /// Indicates to use the `EC` cryptographic family of algorithms.
    EC,
}

/// All possible uses as stated by the RFC.
///
/// This enumeration is fully complete.
///
/// Namely, all variants declared in this enum are mentioned in the RFC and all
/// variants mentioned in the RFC are declared in this enum.
///
/// Note that [`super::RemoteCache`] still expects [`Use::sig`] only.
#[allow(non_camel_case_types)]
#[derive(Hash, Debug, Deserialize, PartialEq, Eq)]
pub enum Use {
    /// Indicates that this [`Key`] is intended to be used to encrypt data.
    enc,

    /// Indicates that this [`Key`] is intended to be used to verify the
    /// signature on data.
    sig,
}
