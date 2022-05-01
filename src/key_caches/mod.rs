//! A local or remote `JWK` storage and caching implementation.
//!
//! Caching keys and their corresponding [`DecodingKey`] helps in optimizing
//! performance.
//!
//! Namely, your application will not need to continuously fetch keys from a
//! source and re-compute the corresponding [`DecodingKey`] if the `JWK`s at the
//! source have not been rotated yet.

use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::TokenData;
use jsonwebtoken::Validation;
use serde::Deserialize;

use crate::prelude;
use crate::prelude::Error;

pub mod local;
pub mod remote;

/// Decrypt the given token into it's [`TokenData`] struct.
///
/// If the `alg` in the headers is not [`Algorithm::RS256`], or if a `kid` is
/// not present (or if it is present but the cache does not contain a match),
/// this function will return an error. Otherwise, the function will return try
/// to decrypt the data using the [`DecodingKey`] found by calling the call-back
/// function.
fn decrypt<'b, Claims, I, F>(
    token: I,
    selector: F,
    validation: Option<Validation>,
) -> prelude::Result<TokenData<Claims>>
where
    String: From<I>,
    Claims: for<'a> Deserialize<'a>,
    F: for<'a> Fn(&'a String) -> prelude::Result<&'b DecodingKey>,
{
    let token: String = token.into();
    let Header { typ, alg, kid, .. } = decode_header(&token)?;

    match alg {
        Algorithm::RS256 => (),
        _ => Err(Error::invalid_algorithm)?,
    };

    let validation = validation.unwrap_or(Validation::new(alg));

    let _ = typ
        .map(|typ| typ.to_lowercase())
        .and_then(|typ| match &*typ {
            "jwt" => Some(()),
            _ => None,
        })
        .ok_or(Error::unrecognized_jws_type)?;

    let kid = kid.ok_or(Error::no_kid_present)?;

    let decoding_key = selector(&kid)?;

    let claim = decode(&token, decoding_key, &validation)?;

    Ok(claim)
}
