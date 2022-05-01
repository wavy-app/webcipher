use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::TokenData;
use jsonwebtoken::Validation;
use serde::Deserialize;

use crate::prelude::Error;
use crate::prelude::{self};

pub mod local;
pub mod remote;

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
