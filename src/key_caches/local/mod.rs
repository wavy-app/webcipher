use std::collections::BTreeMap;
use std::str::FromStr;

use jsonwebtoken::encode;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::TokenData;
use jsonwebtoken::Validation;
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

use crate::error::Error;
use crate::key_caches::decrypt;
use crate::prelude;

#[cfg(test)]
mod tests;

#[derive(Default)]
pub struct LocalCache {
    pub(crate) algorithm: Algorithm,
    pub(crate) keys: BTreeMap<Uuid, (EncodingKey, DecodingKey)>,
}

impl LocalCache {
    pub fn new(algorithm: Algorithm) -> Self {
        let keys = BTreeMap::default();

        Self { algorithm, keys }
    }

    pub fn add_key(
        &mut self,
        encoding_key: EncodingKey,
        decoding_key: DecodingKey,
    ) -> Uuid {
        let Self { keys, .. } = self;
        let kid = Uuid::new_v4();
        let _ = keys.insert(kid, (encoding_key, decoding_key));

        kid
    }

    pub fn remove_key(
        &mut self,
        kid: Uuid,
    ) {
        let Self { keys, .. } = self;
        keys.remove(&kid);
    }

    pub fn encrypt<Claims>(&self, claims: Claims) -> prelude::Result<String>
    where
        Claims: Serialize,
    {
        let Self { algorithm, keys } = self;

        let length = keys.len();
        let rand_index = match length {
            0 => 0,
            _ => fastrand::usize(..length),
        };

        let kid = *keys
            .keys()
            .collect::<Vec<_>>()
            .get(rand_index)
            .ok_or(Error::no_corresponding_kid_in_store)?;

        let (encoding_key, _) =
            keys.get(&kid).ok_or(Error::no_corresponding_kid_in_store)?;

        let header = Header {
            alg: *algorithm,
            typ: Some("JWT".into()),
            kid: Some(kid.to_string()),
            ..Default::default()
        };

        let token = encode(&header, &claims, encoding_key)?;

        Ok(token)
    }

    pub fn decrypt<Claims, I>(
        &self,
        token: &I,
        validate_exp: bool,
    ) -> prelude::Result<TokenData<Claims>>
    where
        String: for<'a> From<&'a I>,
        Claims: for<'de> Deserialize<'de>,
    {
        let Self { algorithm, keys } = self;

        let selector = |kid: &String| {
            let kid = Uuid::from_str(&*kid)?;
            let x = keys
                .get(&kid)
                .map(|(_, decoding_key)| decoding_key)
                .ok_or(Error::no_corresponding_kid_in_store);
            x
        };

        let mut validation = Validation::new(*algorithm);
        validation.validate_exp = validate_exp;

        decrypt(token, selector, Some(validation), false)
    }

    pub fn keys(&self) -> &BTreeMap<Uuid, (EncodingKey, DecodingKey)> {
        &self.keys
    }

    pub fn keys_mut(
        &mut self,
    ) -> &mut BTreeMap<Uuid, (EncodingKey, DecodingKey)> {
        &mut self.keys
    }

    pub fn algorithm(&self) -> &Algorithm {
        &self.algorithm
    }

    pub fn algorithm_mut(&mut self) -> &mut Algorithm {
        &mut self.algorithm
    }
}
