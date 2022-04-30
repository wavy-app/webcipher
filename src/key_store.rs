use std::collections::HashMap;
use std::collections::HashSet;

use hyper::Client;
use hyper_tls::HttpsConnector;
use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::TokenData;
use jsonwebtoken::Validation;
use serde::Deserialize;
use serde_json::Value;

use crate::error::Error;
use crate::jwk_registry;
use crate::key::Key;

pub struct KeyStore {
    pub(crate) uri: http::Uri,
    pub(crate) keys: HashMap<String, Key>,
}

impl KeyStore {
    pub async fn new<I>(uri: I) -> jwk_registry::Result<Self>
    where
        String: From<I>,
    {
        let uri = String::from(uri).parse::<http::Uri>()?;
        let keys = fetch(uri.clone()).await?;

        let store = Self { uri, keys };

        Ok(store)
    }

    pub async fn refresh(&mut self) -> jwk_registry::Result<()> {
        let Self { uri, .. } = self;
        let keys = fetch(uri.clone()).await?;

        self.keys = keys;

        Ok(())
    }

    pub async fn decode<Claim, I>(
        &self,
        token: I,
    ) -> jwk_registry::Result<TokenData<Claim>>
    where
        String: From<I>,
        Claim: for<'a> Deserialize<'a>,
    {
        let Self { keys, .. } = self;

        let token: String = token.into();
        let jsonwebtoken::Header { typ, alg, kid, .. } =
            decode_header(&token).unwrap();

        let _ = typ
            .map(|typ| typ.to_lowercase())
            .and_then(|typ| match &*typ {
                "jwt" => Some("jwt"),
                _ => None,
            })
            .ok_or(Error::unrecognized_jws_type)?;
        let kid = kid.ok_or(Error::no_kid_present)?;

        let Key { e, n, .. } =
            keys.get(&kid).ok_or(Error::no_corresponding_kid_in_store)?;

        let validation = Validation::new(alg);
        let key = DecodingKey::from_rsa_components(n, e)?;

        let claim = decode::<Claim>(&token, &key, &validation)?;

        Ok(claim)
    }

    pub fn uri(&self) -> &http::Uri {
        &self.uri
    }

    pub fn uri_mut(&mut self) -> &mut http::Uri {
        &mut self.uri
    }

    pub fn keys(&self) -> &HashMap<String, Key> {
        &self.keys
    }

    pub fn keys_mut(&mut self) -> &mut HashMap<String, Key> {
        &mut self.keys
    }
}

async fn fetch(uri: http::Uri) -> jwk_registry::Result<HashMap<String, Key>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let mut response = client.get(uri).await?;

    let bytes = hyper::body::to_bytes(response.body_mut()).await?;
    let bytes = bytes.as_ref();
    let body: Value = serde_json::from_slice(bytes)?;
    let body = body
        .get("keys")
        .ok_or(Error::unable_to_fetch_keys {
            message: "No 'keys' array contained in the returned object.".into(),
        })?
        .clone();

    let keys = serde_json::from_value::<HashSet<Key>>(body)?
        .into_iter()
        .map(|key| {
            let Key { kid, .. } = &key;
            let kid = kid.clone();
            (kid, key)
        })
        .collect::<HashMap<String, Key>>();

    Ok(keys)
}
