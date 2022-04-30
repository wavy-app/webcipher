//! An abstraction over the key management for `JWKs`.

use std::collections::HashMap;
use std::collections::HashSet;

use derivative::*;
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

/// A storage location for all `JWK`'s used for encryption for `OAuth2`.
/// The `URI` of the target is stored and the corresponding keys are fetched
/// upon creation.
///
/// One can then decode tokens presumably signed by the target by calling
/// [`decode`](`KeyStore::decode`). If the token was indeed provisioned by the
/// target, this operation will be successful. Otherwise, it will fail.
///
/// For example, consider a struct, `MyClaims`, which contains the required
/// public claims, as well as your own specific private claims.
/// ```no_run
/// struct MyClaims {
///     // public claims:
///     // ...
///
///     // private claims (examples):
///     // ...
///     user_id: Uuid,
///     first_name: String,
///     last_name: String,
/// }
///
/// let uri = "https://my_target.com/certs";
/// let key_store = KeyStore::new(uri).await?;
///
/// let token = "a.b.c";
/// let claims: MyClaims = key_store.decode::<MyClaims>(&token)?;
/// ```
/// 
/// Many targets rotate their keys, and as such, cached keys will fail after a
/// certain period of time. [`KeyStore`] provides the
/// [`refresh`](`KeyStore::refresh`) function to refresh a given [`KeyStore`].
/// [`refresh`](`KeyStore::refresh`) will re-fetch the new keys (from its
/// current `uri`).
#[derive(Derivative)]
#[derivative(Hash, PartialEq, Eq)]
pub struct KeyStore {
    /// The [`URI`] from which to fetch the keys.
    ///
    /// [`URI`]: https://docs.rs/http/latest/http/uri/struct.Uri.html
    pub(crate) uri: http::Uri,

    /// A mapping of `kid`s (i.e., Key-IDs) and the [`Key`] that they
    /// originated from.
    ///
    /// Since `JWT`'s are signed by a [`Key`] that has a matching `kid`, this
    /// mapping makes it easy to find the corresponding [`Key`].
    ///
    /// Two [`KeyStore`]'s are considered equivalent if and only if their
    /// `uri`'s match.
    #[derivative(PartialEq = "ignore", Hash = "ignore")]
    pub(crate) keys: HashMap<String, Key>,
}

impl KeyStore {
    /// Generate a new [`KeyStore`] by asynchronously fetching the keys at the
    /// given [`URI`].
    ///
    /// [`URI`]: https://docs.rs/http/latest/http/uri/struct.Uri.html
    pub async fn new<I>(uri: I) -> jwk_registry::Result<Self>
    where
        String: From<I>,
    {
        let uri = String::from(uri).parse::<http::Uri>()?;
        let keys = fetch(uri.clone()).await?;

        let store = Self { uri, keys };

        Ok(store)
    }

    /// Refreshes the current [`KeyStore`] by asynchronously fetching the keys
    /// at the given [`URI`].
    ///
    /// Useful for when targets rotate their keys.
    ///
    /// [`URI`]: https://docs.rs/http/latest/http/uri/struct.Uri.html
    pub async fn refresh(&mut self) -> jwk_registry::Result<()> {
        let Self { uri, .. } = self;
        let keys = fetch(uri.clone()).await?;

        self.keys = keys;

        Ok(())
    }

    pub fn decode<Claim, I>(
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

    /// Get an immutable reference to the inner `uri` used to locate the keys.
    pub fn uri(&self) -> &http::Uri {
        &self.uri
    }

    /// Get a mutable reference to the inner `uri` used to locate the keys.
    pub fn uri_mut(&mut self) -> &mut http::Uri {
        &mut self.uri
    }

    /// Get an immutable reference to the inner `keys` cache-map.
    pub fn keys(&self) -> &HashMap<String, Key> {
        &self.keys
    }

    /// Get a mutable reference to the inner `keys` cache-map.
    pub fn keys_mut(&mut self) -> &mut HashMap<String, Key> {
        &mut self.keys
    }
}

/// Fetches the according [`Key`]s from the given URI.
///
/// The keys are unique by their `kid` (i.e., their Key-ID).
/// Each JWT can be decrypted by a corresponding [`Key`] that has a matching
/// `kid`.
/// Therefore, the returned hashmap is indexed as: `kid -> Key`.
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
