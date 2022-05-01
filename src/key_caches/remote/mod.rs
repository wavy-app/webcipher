//! A `JWK` key struct and a refreshable key cache for remote key storage.
//!
//! A [`RemoteCache`] can be used to fetch `JKW`'s from some target providing,
//! for example, `OAuth2` services.
//!
//! ```no_run
//! let uri = "https://example_target.com/certs_service";
//! let remote_cache = RemoteCache::new(target_uri).await?;
//! ```
//!
//! Validation of a signed `JWT` is simply done by calling the
//! [`decode`](`RemoteCache::decode`) function. ```no_run
//! let token = "a.b.c";
//! let claims: jsonwebtoken::TokenData<MyClaims>=
//! remote_cache.decode::<MyClaims>(token)?; ```
//!
//! The fetched keys will be stored, as well as their expiry times.
//! This can greatly improve performance by avoiding duplicate calls.
//! ```no_run
//! let uri = "https://example_target.com/certs_service";
//! // this will perform a network request
//! let mut remote_cache = RemoteCache::new(target_uri).await?;
//!
//! let token1 = "a.b.c";
//! // this will not perform a network request
//! let claims1: jsonwebtoken::TokenData<MyClaims> =
//! remote_cache.decode::<MyClaims>(token)?;
//!
//! // perform an arbitrary number of calls to decode...
//!
//! let token_n = "e.f.g";
//! // this will also not perform a network request
//! let claims_n: jsonwebtoken::TokenData<MyClaims>=
//! remote_cache.decode::<MyClaims>(token)?;
//!
//! // this will perform a network request
//! remote_cache.refresh().await?;
//! ```
//!
//! Using your own preferred methods, you can refresh the cache intermittently.
//!
//! The [`tokio`] documentation page has some pretty interesting examples on how
//! to perform intermittent updates to shared state.
//! You can find them [here](https://tokio.rs/tokio/tutorial/shared-state).
//!
//! The [`Key`] struct represents the information present inside of a `JWK`
//! (mandatory and optional) as defined by the RFC.

pub mod key;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use derivative::*;
use hyper::Client;
use hyper_tls::HttpsConnector;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::TokenData;
use serde::Deserialize;
use serde_json::Value;

use crate::error::Error;
use crate::key_caches::decrypt;
use crate::key_caches::remote::key::Key;
use crate::key_caches::remote::key::KeyType;
use crate::key_caches::remote::key::Use;
use crate::prelude;

/// A refreshable key cache for remote keys used for JWT authentication.
///
/// The `URI` of the target is stored and the corresponding keys are fetched
/// upon creation.
///
/// One can then decode tokens presumably signed by the target by calling
/// [`decode`](`RemoteCache::decode`).
/// If the token was indeed provisioned by the target, this operation will be
/// successful. Otherwise, it will fail.
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
/// let key_store = RemoteCache::new(uri).await?;
///
/// let token = "a.b.c";
/// let claims: MyClaims = key_store.decode::<MyClaims>(&token)?;
/// ```
///
/// Many targets rotate their keys, and as such, cached keys will fail after a
/// certain period of time. [`RemoteCache`] provides the
/// [`refresh`](`RemoteCache::refresh`) function to refresh a given
/// [`RemoteCache`]. [`refresh`](`RemoteCache::refresh`) will re-fetch the new
/// keys (from its current `uri`).
///
/// For performance considerations, the [`DecodingKey`] is computed (eagerly)
/// once per key, and not per every call to [`decode`](`RemoteCache::decode`).
#[derive(Derivative)]
#[derivative(Hash, PartialEq, Eq)]
pub struct RemoteCache {
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
    /// Two [`RemoteCache`]'s are considered equivalent if and only if their
    /// `uri`'s match.
    #[derivative(PartialEq = "ignore", Hash = "ignore")]
    pub(crate) keys: BTreeMap<String, (Key, DecodingKey)>,
}

impl RemoteCache {
    /// Generate a new [`RemoteCache`] by asynchronously fetching the keys at
    /// the given [`URI`].
    ///
    /// [`URI`]: https://docs.rs/http/latest/http/uri/struct.Uri.html
    pub async fn new<I>(uri: I) -> prelude::Result<Self>
    where
        String: From<I>,
    {
        let uri = String::from(uri).parse::<http::Uri>()?;
        let keys = fetch(uri.clone()).await?;
        // let keys = attach_decoding_keys(keys);

        let store = Self { uri, keys };

        Ok(store)
    }

    /// Refreshes the current [`RemoteCache`] by asynchronously fetching the
    /// keys at the given [`URI`].
    ///
    /// Useful for when targets rotate their keys.
    ///
    /// [`URI`]: https://docs.rs/http/latest/http/uri/struct.Uri.html
    pub async fn refresh(&mut self) -> prelude::Result<()> {
        let Self { uri, .. } = self;
        let keys = fetch(uri.clone()).await?;
        // let keys = attach_decoding_keys(keys);

        self.keys = keys;

        Ok(())
    }

    /// Safely decode the given token.
    ///
    /// Namely, by "safe", I mean that the `exp` time is checked to make sure
    /// that it has *not* elapsed already. In the case that it has, the
    /// given token will be rejected.
    ///
    /// ```no_run
    /// let remote_cache = RemoteCache::new("https://target.com/certs_service").await?;
    ///
    /// let token = "a.b.c";
    /// let my_claims: TokenData<MyClaims> = remote_cache.decode(token)?;
    /// ```
    pub fn decode<Claim, I>(
        &self,
        token: I,
    ) -> prelude::Result<TokenData<Claim>>
    where
        String: From<I>,
        Claim: for<'a> Deserialize<'a>,
    {
        let Self { keys, .. } = self;
        let selector = |kid: &String| {
            keys.get(&*kid)
                .ok_or(Error::no_corresponding_kid_in_store)
                .map(|(_, decoding_key)| decoding_key)
        };

        decrypt(token, selector, None)
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
    pub fn keys(&self) -> &BTreeMap<String, (Key, DecodingKey)> {
        &self.keys
    }

    /// Get a mutable reference to the inner `keys` cache-map.
    pub fn keys_mut(&mut self) -> &mut BTreeMap<String, (Key, DecodingKey)> {
        &mut self.keys
    }
}

/// Fetches the according [`Key`]s from the given URI and computes the
/// respective [`DecodingKey`] for each [`Key`].
///
/// The keys are unique by their `kid` (i.e., their Key-ID).
/// Each JWT can be decrypted by a corresponding [`Key`] that has a matching
/// `kid`.
/// Therefore, the returned BTreeMap is indexed as: `kid -> Key`.
///
/// This function filters out all keys which don't can't be serialized into a
/// [`Key`]. Furthermore, this function also filters out all keys whose `kty !=
/// "RSA"`. This includes valid keys which use a different encryption mechanism.
///
/// This function specifically uses the
/// [`from_rsa_components`](`DecodingKey::from_rsa_components`) function.
/// This is because we expect that the target is using "RSA" encryption scheme.
async fn fetch(
    uri: http::Uri,
) -> prelude::Result<BTreeMap<String, (Key, DecodingKey)>> {
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

    let keys = serde_json::from_value::<Vec<Value>>(body)?
        .into_iter()
        .filter_map(|value| {
            serde_json::from_value::<Key>(value).ok().and_then(|key| {
                let Key {
                    kty,
                    alg,
                    e,
                    n,
                    kid,
                    r#use,
                    ..
                } = &key;

                match kty {
                    KeyType::RSA => (),
                    _ => return None,
                };

                match alg {
                    Some(Algorithm::RS256) => (),
                    _ => return None,
                };

                match r#use {
                    Use::sig => (),
                    Use::enc => return None,
                };

                let kid = kid.clone();

                DecodingKey::from_rsa_components(n, e)
                    .ok()
                    .map(|decoding_key| (kid, (key, decoding_key)))
            })
        })
        .collect::<BTreeMap<String, (Key, DecodingKey)>>();

    Ok(keys)
}
