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
//! [`decrypt_unchecked`](`RemoteCache::decrypt_unchecked`) function.
//!
//! ```no_run
//! let token = "a.b.c";
//! let claims: jsonwebtoken::TokenData<MyClaims>=
//! remote_cache.decrypt_unchecked::<MyClaims>(token)?;
//! ```
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
//! remote_cache.decrypt_unchecked::<MyClaims>(token)?;
//!
//! // perform an arbitrary number of calls to decrypt_unchecked...
//!
//! let token_n = "e.f.g";
//! // this will also not perform a network request
//! let claims_n: jsonwebtoken::TokenData<MyClaims>=
//! remote_cache.decrypt_unchecked::<MyClaims>(token)?;
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

pub mod apple;
pub mod facebook;
pub mod google;
pub mod key;
#[cfg(test)]
mod tests;

use std::cmp::Ordering;
use std::collections::BTreeMap;

use chrono::Utc;
use derivative::*;
use hyper::Client;
use hyper_tls::HttpsConnector;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::TokenData;
use serde::Deserialize;
use serde_json::Value;

pub use self::apple::AppleClaims;
pub use self::apple::APPLE_JWK_URI;
pub use self::facebook::FacebookClaims;
pub use self::facebook::FACEBOOK_JWK_URI;
pub use self::google::GoogleClaims;
pub use self::google::GOOGLE_JWK_URI;
use crate::error::Error;
use crate::key_caches::decrypt;
use crate::key_caches::remote::key::Key;
use crate::key_caches::remote::key::KeyType;
use crate::key_caches::remote::key::Use;
use crate::prelude;

type Cache = BTreeMap<String, (Key, DecodingKey)>;

/// A refreshable key cache for remote keys used for JWT authentication.
///
/// The `URI` of the target is stored and the corresponding keys are fetched
/// upon creation.
///
/// One can then decrypt tokens presumably signed by the target by calling
/// [`decrypt_unchecked`](`RemoteCache::decrypt_unchecked`).
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
/// let claims: MyClaims = key_store.decrypt_unchecked::<MyClaims>(&token)?;
/// ```
///
/// Many targets rotate their keys, and as such, cached keys will fail after a
/// certain period of time. [`RemoteCache`] provides the
/// [`refresh`](`RemoteCache::refresh`) function to refresh a given
/// [`RemoteCache`]. [`refresh`](`RemoteCache::refresh`) will re-fetch the new
/// keys (from its current `uri`).
///
/// For performance considerations, the [`DecodingKey`] is computed (eagerly)
/// once per key, and not per every call to [`decrypt_unchecked`](`RemoteCache::decrypt_unchecked`).
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
    pub(crate) keys: Cache,

    /// The maximum age the [`Key`]s in this [`RemoteCache`] will live for.
    /// When this time has expired, [`refresh`](`RemoteCache::refresh`) should
    /// be called to renew the keys.
    #[derivative(PartialEq = "ignore", Hash = "ignore")]
    pub(crate) expiry_time: Option<u64>,
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
        let (keys, expiry_time) = fetch(uri.clone()).await?;

        let store = Self {
            uri,
            keys,
            expiry_time,
        };

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
        let (keys, expiry_time) = fetch(uri.clone()).await?;

        self.keys = keys;
        self.expiry_time = expiry_time;

        Ok(())
    }

    /// Safely decrypt the given token.
    ///
    /// Namely, by "safe", we mean that the `exp` time of the `JWT` is checked
    /// to make sure that it has *not* elapsed already. In the case that it
    /// has, the given token will be rejected.
    ///
    /// ```no_run
    /// let remote_cache = RemoteCache::new("https://target.com/certs_service").await?;
    ///
    /// let token = "a.b.c";
    /// let my_claims: TokenData<MyClaims> = remote_cache.decrypt_unchecked(token)?;
    /// ```
    ///
    /// ### Warning:
    /// If the cache is stale (i.e., contains `JWK`s that are expired), this
    /// function will produce undefined behaviour.
    ///
    /// Please check the cache is fresh by calling
    /// [`is_cache_fresh`](`RemoteCache::is_cache_fresh`).
    pub fn decrypt_unchecked<Claim, I>(
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

    /// Check to see if the keys in this [`RemoteCache`] instance are fresh.
    ///
    /// By "fresh", we mean that the `JWK`s have not expired yet.
    ///
    /// ### Note
    /// Certain `OAuth2` providers don't necessarily inform clients on how long
    /// their `JWK`s should be cached for. For example, `Apple` provides no
    /// information on when their public keys are going to be rotated.
    ///
    /// If this is the case, `expiry_time` will be set to [`None`] and
    /// [`is_cache_fresh`](`RemoteCache::is_cache_fresh`) will always return
    /// `false`. Therefore, you should *always* call
    /// [`refresh`](`RemoteCache::refresh`) before decrypting using
    /// [`decrypt_unchecked`](`RemoteCache::decrypt_unchecked`).
    ///
    /// ```no_run
    /// // Assume `target.com` provides no `cache-control` header in their `http` response.
    /// // Therefore, it will be assumed that the cache is always stale.
    /// let uri = "https://target.com/api/certs";
    /// let mut remote_cache = RemoteCache::new(uri).await?;
    ///
    /// // an arbitrary amount of time passes...
    ///
    /// let token = "a.b.c";
    ///
    /// // Call refresh first!
    /// remote_cache.refresh();
    /// let TokenData { claims: MyClaims { .. }, .. } = remote_cache.decrypt_unchecked::<MyClaims, _>(token)?;
    /// ```
    ///
    /// If you somehow know the actual expiry time of the keys, you can always
    /// mutably set the `expiry-time` manually.
    ///
    /// ```no_run
    /// // Once again, assume `target.com` provides no `cache-control` header in their `http` response.
    /// // Therefore, it will be assumed that the cache is always stale.
    /// let uri = "https://target.com/api/certs";
    /// let mut remote_cache = RemoteCache::new(uri).await?;
    ///
    /// // However, you somehow know that the keys are always rotated every 4hrs.
    /// let now = Utc::now().timestamp() as u64;
    /// let four_hours = 3600u64 * 4u64;
    /// let real_expiry_time = now + four_hours;
    ///
    /// let expiry_time = remote_cache.expiry_time_mut();
    /// *expiry_time = Some(real_expiry_time);
    /// ```
    pub fn is_cache_fresh(&self) -> bool {
        let Self { expiry_time, .. } = self;

        expiry_time
            .map(|expiry_time| {
                let now = Utc::now().timestamp() as u64;
                let time_comparison = now.cmp(&expiry_time);

                match time_comparison {
                    Ordering::Less => true,
                    Ordering::Equal | Ordering::Greater => false,
                }
            })
            .unwrap_or(false)
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
    pub fn keys(&self) -> &Cache {
        &self.keys
    }

    /// Get a mutable reference to the inner `keys` cache-map.
    pub fn keys_mut(&mut self) -> &mut Cache {
        &mut self.keys
    }

    /// Get an immutable reference to the inner `expiry-time` of the keys in
    /// this cache.
    pub fn expiry_time(&self) -> &Option<u64> {
        &self.expiry_time
    }

    /// Get a mutable reference to the inner `expiry-time` of the keys in this
    /// cache.
    pub fn expiry_time_mut(&mut self) -> &mut Option<u64> {
        &mut self.expiry_time
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
///
/// The expiry time is calculated by taking the max-age (in Unix-Time) and
/// adding it to the current time (in Unix-Time). 1hr (i.e, 3600s) are
/// subtracted in order to provide leeway.
async fn fetch(uri: http::Uri) -> prelude::Result<(Cache, Option<u64>)> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let mut response = client.get(uri).await?;

    let max_ages = response
        .headers()
        .get("cache-control")
        .ok_or(Error::no_cache_control)?
        .to_str()?
        .split(",")
        .filter_map(|value| {
            let is_max_age_header = value.contains("max-age=");
            match is_max_age_header {
                true => {
                    value.trim().replace("max-age=", "").parse::<u64>().ok()
                },
                false => None,
            }
        })
        .collect::<Vec<_>>();

    let expiry_time = max_ages.first().map(|max_age| {
        let now = Utc::now().timestamp() as u64;
        let one_hour = 3600;
        now + max_age - one_hour
    });

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
        .collect::<Cache>();

    Ok((keys, expiry_time))
}
