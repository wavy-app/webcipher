//! An abstraction over a collection of [`RemoteCache`]s.
//!
//! A [`KeyRegistry`] contains a [`BTreeMap`] of all [`RemoteCache`]s of `TPA`
//! that you wish to decrypt with.
//!
//! I refer to a `TPA` as a Third-Party-Authenticator, i.e., a
//! platform/organization which provides `OAuth2` services and has their public
//! `JWK`s available at some [`http::Uri`].
//!
//! For example, some `TPA`s that [Wavy](https://hiwavy.com) is using for
//! its authentication/authorization services are `Google`, `Facebook`,
//! and `Apple`.
//!
//! For example, assume your application supports `OAuth2` signin with the
//! following Third-Party-Authenticators:
//! - `Apple`
//! - `Facebook`
//! - `Google`
//!
//! ```no_run
//! enum Tpas {
//!     Google,
//!     Facebook,
//!     Apple,
//! }
//!
//! let mut key_registry = KeyRegistryBuilder::default()
//!     .add_remote(Tpas::Google, "<Google's JWKs URI>")
//!     .add_remote(Tpas::Apple, "<Apple's JWKs URI>")
//!     .add_remote(Tpas::Facebook, "<Facebook's JWKs URI>")
//!     .build()
//!     .await?;
//!
//! // Now assume that we get an incoming `JWT` that we want to validate.
//! // Furthermore, assume that this `JWT` is claimed to be signed by `Google`.
//! let tpa = Tpas::Google;
//! let token = "a.b.c";
//! let auto_refresh = true;
//!
//! let TokenData { claims: GoogleClaims { .. }, .. } =  key_registry.decrypt::<GoogleClaims, _>(tpa, token, auto_refresh).await?;
//! ```

pub mod builder;

use std::collections::BTreeMap;

use jsonwebtoken::TokenData;
use prelude::Error;
use serde::Deserialize;

use crate::key_caches::remote::RemoteCache;
use crate::prelude;

type RemoteCaches<Tpa> = BTreeMap<Tpa, RemoteCache>;

/// A collection of [`RemoteCache`]s which can quickly indexed to find the
/// specific key-cache that you need in order to decrypt/validate a token.
///
/// For example, assume your application supports `OAuth2` signin with some
/// arbitrary `Tpa` targets:
/// - Service1
/// - Platform2
/// - Organization3
///
/// ```no_run
/// enum Tpas {
///     Service1,
///     Platform2,
///     Organization3,
/// }
///
/// let mut key_registry = KeyRegistryBuilder::default()
///     .add_remote(Tpas::Service1, "<Service1's JWKs URI>")
///     .add_remote(Tpas::Platform2, "<Platform2's JWKs URI>")
///     .add_remote(Tpas::Organization3, "<Organization3's JWKs URI>")
///     .build()
///     .await?;
///
/// // Now assume that we get an incoming `JWT` that we want to validate.
/// // Furthermore, assume that this `JWT` is claimed to be signed by `Google`.
/// let tpa = Tpas::Organization3;
/// let token = "a.b.c";
/// let auto_refresh = true;
///
/// let TokenData { claims: Organization3Claims { .. }, .. } =  key_registry.decrypt::<Organization3Claims, _>(tpa, token, auto_refresh).await?;
/// ```
#[derive(Default)]
pub struct KeyRegistry<Tpa> {
    pub(crate) remote_caches: RemoteCaches<Tpa>,
}

impl<Tpa> KeyRegistry<Tpa>
where
    Tpa: Ord,
{
    /// Get an immutable reference to the inner [`RemoteCaches`].
    pub fn remote_caches(&self) -> &RemoteCaches<Tpa> {
        &self.remote_caches
    }

    /// Get a mutable reference to the inner [`RemoteCaches`].
    pub fn remote_caches_mut(&mut self) -> &mut RemoteCaches<Tpa> {
        &mut self.remote_caches
    }

    /// Decrypt the given `token` with the specified `tpa`.
    ///
    /// If the `auto_refresh` parameter is `true`, then if the cache
    /// corresponding to the given `tpa` is stale (i.e., contains `JWK`s that
    /// have expired), then a network request will *automatically* be sent out
    /// to fetch fresh `JWK`s.
    /// However, if `false` is given, then an error
    /// will be returned if the cache is stale.
    ///
    /// We recommend that `true` is always passed.
    /// Note that if the cache is not stale, no network request will be made at
    /// all.
    ///
    /// ```no_run
    /// // assume we've already initialized a `KeyRegistry` instance.
    /// // furthermore, assume that we have some target we want to decrypt for.
    ///
    /// // example token to verify
    /// let token = "a.b.c";
    /// let auto_refresh = true;
    ///
    /// // if the `RemoteCache` pertaining to `target_tpa` is not stale, this function will not perform any network request.
    /// key_registry.decrypt::<MyClaims, _>(target_tpa, token, auto_refresh).await?;
    /// ```
    pub async fn decrypt<Claim, I>(
        &mut self,
        tpa: Tpa,
        token: I,
        auto_refresh: bool,
    ) -> prelude::Result<TokenData<Claim>>
    where
        String: From<I>,
        Claim: for<'de> Deserialize<'de>,
    {
        let Self { remote_caches } = self;
        let tpa_remote_cache =
            remote_caches.get_mut(&tpa).ok_or(Error::unrecognized_tpa)?;

        tpa_remote_cache.decrypt(token, auto_refresh).await
    }
}
