//! Builder pattern implementation to assist in the construction of a
//! [`KeyRegistry`] instance.
//!
//! ```no_run
//! #[derive(PartialEq, Eq, PartialOrd, Ord)]
//! enum Tpas {
//!     CoolNewPlatform,
//!     // etc...
//! }
//!
//! let builder = KeyRegistryBuilder::default()
//!     .add_remote(Tpas::CoolNewPlatform, "<CoolNewPlatform's JWKs URI>")
//!     .build()
//!     .await?;
//! ```
//!
//! The simple function to add a [`RemoteCache`] is exposed for convenience.
//! For more hands-on control over the inner `uris` field, you can either
//! dereference the builder object or destructure it.
//!
//! ```no_run
//! // (Mutably or Immutably) dereference the `KeyRegistryBuilder` instance.
//! let uris = *builder;
//!
//! // Destructure the `KeyRegistryBuilder` instance.
//! let KeyRegistryBuilder { uris } = builder;
//! ```

use std::collections::BTreeMap;
use std::ops::Deref;
use std::ops::DerefMut;

use crate::key_caches::remote::RemoteCache;
use crate::prelude;
use crate::registry::KeyRegistry;

type Uris<Tpa> = BTreeMap<Tpa, String>;

/// An implementation of the builder-patten for a [`KeyRegistry`] instance.
///
/// By calling [`add_remote`](`KeyRegistryBuilder::add_remote`), the given `Tpa`
/// and its corresponding `Uri` are cached until this struct is built.
///
/// ```no_run
/// let builder = KeyRegistryBuilder::default()
///     .add_remote(target_tpa, "<target_tpa's JWK URI>");
/// ```
///
/// In order to actually build the [`KeyRegistry`] instance, call
/// [`build`](`KeyRegistryBuilder::build`).
/// This will take all the cached `Tpa`s and their respective `Uri`s and
/// perform all the network requests to fetch the respective `JWK`s.
///
/// ```no_run
/// let key_registry = builder.
///     .build()
///     .await?;
///
/// // Now you can decrypt incoming tokens by calling `KeyRegistry::decrypt`!
/// ```
pub struct KeyRegistryBuilder<Tpa> {
    pub uris: Uris<Tpa>,
}

impl<Tpa> KeyRegistryBuilder<Tpa>
where
    Tpa: Ord,
{
    /// Add a `Tpa` to the set of [`RemoteCache`]s.
    ///
    /// ```no_run
    /// let builder = KeyRegistryBuilder::default()
    ///     .add_remote(target_tpa, "<target_tpa's JWK URI>");
    /// ```
    ///
    /// If an entry was previously inserted, it is updated.
    pub fn add_remote<I>(mut self, tpa: Tpa, uri: I) -> Self
    where
        String: From<I>,
    {
        let Self { uris } = &mut self;
        let uri = uri.into();

        uris.insert(tpa, uri);

        self
    }

    /// Build instances of [`RemoteCache`] from each entry in the inner `uris`
    /// field.
    ///
    /// If a single request to fetch a key fails, then this entire function will
    /// fail as well.
    /// This was purposefully designed so that the end-developer can be
    /// notified of a failure instead of a silent failure occurring
    /// and going unnoticed (and thus untreated).
    ///
    /// If this feature is unappealing to you, you can always create a
    /// [`KeyRegistry`] instance without using this [`KeyRegistryBuilder`]
    /// proxy.
    ///
    /// ```no_run
    /// let builder = KeyRegistryBuilder::default()
    ///     .add_remote(target_tpa, "<target_tpa's JWK URI>");
    /// ```
    pub async fn build(self) -> prelude::Result<KeyRegistry<Tpa>> {
        let Self { uris } = self;

        let mut remote_caches = BTreeMap::default();

        for (tpa, uri) in uris {
            let remote_cache = RemoteCache::new(uri).await?;
            remote_caches.insert(tpa, remote_cache);
        }

        let key_registry = KeyRegistry { remote_caches };

        Ok(key_registry)
    }
}

impl<Tpa> Default for KeyRegistryBuilder<Tpa> {
    fn default() -> Self {
        let uris = BTreeMap::default();
        Self { uris }
    }
}

impl<Tpa> Deref for KeyRegistryBuilder<Tpa> {
    type Target = Uris<Tpa>;

    fn deref(&self) -> &Self::Target {
        &self.uris
    }
}

impl<Tpa> DerefMut for KeyRegistryBuilder<Tpa> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.uris
    }
}
