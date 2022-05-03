//! `webcipher` provides `JWT` authentication utilities and storage mechanism
//! for caching keys and optimizing decryption/encryption processes.
//!
//! Instead of performing an unnecessary amount of network requests to the `JWK`
//! `uri` of some `OAuth2` provider, one can cache the keys inside of a
//! [`crate::key_caches::remote::RemoteCache`] instead.
//! This struct automatically parses responses from the `OAuth2` providers and
//! determines how long to cache keys for.
//!
//! You can easily refresh caches when the keys inside have expired, or leverage
//! the fact that the keys are still valid and continue to utilize the fresh
//! keys without performing unnecessary network requests.
//!
//! For example, over at [`Wavy`](`https://hiwavy.com`), we are using `Google`, `Facebook`, and `Apple` to allow users to sign in with.
//! Therefore, for each provider, we cache their public `JWK` keys into a
//! struct, parse their expiry date (if it exists), and leverage caching
//! mechanisms to optimize performance.
//!
//! Caching can lead to a great deal of improvement in performance if the cache
//! is guaranteed to be fresh and is frequently hit.
//!
//! ```no_run
//! enum Tpas {
//!     Google,
//!     Facebook,
//!     Apple,
//! }
//!
//! let googles_jwks_url = "https://...";
//! let facebooks_jwks_url = "https://...";
//! let apples_jwks_url = "https://...";
//!
//! let mut remote_cache_google = RemoteCache::new(googles_jwks_url).await?;
//! let mut remote_cache_facebook = RemoteCache::new(facebooks_jwks_url).await?;
//! let mut remote_cache_apple = RemoteCache::new(apples_jwks_url).await?;
//!
//! // Incoming token to be verified!
//! // Token is claimed to be signed by `Google`!
//! let token = "a.b.c";
//!
//! // check to make sure the cache is fresh...
//! let is_fresh = remote_cache_google.is_fresh();
//!
//! // If the cache is *not* fresh, refresh it!
//! if !is_fresh {
//!     remote_cache.refresh().await?;
//! };
//!
//! // decrypt the incoming token!
//! let jsonwebtoken::TokenData { claims: GoogleClaims { .. }, .. } = remote_cache_google.decrypt_unchecked::<GoogleClaims, _>(token)?;
//! ```
//!
//! ### Notes
//! [`crate::key_caches::remote::RemoteCache`] expects the `JWK`s to use the
//! `RSA` family of cryptographic algorithms.

pub mod error;
pub mod key_caches;

pub mod prelude {
    //! Convenience re-exports for when working with this crate.

    /// The [`Result`] type that this [`crate`] uses.
    ///
    /// Locks the `Err` type to [`crate::error::Error`] for convenience
    /// purposes.
    pub type Result<T> = std::result::Result<T, crate::error::Error>;

    pub use crate::error::Error;
    pub use crate::key_caches::remote::apple::AppleClaims;
    pub use crate::key_caches::remote::apple::APPLE_JWK_URI;
    pub use crate::key_caches::remote::facebook::FacebookClaims;
    pub use crate::key_caches::remote::facebook::FACEBOOK_JWK_URI;
    pub use crate::key_caches::remote::google::GoogleClaims;
    pub use crate::key_caches::remote::google::GOOGLE_JWK_URI;
    pub use crate::key_caches::remote::key::Key;
    pub use crate::key_caches::remote::key::KeyType;
    pub use crate::key_caches::remote::key::Use;
    pub use crate::key_caches::remote::RemoteCache;
}
