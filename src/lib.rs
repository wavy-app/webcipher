pub mod error;
pub mod key_caches;
pub mod registry;

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
