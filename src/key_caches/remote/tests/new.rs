use crate::key_caches::remote::RemoteCache;
use crate::prelude::APPLE_JWK_URI;
use crate::prelude::FACEBOOK_JWK_URI;
use crate::prelude::GOOGLE_JWK_URI;

#[tokio::test]
/// Test basic creation of the [`RemoteCache`].
///
/// This will ensure that the [`fetch`] function works too.
async fn test_creation() {
    let uris = vec![FACEBOOK_JWK_URI, GOOGLE_JWK_URI, APPLE_JWK_URI];

    for uri in uris {
        let mut remote_cache = RemoteCache::new(uri).unwrap();

        let is_fresh = remote_cache.is_cache_fresh();
        assert!(!is_fresh);

        remote_cache.refresh().await.unwrap();
    }
}
