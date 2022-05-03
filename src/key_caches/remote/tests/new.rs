use crate::{key_caches::remote::RemoteCache, prelude::{FACEBOOK_JWK_URI, GOOGLE_JWK_URI, APPLE_JWK_URI}};

#[tokio::test]
/// Test basic creation of the [`RemoteCache`].
///
/// This will ensure that the [`fetch`] function works too.
async fn test_creation() {
    let uri = FACEBOOK_JWK_URI;
    let _ = RemoteCache::new(uri).await.unwrap();

    let uri = APPLE_JWK_URI;
    let _ = RemoteCache::new(uri).await.unwrap();

    let uri = GOOGLE_JWK_URI;
    let _ = RemoteCache::new(uri).await.unwrap();
}
