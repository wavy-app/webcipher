use crate::key_caches::remote::RemoteCache;

#[tokio::test]
/// Test basic creation of the [`RemoteCache`].
///
/// This will ensure that the [`fetch`] function works too.
async fn test_creation() {
    let uri = "https://www.facebook.com/.well-known/oauth/openid/jwks/";
    let _ = RemoteCache::new(uri).await.unwrap();
}
