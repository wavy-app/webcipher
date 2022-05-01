use serde::Deserialize;

use crate::key_caches::remote::RemoteCache;
use crate::prelude::Error;

#[tokio::test]
/// Test basic creation of the [`RemoteCache`].
///
/// This will ensure that the [`fetch`] function works too.
async fn test_creation() {
    let uri = "https://www.facebook.com/.well-known/oauth/openid/jwks/";
    let _ = RemoteCache::new(uri).await.unwrap();
}

#[tokio::test]
/// This test will test whether or not parsing of `JWK`'s works.
///
/// We expect the algorithm to be `RS256` only.
/// If we see anything else, we reject it.
async fn test_fail_invalid_algorithm() {
    let uri = "https://www.googleapis.com/oauth2/v2/certs";
    let remote_cache = RemoteCache::new(uri).await.unwrap();

    #[derive(Deserialize, Debug)]
    struct GoogleClaims;

    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let err = remote_cache.decode::<GoogleClaims, _>(token).unwrap_err();

    assert_eq!(err, Error::invalid_algorithm);
}

#[tokio::test]
/// This test will test whether or not parsing of `JWK`'s works.
///
/// We expect a `kid` field to be present in the headers, and that it is a
/// string.
/// If we don't find one, we should reject the key.
///
/// The given token has the correct `alg`, but no `kid`.
async fn test_fail_no_kid() {
    let uri = "https://www.googleapis.com/oauth2/v2/certs";
    let remote_cache = RemoteCache::new(uri).await.unwrap();

    #[derive(Deserialize, Debug)]
    struct GoogleClaims;

    let token = "ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIlJTMjU2Igp9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let err = remote_cache.decode::<GoogleClaims, _>(token).unwrap_err();

    assert_eq!(err, Error::no_kid_present);
}

#[tokio::test]
/// This test will test whether or not the matching `kid` lookup in the cache
/// will succeed.
///
/// The given `JWT` has a `kid` field, but it's just a dummy value (i.e., `kid
/// == "a"`). `Facebook` will not (or is very unlikely to) have a `kid` that
/// matches this value.
///
/// Therefore, a lookup for a matching `kid` value will fail.
async fn test_fail_no_corresponding_kid() {
    let uri = "https://www.facebook.com/.well-known/oauth/openid/jwks/";
    let remote_cache = RemoteCache::new(uri).await.unwrap();

    #[derive(Deserialize, Debug)]
    struct GoogleClaims;

    let token = "ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIlJTMjU2IiwKICAia2lkIjogImEiCn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.HB2a_ACXy864GVupVbigGzT1Lo-9xpF-RKy9DelIIYM";
    let err = remote_cache.decode::<GoogleClaims, _>(token).unwrap_err();

    assert_eq!(err, Error::no_corresponding_kid_in_store);
}

#[tokio::test]
#[ignore = "Time-sensitive test. Will pass until `Facebook` rotates their keys."]
/// This test will test whether or not the the decryption with a token
/// containing a valid `alg` and a valid `kid` but is an invalid signature.
async fn test_fail_decryption() {
    let uri = "https://www.facebook.com/.well-known/oauth/openid/jwks/";
    let remote_cache = RemoteCache::new(uri).await.unwrap();

    #[derive(Deserialize, Debug)]
    struct GoogleClaims;

    let token = "ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIlJTMjU2IiwKICAia2lkIjogIjJhYTZiYWFiMWRjY2MxNWI4YmY3NzkwM2VlMmE5OGRiNjNjZTc4MDMiCn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.HB2a_ACXy864GVupVbigGzT1Lo-9xpF-RKy9DelIIYM";
    let err = remote_cache.decode::<GoogleClaims, _>(token).unwrap_err();

    assert_eq!(err, Error::unable_to_verify_token {
        message: "InvalidSignature".into()
    });
}
