use serde::Deserialize;

use crate::key_caches::remote::RemoteCache;
use crate::prelude::Error;

#[tokio::test]
/// This test will test whether or not parsing of `JWK`'s works.
///
/// We expect the algorithm to be `RS256` only.
/// If we see anything else, we reject it.
async fn test_fail_invalid_algorithm() {
    let uri = "https://www.googleapis.com/oauth2/v2/certs";
    let mut remote_cache = RemoteCache::new(uri).unwrap();
    remote_cache.refresh().await.unwrap();

    #[derive(Deserialize, Debug)]
    struct GoogleClaims;

    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let err = remote_cache
        .decrypt_unchecked::<GoogleClaims, _>(token)
        .unwrap_err();

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
    let mut remote_cache = RemoteCache::new(uri).unwrap();
    remote_cache.refresh().await.unwrap();

    #[derive(Deserialize, Debug)]
    struct GoogleClaims;

    let token = "ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIlJTMjU2Igp9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let err = remote_cache
        .decrypt_unchecked::<GoogleClaims, _>(token)
        .unwrap_err();

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
    let mut remote_cache = RemoteCache::new(uri).unwrap();
    remote_cache.refresh().await.unwrap();

    #[derive(Deserialize, Debug)]
    struct GoogleClaims;

    let token = "ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIlJTMjU2IiwKICAia2lkIjogImEiCn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.HB2a_ACXy864GVupVbigGzT1Lo-9xpF-RKy9DelIIYM";
    let err = remote_cache
        .decrypt_unchecked::<GoogleClaims, _>(token)
        .unwrap_err();

    assert_eq!(err, Error::no_corresponding_kid_in_store);
}

#[tokio::test]
#[ignore = "Time-sensitive test. Will pass until `Facebook` rotates their keys."]
/// This test will test whether or not the the decryption with a token
/// containing a valid `alg` and a valid `kid` but is an invalid signature.
async fn test_fail_decryption() {
    let uri = "https://www.facebook.com/.well-known/oauth/openid/jwks/";
    let mut remote_cache = RemoteCache::new(uri).unwrap();
    remote_cache.refresh().await.unwrap();

    #[derive(Deserialize, Debug)]
    struct GoogleClaims;

    let token = "ewogICJ0eXAiOiAiSldUIiwKICAiYWxnIjogIlJTMjU2IiwKICAia2lkIjogIjJhYTZiYWFiMWRjY2MxNWI4YmY3NzkwM2VlMmE5OGRiNjNjZTc4MDMiCn0=.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.HB2a_ACXy864GVupVbigGzT1Lo-9xpF-RKy9DelIIYM";
    let err = remote_cache
        .decrypt_unchecked::<GoogleClaims, _>(token)
        .unwrap_err();

    assert_eq!(err, Error::unable_to_verify_token {
        message: "InvalidSignature".into()
    });
}

#[tokio::test]
async fn test() {
    let uri = "https://www.googleapis.com/oauth2/v2/certs";
    let mut remote_cache = RemoteCache::new(uri).unwrap();
    remote_cache.refresh().await.unwrap();

    #[derive(Deserialize, Debug)]
    struct GoogleClaims {}

    let token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2MTY0OWU0NTAzMTUzODNmNmI5ZDUxMGI3Y2Q0ZTkyMjZjM2NkODgiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXpwIjoiOTExODgzMDY4NTg3LW9qNWFuMnBqNTU1MGcyNW9rbTlmYmxucjNwczk5NTY5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiOTExODgzMDY4NTg3LW9qNWFuMnBqNTU1MGcyNW9rbTlmYmxucjNwczk5NTY5LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTE3ODAyNDQ0OTcxNjA4NDA4ODU3IiwiZW1haWwiOiJyYWJoYWdhdDMxQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiMmY2WG9uR3E3SEd0MzdSaWRFaEZ1QSIsIm5hbWUiOiJSYXVuYWsgQmhhZ2F0IiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FBVFhBSnp1V1pDYTAyOEhGRERnazhhbXhvelpzWGkxcnpIX2VNZWJWd2syeEE9czk2LWMiLCJnaXZlbl9uYW1lIjoiUmF1bmFrIiwiZmFtaWx5X25hbWUiOiJCaGFnYXQiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY1MTQzODc3OCwiZXhwIjoxNjUxNDQyMzc4LCJqdGkiOiI0YjgwOTYxOGQ2M2M5MDZiYTcwYjEyMzZlYWU3ZjU1N2Y4MzliMmI3In0.QIQArpNF3BVXsT9TM2zPIstG2WDOFBrdedf0bbRb5qjjF3JJbLWMnJPe0bQPXK-nnoDkQPDZUMyNM_8IVZqEs-xRy9TZTao2upqpkIx0_5KLnvRP-o-Va24fqYrUNAZREgm-t6f6ShJHhCR-dMuvF7nklrp26fTUywTJ7gstfk_OjbYYTXYdcTMpj80fk0V0g28EF_5KvK4YCQIw1Qvohe5IfO9UQuF_XdlGmARKQhqWbMcbK52cH8t4gu_tgzvvZVzjjBTLW0MI87Q2asUQoLFm9RlP359lLZRnPJk3wLpqu-7T5Xp-uk455BrU3xbCM9GjRBtgW9OEOrG77LZN1Q";
    let err = remote_cache
        .decrypt_unchecked::<GoogleClaims, _>(token)
        .unwrap_err();

    assert_eq!(err, Error::invalid_algorithm);
}
