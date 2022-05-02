//! `Google` JWT Claim object.
//!
//! For more information, please visit: <https://cloud.google.com/api-gateway/docs/authenticating-users-jwt>.

use serde::Deserialize;

/// The URI for `Google`'s public `JWK`s.
pub const GOOGLE_JWK_URI: &'static str =
    "https://www.googleapis.com/oauth2/v2/certs";

/// Claims made by `Google`.
///
/// `JWT`'s issued by `Google` should have a body (i.e., the second portion of
/// the `JWT`) that are `base64URL` decrypted into the below struct.
#[derive(Debug, Deserialize)]
pub struct GoogleClaims {
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub iss: String,

    pub azp: String,
    pub sub: String,
    pub email: String,
    pub email_verified: bool,
    pub at_hash: String,
    pub name: String,

    #[serde(with = "http_serde::uri")]
    pub picture: http::Uri,

    pub given_name: String,
    pub family_name: String,
    pub locale: String,
    pub jti: String,
}
