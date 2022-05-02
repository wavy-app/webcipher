//! `Facebook` JWT Claim object.
//!
//! For more information, please visit: <https://developers.facebook.com/docs/facebook-login/limited-login/token/validating>.

use serde::Deserialize;

/// The URI for `Facebook`'s public `JWK`s.
pub const FACEBOOK_JWK_URI: &'static str =
    "https://www.facebook.com/.well-known/oauth/openid/jwks/";

/// Claims made by `Facebook`.
///
/// `JWT`'s issued by `Facebook` should have a body (i.e., the second portion of
/// the `JWT`) that are `base64URL` decrypted into the below struct.
#[derive(Debug, Deserialize)]
pub struct FacebookClaims;
