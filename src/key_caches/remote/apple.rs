//! `Apple` JWT Claim object.
//!
//! For more information, please visit: <https://developer.apple.com/documentation/sign_in_with_apple/fetch_apple_s_public_key_for_verifying_token_signature>.

use serde::Deserialize;

/// The URI for `Apple`'s public `JWK`s.
pub const APPLE_JWK_URI: &'static str = "https://appleid.apple.com/auth/keys";

/// Claims made by `Apple`.
///
/// `JWT`'s issued by `Apple` should have a body (i.e., the second portion of
/// the `JWT`) that are `base64URL` decrypted into the below struct.
#[derive(Debug, Deserialize)]
pub struct AppleClaims;
