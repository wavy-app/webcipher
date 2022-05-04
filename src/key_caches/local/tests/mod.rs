use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::TokenData;
use uuid::Uuid;

use crate::key_caches::local::LocalCache;

#[test]
/// This test will test to make sure that encryption and decryption using the
/// [`Algorithm::HS512`] cryptographic algorithm and some secret are equivalent.
fn basic() {
    let kid = Uuid::new_v4();
    let ek = EncodingKey::from_secret("Hailey is the best!".as_ref());
    let dk = DecodingKey::from_secret("Hailey is the best!".as_ref());

    let alg = Algorithm::HS512;
    let mut local_cache = LocalCache::new(alg);

    local_cache.add_key(kid, ek, dk);

    #[derive(
        serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug, Clone, Copy,
    )]
    struct MyClaims {
        exp: u64,
    }

    let claims = MyClaims {
        exp: 20_000_000_000,
    };
    let token = local_cache.encrypt(claims).unwrap();
    let TokenData {
        claims: decrypted_claims,
        ..
    } = local_cache.decrypt::<MyClaims, _>(&token, true).unwrap();

    assert_eq!(claims, decrypted_claims);
}
