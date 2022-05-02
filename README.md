# WebCipher
`webcipher` provides `JWT` authentication utilities and storage mechanism for caching keys and optimizing decryption/encryption processes.

## Overview
The primary abstraction provided by `webcipher` is the `KeyRegistry` struct.
This struct caches all keys for various OAuth2 service providers, such as `Google`, `Facebook`, etc.
Public keys can be stored internally, and `JWT` tokens can be decrypted by its according `OAuth2` provider.

### Third Party Auth Providers
An example of using a `KeyRegistry` instance to decrypt (and verify) an incoming `JWT` can be seen below:
```rust
enum ThirdPartyAuthProviders {
    Google,
    Facebook,
    ExampleProvider,
}

let registry = KeyRegistry::builder()
    .add_remote(ThirdPartyAuthProviders::Google, "https://www.googleapis.com/oauth2/v2/certs")
    .finish()
    .await?;

// Now assume that we receive some token that we wish to decrypt.
// Furthermore, let's assume that the token is claimed to be signed by `Google`.
// The claims made by `Google` are located in some arbitrary struct named `GoogleClaims` (defined elsewhere).
let received_jwt_token = "a.b.c";

let data: jsonwebtoken::TokenData<GoogleClaims> = registry.decrypt_remote::<GoogleClaims>(ThirdPartyAuthProviders::Google)?;

let jsonwebtoken::TokenData { claims: GoogleClaims { /* access to all of Google's claims! */ .. }, .. } = data;
```

### Local Auth Services
It may be the case that your own application wants to perform `JWT` encryption/decryption using locally defined secrets/keypairs.
`webcipher` also contains a `LocalCache`, which, for the most part, behaves as the above `RemoteCache`, except that it also provides encryption services.

```rust
struct OurClaims {
    // Public Claims:
    exp: u64,
    iat: u64,
    iss: String,
    // ...

    // Private Claims:
    user_id: Uuid,
    name: String,
    age: u8,
    // ...
}

// Assume some `read_file` function which reads a file at some path and returns the read bytes.
let bytes: &[u8] = read_file("path/to/priv_file.pem");
let encoding_key = EncodingKey::from_rsa_pem(bytes);

let bytes: &[u8] = read_file("path/to/pub_file.pem");
let decoding_key = DecodingKey::from_rsa_pem(bytes);

let registry = KeyRegistry::builder()
    .add_local(jsonwebtoken::Algorithm::RS256, encoding_key, decoding_key);

// Once again, assume that we receive some token that we wish to decrypt.
// Furthermore, let's assume that the token is claimed to be signed by us!
// The claims we made are located in some arbitrary struct named `OurClaims`.
let received_jwt_token = "a.b.c";

let data: jsonwebtoken::TokenData<OurClaims> = registry.decrypt_local::<OurClaims>()?;

let jsonwebtoken::TokenData { claims: OurClaims { /* access to all of our claims! */ .. }, .. } = data;
```

We can *also* sign outgoing messages using our public key.

```rust
let our_claims = OurClaims::default(); // in reality, we would use some actual data, not default data.
let token = register.encode_local::<OurClaims>(); // we can now send this token to someone else!
```

## Limitations
This library is not very... "generic".
It does enforce that remotes send back `Key`'s which have a `kty == "RSA"`, as well as an `e` (i.e., exponent) and `m` (i.e., modulus) element.
If they do not, then those keys are rejected from being stored in the `RemoteCache`.

Lastly, I am still working on multithreaded access to this store and the best practices for which to perform some of these operations.
The refreshing mechanism is still manual.
Namely, the user of this library will need to remember to refresh the cache of their own accord.
This will (hopefully) be fixed in a future release.

## Ending Remarks
PRs are always welcome.
Please take a look at the [`CONTRIBUTING.MD`](CONTRIBUTING.md) for [`Wavy`](https://hiwavy.com)'s policy on contributing to our Open Source Software.

This work is released under the `MIT` license.
The claims of this license can be found in [`LICENSE.MD`](LICENSE.md).

Lastly, this project has still yet to undergo major testing.
