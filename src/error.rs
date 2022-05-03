//! Errors that can appear during performing operations required by this crate.

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The given `Uri` is invalid.
    ///
    /// ### Note:
    /// We expect the `Uri` to use the `https` scheme.
    ///
    /// ### Extension:
    /// We may extend this library to support the `http` scheme as well.
    invalid_uri,

    /// The given `JWT` or fetched `JWK` contained an invalid algorithm.
    ///
    /// ### Note:
    /// We only expect `alg == "RS256"`.
    invalid_algorithm,

    /// Something went wrong while trying to fetch the `JWK`s from the given
    /// `Uri`.
    ///
    /// The message string contains the error that [`hyper`] issued.
    /// [`hyper`] is the library that this crate uses internally to make
    /// requests.
    unable_to_fetch_keys {
        message: String,
    },

    /// A response was received, but it was not able to be parsed into a `Json`
    /// object.
    unrecognized_response {
        message: String,
    },

    unable_to_verify_token {
        message: String,
    },

    /// The `typ` field inside of the received `JWT` *must* have the value of
    /// "JWT". Any other values will raise an error.
    ///
    /// ### Note:
    /// This library is specifically dealing with `JWT`s only.
    /// Other types are not supported.
    unrecognized_typ,

    /// A `kid` field *must* be present in the fetched `JWK`, as well as the
    /// received `JWT`.
    ///
    /// ### Note:
    /// This is because if either do not contain one, there will not be
    /// sufficient information required to decrypt the incoming token.
    no_kid_present,

    /// The incoming token has a `kid` field, but the value has no
    /// corresponding `JWK` with the same `kid` in the cache.
    ///
    /// ### Note:
    /// This *may* be because the cache is stale.
    /// If this is the case, call
    /// [`refresh`](`crate::key_caches::remote::RemoteCache::refresh`).
    no_corresponding_kid_in_store,

    unable_to_parse_kid_into_uuid,

    /// The [`hyper::http::Response`] that was received contained a header that
    /// was unable to be parsed.
    unable_to_parse_headers,
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Self::unable_to_fetch_keys {
            message: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::unrecognized_response {
            message: e.to_string(),
        }
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(_: http::uri::InvalidUri) -> Self {
        Self::invalid_uri
    }
}

impl From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Self::unable_to_verify_token {
            message: e.to_string(),
        }
    }
}

impl From<uuid::Error> for Error {
    fn from(_: uuid::Error) -> Self {
        Self::unable_to_parse_kid_into_uuid
    }
}

impl From<http::header::ToStrError> for Error {
    fn from(_: http::header::ToStrError) -> Self {
        Self::unable_to_parse_headers
    }
}
