#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    invalid_uri,
    invalid_algorithm,
    unable_to_fetch_keys { message: String },
    unrecognized_response { message: String },
    unable_to_verify_token { message: String },
    invalid_token,
    unrecognized_jwt_type,
    no_kid_present,
    no_corresponding_kid_in_store,
    unable_to_parse_kid_into_uuid,
    no_cache_control,
    no_max_age,
    unable_to_parse_headers,
    stale_cache,
    unrecognized_tpa,
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
