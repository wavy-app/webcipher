use jsonwebtoken::Algorithm;
use serde::Deserialize;
use serde::Serialize;

#[derive(Hash, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Key {
    #[serde(default)]
    pub e: String,
    pub kty: String,
    pub alg: Option<Algorithm>,
    #[serde(default)]
    pub n: String,
    pub kid: String,
}
