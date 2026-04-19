use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Jwk {
    pub alg: String,
    pub e: String,
    pub kid: String,
    pub kty: String,
    pub n: String,
    #[serde(rename = "use")]
    pub token_use: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}
