use serde::Serialize;

#[derive(Serialize)]
pub struct OpenIdConfig {
    pub issuer: String,
    pub jwks_uri: String,
}
