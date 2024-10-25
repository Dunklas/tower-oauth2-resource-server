use async_trait::async_trait;
use jsonwebtoken::{
    jwk::{AlgorithmParameters, Jwk, JwkSet},
    DecodingKey,
};
use log::{info, warn};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    sync::RwLock,
    time::{self, Duration},
};

use crate::error::JwkError;

#[cfg(test)]
use mockall::automock;
#[cfg_attr(test, automock)]
#[async_trait]
pub trait DecodingKeysProvider {
    async fn get_decoding_key(&self, kid: &str) -> Option<Arc<DecodingKey>>;
}

pub struct JwksDecodingKeysProvider {
    decoding_keys: Arc<RwLock<HashMap<String, Arc<DecodingKey>>>>,
}

impl JwksDecodingKeysProvider {
    pub fn new(jwks_uri: &str, refresh_interval: Duration) -> Self {
        let decoding_keys = Arc::new(RwLock::new(HashMap::new()));
        tokio::spawn(Self::fetch_jwks_job(
            jwks_uri.to_owned(),
            decoding_keys.clone(),
            refresh_interval,
        ));
        Self { decoding_keys }
    }

    async fn fetch_jwks_job(
        jwks_uri: String,
        decoding_keys: Arc<RwLock<HashMap<String, Arc<DecodingKey>>>>,
        refresh_interval: Duration,
    ) {
        let mut interval = time::interval(refresh_interval);
        loop {
            interval.tick().await;
            match fetch_jwks(&jwks_uri).await {
                Ok(jwks) => match jwks
                    .keys
                    .into_iter()
                    .map(to_decoding_key)
                    .collect::<Result<HashMap<_, _>, _>>()
                {
                    Ok(new_decoding_keys) => {
                        let mut keys = decoding_keys.write().await;
                        info!("Successfully fetched JWK set");
                        *keys = new_decoding_keys;
                    }
                    Err(e) => {
                        warn!("Unable to parse at least one JWK due to: {:?}", e);
                    }
                },
                Err(e) => {
                    warn!("Failed to fetch JWK set: {:?}", e);
                }
            }
        }
    }
}

#[async_trait]
impl DecodingKeysProvider for JwksDecodingKeysProvider {
    async fn get_decoding_key(&self, kid: &str) -> Option<Arc<DecodingKey>> {
        let keys = self.decoding_keys.read().await;
        keys.get(kid).cloned()
    }
}

async fn fetch_jwks(jwks_uri: &str) -> Result<JwkSet, JwkError> {
    let response = reqwest::get(jwks_uri)
        .await
        .map_err(|_| JwkError::FetchFailed)?;
    let parsed = response
        .json::<JwkSet>()
        .await
        .map_err(|_| JwkError::ParseFailed)?;
    Ok(parsed)
}

fn to_decoding_key(jwk: Jwk) -> Result<(String, Arc<DecodingKey>), JwkError> {
    let key_id = jwk.common.key_id.ok_or(JwkError::MissingKeyId)?;
    let decoding_key = match jwk.algorithm {
        AlgorithmParameters::RSA(rsa) => {
            DecodingKey::from_rsa_components(&rsa.n, &rsa.e).or(Err(JwkError::DecodingFailed))
        }
        _ => Err(JwkError::UnexpectedAlgorithm),
    }?;
    Ok((key_id, Arc::new(decoding_key)))
}
