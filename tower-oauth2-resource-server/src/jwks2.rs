use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;
use log::{info, warn};
use reqwest::Url;
use std::{sync::Arc, time::Duration};
use tokio::time;

use crate::error::JwkError;

pub trait JwksProducer {
    fn add_receiver(&mut self, receiver: Arc<dyn JwksConsumer>);
    fn start(&self);
}

#[async_trait]
pub trait JwksConsumer: Send + Sync {
    async fn receive_jwks(&self, jwks: JwkSet);
}

pub struct TimerJwksProducer {
    jwks_url: Url,
    refresh_interval: Duration,
    receivers: Vec<Arc<dyn JwksConsumer>>,
}

impl TimerJwksProducer {
    pub fn new(jwks_url: Url, refresh_interval: Duration) -> Self {
        Self {
            jwks_url,
            refresh_interval,
            receivers: Vec::new(),
        }
    }
}

impl JwksProducer for TimerJwksProducer {
    fn add_receiver(&mut self, receiver: Arc<dyn JwksConsumer>) {
        self.receivers.push(receiver);
    }

    fn start(&self) {
        tokio::spawn(fetch_jwks_job(
            self.jwks_url.clone(),
            self.refresh_interval,
            self.receivers.clone(),
        ));
    }
}

async fn fetch_jwks_job(
    jwks_url: Url,
    refresh_interval: Duration,
    receivers: Vec<Arc<dyn JwksConsumer>>,
) {
    let mut interval = time::interval(refresh_interval);
    loop {
        interval.tick().await;
        match fetch_jwks(jwks_url.clone()).await {
            Ok(jwks) => {
                for receiver in &receivers {
                    receiver.receive_jwks(jwks.clone()).await;
                }
            }
            Err(e) => {
                warn!("Failed to fetch JWK set: {:?}", e);
            }
        }
    }
}

async fn fetch_jwks(jwks_url: Url) -> Result<JwkSet, JwkError> {
    let response = reqwest::get(jwks_url)
        .await
        .map_err(|_| JwkError::FetchFailed)?;
    let parsed = response
        .json::<JwkSet>()
        .await
        .map_err(|_| JwkError::ParseFailed)?;
    Ok(parsed)
}
