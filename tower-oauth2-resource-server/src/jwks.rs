use async_trait::async_trait;
use jsonwebtoken::jwk::JwkSet;
use log::warn;
use reqwest::Url;
use std::{sync::Arc, time::Duration};
use tokio::time;

use crate::error::JwkError;

pub trait JwksProducer {
    fn add_consumer(&mut self, receiver: Arc<dyn JwksConsumer>);
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
    fn add_consumer(&mut self, consumer: Arc<dyn JwksConsumer>) {
        self.receivers.push(consumer);
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
    consumers: Vec<Arc<dyn JwksConsumer>>,
) {
    let mut interval = time::interval(refresh_interval);
    loop {
        interval.tick().await;
        match fetch_jwks(jwks_url.clone()).await {
            Ok(jwks) => {
                for consumer in &consumers {
                    consumer.receive_jwks(jwks.clone()).await;
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

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use base64::{
        alphabet,
        engine::{general_purpose, GeneralPurpose},
        Engine,
    };
    use jsonwebtoken::jwk::Jwk;
    use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
    use serde_json::json;
    use tokio::sync::RwLock;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;

    struct TestConsumer {
        jwks: Arc<RwLock<Option<JwkSet>>>,
    }

    impl TestConsumer {
        pub fn new() -> Self {
            Self {
                jwks: Arc::new(RwLock::new(None)),
            }
        }
        pub async fn has_jwks(&self) -> bool {
            self.jwks.read().await.is_some()
        }
    }

    #[async_trait]
    impl JwksConsumer for TestConsumer {
        async fn receive_jwks(&self, jwks: JwkSet) {
            self.jwks.write().await.replace(jwks);
        }
    }

    #[tokio::test]
    async fn test_should_notify_consumers() {
        let mock_server = MockServer::start().await;
        mock_jwks(&mock_server, "/jwks.json").await;

        let consumer = Arc::new(TestConsumer::new());
        let mut producer = TimerJwksProducer::new(
            format!("{}/jwks.json", &mock_server.uri())
                .parse::<Url>()
                .unwrap(),
            Duration::from_millis(5),
        );
        producer.add_consumer(consumer.clone());
        producer.start();

        let mut success = false;
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(500) {
            if consumer.has_jwks().await {
                success = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(success, "Consumer did not receive JWKS in time");
    }

    async fn mock_jwks(server: &MockServer, jwks_path: &str) {
        let private = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let public = RsaPublicKey::from(private);
        let base64_engine = GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "RSA",
            "use_": "sig",
            "alg": "RS256",
            "kid": "test-kid",
            "n": base64_engine.encode(public.n().to_bytes_be()),
            "e": base64_engine.encode(public.e().to_bytes_be())
        }))
        .unwrap();
        Mock::given(method("GET"))
            .and(path(jwks_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(JwkSet { keys: vec![jwk] }))
            .mount(server)
            .await
    }
}
