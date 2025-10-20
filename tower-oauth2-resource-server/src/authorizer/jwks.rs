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

    use jsonwebtoken::jwk::Jwk;
    use serde_json::json;
    use tokio::sync::RwLock;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
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
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "RSA",
            "use_": "sig",
            "alg": "RS256",
            "kid": "test-kid",
            "n": "oEz_RrupHP9d9XiFbXLoJMwG-75Z18t4ziBy2PHTZHxkHOep7aFeNj-13NmIcL4ooj-2nxrLhWbgA2iBaWr95wKkf5peTsc-5Q6-B2uCcn9xPSQK08Y_jNVhtly3mAOdsT4Y9mQIO_oqaqEyzutypZBEu-18NkbGVwkNhG9sxvUjFXHvMoJs5iwILaDA2FhuEioIDzOy-ZjD8p928ye2v8CdPWl1xPxoBXd2KIe3RkocRDxLeeBg3wH8a9tQ5Z7fOmiXiAI8_lN57zYf078yazvLUlKzCo1pQoR25MU51d7zgI_I7H2Fb5PZGcCmfvN1Up41OfEQyMLL6JYyoP23XQ",
            "e": "AQAB"
        }))
        .unwrap();
        Mock::given(method("GET"))
            .and(path(jwks_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(JwkSet { keys: vec![jwk] }))
            .mount(server)
            .await
    }
}
