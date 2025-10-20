use futures_util::{Future, future::BoxFuture};
use http::{Request, Response};
use pin_project::pin_project;
use serde::de::DeserializeOwned;

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tower::{Layer, Service};

use crate::{error_handler::ErrorHandler, server::OAuth2ResourceServer};

trait Authorize<ReqBody, ResBody> {
    type Future: Future<Output = Result<Request<ReqBody>, Response<ResBody>>>;

    fn authorize(&mut self, request: Request<ReqBody>) -> Self::Future;
}

impl<S, ReqBody, ResBody, Claims> Authorize<ReqBody, ResBody>
    for OAuth2ResourceServerService<S, ResBody, Claims>
where
    Claims: DeserializeOwned + Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Future = BoxFuture<'static, Result<Request<ReqBody>, Response<ResBody>>>;

    fn authorize(&mut self, request: Request<ReqBody>) -> Self::Future {
        let auth = self.auth_manager.clone();
        let error_handler = self.error_handler.clone();
        Box::pin(async move {
            match auth.authorize_request(request).await {
                Ok(request) => Ok(request),
                Err(error) => Err(error_handler.map_error(error)),
            }
        })
    }
}

pub struct OAuth2ResourceServerLayer<ResBody, Claims> {
    auth_manager: OAuth2ResourceServer<Claims>,
    error_handler: Arc<dyn ErrorHandler<ResBody>>,
}

impl<ResBody, Claims> Clone for OAuth2ResourceServerLayer<ResBody, Claims>
where
    Claims: Clone,
{
    fn clone(&self) -> Self {
        Self {
            auth_manager: self.auth_manager.clone(),
            error_handler: self.error_handler.clone(),
        }
    }
}

impl<S, ResBody, Claims> Layer<S> for OAuth2ResourceServerLayer<ResBody, Claims>
where
    Claims: Clone + DeserializeOwned + Send + 'static,
{
    type Service = OAuth2ResourceServerService<S, ResBody, Claims>;

    fn layer(&self, inner: S) -> Self::Service {
        OAuth2ResourceServerService::new(
            inner,
            self.auth_manager.clone(),
            self.error_handler.clone(),
        )
    }
}

impl<ResBody, Claims> OAuth2ResourceServerLayer<ResBody, Claims> {
    pub(crate) fn new(
        auth_manager: OAuth2ResourceServer<Claims>,
        error_handler: Arc<dyn ErrorHandler<ResBody>>,
    ) -> Self {
        OAuth2ResourceServerLayer {
            auth_manager,
            error_handler,
        }
    }
}

pub struct OAuth2ResourceServerService<S, ResBody, Claims> {
    inner: S,
    auth_manager: OAuth2ResourceServer<Claims>,
    error_handler: Arc<dyn ErrorHandler<ResBody>>,
}

impl<S, ResBody, Claims> Clone for OAuth2ResourceServerService<S, ResBody, Claims>
where
    S: Clone,
    Claims: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            auth_manager: self.auth_manager.clone(),
            error_handler: self.error_handler.clone(),
        }
    }
}

impl<S, ResBody, Claims> OAuth2ResourceServerService<S, ResBody, Claims> {
    fn new(
        inner: S,
        auth_manager: OAuth2ResourceServer<Claims>,
        error_handler: Arc<dyn ErrorHandler<ResBody>>,
    ) -> Self {
        Self {
            inner,
            auth_manager,
            error_handler,
        }
    }
}

impl<S, ReqBody, ResBody, Claims> Service<Request<ReqBody>>
    for OAuth2ResourceServerService<S, ResBody, Claims>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone,
    ResBody: Default + Send + 'static,
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S, ReqBody, ResBody, Claims>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let inner = self.inner.clone();
        let authorize = self.authorize(request);

        ResponseFuture {
            state: State::Authorize { authorize },
            service: inner,
        }
    }
}

type AuthorizeFuture<S, ReqBody, ResBody, Claims> =
    <OAuth2ResourceServerService<S, ResBody, Claims> as Authorize<ReqBody, ResBody>>::Future;

#[pin_project]
pub struct ResponseFuture<S, ReqBody, ResBody, Claims>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
    ResBody: Send + 'static,
{
    #[pin]
    state: State<AuthorizeFuture<S, ReqBody, ResBody, Claims>, S::Future>,
    service: S,
}

#[pin_project(project = StateProj)]
enum State<A, SFut> {
    Authorize {
        #[pin]
        authorize: A,
    },
    Authorized {
        #[pin]
        fut: SFut,
    },
}

impl<S, ReqBody, ResBody, Claims> Future for ResponseFuture<S, ReqBody, ResBody, Claims>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default + Send + 'static,
    ReqBody: Send + 'static,
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    type Output = Result<Response<ResBody>, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        loop {
            match this.state.as_mut().project() {
                StateProj::Authorize { authorize } => {
                    let auth = ready!(authorize.poll(cx));
                    match auth {
                        Ok(req) => {
                            let fut = this.service.call(req);
                            this.state.set(State::Authorized { fut })
                        }
                        Err(res) => {
                            return Poll::Ready(Ok(res));
                        }
                    };
                }
                StateProj::Authorized { fut } => {
                    return fut.poll(cx);
                }
            }
        }
    }
}
