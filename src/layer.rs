use futures_util::{future::BoxFuture, Future};
use http::{Request, Response};
use pin_project::pin_project;
use serde::de::DeserializeOwned;

use std::{
    pin::Pin,
    task::{ready, Context, Poll},
};
use tower::{Layer, Service};

use crate::{error::AuthError, server::OAuth2ResourceServer};

trait Authorize<B> {
    type Future: Future<Output = Result<Request<B>, AuthError>>;

    fn authorize(&mut self, request: Request<B>) -> Self::Future;
}

impl<S, ReqBody, Claims> Authorize<ReqBody> for OAuth2ResourceServerService<S, Claims>
where
    Claims: DeserializeOwned + Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Future = BoxFuture<'static, Result<Request<ReqBody>, AuthError>>;

    fn authorize(&mut self, request: Request<ReqBody>) -> Self::Future {
        let auth = self.auth_manager.clone();
        Box::pin(async move { auth.authorize_request(request).await })
    }
}

#[derive(Clone, Debug)]
pub struct OAuth2ResourceServerLayer<Claims>
where
    Claims: DeserializeOwned,
{
    auth_manager: OAuth2ResourceServer<Claims>,
}

impl<S, Claims> Layer<S> for OAuth2ResourceServerLayer<Claims>
where
    Claims: Clone + DeserializeOwned + Send + 'static,
{
    type Service = OAuth2ResourceServerService<S, Claims>;

    fn layer(&self, inner: S) -> Self::Service {
        OAuth2ResourceServerService::new(inner, self.auth_manager.clone())
    }
}

impl<Claims> OAuth2ResourceServerLayer<Claims>
where
    Claims: DeserializeOwned,
{
    pub(crate) fn new(auth_manager: OAuth2ResourceServer<Claims>) -> Self
    where
        Claims: DeserializeOwned,
    {
        OAuth2ResourceServerLayer { auth_manager }
    }
}

#[derive(Clone, Debug)]
pub struct OAuth2ResourceServerService<S, Claims>
where
    Claims: Clone + DeserializeOwned + Send + 'static,
{
    inner: S,
    auth_manager: OAuth2ResourceServer<Claims>,
}

impl<S, Claims> OAuth2ResourceServerService<S, Claims>
where
    Claims: Clone + DeserializeOwned + Send + 'static,
{
    fn new(inner: S, auth_manager: OAuth2ResourceServer<Claims>) -> Self {
        Self {
            inner,
            auth_manager,
        }
    }
}

impl<S, ReqBody, ResBody, Claims> Service<Request<ReqBody>>
    for OAuth2ResourceServerService<S, Claims>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone,
    ResBody: Default,
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S, ReqBody, Claims>;

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

#[pin_project]
pub struct ResponseFuture<S, ReqBody, Claims>
where
    S: Service<Request<ReqBody>>,
    ReqBody: Send + 'static,
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    #[pin]
    state: State<<OAuth2ResourceServerService<S, Claims> as Authorize<ReqBody>>::Future, S::Future>,
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

impl<S, ReqBody, B, Claims> Future for ResponseFuture<S, ReqBody, Claims>
where
    S: Service<Request<ReqBody>, Response = Response<B>>,
    B: Default,
    ReqBody: Send + 'static,
    Claims: Clone + DeserializeOwned + Send + Sync + 'static,
{
    type Output = Result<Response<B>, S::Error>;

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
                            let response = Response::<B>::from(res);
                            return Poll::Ready(Ok(response));
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
