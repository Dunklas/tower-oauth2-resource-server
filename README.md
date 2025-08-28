# tower-oauth2-resource-server

Tower middleware that provides JWT authorization against an OpenID Connect (OIDC) Provider.

[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/tower-oauth2-resource-server.svg
[crates-url]: https://crates.io/crates/tower-oauth2-resource-server
[docs-badge]: https://docs.rs/tower-oauth2-resource-server/badge.svg
[docs-url]: https://docs.rs/tower-oauth2-resource-server
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: LICENSE
[actions-badge]: https://github.com/Dunklas/tower-oauth2-resource-server/workflows/main/badge.svg
[actions-url]:https://github.com/Dunklas/tower-oauth2-resource-server/actions?query=workflow%3Amain

## Overview
This crate is useful when an application has delegated authentication and/or authorization to an external authorization service (e.g. Auth0, Microsoft Entra, etc).

Main inspiration for this middleware (both in naming and functionality) is [Spring Security OAuth 2.0 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html).

The middleware will attempt to process each request by:
 - Read JWT from `Authorization` header (with `Bearer` prefix)
 - Validate the JWT's signature against a public key obtained from `jwks_url`
 - Validate `iss`, `exp`, `aud` and possibly `nbf` scopes of the JWT

If validation fails, a HTTP 401 is returned.
Otherwise next service in the middleware chain will be called.
Claims of the JWT are made available as a [Request extension](https://docs.rs/http/latest/http/struct.Extensions.html).
This enables you to write further application logic based on the claims, e.g. rejecting request that lack a certain scope.

## Configuration

See docs for [OAuth2ResourceServerBuilder](https://docs.rs/tower-oauth2-resource-server/latest/tower_oauth2_resource_server/builder/struct.OAuth2ResourceServerBuilder.html).

## Example usage

Check the [examples](https://github.com/Dunklas/tower-oauth2-resource-server/tree/main/examples).
