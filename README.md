# tower-oauth2-resource-server

Tower middleware that provides JWT authorization against an OpenID Connect (OIDC) Provider.
This is useful when an application has delegated authentication and/or authorization to an external authorization service (e.g. Auth0, Microsoft Entra, etc).

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

See docs for [OAuth2ResourceServerBuilder](https://insert-docs-url).

## Example usage

Check the [examples](https://github.com/Dunklas/tower-oauth2-resource-server/tree/main/examples).
