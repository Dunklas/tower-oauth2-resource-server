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
### Issuer

The `issuer_url` property is used to configure what authorization server to use.

On startup, the OIDC Provider Configuration endpoint of the authorization server will be queried in order to self-configure the middleware.
If `issuer_url` is set to `https://authorization-server.com/issuer`, at least one of the following endpoints need to available.

 - `https://authorization-server.com/issuer/.well-known/openid-configuration`
 - `https://authorization-server.com/.well-known/openid-configuration/issuer`
 - `https://authorization-server.com/.well-known/oauth-authorization-server/issuer`

A consequence of the self-configuration is that the authorization server must be available when the middleware is started.

In cases where the middleware must be able to start independently from the authorization server, the `jwks_url` property can be set.
This will prevent the self-configuration on start up.

**Note** that it's still required to provide `issuer_url`, since it's used to validate the `iss` claim in JWTs.

### Audiences

### JWKS rotation
The middleware will periodically call the `jwks_url` of the authorization server in order to update the public keys that JWT signatures will be validated against.
By default this is done once a minute.

You can change this interval by setting the `jwks_refresh_interval` property.

### Claims validation

## Example usage

Check the [examples](./examples/).
