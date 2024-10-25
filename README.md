# tower-oauth2-resource-server

Tower middleware that provides JWT authorization against an OpenID Connect (OIDC) Provider.

Main inspiration for this middleware (both in naming and functionality) is [Spring Security OAuth 2.0 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html).

## Configuration

The `issuer_uri` property is used to configure what authorization server to use.

On startup, the OIDC Provider Configuration endpoint (`<issuer_uri>/.well-known/openid-configuration`) will be queried in order to self-configure the middleware.
A consequence of this is that the authorization server must be available when the middleware is started.

In cases where the middleware must be able to start independently from the authorization server, the `jwks_uri` property can be set.
This will prevent the self-configuration on start up.

**Note** that it's still required to provide `issuer_uri`, since it's used to validate the `iss` claim in JWTs.

## Example usage

Check the [examples](./examples/).

To run one of them: `RUST_LOG=info cargo run -p <name-of-example>`

**Note!** Since a running OIDC Provider is needed to use this middleware, a local instance of [Keycloak](https://www.keycloak.org/) is started in each example.
It's seeded with a single user, *user@example.com* / *password*.

Each example will log what port the OIDC provider runs on.

To obtain a valid JWT for *user@example.com*, you can run:

```
curl -X POST localhost:<PORT>/realms/tors/protocol/openid-connect/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=tors-example&username=user@example.com&password=password&scope=openid&client_secret=SGkkbV1nCLfKfr0Zxyig6isRgT1RdK2q" \
    | jq '.access_token'
```
