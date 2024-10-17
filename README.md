# tower-oauth2-resource-server

Tower middleware that provides JWT authorization against an OpenID Connect (OIDC) Provider.

Main inspiration for this middleware (both in naming and functionality) is [OAuth 2.0 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html).

## Example usage

Check the [examples](./examples/).

**Note!** To have an actual OIDC Provider in the examples, a local instance of [Keycloak](https://www.keycloak.org/) is started using docker.
Each example will print what port the OIDC provider runs on to stdout.

To obtain a valid jwt to use for the examples, you can run:
```
curl -X POST localhost:<PORT>/realms/tors/protocol/openid-connect/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=tors-example&username=user@example.com&password=password&scope=openid&client_secret=SGkkbV1nCLfKfr0Zxyig6isRgT1RdK2q" \
    | jq '.access_token'
```
