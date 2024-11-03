# examples

To run one of the examples, run `RUST_LOG=info cargo run -p <name-of-example>` from the repository root.

**Note!** Since a running OIDC Provider is needed to use this middleware, a local instance of [Keycloak](https://www.keycloak.org/) is started in each example.
It's seeded with a single user, *user@example.com* / *password*.

Each example will log what port the OIDC provider runs on.

To obtain a valid JWT for *user@example.com*, you can run:

```text
curl -X POST localhost:<PORT>/realms/tors/protocol/openid-connect/token \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=tors-example&username=user@example.com&password=password&scope=openid&client_secret=SGkkbV1nCLfKfr0Zxyig6isRgT1RdK2q" \
    | jq '.access_token'
```
