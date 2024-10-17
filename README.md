# tower-oauth2-resource-server

Tower middleware that provides JWT authorization against an OpenID Connect (OIDC) Provider.

Main inspiration for this middleware (both in naming and functionality) is [OAuth 2.0 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html).

```
curl -X POST localhost:8081/realms/master/protocol/openid-connect/token -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=password&client_id=tors-example&username=user@example.com&password=password&scope=openid&client_secret=zfjMpZoVPs99ROKQrBCDJ6IbrMT7d38L
```