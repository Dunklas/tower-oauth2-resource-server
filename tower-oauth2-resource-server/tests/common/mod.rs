use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Serialize;
use serde_json::Value;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[derive(Serialize)]
struct OpenIdConfig {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Serialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Serialize)]
struct Jwk {
    kty: String,
    use_: String,
    alg: String,
    kid: String,
    n: String,
    e: String,
}

pub const DEFAULT_RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCgTP9Gu6kc/131
eIVtcugkzAb7vlnXy3jOIHLY8dNkfGQc56ntoV42P7Xc2YhwviiiP7afGsuFZuAD
aIFpav3nAqR/ml5Oxz7lDr4Ha4Jyf3E9JArTxj+M1WG2XLeYA52xPhj2ZAg7+ipq
oTLO63KlkES77Xw2RsZXCQ2Eb2zG9SMVce8ygmzmLAgtoMDYWG4SKggPM7L5mMPy
n3bzJ7a/wJ09aXXE/GgFd3Yoh7dGShxEPEt54GDfAfxr21Dlnt86aJeIAjz+U3nv
Nh/TvzJrO8tSUrMKjWlChHbkxTnV3vOAj8jsfYVvk9kZwKZ+83VSnjU58RDIwsvo
ljKg/bddAgMBAAECggEAToB2kU6simlau7A6c3eOzRpnnxhAikf4UMWeSLTgx7iN
FIS0+I0KhLmdl9qmEURmxNI73l3yZlGTice/fH8reVqXcXAJGD5GBEm8cQjK2MSl
kYIZlU1kaNVEpVhxho3ax2Z4Ng2V5L1l0VNA/Qlb2020A25RYok1b4Ec8ArbM/Ep
ECxHjMjViHlqFLo25AfqxW0Q/TeNyMdYDWn/l6+qw9OI5OYswGwW1xwjL6ElcqnT
tDDC/wqorxv+sRrTTyxQ1mUg1K2vm7wjml2PlVgjv7P28O0LjlDspPFChVZ2xbp0
+ohEiNARBabqVt1gs/aYmoN8SZ9NDneCCzFSL/P4lwKBgQDT9QQXMB2lgEMaEIS/
1z2E1ByL6cN7uiqo4rTDrvnLGL/vBqb3751YV/sJubi6Da1QpAZJQ/ssHNs6T1zh
nImXkSWG+OravA10driJL8wWcKD3bIQOEc6FFrz+t/tiLf6tx5Ok6+vWL89muiWw
xouU/msV0ZXHcIoKonB2a7sYqwKBgQDBnCQYhbb8T7U248Cd6jv0gaJn5VHA9mF7
/Wg0oHgAi/TFGlO/1nktkmHbDE0BH4Y9NM3vOmik5ag4tVGFIQU7MkDx9HKo9GnZ
Tx2OcwpQ5l/02GMO634y2w/zoS1GoGNqWLYVPsK3kyM+LmzAc29fpOBxxomqA1Pw
SRuVBouAFwKBgHpL5z5R3uk9ZnpFibL/SFm54XbBPK/JLRAhLtexwCN1dlk+Z1yr
fwgYS5rC9Fk1xwi+e3oOpYBAbiXo4Ni0b5dqglKskSYAV2sZjURqtcFE3zuj+1X6
5ERaaFY4Ze2ySD6Q5xnDnmIJWAwX3+Nty9/+JF+EfH2E68FTFLzfUCbdAoGBALzB
k9dslegLdesbxLCwqt9Ie6O7SSdNjeEqP6v/Pr+Zs3tunXQMj3vEmS7MIU8VAvUt
RBEV6uvJE2amL+IRPV5nMjYyUo8yKvg4T+KPeeFBmQ/G31yubwz50eV+n/uZZxNJ
hcvUslXzV4rKDDDc2hpvTnreS1y7fdxoCkISbXLlAoGAQ2W04sNMa6sFI/9rAcFv
yviLtRw4G2epS0AtGhPsy3cPX8XIiRbkQXrZSSV9FSlZyC0Fr1IS8qTCF9rJMawm
iiVw58CWKo4qO6HQGC/W5nD3maFnHnnp3mtIgfGsWEyc9tgdhFZuTtHxDPTjm/xU
kTlUuvwRMeoB7RdcxaYHaQo=
-----END PRIVATE KEY-----"#;

const DEFAULT_RSA_MODULUS: &str = "oEz_RrupHP9d9XiFbXLoJMwG-75Z18t4ziBy2PHTZHxkHOep7aFeNj-13NmIcL4ooj-2nxrLhWbgA2iBaWr95wKkf5peTsc-5Q6-B2uCcn9xPSQK08Y_jNVhtly3mAOdsT4Y9mQIO_oqaqEyzutypZBEu-18NkbGVwkNhG9sxvUjFXHvMoJs5iwILaDA2FhuEioIDzOy-ZjD8p928ye2v8CdPWl1xPxoBXd2KIe3RkocRDxLeeBg3wH8a9tQ5Z7fOmiXiAI8_lN57zYf078yazvLUlKzCo1pQoR25MU51d7zgI_I7H2Fb5PZGcCmfvN1Up41OfEQyMLL6JYyoP23XQ";
const DEFAULT_RSA_EXPONENT: &str = "AQAB";

pub async fn mock_oidc_config(mock_server: &MockServer, issuer: &str) {
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(OpenIdConfig {
            issuer: issuer.to_owned(),
            jwks_uri: format!("{}/jwks", &mock_server.uri()),
        }))
        .mount(mock_server)
        .await;
}

pub async fn mock_jwks(mock_server: &MockServer, kids: Vec<String>) {
    let keys = kids
        .into_iter()
        .map(|kid| Jwk {
            kty: "RSA".to_string(),
            use_: "sig".to_string(),
            alg: "RS256".to_string(),
            kid,
            n: DEFAULT_RSA_MODULUS.to_owned(),
            e: DEFAULT_RSA_EXPONENT.to_owned(),
        })
        .collect::<Vec<_>>();
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(Jwks { keys }))
        .mount(mock_server)
        .await;
}

pub fn jwt_from(private_key_pem: &str, kid: &str, claims: Value) -> String {
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap();
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    encode(&header, &claims, &encoding_key).unwrap()
}
