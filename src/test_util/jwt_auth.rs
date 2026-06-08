//! Shared JWT auth test helpers used by `sources/util/jwt_auth` unit tests
//! and `sources/vector` integration tests.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

use crate::sources::util::jwt_auth::{
    Auth, AuthConfig, Authority, AuthorityData, MembershipClaimConfig,
};

// RSA-2048 test key pair (not used outside of tests).
pub const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJ5D7lpMrGJpl7
zCcZ73XqbzBaagaPa9QDoGmypTbOoiysnnmcTHfy+wcP2aBlDTC8aB+7iPdZr0tA
ENdzIQ0/kZFBWCdwqAtQYDyfGuZx9y+3E9I8RFleDqDSwA6aUrSoesC9OBHztebX
0m4T9dAWzn8Vr3CYKVpp4XcYwfX6iWszCm43zv4fCJu/qYX67IvOP8h66OMBZ8s7
A4K15z1n8ScI3R6v6amc94iB7z2B9hdvuoTKk89dF5XGxE1ZVnIzSPr/8/oQQJgG
RaYqQAViy4kPmctW4uaI9ajQPIQe58LpNh1lDw+aLRHO/e0SCqbUNARTLSdSIwNV
3dltWgS9AgMBAAECggEAHPo4NuDYw+kdZYHvaM8QdyYfZBLMv0AkTaL0GNKS08S+
McaLQO5O1x7FrDY5yddDU/+D8nhdvE8nN1pTejBXxPSBS0Y6XvaXrSErAlErm1b1
z8q2BbVvuErUNXugfPD7AiWgTWhjVz4YFIkdCJtjEyrvXa7xM73XvtPAMtsAEcXv
MgeRaZVdIledQUozu72RfPuG0yYWG5j+1W1IjNDcuLvld+RrZZ6JqyedhHMwlsFU
bi1DDGaBvp7jkDr6hDp81dqUVposvq+yw3THoyDnQCNxrSCfDpRkYk7DWJKVD8XS
6GvFHuHfaktzm+KkUHBQAebGn6qM+3QBIOWXZkHBdwKBgQDwhVtLUNnz7LLOlAxH
/IF5WM96DoPilOG548yMt/81Zez9QzgJXhxefhCpl2ZQDUCWr9CFvn+98XFai8jt
voVQMV23AGi6nJJ+jGw9koQUt/uYAxZ4U8tG0KqxVGhmrab1MfTpLp2mQWkJN7y1
Hk5moPHwpQhxW73qlzwR8Ug8FwKBgQDW4nX8ZvFfmyJcrckquh0KMpILe5i+klmd
ENU7TmlQ8Sq1QX2j+w4gOWpUR6/bnij1XeEsI21z10Sv3yEgu2E8V7Cqf9mJX0in
+H5+WpEbTHqgfWhA8wXoZIizRfHDKOsOnhNmTFMBBrcp0zd4V1N1xH+APkw1q3jF
YxnmMAMmSwKBgBH5xYLxffiO/iYWRnyy0HJjQs5ae1zZx6z+63Cw56/z+CxNc8iv
cetV/KTQHeNpuiQI68qzHBT0EIa138R08r21ks10iF86CHDQyd4oLxrlTTZlNK61
hIG8YqVyK4NRAyNcInOy+jFMvi7kLYRTyYQ+DxbvHpxqQN1hhCnLIJztAoGAakX9
zCKtZXc3+1YHk5YQHqb8C6nI1RdUMpXMn1QcSee8E4CcPqk/RzieGaiKlLcX0qHn
ZwjubMgeNEzJ+YIyiMFloi0wzPvO1yPSi3MHKNUeIJllIhoO5ewyn1cMRlTKS6Rq
O8Grm2pS0+CeImot4KSZ2jb1QeXYCOcGPA2qwRkCgYEAnCI12DQuInN8nLEo4qtq
XEgyvUZ0fGaezcmeT4hhY94l0/HXS0D0qXs/f/rvfFFnvRYlEyiycA4pClkNRNkM
TM9RBaFTEKw9NQP895KUx6hHIAM/LB1Qyf7cDixtwf8ly7Gqhx4vU9tCiiDGSr9Z
T+QEb2Rxj5SJ8cGbNr+NAEI=
-----END PRIVATE KEY-----";

pub const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyeQ+5aTKxiaZe8wnGe91
6m8wWmoGj2vUA6BpsqU2zqIsrJ55nEx38vsHD9mgZQ0wvGgfu4j3Wa9LQBDXcyEN
P5GRQVgncKgLUGA8nxrmcfcvtxPSPERZXg6g0sAOmlK0qHrAvTgR87Xm19JuE/XQ
Fs5/Fa9wmClaaeF3GMH1+olrMwpuN87+Hwibv6mF+uyLzj/IeujjAWfLOwOCtec9
Z/EnCN0er+mpnPeIge89gfYXb7qEypPPXReVxsRNWVZyM0j6//P6EECYBkWmKkAF
YsuJD5nLVuLmiPWo0DyEHufC6TYdZQ8Pmi0Rzv3tEgqm1DQEUy0nUiMDVd3ZbVoE
vQIDAQAB
-----END PUBLIC KEY-----";

// Self-signed X.509 certificate wrapping `TEST_PUBLIC_KEY` (CN=vector-test-jwt-signer,
// SHA-256/RSA-2048, valid until ~2126). Used to verify that `AuthConfig` accepts a
// `BEGIN CERTIFICATE` PEM and extracts the embedded public key correctly.
pub const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUVbKf6yXWhoONy5OO4QQmDddORmgwDQYJKoZIhvcNAQEL
BQAwITEfMB0GA1UEAwwWdmVjdG9yLXRlc3Qtand0LXNpZ25lcjAgFw0yNjA1MjYx
MjI5NTlaGA8yMTI2MDUwMjEyMjk1OVowITEfMB0GA1UEAwwWdmVjdG9yLXRlc3Qt
and0LXNpZ25lcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnkPuWk
ysYmmXvMJxnvdepvMFpqBo9r1AOgabKlNs6iLKyeeZxMd/L7Bw/ZoGUNMLxoH7uI
91mvS0AQ13MhDT+RkUFYJ3CoC1BgPJ8a5nH3L7cT0jxEWV4OoNLADppStKh6wL04
EfO15tfSbhP10BbOfxWvcJgpWmnhdxjB9fqJazMKbjfO/h8Im7+phfrsi84/yHro
4wFnyzsDgrXnPWfxJwjdHq/pqZz3iIHvPYH2F2+6hMqTz10XlcbETVlWcjNI+v/z
+hBAmAZFpipABWLLiQ+Zy1bi5oj1qNA8hB7nwuk2HWUPD5otEc797RIKptQ0BFMt
J1IjA1Xd2W1aBL0CAwEAAaNTMFEwHQYDVR0OBBYEFI+RBPkshN3T+Ua4+eNeKtDM
Rfn/MB8GA1UdIwQYMBaAFI+RBPkshN3T+Ua4+eNeKtDMRfn/MA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAI6hkfHsDJfpNXQFyFqmJDXDeSOkKviw
s7Wn8T6+u1e0iV8ufji9kTjs1g25311KQnl3v0nBbg6KtYZm8nmjE69zPLwswjkT
hub2+oIA99DY5VZh8HUxw2GzJttu/sfXM+CzTMz4kr0aiYnTlcDYI7D0dT0uuzTw
Trls8yi+PL94c8Eb+m6qr8q6BGob2N6HwVJtcpgFfzmjubmg+o8dT78Ual2XtnP9
SUp/fertFUmpey5ERyaNtuA5pY3ApOOg7elHSyL7BGdoAHwduCk52JHsIA2mFhvb
q2PnSLA/85i34yxEJ8lUekVbx4VBaZZpmaNMpNbtabYGkxEgK59kMws=
-----END CERTIFICATE-----";

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Sign a JWT with the test private key.
///
/// Default claims: `sub="test-subject"`, `exp=now+1h`,
/// `site_ids=["site-123","site-456"]`. Values in `extra` are merged in
/// last and override the defaults.
pub fn make_token(extra: HashMap<&str, serde_json::Value>) -> String {
    let mut claims = serde_json::Map::new();
    claims.insert("sub".into(), serde_json::json!("test-subject"));
    claims.insert("exp".into(), serde_json::json!(now_secs() + 3600));
    claims.insert("site_ids".into(), serde_json::json!(["site-123", "site-456"]));
    for (k, v) in extra {
        claims.insert(k.into(), v);
    }
    let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
    encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap()
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// Build an `Auth` from the test public key with optional issuer/audience.
pub async fn build_auth(issuer: Option<&str>, audience: Option<Vec<&str>>) -> Auth {
    AuthConfig {
        authority: Authority::PublicKey(AuthorityData::Inline {
            value: TEST_PUBLIC_KEY.to_string(),
        }),
        issuer: issuer.map(str::to_string),
        audience: audience.map(|v| v.iter().map(|s| s.to_string()).collect()),
        membership_claim: Some(MembershipClaimConfig::Identity("site_ids".to_string())),
        value_path: None,
        algorithms: None,
    }
    .build()
    .await
    .unwrap()
}
