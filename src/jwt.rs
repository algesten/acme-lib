use openssl::bn::BigNumRef;
use serde::{Deserialize, Serialize};

use crate::acc::AcmeKey;
use crate::cert::ec_group_p256;
use crate::util::{base64url, p256_component_bytes};

#[derive(Debug, Serialize, Deserialize, Default)]
pub(crate) struct JwsProtected {
    alg: String,
    url: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl JwsProtected {
    pub(crate) fn new_jwk(jwk: Jwk, url: &str, nonce: String) -> Self {
        JwsProtected {
            alg: "ES256".into(),
            url: url.into(),
            nonce,
            jwk: Some(jwk),
            ..Default::default()
        }
    }
    pub(crate) fn new_kid(kid: &str, url: &str, nonce: String) -> Self {
        JwsProtected {
            alg: "ES256".into(),
            url: url.into(),
            nonce,
            kid: Some(kid.into()),
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct Jwk {
    alg: String,
    crv: String,
    kty: String,
    #[serde(rename = "use")]
    _use: String,
    x: String,
    y: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
// LEXICAL ORDER OF FIELDS MATTER!
pub(crate) struct JwkThumb {
    crv: String,
    kty: String,
    x: String,
    y: String,
}

impl From<&AcmeKey> for Jwk {
    fn from(a: &AcmeKey) -> Self {
        let mut ctx = openssl::bn::BigNumContext::new().expect("BigNumContext");
        let mut x = openssl::bn::BigNum::new().expect("BigNum");
        let mut y = openssl::bn::BigNum::new().expect("BigNum");
        a.private_key()
            .public_key()
            .affine_coordinates_gfp(ec_group_p256(), &mut x, &mut y, &mut ctx)
            .expect("affine_coordinates_gfp");
        Jwk {
            alg: "ES256".into(),
            kty: "EC".into(),
            crv: "P-256".into(),
            _use: "sig".into(),
            x: jwk_coordinate(&x),
            y: jwk_coordinate(&y),
        }
    }
}

fn jwk_coordinate(coordinate: &BigNumRef) -> String {
    base64url(&p256_component_bytes(coordinate))
}

impl From<&Jwk> for JwkThumb {
    fn from(a: &Jwk) -> Self {
        JwkThumb {
            crv: a.crv.clone(),
            kty: a.kty.clone(),
            x: a.x.clone(),
            y: a.y.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Jws {
    protected: String,
    payload: String,
    signature: String,
}

impl Jws {
    pub(crate) fn new(protected: String, payload: String, signature: String) -> Self {
        Jws {
            protected,
            payload,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::Jwk;
    use crate::acc::AcmeKey;

    const P256_COMPONENT_LENGTH: usize = 32;

    const KEY_WITH_LEADING_ZERO_X: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGGj9y1IuJmCHR76uYxA/mM/AciUFVCG/jIrJ27mo77boAoGCCqGSM49
AwEHoUQDQgAEAIremSXMAtjvYHe2x7IEhpoXkg0BjRWB8oSvwf82inCZ+x1M0eWy
VuDmmZJmR2Tekx6gwHOsnkGxWmOVSsi3hw==
-----END EC PRIVATE KEY-----
"#;

    #[test]
    fn jwk_coordinates_are_fixed_width() {
        let key = AcmeKey::from_pem(KEY_WITH_LEADING_ZERO_X).expect("valid P-256 key");
        let jwk = Jwk::from(&key);

        let x = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(jwk.x)
            .expect("valid base64url x coordinate");
        let y = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(jwk.y)
            .expect("valid base64url y coordinate");

        assert_eq!(x.len(), P256_COMPONENT_LENGTH);
        assert_eq!(x[0], 0);
        assert_eq!(y.len(), P256_COMPONENT_LENGTH);
    }
}
