use openssl::ecdsa::EcdsaSig;
use openssl::sha::sha256;
use serde::{Deserialize, Serialize};

use crate::cert::EC_GROUP_P256;
use crate::util::{base64url, AcmeKey};
use crate::Result;

#[derive(Debug, Serialize, Deserialize, Default)]
struct JwsProtected {
    alg: String,
    url: String,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl JwsProtected {
    fn new_jwk(jwk: Jwk, url: &str, nonce: String) -> Self {
        JwsProtected {
            alg: "ES256".into(),
            url: url.into(),
            nonce,
            jwk: Some(jwk),
            ..Default::default()
        }
    }
    fn new_kid(kid: &str, url: &str, nonce: String) -> Self {
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
struct Jwk {
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
struct JwkThumb {
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
            .affine_coordinates_gfp(&*EC_GROUP_P256, &mut x, &mut y, &mut ctx)
            .expect("affine_coordinates_gfp");
        Jwk {
            alg: "ES256".into(),
            kty: "EC".into(),
            crv: "P-256".into(),
            _use: "sig".into(),
            x: base64url(&x.to_vec()),
            y: base64url(&y.to_vec()),
        }
    }
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
struct Jws {
    protected: String,
    payload: String,
    signature: String,
}

pub(crate) fn make_jws_kid<T: Serialize + ?Sized>(
    url: &str,
    nonce: String,
    key: &AcmeKey,
    payload: &T,
) -> Result<String> {
    let protected = JwsProtected::new_kid(key.key_id(), url, nonce);
    do_make(protected, key, Some(payload))
}

pub(crate) fn make_jws_jwk<T: Serialize + ?Sized>(
    url: &str,
    nonce: String,
    key: &AcmeKey,
    payload: Option<&T>,
) -> Result<String> {
    let jwk: Jwk = key.into();
    let protected = JwsProtected::new_jwk(jwk, url, nonce);
    do_make(protected, key, payload)
}

pub(crate) fn make_jws_kid_empty(url: &str, nonce: String, key: &AcmeKey) -> Result<String> {
    let protected = JwsProtected::new_kid(key.key_id(), url, nonce);
    do_make::<String>(protected, key, None)
}

fn do_make<T: Serialize + ?Sized>(
    protected: JwsProtected,
    key: &AcmeKey,
    payload: Option<&T>,
) -> Result<String> {
    let protected = {
        let pro_json = serde_json::to_string(&protected)?;
        base64url(pro_json.as_bytes())
    };
    let payload = if let Some(payload) = payload {
        let pay_json = serde_json::to_string(payload)?;
        base64url(pay_json.as_bytes())
    } else {
        "".into()
    };

    let to_sign = format!("{}.{}", protected, payload);
    let digest = sha256(to_sign.as_bytes());
    let sig = EcdsaSig::sign(&digest, key.private_key()).expect("EcdsaSig::sign");
    let r = sig.r().to_vec();
    let s = sig.s().to_vec();

    let mut v = Vec::with_capacity(r.len() + s.len());
    v.extend_from_slice(&r);
    v.extend_from_slice(&s);
    let signature = base64url(&v);

    let jws = Jws {
        protected,
        payload,
        signature,
    };

    Ok(serde_json::to_string(&jws)?)
}

pub(crate) fn key_authorization(token: &str, key: &AcmeKey, extra_sha256: bool) -> String {
    let jwk: Jwk = key.into();
    let jwk_thumb: JwkThumb = (&jwk).into();
    let jwk_json = serde_json::to_string(&jwk_thumb).expect("jwk_thumb");
    let digest = base64url(&sha256(jwk_json.as_bytes()));
    let key_auth = format!("{}.{}", token, digest);
    if extra_sha256 {
        base64url(&sha256(key_auth.as_bytes()))
    } else {
        key_auth
    }
}
