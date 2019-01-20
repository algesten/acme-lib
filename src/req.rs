#![allow(unused)]
use openssl::ecdsa::EcdsaSig;
use openssl::sha::sha256;
use serde::{Deserialize, Serialize};

use crate::acc::AcmeKey;
use crate::cert::EC_GROUP_P256;
use crate::jwt::*;
use crate::util::base64url;
use crate::Result;

fn make_jws_kid<T: Serialize + ?Sized>(
    url: &str,
    nonce: String,
    key: &AcmeKey,
    payload: &T,
) -> Result<String> {
    let protected = JwsProtected::new_kid(key.key_id(), url, nonce);
    do_make(protected, key, Some(payload))
}

fn make_jws_kid_empty(url: &str, nonce: String, key: &AcmeKey) -> Result<String> {
    let protected = JwsProtected::new_kid(key.key_id(), url, nonce);
    do_make::<String>(protected, key, None)
}

fn make_jws_jwk<T: Serialize + ?Sized>(
    url: &str,
    nonce: String,
    key: &AcmeKey,
    payload: &T,
) -> Result<String> {
    let jwk: Jwk = key.into();
    let protected = JwsProtected::new_jwk(jwk, url, nonce);
    do_make(protected, key, Some(payload))
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

    let jws = Jws::new(protected, payload, signature);

    Ok(serde_json::to_string(&jws)?)
}
