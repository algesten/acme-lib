use openssl::ecdsa::EcdsaSig;
use openssl::sha::sha256;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::acc::AcmeKey;
use crate::jwt::*;
use crate::req::{HttpClient, HttpResponse};
use crate::util::base64url;
use crate::Result;

/// JWS payload and nonce handling for requests to the API.
///
/// Setup is:
///
/// 1. `Transport::new()`
/// 2. `call_jwk()` against newAccount url
/// 3. `set_key_id` from the returned `Location` header.
/// 4. `call()` for all calls after that.
#[derive(Clone, Debug)]
pub(crate) struct Transport<H: HttpClient> {
    acme_key: AcmeKey,
    client: H,
    nonce_pool: Arc<NoncePool<H>>,
}

impl<H: HttpClient> Transport<H> {

    pub fn new_with(nonce_pool: &Arc<NoncePool<H>>, client: H, acme_key: AcmeKey) -> Self {
        Transport {
            acme_key,
            client,
            nonce_pool: nonce_pool.clone(),
        }
    }

    /// Update the key id once it is known (part of setting up the transport).
    pub fn set_key_id(&mut self, kid: String) {
        self.acme_key.set_key_id(kid);
    }

    /// The key used in the transport
    pub fn acme_key(&self) -> &AcmeKey {
        &self.acme_key
    }

    /// Make call using the full jwk. Only for the first newAccount request.
    pub fn call_jwk<T: Serialize + ?Sized>(&self, url: &str, body: &T) -> Result<impl HttpResponse> {
        self.do_call(url, body, jws_with_jwk)
    }

    /// Make call using the key id
    pub fn call<T: Serialize + ?Sized>(&self, url: &str, body: &T) -> Result<impl HttpResponse> {
        self.do_call(url, body, jws_with_kid)
    }

    fn do_call<T: Serialize + ?Sized, F: Fn(&str, String, &AcmeKey, &T) -> Result<String>>(
        &self,
        url: &str,
        body: &T,
        make_body: F,
    ) -> Result<impl HttpResponse> {
        // The ACME API may at any point invalidate all nonces. If we detect such an
        // error, we loop until the server accepts the nonce.
        loop {
            // Either get a new nonce, or reuse one from a previous request.
            let nonce = self.nonce_pool.get_nonce()?;

            // Sign the body.
            let body = make_body(url, nonce, &self.acme_key, body)?;

            debug!("Call endpoint {}", url);

            // Post it to the URL
            let response = self.client.post(url, &body);

            // Regardless of the request being a success or not, there might be
            // a nonce in the response.
            self.nonce_pool.extract_nonce(&response);

            // Turn errors into ApiProblem.
            let result = response.handle_errors();

            if let Err(problem) = &result {
                if problem.is_bad_nonce() {
                    // retry the request with a new nonce.
                    debug!("Retrying on bad nonce");
                    continue;
                }
                // it seems we sometimes make bad JWTs. Why?!
                if problem.is_jwt_verification_error() {
                    debug!("Retrying on: {}", problem);
                    continue;
                }
            }

            return Ok(result?);
        }
    }
}

/// Shared pool of nonces.
#[derive(Default, Debug)]
pub(crate) struct NoncePool<H: HttpClient> {
    nonce_url: String,
    client: H,
    pool: Mutex<VecDeque<String>>,
}

impl<H: HttpClient> NoncePool<H> {
    pub fn new(client: H, nonce_url: &str) -> Self {
        NoncePool {
            nonce_url: nonce_url.into(),
            client,
            pool: Default::default()
        }
    }

    fn extract_nonce(&self, res: &impl HttpResponse) {
        if let Ok(nonce) = res.header("replay-nonce") {
            trace!("Extract nonce");
            let mut pool = self.pool.lock().unwrap();
            pool.push_back(nonce.to_string());
            if pool.len() > 10 {
                pool.pop_front();
            }
        }
    }

    fn get_nonce(&self) -> Result<String> {
        {
            let mut pool = self.pool.lock().unwrap();
            if let Some(nonce) = pool.pop_front() {
                trace!("Use previous nonce");
                return Ok(nonce);
            }
        }
        debug!("Request new nonce");
        let res = self.client.head(&self.nonce_url);
        Ok(res.header("replay-nonce")?.to_string())
    }
}

fn jws_with_kid<T: Serialize + ?Sized>(
    url: &str,
    nonce: String,
    key: &AcmeKey,
    payload: &T,
) -> Result<String> {
    let protected = JwsProtected::new_kid(key.key_id(), url, nonce);
    jws_with(protected, key, payload)
}

fn jws_with_jwk<T: Serialize + ?Sized>(
    url: &str,
    nonce: String,
    key: &AcmeKey,
    payload: &T,
) -> Result<String> {
    let jwk: Jwk = key.into();
    let protected = JwsProtected::new_jwk(jwk, url, nonce);
    jws_with(protected, key, payload)
}

fn jws_with<T: Serialize + ?Sized>(
    protected: JwsProtected,
    key: &AcmeKey,
    payload: &T,
) -> Result<String> {
    let protected = {
        let pro_json = serde_json::to_string(&protected)?;
        base64url(pro_json.as_bytes())
    };
    let payload = {
        let pay_json = serde_json::to_string(payload)?;
        if pay_json == "\"\"" {
            // This is a special case produced by ApiEmptyString and should
            // not be further base64url encoded.
            "".to_string()
        } else {
            base64url(pay_json.as_bytes())
        }
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
