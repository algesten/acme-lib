use base64::Engine;
use openssl::bn::BigNumRef;
use serde::de::DeserializeOwned;
use ureq::{http, Body};

use crate::req::req_safe_read_body;
use crate::Result;

pub(crate) const P256_COMPONENT_LENGTH: usize = 32;

pub(crate) fn base64url<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(input)
}

pub(crate) fn p256_component_bytes(value: &BigNumRef) -> [u8; P256_COMPONENT_LENGTH] {
    let value = value.to_vec();
    let mut encoded = [0; P256_COMPONENT_LENGTH];

    for (source, destination) in value.iter().rev().zip(encoded.iter_mut().rev()) {
        *destination = *source;
    }

    encoded
}

pub(crate) fn read_json<T: DeserializeOwned>(res: http::Response<Body>) -> Result<T> {
    let res_body = req_safe_read_body(res);
    debug!("{}", res_body);
    Ok(serde_json::from_str(&res_body)?)
}
