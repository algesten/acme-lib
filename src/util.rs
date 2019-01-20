use lazy_static::lazy_static;
use serde::de::DeserializeOwned;
use std::io::Read;

use crate::{Error, Result};

lazy_static! {
    static ref BASE64_CONFIG: base64::Config =
        { base64::Config::new(base64::CharacterSet::UrlSafe, false) };
}

pub(crate) fn base64url<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::encode_config(input, *BASE64_CONFIG)
}

#[allow(unused)]
pub(crate) fn unbase64url(input: &str) -> Result<Vec<u8>> {
    base64::decode_config(input, *BASE64_CONFIG).map_err(Error::Base64Decode)
}

pub(crate) fn read_json<T: DeserializeOwned>(res: ureq::Response) -> Result<T> {
    let res_body = safe_read_string(res)?;
    debug!("{}", res_body);
    Ok(serde_json::from_str(&res_body)?)
}

fn safe_read_string(res: ureq::Response) -> Result<String> {
    let mut res_body = String::new();
    let mut read = res.into_reader();
    // letsencrypt sometimes closes the TLS abruptly causing io error
    // even though we did capture the body.
    read.read_to_string(&mut res_body).ok();
    Ok(res_body)
}

pub(crate) fn configure_req(req: &mut ureq::Request) {
    req.timeout_connect(30_000);
    req.timeout_read(30_000);
    req.timeout_write(30_000);
}

pub(crate) fn retry_call<F: Fn() -> Result<(ureq::Request, Option<String>)>>(
    f: F,
) -> Result<ureq::Response> {
    let mut i = 0;
    loop {
        let (mut req, body) = f()?;
        i += 1;
        configure_req(&mut req);
        let res = if let Some(body) = body {
            trace!("{:?}: {}", req, body);
            req.send_string(&body)
        } else {
            trace!("{:?}", req);
            req.call()
        };
        if res.ok() {
            trace!("Status: {}", res.status());
            return Ok(res);
        }
        trace!("{:?}", res);
        if i == 3 || res.status() == 400 {
            trace!("No more retries");
            let status = res.status();
            let res_body = safe_read_string(res)?;
            return Err(Error::Call(format!(
                "Call failed ({}): {}",
                status, res_body
            )));
        }
        trace!("Retry call");
    }
}

pub(crate) fn expect_header(res: &ureq::Response, name: &str) -> Result<String> {
    res.header(name)
        .map(|v| v.to_string())
        .ok_or_else(|| format!("Missing header: {}", name).into())
}
