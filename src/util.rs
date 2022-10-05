use lazy_static::lazy_static;
use serde::de::DeserializeOwned;
use crate::req::HttpResponse;

use crate::Result;

lazy_static! {
    static ref BASE64_CONFIG: base64::Config =
        base64::Config::new(base64::CharacterSet::UrlSafe, false);
}

pub(crate) fn base64url<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::encode_config(input, *BASE64_CONFIG)
}

pub(crate) fn read_json<T: DeserializeOwned>(res: impl HttpResponse) -> Result<T> {
    let res_body = res.body();
    debug!("{}", res_body);
    Ok(serde_json::from_str(&res_body)?)
}
