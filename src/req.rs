use crate::api::ApiProblem;

extern crate reqwest;

pub(crate) type ReqResult<T> = std::result::Result<T, ApiProblem>;

pub(crate) fn req_get(client: &reqwest::Client, url: &str) -> reqwest::Result<reqwest::Response> {
    let resp = client.get(url).send();
    trace!("{:#?}", resp);
    resp
}

pub(crate) fn req_head(client: &reqwest::Client, url: &str) -> reqwest::Result<reqwest::Response> {
    let resp= client.head(url).send();
    trace!("{:?}", resp);
    resp
}

pub(crate) fn req_post(client: &reqwest::Client, url: &str, body: &str) -> reqwest::Result<reqwest::Response> {
    let req= client.post(url)
        .header("content-type", "application/jose+json")
        .body(body.to_string());
    let resp = req.send();
    trace!("{:?} {}", resp, body);
    resp
}

/*
fn req_configure(req: &mut ureq::Request) {
    req.timeout_connect(30_000);
    req.timeout_read(30_000);
    req.timeout_write(30_000);
}
*/

pub(crate) fn req_handle_error(res: reqwest::Result<reqwest::Response>) -> ReqResult<reqwest::Response> {
    match res {
        Ok(res) => Ok(res),
        Err(err) => Err(ApiProblem{
            _type: "reqwest".to_string(),
            detail: Some(err.to_string()),
            subproblems: None
        })
    }
}

pub(crate) fn req_expect_header(res: &reqwest::Response, name: &str) -> ReqResult<String> {
    match res.headers().get(name) {
        Some(header) => match header.to_str() {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Err(ApiProblem {
                _type: format!("to_str failed for header: {}", name),
                detail: None,
                subproblems: None
            })
        },
        None => Err(ApiProblem {
            _type: format!("Missing header: {}", name),
            detail: None,
            subproblems: None,
        })
    }
}

pub(crate) fn req_safe_read_body(res: &mut reqwest::Response) -> String {
    match res.text() {
        Ok(s) => s.to_string(),
        Err(_) => String::new()
    }
}
