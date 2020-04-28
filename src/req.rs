use crate::api::ApiProblem;

pub(crate) type ReqResult<T> = std::result::Result<T, ApiProblem>;

pub(crate) fn req_get(url: &str) -> ureq::Response {
    let mut req = ureq::get(url);
    req_configure(&mut req);
    trace!("{:?}", req);
    req.call()
}

pub(crate) fn req_head(url: &str) -> ureq::Response {
    let mut req = ureq::head(url);
    req_configure(&mut req);
    trace!("{:?}", req);
    req.call()
}

pub(crate) fn req_post(url: &str, body: &str) -> ureq::Response {
    let mut req = ureq::post(url);
    req.set("content-type", "application/jose+json");
    req_configure(&mut req);
    trace!("{:?} {}", req, body);
    req.send_string(body)
}

fn req_configure(req: &mut ureq::Request) {
    req.timeout_connect(30_000);
    req.timeout_read(30_000);
    req.timeout_write(30_000);
}

pub(crate) fn req_handle_error(res: ureq::Response) -> ReqResult<ureq::Response> {
    // ok responses pass through
    if res.ok() {
        return Ok(res);
    }

    let problem = if res.content_type() == "application/problem+json" {
        // if we were sent a problem+json, deserialize it
        let body = req_safe_read_body(res);
        serde_json::from_str(&body).unwrap_or_else(|e| ApiProblem {
            _type: "problemJsonFail".into(),
            detail: Some(format!(
                "Failed to deserialize application/problem+json ({}) body: {}",
                e.to_string(),
                body
            )),
            subproblems: None,
        })
    } else {
        // some other problem
        let status = format!("{} {}", res.status(), res.status_text());
        let body = req_safe_read_body(res);
        let detail = format!("{} body: {}", status, body);
        ApiProblem {
            _type: "httpReqError".into(),
            detail: Some(detail),
            subproblems: None,
        }
    };

    Err(problem)
}

pub(crate) fn req_expect_header(res: &ureq::Response, name: &str) -> ReqResult<String> {
    res.header(name)
        .map(|v| v.to_string())
        .ok_or_else(|| ApiProblem {
            _type: format!("Missing header: {}", name),
            detail: None,
            subproblems: None,
        })
}

pub(crate) fn req_safe_read_body(res: ureq::Response) -> String {
    use std::io::Read;
    let mut res_body = String::new();
    let mut read = res.into_reader();
    // letsencrypt sometimes closes the TLS abruptly causing io error
    // even though we did capture the body.
    read.read_to_string(&mut res_body).ok();
    res_body
}
