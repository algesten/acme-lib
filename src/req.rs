use crate::api::ApiProblem;

pub(crate) type ReqResult<T> = std::result::Result<T, ApiProblem>;

const TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) fn req_get(url: &str) -> Result<ureq::Response, ureq::Error> {
    let req = ureq::get(url).timeout(TIMEOUT_DURATION);
    trace!("{:?}", req);
    req.call()
}

pub(crate) fn req_head(url: &str) -> Result<ureq::Response, ureq::Error> {
    let req = ureq::head(url).timeout(TIMEOUT_DURATION);
    trace!("{:?}", req);
    req.call()
}

pub(crate) fn req_post(url: &str, body: &str) -> Result<ureq::Response, ureq::Error> {
    let req = ureq::post(url)
        .set("content-type", "application/jose+json")
        .timeout(TIMEOUT_DURATION);
    trace!("{:?} {}", req, body);
    req.send_string(body)
}

pub(crate) fn req_handle_error(
    res: Result<ureq::Response, ureq::Error>,
) -> ReqResult<ureq::Response> {
    let res = match res {
        // ok responses pass through
        Ok(res) => return Ok(res),
        Err(ureq::Error::Status(_, res)) => res,
        Err(ureq::Error::Transport(_)) => {
            return Err(ApiProblem {
                _type: "httpReqError".into(),
                detail: Some("Transport error".into()),
                subproblems: None,
            })
        }
    };

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
