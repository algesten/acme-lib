use ureq::{http, Body};

use crate::api::ApiProblem;

pub(crate) type ReqResult<T> = std::result::Result<T, ApiProblem>;

const TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) fn req_get(url: &str) -> Result<http::Response<Body>, ureq::Error> {
    let req = ureq::get(url)
        .config()
        .timeout_global(Some(TIMEOUT_DURATION))
        .http_status_as_error(false)
        .build();
    trace!("{:?}", req);
    req.call()
}

pub(crate) fn req_head(url: &str) -> Result<http::Response<Body>, ureq::Error> {
    let req = ureq::head(url)
        .config()
        .timeout_global(Some(TIMEOUT_DURATION))
        .http_status_as_error(false)
        .build();
    trace!("{:?}", req);
    req.call()
}

pub(crate) fn req_post(url: &str, body: &str) -> Result<http::Response<Body>, ureq::Error> {
    let req = ureq::post(url)
        .header("content-type", "application/jose+json")
        .config()
        .timeout_global(Some(TIMEOUT_DURATION))
        .http_status_as_error(false)
        .build();
    trace!("{:?} {}", req, body);
    req.send(body)
}

pub(crate) fn req_handle_error(
    res: Result<http::Response<Body>, ureq::Error>,
) -> ReqResult<http::Response<Body>> {
    let res = match res {
        // ok responses pass through
        Ok(res) => res,
        Err(e) => {
            return Err(ApiProblem {
                _type: "httpReqError".into(),
                detail: Some(e.to_string()),
                subproblems: None,
            })
        }
    };

    if res.status().is_success() {
        return Ok(res);
    }

    let problem = if res.body().mime_type() == Some("application/problem+json") {
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
        let status = format!(
            "{} {}",
            res.status(),
            res.status().canonical_reason().unwrap_or_default()
        );
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

pub(crate) fn req_expect_header(res: &http::Response<Body>, name: &str) -> ReqResult<String> {
    res.headers()
        .get(name)
        .map(|v| v.to_str().unwrap_or_default())
        .ok_or_else(|| ApiProblem {
            _type: format!("Missing header: {}", name),
            detail: None,
            subproblems: None,
        })
        .map(|v| v.to_string())
}

pub(crate) fn req_safe_read_body(mut res: http::Response<Body>) -> String {
    // letsencrypt sometimes closes the TLS abruptly causing io error
    // even though we did capture the body.
    let res_body = res.body_mut().read_to_string().unwrap_or_default();
    res_body
}
