use crate::api::ApiProblem;
use crate::req::{HttpClient, HttpResponse, HttpResult};

#[derive(Copy, Clone, Default)]
pub struct UReq;

impl HttpClient for UReq {
    type Response = ureq::Response;

    fn get(&self, url: &str) -> Self::Response {
        let mut req = ureq::get(url);
        Self::set_timeouts(&mut req);
        trace!("{:?}", req);
        req.call()
    }

    fn head(&self, url: &str) -> Self::Response {
        let mut req = ureq::head(url);
        Self::set_timeouts(&mut req);
        trace!("{:?}", req);
        req.call()
    }

    fn post(&self, url: &str, body: &str) -> Self::Response {
        let mut req = ureq::post(url);
        req.set("content-type", "application/jose+json");
        Self::set_timeouts(&mut req);
        trace!("{:?} {}", req, body);
        req.send_string(body)
    }
}

impl UReq {
    fn set_timeouts(req: &mut ureq::Request) {
        req.timeout_connect(30_000);
        req.timeout_read(30_000);
        req.timeout_write(30_000);
    }
}

impl HttpResponse for ureq::Response {
    fn body(self) -> String {
        use std::io::Read;
        let mut res_body = String::new();
        let mut read = self.into_reader();
        // letsencrypt sometimes closes the TLS abruptly causing io error
        // even though we did capture the body.
        read.read_to_string(&mut res_body).ok();
        res_body
    }

    fn header(&self, name: &str) -> HttpResult<&str> {
        self.header(name)
            .ok_or_else(|| ApiProblem {
                _type: format!("Missing header: {}", name),
                detail: None,
                subproblems: None,
            })
    }

    fn handle_errors(self) -> HttpResult<Self> {
        // ok responses pass through
        if self.ok() {
            return Ok(self);
        }

        let problem = if self.content_type() == "application/problem+json" {
            // if we were sent a problem+json, deserialize it
            let body = self.body();
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
            let status = format!("{} {}", self.status(), self.status_text());
            let body = self.body();
            let detail = format!("{} body: {}", status, body);
            ApiProblem {
                _type: "httpReqError".into(),
                detail: Some(detail),
                subproblems: None,
            }
        };

        Err(problem)
    }
}
