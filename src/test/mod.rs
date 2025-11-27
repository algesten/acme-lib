#![allow(clippy::trivial_regex)]

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

static RE_URL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();

fn re_url() -> &'static regex::Regex {
    RE_URL.get_or_init(|| regex::Regex::new("<URL>").unwrap())
}

pub struct TestServer {
    pub dir_url: String,
    shutdown: Arc<AtomicBool>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread_handle.take() {
            handle.join().ok();
        }
    }
}

fn get_directory(url: &str) -> String {
    const BODY: &str = r#"{
    "keyChange": "<URL>/acme/key-change",
    "newAccount": "<URL>/acme/new-acct",
    "newNonce": "<URL>/acme/new-nonce",
    "newOrder": "<URL>/acme/new-order",
    "revokeCert": "<URL>/acme/revoke-cert",
    "meta": {
        "caaIdentities": [
        "testdir.org"
        ]
    }
    }"#;
    re_url().replace_all(BODY, url).to_string()
}

fn head_new_nonce() -> (u16, Vec<(&'static str, &'static str)>, String) {
    (
        204,
        vec![("Replay-Nonce", "8_uBBV3N2DBRJczhoiB46ugJKUkUHxGzVe6xIMpjHFM")],
        String::new(),
    )
}

fn post_new_acct(url: &str) -> (u16, Vec<(String, String)>, String) {
    const BODY: &str = r#"{
    "id": 7728515,
    "key": {
        "use": "sig",
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "x": "ttpobTRK2bw7ttGBESRO7Nb23mbIRfnRZwunL1W6wRI",
        "y": "h2Z00J37_2qRKH0-flrHEsH0xbit915Tyvd2v_CAOSk"
    },
    "contact": [
        "mailto:foo@bar.com"
    ],
    "initialIp": "90.171.37.12",
    "createdAt": "2018-12-31T17:15:40.399104457Z",
    "status": "valid"
    }"#;
    let location = re_url()
        .replace_all("<URL>/acme/acct/7728515", url)
        .to_string();
    (
        201,
        vec![("Location".to_string(), location)],
        BODY.to_string(),
    )
}

fn post_new_order(url: &str) -> (u16, Vec<(String, String)>, String) {
    const BODY: &str = r#"{
    "status": "pending",
    "expires": "2019-01-09T08:26:43.570360537Z",
    "identifiers": [
        {
        "type": "dns",
        "value": "acmetest.example.com"
        }
    ],
    "authorizations": [
        "<URL>/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs"
    ],
    "finalize": "<URL>/acme/finalize/7738992/18234324"
    }"#;
    let location = re_url()
        .replace_all("<URL>/acme/order/YTqpYUthlVfwBncUufE8", url)
        .to_string();
    let body = re_url().replace_all(BODY, url).to_string();
    (201, vec![("Location".to_string(), location)], body)
}

fn post_get_order(url: &str) -> (u16, Vec<(String, String)>, String) {
    const BODY: &str = r#"{
    "status": "<STATUS>",
    "expires": "2019-01-09T08:26:43.570360537Z",
    "identifiers": [
        {
        "type": "dns",
        "value": "acmetest.example.com"
        }
    ],
    "authorizations": [
        "<URL>/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs"
    ],
    "finalize": "<URL>/acme/finalize/7738992/18234324",
    "certificate": "<URL>/acme/cert/fae41c070f967713109028"
    }"#;
    let body = re_url().replace_all(BODY, url).to_string();
    (200, vec![], body)
}

fn post_authz(url: &str) -> (u16, Vec<(String, String)>, String) {
    const BODY: &str = r#"{
        "identifier": {
            "type": "dns",
            "value": "acmetest.algesten.se"
        },
        "status": "pending",
        "expires": "2019-01-09T08:26:43Z",
        "challenges": [
        {
            "type": "http-01",
            "status": "pending",
            "url": "<URL>/acme/challenge/YTqpYUthlVfwBncUufE8IRWLMSRqcSs/216789597",
            "token": "MUi-gqeOJdRkSb_YR2eaMxQBqf6al8dgt_dOttSWb0w"
        },
        {
            "type": "tls-alpn-01",
            "status": "pending",
            "url": "<URL>/acme/challenge/YTqpYUthlVfwBncUufE8IRWLMSRqcSs/216789598",
            "token": "WCdRWkCy4THTD_j5IH4ISAzr59lFIg5wzYmKxuOJ1lU"
        },
        {
            "type": "dns-01",
            "status": "pending",
            "url": "<URL>/acme/challenge/YTqpYUthlVfwBncUufE8IRWLMSRqcSs/216789599",
            "token": "RRo2ZcXAEqxKvMH8RGcATjSK1KknLEUmauwfQ5i3gG8"
        }
        ]
    }"#;
    let body = re_url().replace_all(BODY, url).to_string();
    (201, vec![], body)
}

fn post_finalize(_url: &str) -> (u16, Vec<(String, String)>, String) {
    (200, vec![], String::new())
}

fn post_certificate(_url: &str) -> (u16, Vec<(String, String)>, String) {
    (200, vec![], "CERT HERE".to_string())
}

fn route_request(
    method: &str,
    path: &str,
    url: &str,
) -> (u16, Vec<(String, String)>, String) {
    match (method, path) {
        ("GET", "/directory") => (200, vec![], get_directory(url)),
        ("HEAD", "/acme/new-nonce") => {
            let (status, headers, body) = head_new_nonce();
            (
                status,
                headers.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
                body,
            )
        }
        ("POST", "/acme/new-acct") => post_new_acct(url),
        ("POST", "/acme/new-order") => post_new_order(url),
        ("POST", "/acme/order/YTqpYUthlVfwBncUufE8") => post_get_order(url),
        ("POST", "/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs") => post_authz(url),
        ("POST", "/acme/finalize/7738992/18234324") => post_finalize(url),
        ("POST", "/acme/cert/fae41c070f967713109028") => post_certificate(url),
        _ => (404, vec![], String::new()),
    }
}

pub fn with_directory_server() -> TestServer {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();

    let url = format!("http://127.0.0.1:{}", port);
    let dir_url = format!("{}/directory", url);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    let handle = thread::spawn(move || {
        let server = tiny_http::Server::from_listener(tcp, None).unwrap();

        while !shutdown_clone.load(Ordering::SeqCst) {
            let request = match server.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(Some(req)) => req,
                Ok(None) => continue,
                Err(_) => break,
            };

            let method = request.method().as_str();
            let path = request.url();
            let (status, headers, body) = route_request(method, path, &url);

            let mut response = tiny_http::Response::from_string(body).with_status_code(status);

            for (key, value) in headers {
                if let Ok(header) = tiny_http::Header::from_bytes(key.as_bytes(), value.as_bytes())
                {
                    response.add_header(header);
                }
            }

            let _ = request.respond(response);
        }
    });

    TestServer {
        dir_url,
        shutdown,
        thread_handle: Some(handle),
    }
}

#[test]
pub fn test_make_directory() {
    let server = with_directory_server();
    let res = ureq::get(&server.dir_url).call();
    assert!(res.is_ok());
}
