//
use openssl::sha::sha256;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::acc::AccountInner;
use crate::acc::AcmeKey;
use crate::api::{ApiAuth, ApiChallenge, ApiEmptyObject, ApiEmptyString};
use crate::jwt::*;
use crate::persist::Persist;
use crate::util::{base64url, read_json};
use crate::Result;

/// An authorization ([ownership proof]) for a domain name.
///
/// Each authorization for an order much be progressed to a valid state before the ACME API
/// will issue a certificate.
///
/// Authorizations may or may not be required depending on previous orders against the same
/// ACME account. The ACME API decides if the authorization is needed.
///
/// Currently there are two ways of providing the authorization.
///
/// * In a text file served using [HTTP] from a web server of the domain being authorized.
/// * A `TXT` [DNS] record under the domain being authorized.
///
/// [ownership proof]: ../index.html#domain-ownership
/// [HTTP]: #method.http_challenge
/// [DNS]: #method.dns_challenge
#[derive(Debug)]
pub struct Auth<P: Persist> {
    inner: Arc<AccountInner<P>>,
    api_auth: ApiAuth,
    auth_url: String,
}

impl<P: Persist> Auth<P> {
    pub(crate) fn new(inner: &Arc<AccountInner<P>>, api_auth: ApiAuth, auth_url: &str) -> Self {
        Auth {
            inner: inner.clone(),
            api_auth,
            auth_url: auth_url.into(),
        }
    }

    /// Domain name for this authorization.
    pub fn domain_name(&self) -> &str {
        &self.api_auth.identifier.value
    }

    /// Whether we actually need to do the authorization. This might not be needed if we have
    /// proven ownership of the domain recently in a previous order.
    pub fn need_challenge(&self) -> bool {
        !self.api_auth.is_status_valid()
    }

    /// Get the http challenge.
    ///
    /// The http challenge must be placed so it is accessible under:
    ///
    /// ```text
    /// http://<domain-to-be-proven>/.well-known/acme-challenge/<token>
    /// ```
    ///
    /// The challenge will be accessed over HTTP (not HTTPS), for obvious reasons.
    ///
    /// ```no_run
    /// use acme_lib::persist::Persist;
    /// use acme_lib::order::Auth;
    /// use acme_lib::Error;
    /// use std::fs::File;
    /// use std::io::Write;
    ///
    /// fn web_authorize<P: Persist>(auth: &Auth<P>) -> Result<(), Error> {
    ///   let challenge = auth.http_challenge();
    ///   // Assuming our web server's root is under /var/www
    ///   let path = {
    ///     let token = challenge.http_token();
    ///     format!("/var/www/.well-known/acme-challenge/{}", token)
    ///   };
    ///   let mut file = File::create(&path)?;
    ///   file.write_all(challenge.http_proof().as_bytes())?;
    ///   challenge.validate(5000)?;
    ///   Ok(())
    /// }
    /// ```
    pub fn http_challenge(&self) -> Challenge<P, Http> {
        self.api_auth
            .http_challenge()
            .map(|c| Challenge::new(&self.inner, c.clone(), &self.auth_url))
            .expect("http-challenge")
    }

    /// Get the dns challenge.
    ///
    /// The dns challenge is a `TXT` record that must put created under:
    ///
    /// ```text
    /// _acme-challenge.<domain-to-be-proven>.  TXT  <proof>
    /// ```
    ///
    /// The <proof> contains the signed token proving this account update it.
    ///
    /// ```no_run
    /// use acme_lib::persist::Persist;
    /// use acme_lib::order::Auth;
    /// use acme_lib::Error;
    ///
    /// fn dns_authorize<P: Persist>(auth: &Auth<P>) -> Result<(), Error> {
    ///   let challenge = auth.dns_challenge();
    ///   let record = format!("_acme-challenge.{}.", auth.domain_name());
    ///   // route_53_set_record(&record, "TXT", challenge.dns_proof());
    ///   challenge.validate(5000)?;
    ///   Ok(())
    /// }
    /// ```
    ///
    /// The dns proof is not the same as the http proof.
    pub fn dns_challenge(&self) -> Challenge<P, Dns> {
        self.api_auth
            .dns_challenge()
            .map(|c| Challenge::new(&self.inner, c.clone(), &self.auth_url))
            .expect("dns-challenge")
    }

    /// Get the TLS ALPN challenge.
    ///
    /// The TLS ALPN challenge is a certificate that must be served when a
    /// request is made for the ALPN protocol "tls-alpn-01". The certificate
    /// must contain a single dNSName SAN containing the domain being
    /// validated, as well as an ACME extension containing the SHA256 of the
    /// key authorization.
    pub fn tls_alpn_challenge(&self) -> Challenge<P, TlsAlpn> {
        self.api_auth
            .tls_alpn_challenge()
            .map(|c| Challenge::new(&self.inner, c.clone(), &self.auth_url))
            .expect("tls-alpn-challenge")
    }

    /// Access the underlying JSON object for debugging. We don't
    /// refresh the authorization when the corresponding challenge is validated,
    /// so there will be no changes to see here.
    pub fn api_auth(&self) -> &ApiAuth {
        &self.api_auth
    }
}

/// Marker type for http challenges.
#[doc(hidden)]
pub struct Http;

/// Marker type for dns challenges.
#[doc(hidden)]
pub struct Dns;

/// Marker type for tls alpn challenges.
#[doc(hidden)]
pub struct TlsAlpn;

/// A DNS, HTTP, or TLS-ALPN challenge as obtained from the [`Auth`].
///
/// [`Auth`]: struct.Auth.html
pub struct Challenge<P: Persist, A> {
    inner: Arc<AccountInner<P>>,
    api_challenge: ApiChallenge,
    auth_url: String,
    _ph: std::marker::PhantomData<A>,
}

impl<P: Persist> Challenge<P, Http> {
    /// The `token` is a unique identifier of the challenge. It is the file name in the
    /// http challenge like so:
    ///
    /// ```text
    /// http://<domain-to-be-proven>/.well-known/acme-challenge/<token>
    /// ```
    pub fn http_token(&self) -> &str {
        &self.api_challenge.token
    }

    /// The `proof` is some text content that is placed in the file named by `token`.
    pub fn http_proof(&self) -> String {
        let acme_key = self.inner.transport.acme_key();
        key_authorization(&self.api_challenge.token, acme_key, false)
    }
}

impl<P: Persist> Challenge<P, Dns> {
    /// The `proof` is the `TXT` record placed under:
    ///
    /// ```text
    /// _acme-challenge.<domain-to-be-proven>.  TXT  <proof>
    /// ```
    pub fn dns_proof(&self) -> String {
        let acme_key = self.inner.transport.acme_key();
        key_authorization(&self.api_challenge.token, acme_key, true)
    }
}

impl<P: Persist> Challenge<P, TlsAlpn> {
    /// The `proof` is the contents of the ACME extension to be placed in the
    /// certificate used for validation.
    pub fn tls_alpn_proof(&self) -> [u8; 32] {
        let acme_key = self.inner.transport.acme_key();
        sha256(key_authorization(&self.api_challenge.token, acme_key, false).as_bytes())
    }
}

impl<P: Persist, A> Challenge<P, A> {
    fn new(inner: &Arc<AccountInner<P>>, api_challenge: ApiChallenge, auth_url: &str) -> Self {
        Challenge {
            inner: inner.clone(),
            api_challenge,
            auth_url: auth_url.into(),
            _ph: std::marker::PhantomData,
        }
    }

    /// Check whether this challlenge really need validation. It might already been
    /// done in a previous order for the same account.
    pub fn need_validate(&self) -> bool {
        self.api_challenge.is_status_pending()
    }

    /// Tell the ACME API to attempt validating the proof of this challenge.
    ///
    /// The user must first update the DNS record or HTTP web server depending
    /// on the type challenge being validated.
    pub fn validate(self, delay_millis: u64) -> Result<()> {
        let url_chall = &self.api_challenge.url;
        let res = self.inner.transport.call(url_chall, &ApiEmptyObject)?;
        let _: ApiChallenge = read_json(res)?;

        let auth = wait_for_auth_status(&self.inner, &self.auth_url, delay_millis)?;

        if !auth.is_status_valid() {
            let error = auth
                .challenges
                .iter()
                .filter_map(|c| c.error.as_ref())
                .next();
            let reason = if let Some(error) = error {
                format!(
                    "Failed: {}",
                    error.detail.clone().unwrap_or_else(|| error._type.clone())
                )
            } else {
                "Validation failed and no error found".into()
            };
            return Err(reason.into());
        }

        Ok(())
    }

    /// Access the underlying JSON object for debugging.
    pub fn api_challenge(&self) -> &ApiChallenge {
        &self.api_challenge
    }
}

fn key_authorization(token: &str, key: &AcmeKey, extra_sha256: bool) -> String {
    let jwk: Jwk = key.into();
    let jwk_thumb: JwkThumb = (&jwk).into();
    let jwk_json = serde_json::to_string(&jwk_thumb).expect("jwk_thumb");
    let digest = base64url(&sha256(jwk_json.as_bytes()));
    let key_auth = format!("{}.{}", token, digest);
    if extra_sha256 {
        base64url(&sha256(key_auth.as_bytes()))
    } else {
        key_auth
    }
}

fn wait_for_auth_status<P: Persist>(
    inner: &Arc<AccountInner<P>>,
    auth_url: &str,
    delay_millis: u64,
) -> Result<ApiAuth> {
    let auth = loop {
        let res = inner.transport.call(auth_url, &ApiEmptyString)?;
        let auth: ApiAuth = read_json(res)?;
        if !auth.is_status_pending() {
            break auth;
        }
        thread::sleep(Duration::from_millis(delay_millis));
    };
    Ok(auth)
}

#[cfg(test)]
mod test {
    use crate::persist::*;
    use crate::*;

    #[test]
    fn test_get_challenges() -> Result<()> {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, url)?;
        let acc = dir.account("foo@bar.com")?;
        let ord = acc.new_order("acmetest.example.com", &[])?;
        let authz = ord.authorizations()?;
        assert!(authz.len() == 1);
        let auth = &authz[0];
        {
            let http = auth.http_challenge();
            assert!(http.need_validate());
        }
        {
            let dns = auth.dns_challenge();
            assert!(dns.need_validate());
        }
        Ok(())
    }
}
