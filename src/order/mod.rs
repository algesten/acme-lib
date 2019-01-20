//! Order life cycle.
//!
//! An order goes through a life cycle of different states that require various actions by
//! the user. To ensure the user only use appropriate actions, this library have simple façade
//! structs that wraps the actual [`ApiOrder`].
//!
//! 1. First prove ownership:
//!    * [`NewOrder`] -> [`Auth`]* -> [`Challenge`]
//! 2. Then submit CSR and download the cert.
//!    * [`NewOrder`] -> [`CsrOrder`] -> [`CertOrder`]
//!
//! \* Possibly multiple auths.
//!
//! [`ApiOrder`]: ../api/struct.ApiOrder.html
//! [`NewOrder`]: struct.NewOrder.html
//! [`Auth`]: struct.Auth.html
//! [`Challenge`]: struct.Challenge.html
//! [`CsrOrder`]: struct.CsrOrder.html
//! [`CertOrder`]: struct.CertOrder.html
use openssl::pkey::{self, PKey};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::acc::AccountInner;
use crate::api::{ApiAuth, ApiEmptyString, ApiFinalize, ApiOrder};
use crate::cert::{create_csr, Certificate};
use crate::persist::{Persist, PersistKey, PersistKind};
use crate::util::{base64url, read_json};
use crate::Result;

mod auth;

pub use self::auth::{Auth, Challenge};

/// The order wrapped with an outer façade.
pub(crate) struct Order<P: Persist> {
    inner: Arc<AccountInner<P>>,
    api_order: ApiOrder,
    url: String,
}

impl<P: Persist> Order<P> {
    pub(crate) fn new(inner: &Arc<AccountInner<P>>, api_order: ApiOrder, url: String) -> Self {
        Order {
            inner: inner.clone(),
            api_order,
            url,
        }
    }
}

/// Helper to refresh an order status (POST-as-GET).
pub(crate) fn refresh_order<P: Persist>(
    inner: &Arc<AccountInner<P>>,
    url: String,
    want_status: &'static str,
) -> Result<Order<P>> {
    let res = inner.transport.call(&url, &ApiEmptyString)?;

    // our test rig requires the order to be in `want_status`.
    // api_order_of is different for test compilation
    let api_order = api_order_of(res, want_status)?;

    Ok(Order {
        inner: inner.clone(),
        api_order,
        url,
    })
}

#[cfg(not(test))]
fn api_order_of(res: ureq::Response, _want_status: &str) -> Result<ApiOrder> {
    read_json(res)
}

#[cfg(test)]
// our test rig requires the order to be in `want_status`
fn api_order_of(res: ureq::Response, want_status: &str) -> Result<ApiOrder> {
    let s = res.into_string()?;
    #[allow(clippy::trivial_regex)]
    let re = regex::Regex::new("<STATUS>").unwrap();
    let b = re.replace_all(&s, want_status).to_string();
    let api_order: ApiOrder = serde_json::from_str(&b)?;
    Ok(api_order)
}

/// A new order created by [`Account::new_order`].
///
/// An order is created using one or many domains (a primary `CN` and possible multiple
/// alt names). All domains in the order must have authorizations ([confirmed ownership])
/// before the order can progress to submitting a [CSR].
///
/// This order façade provides calls to provide such authorizations and to progress the order
/// when ready.
///
/// The ACME API provider might "remember" for a time that you already own a domain, which
/// means you might not need to prove the ownership every time. Use appropriate methods to
/// first check whether you really need to handle authorizations.
///
/// [`Account::new_order`]: ../struct.Account.html#method.new_order
/// [confirmed ownership]: ../index.html#domain-ownership
/// [CSR]: https://en.wikipedia.org/wiki/Certificate_signing_request
pub struct NewOrder<P: Persist> {
    pub(crate) order: Order<P>,
}

impl<P: Persist> NewOrder<P> {
    /// Tell if the domains in this order have been authorized.
    ///
    /// This doesn't do any calls against the API. You must manually call [`refresh`].
    ///
    /// In ACME API terms, the order can either be `ready` or `valid`, which both would
    /// mean we have passed the authorization stage.
    ///
    /// [`refresh`]: struct.NewOrder.html#method.refresh
    pub fn is_validated(&self) -> bool {
        self.order.api_order.is_status_ready() || self.order.api_order.is_status_valid()
    }

    /// If the order [`is_validated`] progress it to a [`CsrOrder`].
    ///
    /// This doesn't do any calls against the API. You must manually call [`refresh`].
    ///
    /// [`is_validated`]: struct.NewOrder.html#method.is_validated
    /// [`CsrOrder`]: struct.CsrOrder.html
    pub fn confirm_validations(&self) -> Option<CsrOrder<P>> {
        if self.is_validated() {
            Some(CsrOrder {
                order: Order::new(
                    &self.order.inner,
                    self.order.api_order.clone(),
                    self.order.url.clone(),
                ),
            })
        } else {
            None
        }
    }

    /// Refresh the order state against the ACME API.
    ///
    /// The specification calls this a "POST-as-GET" against the order URL.
    pub fn refresh(&mut self) -> Result<()> {
        let order = refresh_order(&self.order.inner, self.order.url.clone(), "ready")?;
        self.order = order;
        Ok(())
    }

    /// Provide the authorizations. The number of authorizations will be the same as
    /// the number of domains requests, i.e. at least one (the primary CN), but possibly
    /// more (for alt names).
    ///
    /// If the order includes new domain names that have not been authorized before, this
    /// list might contain a mix of already valid and not yet valid auths.
    pub fn authorizations(&self) -> Result<Vec<Auth<P>>> {
        let mut result = vec![];
        if let Some(authorizations) = &self.order.api_order.authorizations {
            for auth_url in authorizations {
                let res = self.order.inner.transport.call(auth_url, &ApiEmptyString)?;
                let api_auth: ApiAuth = read_json(res)?;
                result.push(Auth::new(&self.order.inner, api_auth, auth_url));
            }
        }
        Ok(result)
    }

    /// Access the underlying JSON object for debugging.
    pub fn api_order(&self) -> &ApiOrder {
        &self.order.api_order
    }
}

/// An order that is ready for a [CSR] submission.
///
/// To submit the CSR is called "finalizing" the order.
///
/// To finalize, the user supplies a private and public key pair. This library provides
/// [functions to create key pairs], but the user can opt for creating them in some other way.
///
/// This library makes no attempt at validating which key algorithms are used. Unsupported
/// algorithms will show as an error when finalizing the order. It is up to the ACME API
/// provider to decide which key algorithms to support.
///
/// Right now Let's Encrypt [supports]:
///
/// * RSA keys from 2048 to 4096 bits in length
/// * P-256 and P-384 ECDSA keys
///
/// [CSR]: https://en.wikipedia.org/wiki/Certificate_signing_request
/// [functions to create key pairs]: ../index.html#functions
/// [supports]: https://letsencrypt.org/docs/integration-guide/#supported-key-algorithms
pub struct CsrOrder<P: Persist> {
    pub(crate) order: Order<P>,
}

impl<P: Persist> CsrOrder<P> {
    /// Finalize the order by providing a private and public key pair as PEM.
    ///
    /// Once the CSR has been submitted, the order goes into a `processing` status,
    /// where we must poll until the status changes. The `delay_millis` is the
    /// amount of time to wait between each poll attempt.
    ///
    /// This is a convenience wrapper that in turn calls the lower level [`finalize_pkey`].
    ///
    /// [`finalize_pkey`]: struct.CsrOrder.html#method.finalize_pkey
    pub fn finalize(
        self,
        private_key_pem: &str,
        public_key_pem: &str,
        delay_millis: u64,
    ) -> Result<CertOrder<P>> {
        let pkey_pri = PKey::private_key_from_pem(private_key_pem.as_bytes())
            .map_err(|e| format!("Error reading private key PEM: {}", e))?;
        let pkey_pub = PKey::public_key_from_pem(public_key_pem.as_bytes())
            .map_err(|e| format!("Error reading public key PEM: {}", e))?;
        self.finalize_pkey(pkey_pri, pkey_pub, delay_millis)
    }

    /// Lower level finalize call that works directly with the openssl crate structures.
    ///
    /// Creates the CSR for the domains in the order and submit it to the ACME API.
    ///
    /// Once the CSR has been submitted, the order goes into a `processing` status,
    /// where we must poll until the status changes. The `delay_millis` is the
    /// amount of time to wait between each poll attempt.
    pub fn finalize_pkey(
        self,
        private_key: PKey<pkey::Private>,
        public_key: PKey<pkey::Public>,
        delay_millis: u64,
    ) -> Result<CertOrder<P>> {
        //
        // the domains that we have authorized
        let domains = self.order.api_order.domains();

        // csr from private key and authorized domains.
        let csr = create_csr(&private_key, &public_key, &domains)?;

        // this is not the same as PEM.
        let csr_der = csr.to_der().expect("to_der()");
        let csr_enc = base64url(&csr_der);
        let finalize = ApiFinalize { csr: csr_enc };

        let inner = self.order.inner;
        let order_url = self.order.url;
        let finalize_url = &self.order.api_order.finalize;

        // if the CSR is invalid, we will get a 4xx code back that
        // bombs out from this retry_call.
        inner.transport.call(finalize_url, &finalize)?;

        // wait for the status to not be processing.
        // valid -> cert is issued
        // invalid -> the whole thing is off
        let order = wait_for_order_status(&inner, &order_url, delay_millis)?;

        if !order.api_order.is_status_valid() {
            return Err(format!("Order is in status: {:?}", order.api_order.status).into());
        }

        Ok(CertOrder { private_key, order })
    }

    /// Access the underlying JSON object for debugging.
    pub fn api_order(&self) -> &ApiOrder {
        &self.order.api_order
    }
}

fn wait_for_order_status<P: Persist>(
    inner: &Arc<AccountInner<P>>,
    url: &str,
    delay_millis: u64,
) -> Result<Order<P>> {
    loop {
        let order = refresh_order(inner, url.to_string(), "valid")?;
        if !order.api_order.is_status_processing() {
            return Ok(order);
        }
        thread::sleep(Duration::from_millis(delay_millis));
    }
}

/// Order for an issued certificate that is ready to download.
pub struct CertOrder<P: Persist> {
    private_key: PKey<pkey::Private>,
    order: Order<P>,
}

impl<P: Persist> CertOrder<P> {
    /// Request download of the issued certificate.
    ///
    /// When downloaded, the certificate and key will be saved in the
    /// persistence. They can later be retreived using [`Account::certificate`].
    ///
    /// [`Account::certificate`]: ../struct.Account.html#method.certificate
    pub fn download_and_save_cert(self) -> Result<Certificate> {
        //
        let primary_name = self.order.api_order.domains()[0].to_string();
        let url = self.order.api_order.certificate.expect("certificate url");
        let inner = self.order.inner;
        let realm = inner.contact_email.clone();

        let res = inner.transport.call(&url, &ApiEmptyString)?;

        // save key and cert into persistence
        let persist = &inner.persist;
        let pk_key = PersistKey::new(&realm, PersistKind::PrivateKey, &primary_name);
        let pkey_pem_bytes = self.private_key.private_key_to_pem_pkcs8().expect("to_pem");
        let pkey_pem = String::from_utf8_lossy(&pkey_pem_bytes);
        debug!("Save private key: {}", pk_key);
        persist.put(&pk_key, &pkey_pem_bytes)?;

        let cert = res.into_string()?;
        let pk_crt = PersistKey::new(&realm, PersistKind::Certificate, &primary_name);
        debug!("Save certificate: {}", pk_crt);
        persist.put(&pk_crt, cert.as_bytes())?;

        Ok(Certificate::new(pkey_pem.to_string(), cert))
    }

    /// Access the underlying JSON object for debugging.
    pub fn api_order(&self) -> &ApiOrder {
        &self.order.api_order
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::persist::*;
    use crate::*;

    #[test]
    fn test_get_authorizations() -> Result<()> {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, url)?;
        let acc = dir.account("foo@bar.com")?;
        let ord = acc.new_order("acmetest.example.com", &[])?;
        let _ = ord.authorizations()?;
        Ok(())
    }

    #[test]
    fn test_finalize() -> Result<()> {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, url)?;
        let acc = dir.account("foo@bar.com")?;
        let ord = acc.new_order("acmetest.example.com", &[])?;
        // shortcut auth
        let ord = CsrOrder { order: ord.order };
        let (pri_key, pub_key) = cert::create_p256_key();
        let _ord = ord.finalize_pkey(pri_key, pub_key, 1)?;
        Ok(())
    }

    #[test]
    fn test_download_and_save_cert() -> Result<()> {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, url)?;
        let acc = dir.account("foo@bar.com")?;
        let ord = acc.new_order("acmetest.example.com", &[])?;

        // shortcut auth
        let ord = CsrOrder { order: ord.order };
        let (pri_key, pub_key) = cert::create_p256_key();
        let ord = ord.finalize_pkey(pri_key, pub_key, 1)?;

        let cert = ord.download_and_save_cert()?;
        assert_eq!("CERT HERE", cert.certificate());
        assert!(!cert.private_key().is_empty());

        // check that the keys have been persisted
        let cert2 = acc.certificate("acmetest.example.com")?.unwrap();
        assert_eq!(cert.private_key(), cert2.private_key());
        assert_eq!(cert.certificate(), cert2.certificate());
        assert_eq!(cert.valid_days_left(), 89);

        Ok(())
    }
}
