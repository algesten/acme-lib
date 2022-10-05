//
use std::sync::Arc;

use crate::acc::AcmeKey;
use crate::api::{ApiAccount, ApiDirectory};
use crate::persist::{Persist, PersistKey, PersistKind};
use crate::trans::{NoncePool, Transport};
use crate::util::read_json;
use crate::{Account, Result};
use crate::crypto::Crypto;
use crate::jwt::Jwk;
use crate::req::{HttpClient, HttpResponse};

const LETSENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Enumeration of known ACME API directories.
#[derive(Debug, Clone)]
pub enum DirectoryUrl<'a> {
    /// The main Let's Encrypt directory. Not appropriate for testing and dev.
    LetsEncrypt,
    /// The staging Let's Encrypt directory. Use for testing and dev. Doesn't issue
    /// "valid" certificates. The root signing certificate is not supposed
    /// to be in any trust chains.
    LetsEncryptStaging,
    /// Provide an arbitrary director URL to connect to.
    Other(&'a str),
}

impl<'a> DirectoryUrl<'a> {
    fn to_url(&self) -> &str {
        match self {
            DirectoryUrl::LetsEncrypt => LETSENCRYPT,
            DirectoryUrl::LetsEncryptStaging => LETSENCRYPT_STAGING,
            DirectoryUrl::Other(s) => s,
        }
    }
}

/// Entry point for accessing an ACME API.
#[derive(Clone)]
pub struct Directory<P: Persist, H: HttpClient> {
    persist: P,
    client: H,
    nonce_pool: Arc<NoncePool<H>>,
    api_directory: ApiDirectory,
}

impl<P: Persist, H: HttpClient> Directory<P, H> {
    /// Create a directory over a persistence implementation and directory url.
    pub fn from_url(persist: P, client: H, url: DirectoryUrl) -> Result<Directory<P, H>> {
        let dir_url = url.to_url();
        let res = client.get(dir_url).handle_errors()?;
        let api_directory: ApiDirectory = read_json(res)?;
        let nonce_pool = Arc::new(NoncePool::new(client.clone(), &api_directory.newNonce));
        Ok(Directory {
            persist,
            client,
            nonce_pool,
            api_directory,
        })
    }

    pub fn from_url_with_default(persist: P, url: DirectoryUrl) -> Result<Directory<P, H>> where H: Default {
        Self::from_url(persist, Default::default(), url)
    }

    /// Access an account identified by a contact email.
    ///
    /// If a persisted private key exists for the contact email, it will be read
    /// and used for further access. This way we reuse the same ACME API account.
    ///
    /// If one doesn't exist, it is created and the corresponding public key is
    /// uploaded to the ACME API thus creating the account.
    ///
    /// Either way the `newAccount` API endpoint is called and thereby ensures the
    /// account is active and working.
    ///
    /// This is the same as calling
    /// `account_with_realm(contact_email, ["mailto: <contact_email>"]`)
    pub fn account<C: Crypto>(&self, contact_email: &str) -> Result<Account<P, H, C>> where for <'a> &'a C::AccountKey: Into<Jwk> {
        // Contact email is the persistence realm when using this method.
        let contact = vec![format!("mailto:{}", contact_email)];
        self.account_with_realm(contact_email, Some(contact))
    }

    /// Access an account using a lower level method. The contact is optional
    /// against the ACME API provider and there might be situations where you
    /// either don't need it at all, or need it to be something else than
    /// an email address.
    ///
    /// The `realm` parameter is a persistence realm, i.e. a namespace in the
    /// persistence where all values belonging to this Account will be stored.
    ///
    /// If a persisted private key exists for the `realm`, it will be read
    /// and used for further access. This way we reuse the same ACME API account.
    ///
    /// If one doesn't exist, it is created and the corresponding public key is
    /// uploaded to the ACME API thus creating the account.
    ///
    /// Either way the `newAccount` API endpoint is called and thereby ensures the
    /// account is active and working.
    pub fn account_with_realm<C: Crypto>(
        &self,
        realm: &str,
        contact: Option<Vec<String>>,
    ) -> Result<Account<P, H, C>> where for <'a> &'a C::AccountKey: Into<Jwk> {
        // key in persistence for acme account private key
        let pem_key = PersistKey::new(realm, PersistKind::AccountPrivateKey, "acme_account");

        // Get the key from a saved PEM, or from creating a new
        let mut is_new = false;
        let pem = self.persist().get(&pem_key)?;
        let acme_key = if let Some(pem) = pem {
            // we got a persisted private key. read it.
            debug!("Read persisted acme account key");
            AcmeKey::<C>::from_pem(&pem).map_err(|e: C::Error| e.into())?
        } else {
            // create a new key (and new account)
            debug!("Create new acme account key");
            is_new = true;
            AcmeKey::<C>::new().map_err(|e: C::Error| e.into())?
        };

        // Prepare making a call to newAccount. This is fine to do both for
        // new keys and existing. For existing the spec says to return a 200
        // with the Location header set to the key id (kid).
        let acc = ApiAccount {
            contact,
            termsOfServiceAgreed: Some(true),
            ..Default::default()
        };

        let mut transport = Transport::new_with(&self.nonce_pool, self.client.clone(), acme_key);
        let res = transport.call_jwk(&self.api_directory.newAccount, &acc)?;
        let kid = res.header("location")?;
        debug!("Key id is: {}", kid);
        // fill in the server returned key id
        transport.set_key_id(kid.to_string());

        let api_account: ApiAccount = read_json(res)?;

        // If we did create a new key, save it back to the persistence.
        if is_new {
            debug!("Persist acme account key");
            let pem = transport.acme_key().to_pem();
            self.persist().put(&pem_key, &pem.as_bytes())?;
        }

        // The finished account
        Ok(Account::new(
            self.persist.clone(),
            transport,
            realm,
            api_account,
            self.api_directory.clone(),
        ))
    }

    /// Access the underlying JSON object for debugging.
    pub fn api_directory(&self) -> &ApiDirectory {
        &self.api_directory
    }

    pub(crate) fn persist(&self) -> &P {
        &self.persist
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::persist::*;
    #[test]
    fn test_create_directory() -> Result<()> {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let persist = MemoryPersist::new();
        let _ = Directory::from_url(persist, url)?;
        Ok(())
    }

    #[test]
    fn test_create_acount() -> Result<()> {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, url)?;
        let _ = dir.account("foo@bar.com")?;
        Ok(())
    }

    #[test]
    fn test_persisted_acount() -> Result<()> {
        let server = crate::test::with_directory_server();
        let url = DirectoryUrl::Other(&server.dir_url);
        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, url)?;
        let acc1 = dir.account("foo@bar.com")?;
        let acc2 = dir.account("foo@bar.com")?;
        let acc3 = dir.account("karlfoo@bar.com")?;
        assert_eq!(acc1.acme_private_key_pem(), acc2.acme_private_key_pem());
        assert!(acc1.acme_private_key_pem() != acc3.acme_private_key_pem());
        Ok(())
    }

    // #[test]
    // fn test_the_whole_hog() -> Result<()> {
    //     std::env::set_var("RUST_LOG", "acme_lib=trace");
    //     let _ = env_logger::try_init();

    //     use crate::cert::create_p384_key;

    //     let url = DirectoryUrl::LetsEncryptStaging;
    //     let persist = FilePersist::new(".");
    //     let dir = Directory::from_url(persist, url)?;
    //     let acc = dir.account("foo@bar.com")?;

    //     let mut ord = acc.new_order("myspecialsite.com", &[])?;

    //     let ord = loop {
    //         if let Some(ord) = ord.confirm_validations() {
    //             break ord;
    //         }

    //         let auths = ord.authorizations()?;
    //         let chall = auths[0].dns_challenge();

    //         info!("Proof: {}", chall.dns_proof());

    //         use std::thread;
    //         use std::time::Duration;
    //         thread::sleep(Duration::from_millis(60_000));

    //         chall.validate(5000)?;

    //         ord.refresh()?;
    //     };

    //     let (pkey_pri, pkey_pub) = create_p384_key();

    //     let ord = ord.finalize_pkey(pkey_pri, pkey_pub, 5000)?;

    //     let cert = ord.download_and_save_cert()?;
    //     println!(
    //         "{}{}{}",
    //         cert.private_key(),
    //         cert.certificate(),
    //         cert.valid_days_left()
    //     );
    //     Ok(())
    // }
}
