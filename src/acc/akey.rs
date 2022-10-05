use crate::crypto::{Crypto, PKey};
use crate::jwt::Jwk;

#[derive(Clone, Debug)]
pub(crate) struct AcmeKey<C: Crypto> where for <'a> &'a C::AccountKey: Into<Jwk> {
    private_key: C::AccountKey,
    /// set once we contacted the ACME API to figure out the key id
    key_id: Option<String>,
}

impl<C: Crypto> AcmeKey<C> where for <'a> &'a C::AccountKey: Into<Jwk> {
    pub(crate) fn new() -> Result<Self, C::Error> {
        C::AccountKey::new().map(Self::from_key)
    }

    pub(crate) fn from_pem(pem: &[u8]) -> Result<Self, C::Error> {
        let pri_key = C::AccountKey::from_pem(std::str::from_utf8(pem).expect("non-utf8")).expect("cannot parse pem");
        Ok(Self::from_key(pri_key))
    }

    fn from_key(private_key: C::AccountKey) -> Self {
        AcmeKey {
            private_key,
            key_id: None,
        }
    }

    pub(crate) fn to_pem(&self) -> String {
        self.private_key.to_pem().expect("private_key_to_pem")
    }

    pub(crate) fn private_key(&self) -> &C::AccountKey {
        &self.private_key
    }

    pub(crate) fn key_id(&self) -> &str {
        self.key_id.as_ref().unwrap()
    }

    pub(crate) fn set_key_id(&mut self, kid: String) {
        self.key_id = Some(kid)
    }

    pub(crate) fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.private_key.sign(data).expect("Could not sign data")
    }
}
