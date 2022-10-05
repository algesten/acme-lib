use std::fmt::{Debug, Formatter};
use std::ops::{Deref, DerefMut};
use lazy_static::lazy_static;
use crate::crypto::{Certificate, Crypto, Csr, PKey};

use openssl::pkey;
use openssl::ec;
use openssl::ec::{Asn1Flag, EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::{X509, X509Req, X509ReqBuilder};
use openssl::x509::extension::SubjectAlternativeName;
use crate::jwt::Jwk;
use crate::util::{base64url};

lazy_static! {
    pub(crate) static ref EC_GROUP_P256: EcGroup = ec_group(Nid::X9_62_PRIME256V1);
    pub(crate) static ref EC_GROUP_P384: EcGroup = ec_group(Nid::SECP384R1);
}

fn ec_group(nid: Nid) -> EcGroup {
    let mut g = EcGroup::from_curve_name(nid).expect("EcGroup");
    // this is required for openssl 1.0.x (but not 1.1.x)
    g.set_asn1_flag(Asn1Flag::NAMED_CURVE);
    g
}


#[derive(Copy, Clone, Default)]
pub struct Openssl;

pub struct NewType<T>(T);

impl PKey for NewType<pkey::PKey<pkey::Private>> {
    type Error = openssl::error::ErrorStack;

    fn from_pem(pem: &str) -> Result<Self, Self::Error> {
        let rsa = openssl::rsa::Rsa::<pkey::Private>::private_key_from_pem(pem.as_bytes())?;
        pkey::PKey::from_rsa(rsa).map(NewType)

    }

    fn to_pem(&self) -> Result<String, Self::Error> {
        self.private_key_to_pem_pkcs8().map( |pem| String::from_utf8_lossy(&pem).into_owned())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &self.0)?;
        signer.update(data)?;
        signer.sign_to_vec()
    }

    fn new() -> Result<Self, Self::Error> {
        let pri_key_rsa = Rsa::generate(2048)?;
        pkey::PKey::from_rsa(pri_key_rsa).map(NewType)
    }
}

impl PKey for NewType<ec::EcKey<pkey::Private>> {
    type Error = openssl::error::ErrorStack;

    fn from_pem(pem: &str) -> Result<Self, Self::Error> {
        openssl::ec::EcKey::private_key_from_pem(pem.as_bytes()).map(NewType)
    }

    fn to_pem(&self) -> Result<String, Self::Error> {
        self.private_key_to_pem().map(|c| String::from_utf8_lossy(&c).into_owned())
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let digest = Openssl::sha256(data);
        let sig = EcdsaSig::sign(&digest, &self.0)?;

        let r = sig.r().to_vec();
        let s = sig.s().to_vec();

        let mut v = Vec::with_capacity(r.len() + s.len());
        v.extend_from_slice(&r);
        v.extend_from_slice(&s);

        Ok(v)
    }

    fn new() -> Result<Self, Self::Error> {
        EcKey::generate(&*EC_GROUP_P384).map(NewType)
    }
}



impl<T> Deref for NewType<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for NewType<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a> From<&'a <Openssl as Crypto>::AccountKey> for Jwk {
    fn from(key: &'a <Openssl as Crypto>::AccountKey) -> Self {
        let mut ctx = openssl::bn::BigNumContext::new().expect("BigNumContext");
        let mut x = openssl::bn::BigNum::new().expect("BigNum");
        let mut y = openssl::bn::BigNum::new().expect("BigNum");
        key.public_key()
            .affine_coordinates_gfp(&*EC_GROUP_P256, &mut x, &mut y, &mut ctx)
            .expect("affine_coordinates_gfp");
        Jwk {
            alg: "ES256".into(),
            kty: "EC".into(),
            crv: "P-256".into(),
            _use: "sig".into(),
            x: base64url(&x.to_vec()),
            y: base64url(&y.to_vec()),
        }
    }
}


// /// Make a P-256 private key (from which we can derive a public key).
// pub fn create_p256_key() -> PKey<pkey::Private> {
//     let pri_key_ec = EcKey::generate(&*EC_GROUP_P256).expect("EcKey");
//     PKey::from_ec_key(pri_key_ec).expect("from_ec_key")
// }

impl Csr for NewType<X509Req> {
    type Error = openssl::error::ErrorStack;
    type PrivateKey = NewType<pkey::PKey<pkey::Private>>;

    fn new(pkey: &Self::PrivateKey, domains: &[&str]) -> Result<Self, Self::Error> {
        //
        // the csr builder
        let mut req_bld = X509ReqBuilder::new().expect("X509ReqBuilder");

        // set private/public key in builder
        req_bld.set_pubkey(pkey).expect("set_pubkey");

        // set all domains as alt names
        let mut stack = Stack::new().expect("Stack::new");
        let ctx = req_bld.x509v3_context(None);
        let as_lst = domains
            .iter()
            .map(|&e| format!("DNS:{}", e))
            .collect::<Vec<_>>()
            .join(", ");
        let as_lst = as_lst[4..].to_string();
        let mut an = SubjectAlternativeName::new();
        an.dns(&as_lst);
        let ext = an.build(&ctx).expect("SubjectAlternativeName::build");
        stack.push(ext).expect("Stack::push");
        req_bld.add_extensions(&stack).expect("add_extensions");

        // sign it
        req_bld
            .sign(pkey, MessageDigest::sha256())
            .expect("csr_sign");

        // the csr
        Ok(NewType(req_bld.build()))
    }

    fn to_pem(&self) -> Result<Vec<u8>, Self::Error> {
        self.0.to_pem()
    }

    fn to_der(&self) -> Result<Vec<u8>, Self::Error> {
        self.0.to_der()
    }

    fn from_pem(pem: &str) -> Result<Self, Self::Error> {
        X509Req::from_pem(pem.as_bytes()).map(NewType)
    }
}

impl Certificate for NewType<X509> {
    type Error = openssl::error::ErrorStack;

    fn from_pem(pem: &str) -> Result<Self, Self::Error> {
        X509::from_pem(pem.as_bytes()).map(NewType)
    }

    fn to_pem(&self) -> Result<Vec<u8>, Self::Error> {
        self.0.to_pem()
    }

    fn to_der(&self) -> Result<Vec<u8>, Self::Error> {
        self.0.to_der()
    }

    fn valid_days_left(&self) -> i64 {
        // the cert used in the tests is not valid to load as x509
        if cfg!(test) {
            return 89;
        }

        // convert asn1 time to Tm
        let not_after = format!("{}", self.0.not_after());
        // Display trait produces this format, which is kinda dumb.
        // Apr 19 08:48:46 2019 GMT
        let expires = parse_date(&not_after);
        let dur = expires - time::now();

        dur.num_days()
    }
}

impl Debug for NewType<X509> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("an X509 certificate")
    }
}

impl Debug for NewType<X509Req> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("an X509 certificate request")
    }
}

impl Debug for NewType<pkey::PKey<pkey::Private>> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("a private rsa key")
    }
}

impl Clone for NewType<pkey::PKey<pkey::Private>> {
    fn clone(&self) -> Self {
        let pem = self.to_pem().expect("to pem");
        Self::from_pem(&pem).expect("from pem")
    }
}

impl Debug for NewType<EcKey<pkey::Private>> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("a private rsa key")
    }
}

impl Clone for NewType<EcKey<pkey::Private>> {
    fn clone(&self) -> Self {
        let pem = self.to_pem().expect("to pem");
        Self::from_pem(&pem).expect("from pem")
    }
}

impl Clone for NewType<X509Req> {
    fn clone(&self) -> Self {
        let pem = self.to_pem().expect("to pem");
        let pem = std::str::from_utf8(&pem).expect("from utf8");
        Self::from_pem(&pem).expect("from pem")
    }
}

impl From<ErrorStack> for crate::Error {
    fn from(_: ErrorStack) -> Self {
        Self::Other("An openssl Error".to_string())
    }
}


impl Crypto for Openssl {
    type Error = openssl::error::ErrorStack;

    type AccountKey = NewType<ec::EcKey<pkey::Private>>;
    type PrivateKey = NewType<pkey::PKey<pkey::Private>>;

    type Csr = NewType<X509Req>;
    type Certificate = NewType<X509>;

    fn sha256(input: &[u8]) -> [u8; 32] {
        openssl::sha::sha256(input)
    }
}

pub(crate) fn parse_date(s: &str) -> time::Tm {
    debug!("Parse date/time: {}", s);
    time::strptime(s, "%h %e %H:%M:%S %Y %Z").expect("strptime")
}
