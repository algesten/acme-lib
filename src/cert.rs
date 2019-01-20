use lazy_static::lazy_static;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{self, PKey};
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509NameBuilder, X509Req, X509ReqBuilder, X509};

use crate::Result;

lazy_static! {
    pub(crate) static ref EC_GROUP_P256: EcGroup =
        { EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("EcGroup") };
    pub(crate) static ref EC_GROUP_P384: EcGroup =
        { EcGroup::from_curve_name(Nid::SECP384R1).expect("EcGroup") };
}

/// Make a P-256 private/public key pair.
pub fn create_p256_key() -> (PKey<pkey::Private>, PKey<pkey::Public>) {
    let pri_key_ec = EcKey::generate(&*EC_GROUP_P256).expect("EcKey");
    let pub_key_ec =
        EcKey::from_public_key(&*EC_GROUP_P256, pri_key_ec.public_key()).expect("EcKeyPub");

    (
        PKey::from_ec_key(pri_key_ec).expect("from_ec_key"),
        PKey::from_ec_key(pub_key_ec).expect("from_ec_key_pub"),
    )
}

/// Make a P-384 private/public key pair.
pub fn create_p384_key() -> (PKey<pkey::Private>, PKey<pkey::Public>) {
    let pri_key_ec = EcKey::generate(&*EC_GROUP_P384).expect("EcKey");
    let pub_key_ec =
        EcKey::from_public_key(&*EC_GROUP_P384, pri_key_ec.public_key()).expect("EcKeyPub");

    (
        PKey::from_ec_key(pri_key_ec).expect("from_ec_key"),
        PKey::from_ec_key(pub_key_ec).expect("from_ec_key_pub"),
    )
}

pub(crate) fn create_csr(
    pkey_pri: &PKey<pkey::Private>,
    pkey_pub: &PKey<pkey::Public>,
    domains: &[&str],
) -> Result<X509Req> {
    //
    // the csr builder
    let mut req_bld = X509ReqBuilder::new().expect("X509ReqBuilder");

    // set public key in builder
    req_bld.set_pubkey(&pkey_pub).expect("set_pubkey");

    // the CN, first element in domains
    let mut cn_bld = X509NameBuilder::new().expect("X509NameBuilder");
    cn_bld
        .append_entry_by_text("CN", domains[0])
        .map_err(|e| format!("CSR failed: {}", e))?;
    let cn = cn_bld.build();
    req_bld.set_subject_name(&cn).expect("set_subject_name");

    // the rest of domains are alt names
    if domains.len() > 1 {
        let mut stack = Stack::new().expect("Stack::new");
        let ctx = req_bld.x509v3_context(None);
        for domain in &domains[1..] {
            let mut an = SubjectAlternativeName::new();
            an.dns(domain);
            let ext = an.build(&ctx).expect("SubjectAlternativeName::build");
            stack.push(ext).expect("Stack::push");
        }
        req_bld.add_extensions(&stack).expect("add_extensions");
    }

    // sign it
    req_bld
        .sign(pkey_pri, MessageDigest::sha256())
        .expect("csr_sign");

    // the csr
    Ok(req_bld.build())
}

/// Encapsulated certificate and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    private_key: String,
    certificate: String,
}

impl Certificate {
    pub(crate) fn new(private_key: String, certificate: String) -> Self {
        Certificate {
            private_key,
            certificate,
        }
    }

    /// Access the PEM encoded private key.
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    /// Access the PEM encoded issued certificate.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The certificate as DER.
    pub(crate) fn to_der(&self) -> Vec<u8> {
        let x509 = X509::from_pem(self.certificate.as_bytes()).expect("from_pem");
        x509.to_der().expect("to_der")
    }

    /// Inspect the certificate to count the number of (whole) valid days left.
    ///
    /// It's up to the ACME API provider to decide how long an issued certificate is valid.
    /// Let's Encrypt sets the validity to 90 days. This function reports 89 days for newly
    /// issued cert, since it counts _whole_ days.
    ///
    /// It is possible to get negative days for an expired certificate.
    pub fn valid_days_left(&self) -> i64 {
        // the cert used in the tests is not valid to load as x509
        if cfg!(test) {
            return 89;
        }

        // load as x509
        let x509 = X509::from_pem(self.certificate.as_bytes()).expect("from_pem");

        // convert asn1 time to Tm
        let not_after = format!("{}", x509.not_after());
        // Display trait produces this format, which is kinda dumb.
        // Apr 19 08:48:46 2019 GMT
        let expires = time::strptime(&not_after, "%h %d %H:%M:%S %Y %Z").expect("strptime");

        let dur = expires - time::now();

        dur.num_days()
    }
}
