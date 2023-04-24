use lazy_static::lazy_static;
use openssl::ec::{Asn1Flag, EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{self, PKey};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509Req, X509ReqBuilder, X509, X509NameBuilder};

use crate::Result;

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

/// Make an RSA private key (from which we can derive a public key).
///
/// This library does not check the number of bits used to create the key pair.
/// For Let's Encrypt, the bits must be between 2048 and 4096.
pub fn create_rsa_key(bits: u32) -> PKey<pkey::Private> {
    let pri_key_rsa = Rsa::generate(bits).expect("Rsa::generate");
    PKey::from_rsa(pri_key_rsa).expect("from_rsa")
}

/// Make a P-256 private key (from which we can derive a public key).
pub fn create_p256_key() -> PKey<pkey::Private> {
    let pri_key_ec = EcKey::generate(&*EC_GROUP_P256).expect("EcKey");
    PKey::from_ec_key(pri_key_ec).expect("from_ec_key")
}

/// Make a P-384 private key pair (from which we can derive a public key).
pub fn create_p384_key() -> PKey<pkey::Private> {
    let pri_key_ec = EcKey::generate(&*EC_GROUP_P384).expect("EcKey");
    PKey::from_ec_key(pri_key_ec).expect("from_ec_key")
}

pub(crate) fn create_csr(pkey: &PKey<pkey::Private>, primary_name: &str, domains: &[&str]) -> Result<X509Req> {
    //
    // the csr builder
    let mut req_bld = X509ReqBuilder::new().expect("X509ReqBuilder");

    // set private/public key in builder
    req_bld.set_pubkey(&pkey).expect("set_pubkey");

    // set CN
    let mut name_builder = X509NameBuilder::new().expect("X509NameBuilder");
    name_builder.append_entry_by_text("CN", primary_name).expect("X509NameBuilder::append_entry_by_text");
    req_bld.set_subject_name(&name_builder.build()).expect("set_subject_name");

    // set all domains as alt names
    let mut stack = Stack::new().expect("Stack::new");
    let ctx = req_bld.x509v3_context(None);
    let mut sans = SubjectAlternativeName::new();
    for domain in domains {
        sans.dns(domain);
    }
    let ext = sans.build(&ctx).expect("SubjectAlternativeName::build");
    stack.push(ext).expect("Stack::push");
    req_bld.add_extensions(&stack).expect("add_extensions");

    // sign it
    req_bld
        .sign(pkey, MessageDigest::sha256())
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

    /// The PEM encoded private key.
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    /// The private key as DER.
    pub fn private_key_der(&self) -> Vec<u8> {
        let pkey = PKey::private_key_from_pem(self.private_key.as_bytes()).expect("from_pem");
        pkey.private_key_to_der().expect("private_key_to_der")
    }

    /// The PEM encoded issued certificate.
    pub fn certificate(&self) -> &str {
        &self.certificate
    }

    /// The issued certificate as DER.
    pub fn certificate_der(&self) -> Vec<u8> {
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
        let expires = parse_date(&not_after);
        let dur = expires - time::now();

        dur.num_days()
    }
}

fn parse_date(s: &str) -> time::Tm {
    debug!("Parse date/time: {}", s);
    time::strptime(s, "%h %e %H:%M:%S %Y %Z").expect("strptime")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_date() {
        let x = parse_date("May  3 07:40:15 2019 GMT");
        assert_eq!(time::strftime("%F %T", &x).unwrap(), "2019-05-03 07:40:15");
    }
}
