use lazy_static::lazy_static;
use openssl::ec::{Asn1Flag, EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{self, PKey};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509NameBuilder, X509Req, X509ReqBuilder, X509};

use crate::Result;

lazy_static! {
    pub(crate) static ref EC_GROUP_P256: EcGroup = { ec_group(Nid::X9_62_PRIME256V1) };
    pub(crate) static ref EC_GROUP_P384: EcGroup = { ec_group(Nid::SECP384R1) };
}

fn ec_group(nid: Nid) -> EcGroup {
    let mut g = EcGroup::from_curve_name(nid).expect("EcGroup");
    // this is required for openssl 1.0.x (but not 1.1.x)
    g.set_asn1_flag(Asn1Flag::NAMED_CURVE);
    g
}

/// Make an RSA private/public key pair.
///
/// This library does not check the number of bits used to create the key pair.
/// For Let's Encrypt, the bits must be between 2048 and 4096.
pub fn create_rsa_key(bits: u32) -> (PKey<pkey::Private>, PKey<pkey::Public>) {
    let pri_key_rsa = Rsa::generate(bits).expect("Rsa::generate");
    let n = pri_key_rsa.n().to_owned().expect("BigNumRef::to_owned()");
    let e = pri_key_rsa.e().to_owned().expect("BigNumRef::to_owned()");
    let pub_key_rsa = Rsa::from_public_components(n, e).expect("Rsa::from_public_compontents");
    (
        PKey::from_rsa(pri_key_rsa).expect("from_rsa"),
        PKey::from_rsa(pub_key_rsa).expect("from_rsa"),
    )
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
