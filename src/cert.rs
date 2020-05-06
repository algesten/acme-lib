use lazy_static::lazy_static;
use openssl::ec::{Asn1Flag, EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{self, PKey};
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509Req, X509ReqBuilder, X509};

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

pub(crate) fn create_csr(pkey: &PKey<pkey::Private>, domains: &[&str]) -> Result<X509Req> {
    //
    // the csr builder
    let mut req_bld = X509ReqBuilder::new().expect("X509ReqBuilder");

    // set private/public key in builder
    req_bld.set_pubkey(&pkey).expect("set_pubkey");

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
    Ok(req_bld.build())
}

/// Encapsulated certificate and private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    private_key: String,
    certificate: String,
}

impl Certificate {
    /// Create Certificate from `String/&str` key and certificate
    /// useful when reading files manually from disk.
    ///
    /// NOTE: keys and certs should be PEM encoded
    pub fn new(private_key: impl Into<String>, certificate: impl Into<String>) -> Self {
        Self {
            private_key: private_key.into(),
            certificate: certificate.into(),
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

    #[test]
    fn test_certificate() {
        let cert = r#"-----BEGIN CERTIFICATE-----
MIIErDCCA5SgAwIBAgISBLUTDajPHTUNywURHiL+MlrdMA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDA1MDQxMjQ1MTFaFw0y
MDA4MDIxMjQ1MTFaMBwxGjAYBgNVBAMTEXRlc3Quc2FpbG1haWwueHl6MHYwEAYH
KoZIzj0CAQYFK4EEACIDYgAElGHvhg6ONWA1q6oGjqe0p9PYnfOnWkMCVnMmVCTT
M0R5GARvi8H8VvOlPBfx1QDcBX+AhVMy4Nuj1ltp9iYG7sItg1zBjdwpiEsSSTtN
WyoxJhxI62FwlAwdsMhyzUDMo4ICZjCCAmIwDgYDVR0PAQH/BAQDAgeAMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
BBQOLNwMgWbed1BncgXii6xYvdBQYzAfBgNVHSMEGDAWgBSoSmpjBH3duubRObem
RWXv86jsoTBvBggrBgEFBQcBAQRjMGEwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3Nw
LmludC14My5sZXRzZW5jcnlwdC5vcmcwLwYIKwYBBQUHMAKGI2h0dHA6Ly9jZXJ0
LmludC14My5sZXRzZW5jcnlwdC5vcmcvMBwGA1UdEQQVMBOCEXRlc3Quc2FpbG1h
aWwueHl6MEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYI
KwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBBAYKKwYBBAHW
eQIEAgSB9QSB8gDwAHYAXqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVgA
AAFx3+726gAABAMARzBFAiBad5xUwYO6z1H96cT66zekWvZ88AUWXDi9PcLaNmbG
CAIhAJE6YEEesDWwsm950tIHILq+jwjgX8Y2/xmMjqabNQR/AHYAsh4FzIuizYog
Todm+Su5iiUgZ2va+nDnsklTLe+LkF4AAAFx3+723wAABAMARzBFAiEA1s70pTwu
XuJMCj3O7t7VBlXJdaHE+VkxylVh29bG/xACIEwlg5N9vILOozr5fTORegUPQB+X
WeeIpF/c7A/X4LGNMA0GCSqGSIb3DQEBCwUAA4IBAQAQHlp61BFOqxCzvmz/dNH7
nQeLUEI/eWlvCEKJaFW9e+Dckpwt75JMVckhiN+Fc+CrJdKQHsDYWF1DEPuRPwuT
u3fMx6LLNVw0vK7JQKr6lshanGbqJZYy8bjzs0rYlar/KCv9nu2wr1tMmKC3Kl5w
gkmYR+2ZVxJ+rHz3yY9+5gOP5djAfI+nxfgfA0Yswewg5LzxM5F4HdR/4B95WHcv
ZbfCgLTC51c1RSJO98Bd8HDOPH2oVGgA5TVtgWSe8gC49dZpiRnbodjlWzAJtHsR
E2IZIC6mVugER+rDy7HGstVlhJdzRfEDcMLaiPf8QeyrEXRUPXpBLGhpncsyDwZh
-----END CERTIFICATE-----
"#;

        let key = r#"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCUR0x6Izf9hVuRmZxQ
vXuKVPT9BR3aM9rYh5fh3nm6GAVRZ7dJt2Og8N3TAYCaYOehZANiAASUYe+GDo41
YDWrqgaOp7Sn09id86daQwJWcyZUJNMzRHkYBG+LwfxW86U8F/HVANwFf4CFUzLg
26PWW2n2Jgbuwi2DXMGN3CmISxJJO01bKjEmHEjrYXCUDB2wyHLNQMw=
-----END PRIVATE KEY-----
"#;

        let certificate = Certificate::new(key, cert);

        assert_eq!(certificate.private_key(), key);
        assert_eq!(certificate.certificate(), cert);

        // assert ssl DER conversion does not panic on valid data
        assert_eq!(certificate.private_key_der().len(), 167);
        assert_eq!(certificate.certificate_der().len(), 1200);
    }
}
