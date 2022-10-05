// use crate::crypto::Crypto;

// /// Encapsulated certificate and private key.
// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct Certificate<C: Crypto> {
//     private_key: String,
//     certificate: String,
// }
//
// impl<C: Crypto> Certificate {
//     pub(crate) fn new(private_key: String, certificate: String) -> Self {
//         Certificate {
//             private_key,
//             certificate,
//         }
//     }
//
//     /// The PEM encoded private key.
//     pub fn private_key(&self) -> &str {
//         &self.private_key
//     }
//
//     /// The private key as DER.
//     pub fn private_key_der(&self) -> Vec<u8> {
//         let pkey = PKey::private_key_from_pem(self.private_key.as_bytes()).expect("from_pem");
//         pkey.private_key_to_der().expect("private_key_to_der")
//     }
//
//     /// The PEM encoded issued certificate.
//     pub fn certificate(&self) -> &str {
//         &self.certificate
//     }
//
//     /// The issued certificate as DER.
//     pub fn certificate_der(&self) -> Vec<u8> {
//         let x509 = X509::from_pem(self.certificate.as_bytes()).expect("from_pem");
//         x509.to_der().expect("to_der")
//     }
//
//     /// Inspect the certificate to count the number of (whole) valid days left.
//     ///
//     /// It's up to the ACME API provider to decide how long an issued certificate is valid.
//     /// Let's Encrypt sets the validity to 90 days. This function reports 89 days for newly
//     /// issued cert, since it counts _whole_ days.
//     ///
//     /// It is possible to get negative days for an expired certificate.
//     pub fn valid_days_left(&self) -> i64 {
//     }
// }
//
