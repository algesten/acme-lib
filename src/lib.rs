#![warn(clippy::all)]
//! acme-lib is a library for accessing ACME (Automatic Certificate Management Environment)
//! services such as [Let's Encrypt](https://letsencrypt.org/).
//!
//! Uses ACME v2 to issue/renew certificates.
//!
//! Install it like so:
//!
//! ```toml
//! [dependencies]
//! acme-lib = "0.1"
//! ```
//!
//! # Quick start
//!
//! ```no_run
//! use acme_lib::{Error, Directory, DirectoryUrl};
//! use acme_lib::persist::FilePersist;
//! use acme_lib::create_p384_key;
//!
//! fn request_cert() -> Result<(), Error> {
//!
//! // Use DirectoryUrl::LetsEncrypStaging for dev/testing.
//! let url = DirectoryUrl::LetsEncrypt;
//!
//! // Save/load keys and certificates to current dir.
//! let persist = FilePersist::new(".");
//!
//! // Create a directory entrypoint.
//! let dir = Directory::from_url(persist, url)?;
//!
//! // Reads the private account key from persistence, or
//! // creates a new one before accessing the API.
//! let acc = dir.account("foo@bar.com")?;
//!
//! // Create a new order to get a TLS certificate for a domain. Calls
//! // the API access point to create the new order.
//! let mut ord_new = acc.new_order("myfancydomain.com", &[])?;
//!
//! // If the ownership of the domain(s) have already been authorized
//! // in a previous order, you might be able to skip validation. The
//! // ACME API provider decides.
//! let ord_csr = loop {
//!     // are we done?
//!     if let Some(ord_csr) = ord_new.confirm_validations() {
//!         break ord_csr;
//!     }
//!
//!     // Get the possible authorizations (for a single domain this
//!     // will only be one element).
//!     let auths = ord_new.authorizations()?;
//!
//!     // For HTTP, the challenge is a text file that needs to be
//!     // placed in your web server's root:
//!     //
//!     // /var/www/.well-known/acme-challenge/<token>
//!     //
//!     // The important thing is that it's accessible over the web for
//!     // the domain(s) you are trying to get a certificate for:
//!     //
//!     // http://myfancydomain.com/.well-known/acme-challenge/<token>
//!     let chall = auths[0].http_challenge();
//!
//!     // The token is the filename.
//!     let token = chall.http_token();
//!     let full_path = format!(".well-known/acme-challenge/{}", token);
//!
//!     // The proof is the contents of the file
//!     let proof = chall.http_proof();
//!
//!     // Here you must do "something" to place the file/contents in
//!     // the correct place.
//!     // update_my_web_server(&full_path, &proof);
//!
//!     // After the file is accessible from the web, the calls this
//!     // to tell the ACME API to start checking the existence
//!     // of the proof.
//!     //
//!     // The order at ACME will change status to either confirm
//!     // ownership of the domain, or fail due to the lack of proof.
//!     // The number is milliseconds to wait in between polling for
//!     // the order status change. If the proof is not placed
//!     // correctly, the library will return an error.
//!     chall.validate(5000)?;
//!
//!     // Update the state against the ACME API.
//!     ord_new.refresh()?;
//! };
//!
//! // Ownership is proven. Create a private/public key pair for the
//! // certificate. These are provided for convenience, you can provide
//! // your own keypair instead if you want.
//! let (pkey_pri, pkey_pub) = create_p384_key();
//!
//! // Submit the CSR. This causes the ACME provider to enter a state
//! // of "processing" that must be polled until the certificate
//! // is either issued or rejected. The number is the milliseconds
//! // between polling.
//! let ord_cert = ord_csr.finalize_pkey(pkey_pri, pkey_pub, 5000)?;
//!
//! // Now download the certificate. Also stores the cert in
//! // the persistence.
//! let cert = ord_cert.download_and_save_cert()?;
//!
//! Ok(())
//! }
//! ```
//!
//! ## Domain ownership
//!
//! Most website TLS certificates tries to prove ownership/control over the domain they
//! are issued for. For ACME, this means proving you control either a web server answering
//! HTTP requests to the domain, or the DNS server answering name lookups against the domain.
//!
//! To use this library, there are points in the flow where you would need to modify either
//! the web server or DNS server before progressing to get the certificate.
//!
//! See [`http_challenge`] and [`dns_challenge`].
//!
//! ### Multiple domains
//!
//! When creating a new order, it's possible to provide multiple alt-names that will also
//! be part of the certificate. The ACME API requires you to prove ownership of each such
//! domain. See [`authorizations`].
//!
//! [`http_challenge`]: struct.Auth.html#method.http_challenge
//! [`dns_challenge`]: struct.Auth.html#method.dns_challenge
//! [`authorizations`]: order/struct.NewOrder.html#method.authorizations
//!
//! ## Rate limits
//!
//! The ACME API provider Let's Encrypt uses [rate limits] to ensure the API i not being
//! abused. It might be tempting to put the `delay_millis` really low in some of this
//! libraries' polling calls, but balance this against the real risk of having access
//! cut off.
//!
//! [rate limits]: https://letsencrypt.org/docs/rate-limits/
//!
//! ### Use staging for dev!
//!
//! Especially take care to use the Let`s Encrypt staging environment for development
//! where the rate limits are more relaxed.
//!
//! See [`DirectoryUrl::LetsEncryptStaging`].
//!
//! [`DirectoryUrl::LetsEncryptStaging`]: enum.DirectoryUrl.html#variant.LetsEncryptStaging
//!
//! ## Implementation details
//!
//! The library tries to pull in as few dependencies as possible. (For now) that means using
//! synchronous I/O and blocking cals. This doesn't rule out a futures based version later.
//!
//! It is written by following the
//! [ACME draft spec 18](https://tools.ietf.org/html/draft-ietf-acme-acme-18), and relies
//! heavily on the [openssl](https://docs.rs/openssl/) crate to make JWK/JWT and sign requests
//! to the API.
//!
#[macro_use]
extern crate log;

mod acc;
mod cert;
mod dir;
mod error;
mod jwt;
mod util;

pub mod api;
pub mod order;
pub mod persist;

#[cfg(test)]
mod test;

pub use crate::acc::Account;
pub use crate::cert::{create_p256_key, create_p384_key, Certificate};
pub use crate::dir::{Directory, DirectoryUrl};
pub use crate::error::{Error, Result};
