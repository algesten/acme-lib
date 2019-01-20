acme-lib
========

Simple rust library to access an ACME API (Automatic Certificate Management Environment)
provider such as https://letsencrypt.org

  * Uses API version 2.0
  * https://tools.ietf.org/html/draft-ietf-acme-acme-18

# Install

Install it like so:

```toml
[dependencies]
acme-lib = "0.1"
```

# Example

```rust
use acme_lib::{Error, Directory, DirectoryUrl};
use acme_lib::persist::FilePersist;
use acme_lib::create_p384_key;

fn request_cert() -> Result<(), Error> {

// Use DirectoryUrl::LetsEncrypStaging for dev/testing.
let url = DirectoryUrl::LetsEncrypt;

// Save/load keys and certificates to current dir.
let persist = FilePersist::new(".");

// Create a directory entrypoint.
let dir = Directory::from_url(persist, url)?;

// Reads the private account key from persistence, or
// creates a new one before accessing the API.
let acc = dir.account("foo@bar.com")?;

// Create a new order to get a TLS certificate for a domain. Calls
// the API access point to create the new order.
let mut ord_new = acc.new_order("myfancydomain.com", &[])?;

// If the ownership of the domain(s) have already been authorized
// in a previous order, you might be able to skip validation. The
// ACME API provider decides.
let ord_csr = loop {
    // are we done?
    if let Some(ord_csr) = ord_new.confirm_validations() {
        break ord_csr;
    }

    // Get the possible authorizations (for a single domain this
    // will only be one element).
    let auths = ord_new.authorizations()?;

    // For HTTP, the challenge is a text file that needs to be
    // placed in your web server's root:
    //
    // /var/www/.well-known/acme-challenge/<token>
    //
    // The important thing is that it's accessible over the web for
    // the domain(s) you are trying to get a certificate for:
    //
    // http://myfancydomain.com/.well-known/acme-challenge/<token>
    let chall = auths[0].http_challenge();

    // The token is the filename.
    let token = chall.http_token();
    let full_path = format!(".well-known/acme-challenge/{}", token);

    // The proof is the contents of the file
    let proof = chall.http_proof();

    // Here you must do "something" to place the file/contents in
    // the correct place.
    // update_my_web_server(&full_path, &proof);

    // After the file is accessible from the web, the calls this
    // to tell the ACME API to start checking the existence
    // of the proof.
    //
    // The order at ACME will change status to either confirm
    // ownership of the domain, or fail due to the lack of proof.
    // The number is milliseconds to wait in between polling for
    // the order status change. If the proof is not placed
    // correctly, the library will return an error.
    chall.validate(5000)?;

    // Update the state against the ACME API.
    ord_new.refresh()?;
};

// Ownership is proven. Create a private/public key pair for the
// certificate. These are provided for convenience, you can provide
// your own keypair instead if you want.
let (pkey_pri, pkey_pub) = create_p384_key();

// Submit the CSR. This causes the ACME provider to enter a state
// of "processing" that must be polled until the certificate
// is either issued or rejected. The number is the milliseconds
// between polling.
let ord_cert = ord_csr.finalize_pkey(pkey_pri, pkey_pub, 5000)?;

// Now download the certificate. Also stores the cert in
// the persistence.
let cert = ord_cert.download_and_save_cert()?;

Ok(())
}
```


## License (MIT)

Copyright (c) 2019 Martin Algesten

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
