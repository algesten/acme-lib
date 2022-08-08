extern crate acme_lib;

use acme_lib::create_p384_key;
use acme_lib::persist::FilePersist;
use acme_lib::{Directory, DirectoryUrl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let email = std::env::var("EMAIL"); //optional
    let domain = std::env::var("DOMAIN")?; // required
    let ducktoken = std::env::var("DUCKDNS_TOKEN")?; // required
    let optemail = email.map(|x| vec![x]).ok();

    request_cert(optemail, domain, ducktoken)?;

    Ok(())
}

fn request_cert(
    email: Option<Vec<String>>,
    domain: String,
    ducktoken: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use DirectoryUrl::LetsEncrypStaging for dev/testing.
    //let url = DirectoryUrl::LetsEncrypt;
    let url = DirectoryUrl::LetsEncryptStaging;

    // Save/load keys and certificates to current dir.
    let persist = FilePersist::new(".");

    // Create a directory entrypoint.
    let dir = Directory::from_url(persist, url)?;

    // Reads the private account key from persistence, or
    // creates a new one before accessing the API to establish
    // that it's there.
    // let acc = dir.account(&email)?;
    let acc = dir.account_with_realm("realm", email)?;

    // Order a new TLS certificate for a domain.
    let mut ord_new = acc.new_order(&domain, &[])?;

    // If the ownership of the domain(s) have already been
    // authorized in a previous order, you might be able to
    // skip validation. The ACME API provider decides.
    let ord_csr = loop {
        // are we done?
        if let Some(ord_csr) = ord_new.confirm_validations() {
            break ord_csr;
        }

        // Get the possible authorizations (for a single domain
        // this will only be one element).
        let auths = ord_new.authorizations()?;

        // For DNS, the challenge is a string file that needs to
        // be placed in the DNS record: _acme-challenge.example.com
        //

        let chall = auths[0].dns_challenge();

        let txt = chall.dns_proof();

        duckdns(&domain, &ducktoken, &txt, true)?;

        // Here you must do "something" to place
        // the file/contents in the correct place.
        // update_my_web_server(&path, &proof);

        // When the DNS TXT record is visible via the DNS system, the calls
        // this to tell the ACME API to start checking the
        // existence of the proof.
        //
        // The order at ACME will change status to either
        // confirm ownership of the domain, or fail due to the
        // not finding the proof. To see the change, we poll
        // the API with 5000 milliseconds wait between.
        chall.validate(5000)?;

        // Update the state against the ACME API.
        ord_new.refresh()?;
    };

    // Ownership is proven. Create a private key for
    // the certificate. These are provided for convenience, you
    // can provide your own keypair instead if you want.
    let pkey_pri = create_p384_key();

    // Submit the CSR. This causes the ACME provider to enter a
    // state of "processing" that must be polled until the
    // certificate is either issued or rejected. Again we poll
    // for the status change.
    let ord_cert = ord_csr.finalize_pkey(pkey_pri, 5000)?;

    println!("api_order: {:?}", ord_cert.api_order());

    // Now download the certificate. Also stores the cert in
    // the persistence.
    let cert = ord_cert.download_and_save_cert()?;

    println!("got cert {:?}", cert);

    Ok(())
}

// https://www.duckdns.org/update?domains={YOURVALUE}&token={YOURVALUE}&txt={YOURVALUE}[&verbose=true][&clear=true]

fn duckdns(
    domain: &String,
    duckdns_token: &String,
    txt: &String,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    const URL: &str = "https://www.duckdns.org/update";
    // let client = ClientBuilder::new(reqwest::Client::new())
    //     .with(TracingMiddleware::default())
    //     .build();

    let client = reqwest::blocking::Client::new();
    let mut rb = client.get(URL).query(&[("lang", "rust")]);

    rb = rb.query(&[("domains", domain)]);
    rb = rb.query(&[("token", duckdns_token)]);
    rb = rb.query(&[("txt", txt)]);

    if verbose {
        rb = rb.query(&[("verbose", "true")]);
    }

    let result = rb.send()?;
    let r2 = result.text()?;

    println!("duckdns response = {}", r2);

    Ok(())
}
