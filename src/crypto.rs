use std::fmt::Debug;
use crate::error;
use crate::jwt::Jwk;

pub trait PKey: Sized {
    type Error: Sized + Into<error::Error> + Debug;

    fn from_pem(pem: &str) -> Result<Self, Self::Error>;
    fn to_pem(&self) -> Result<String, Self::Error>;

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    fn new() -> Result<Self, Self::Error>;
}

pub trait Csr: Sized {
    type Error: Sized + Into<error::Error> + Debug;
    type PrivateKey: PKey<Error=Self::Error> + Debug + Clone;

    fn new(key: &Self::PrivateKey, domains: &[&str]) -> Result<Self, Self::Error>;
    fn from_pem(pem: &str) -> Result<Self, Self::Error>;
    fn to_der(&self) -> Result<Vec<u8>, Self::Error>;
    fn to_pem(&self) -> Result<Vec<u8>, Self::Error>;
}

pub trait Certificate: Sized {
    type Error: Sized + Into<error::Error> + Debug;

    fn from_pem(pem: &str) -> Result<Self, Self::Error>;
    fn to_pem(&self) -> Result<Vec<u8>, Self::Error>;
    fn to_der(&self) -> Result<Vec<u8>, Self::Error>;

    fn valid_days_left(&self) -> i64;
}


pub trait Crypto: Clone + Default where for <'a> &'a Self::AccountKey: Into<Jwk>  {
    type Error: Sized + Into<error::Error> + Debug;

    type AccountKey: PKey<Error=Self::Error> + Debug + Clone;
    type PrivateKey: PKey<Error=Self::Error> + Debug + Clone;
    type Csr: Csr<Error=Self::Error, PrivateKey = Self::PrivateKey> + Debug + Clone;
    type Certificate: Certificate<Error = Self::Error>;

    fn sha256(input: &[u8]) -> [u8; 32];
}
