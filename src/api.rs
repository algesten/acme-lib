//! Low level API JSON objects.
//!
//! Unstable and not to be used directly. Provided to aid debugging.
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use serde::{
    ser::{SerializeMap, Serializer},
    Deserialize, Serialize,
};

/// Serializes to `""`
pub struct ApiEmptyString;
impl Serialize for ApiEmptyString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("")
    }
}

/// Serializes to `{}`
pub struct ApiEmptyObject;
impl Serialize for ApiEmptyObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let m = serializer.serialize_map(Some(0))?;
        m.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ApiProblem {
    #[serde(rename = "type")]
    pub _type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subproblems: Option<Vec<ApiSubproblem>>,
}

impl ApiProblem {
    pub fn is_bad_nonce(&self) -> bool {
        self._type == "badNonce"
    }
}

impl ::std::fmt::Display for ApiProblem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        if let Some(detail) = &self.detail {
            write!(f, "{}: {}", self._type, detail)
        } else {
            write!(f, "{}", self._type)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ApiSubproblem {
    #[serde(rename = "type")]
    pub _type: String,
    pub detail: Option<String>,
    pub identifier: Option<ApiIdentifier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ApiDirectory {
    pub newNonce: String,
    pub newAccount: String,
    pub newOrder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newAuthz: Option<String>,
    pub revokeCert: String,
    pub keyChange: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ApiDirectoryMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ApiDirectoryMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub termsOfService: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caaIdentities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub externalAccountRequired: Option<bool>,
}

impl ApiDirectoryMeta {
    pub fn externalAccountRequired(&self) -> bool {
        self.externalAccountRequired.unwrap_or(false)
    }
}

//    {
//      "status": "valid",
//      "contact": [
//        "mailto:cert-admin@example.com",
//        "mailto:admin@example.com"
//      ],
//      "termsOfServiceAgreed": true,
//      "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
//    }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ApiAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub contact: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub termsOfServiceAgreed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orders: Option<String>,
}

impl ApiAccount {
    pub fn is_status_valid(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("valid")
    }
    pub fn is_status_deactivated(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("deactivated")
    }
    pub fn is_status_revoked(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("revoked")
    }
    pub fn termsOfServiceAgreed(&self) -> bool {
        self.termsOfServiceAgreed.unwrap_or(false)
    }
}

// {
//   "status": "pending",
//   "expires": "2019-01-09T08:26:43.570360537Z",
//   "identifiers": [
//     {
//       "type": "dns",
//       "value": "acmetest.algesten.se"
//     }
//   ],
//   "authorizations": [
//     "https://example.com/acme/authz/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs"
//   ],
//   "finalize": "https://example.com/acme/finalize/7738992/18234324"
// }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ApiOrder {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    pub identifiers: Vec<ApiIdentifier>,
    pub notBefore: Option<String>,
    pub notAfter: Option<String>,
    pub error: Option<ApiProblem>,
    pub authorizations: Option<Vec<String>>,
    pub finalize: String,
    pub certificate: Option<String>,
}

impl ApiOrder {
    /// As long as there are outstanding authorizations.
    pub fn is_status_pending(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("pending")
    }
    /// When all authorizations are finished, and we need to call
    /// "finalize".
    pub fn is_status_ready(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("ready")
    }
    /// On "finalize" the server is processing to sign CSR.
    pub fn is_status_processing(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("processing")
    }
    /// Once the certificate is issued and can be downloaded.
    pub fn is_status_valid(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("valid")
    }
    /// If the order failed and can't be used again.
    pub fn is_status_invalid(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("invalid")
    }
    /// Return all domains
    pub fn domains(&self) -> Vec<&str> {
        self.identifiers.iter().map(|i| i.value.as_ref()).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiIdentifier {
    #[serde(rename = "type")]
    pub _type: String,
    pub value: String,
}

impl ApiIdentifier {
    pub fn is_type_dns(&self) -> bool {
        self._type == "dns"
    }
}

// {
//   "identifier": {
//     "type": "dns",
//     "value": "acmetest.algesten.se"
//   },
//   "status": "pending",
//   "expires": "2019-01-09T08:26:43Z",
//   "challenges": [
//     {
//       "type": "http-01",
//       "status": "pending",
//       "url": "https://example.com/acme/challenge/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs/216789597",
//       "token": "MUi-gqeOJdRkSb_YR2eaMxQBqf6al8dgt_dOttSWb0w"
//     },
//     {
//       "type": "tls-alpn-01",
//       "status": "pending",
//       "url": "https://example.com/acme/challenge/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs/216789598",
//       "token": "WCdRWkCy4THTD_j5IH4ISAzr59lFIg5wzYmKxuOJ1lU"
//     },
//     {
//       "type": "dns-01",
//       "status": "pending",
//       "url": "https://example.com/acme/challenge/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs/216789599",
//       "token": "RRo2ZcXAEqxKvMH8RGcATjSK1KknLEUmauwfQ5i3gG8"
//     }
//   ]
// }

// on incorrect challenge, something like:
//
//   "challenges": [
//     {
//       "type": "dns-01",
//       "status": "invalid",
//       "error": {
//         "type": "urn:ietf:params:acme:error:dns",
//         "detail": "DNS problem: NXDOMAIN looking up TXT for _acme-challenge.martintest.foobar.com",
//         "status": 400
//       },
//       "url": "https://example.com/acme/challenge/afyChhlFB8GLLmIqEnqqcXzX0Ss3GBw6oUlKAGDG6lY/221695600",
//       "token": "YsNqBWZnyYjDun3aUC2CkCopOaqZRrI5hp3tUjxPLQU"
//     },
// "Incorrect TXT record \"caOh44dp9eqXNRkd0sYrKVF8dBl0L8h8-kFpIBje-2c\" found at _acme-challenge.martintest.foobar.com
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiAuth {
    pub identifier: ApiIdentifier,
    pub status: Option<String>,
    pub expires: Option<String>,
    pub challenges: Vec<ApiChallenge>,
    pub wildcard: Option<bool>,
}

impl ApiAuth {
    pub fn is_status_pending(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("pending")
    }
    pub fn is_status_valid(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("valid")
    }
    pub fn is_status_invalid(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("invalid")
    }
    pub fn is_status_deactivated(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("deactivated")
    }
    pub fn is_status_expired(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("expired")
    }
    pub fn is_status_revoked(&self) -> bool {
        self.status.as_ref().map(|s| s.as_ref()) == Some("revoked")
    }
    pub fn wildcard(&self) -> bool {
        self.wildcard.unwrap_or(false)
    }
    pub fn http_challenge(&self) -> Option<&ApiChallenge> {
        self.challenges.iter().find(|c| c._type == "http-01")
    }
    pub fn dns_challenge(&self) -> Option<&ApiChallenge> {
        self.challenges.iter().find(|c| c._type == "dns-01")
    }
    pub fn tls_alpn_challenge(&self) -> Option<&ApiChallenge> {
        self.challenges.iter().find(|c| c._type == "tls-alpn-01")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiChallenge {
    pub url: String,
    #[serde(rename = "type")]
    pub _type: String,
    pub status: String,
    pub token: String,
    pub validated: Option<String>,
    pub error: Option<ApiProblem>,
}

// {
//   "type": "http-01",
//   "status": "pending",
//   "url": "https://acme-staging-v02.api.letsencrypt.org/acme/challenge/YTqpYUthlVfwBncUufE8IRA2TkzZkN4eYWWLMSRqcSs/216789597",
//   "token": "MUi-gqeOJdRkSb_YR2eaMxQBqf6al8dgt_dOttSWb0w"
// }
impl ApiChallenge {
    pub fn is_status_pending(&self) -> bool {
        &self.status == "pending"
    }
    pub fn is_status_processing(&self) -> bool {
        &self.status == "processing"
    }
    pub fn is_status_valid(&self) -> bool {
        &self.status == "valid"
    }
    pub fn is_status_invalid(&self) -> bool {
        &self.status == "invalid"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiFinalize {
    pub csr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiRevocation {
    pub certificate: String,
    pub reason: usize,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_api_empty_string() {
        let x = serde_json::to_string(&ApiEmptyString).unwrap();
        assert_eq!("\"\"", x);
    }

    #[test]
    fn test_api_empty_object() {
        let x = serde_json::to_string(&ApiEmptyObject).unwrap();
        assert_eq!("{}", x);
    }

}
