use fair_blind_signature::EJPubKey;
use rsa::{RSAPublicKey};
use std::os::raw::c_char;

use crate::utils;

#[derive(Clone)]
pub struct DistributedRSAPubKey {
    public_keys: Vec<RSAPublicKey>
}

impl DistributedRSAPubKey {
    pub fn new(public_keys: Vec<RSAPublicKey>) -> Self {
        DistributedRSAPubKey {
            public_keys
        }
    }

    pub fn from_json(json_str: String) -> Self {
        use serde_json::Value;

        let pks = match serde_json::from_str(&json_str).unwrap() {
            Value::Array(arr) => {
                arr
                    .iter()
                    .map(|v| {
                        if let Value::String(s) = v { s }
                        else { panic!("failed to parse json") }
                    })
            }, 
            _ => panic!("failed to get judge's public key")
        };

        let public_keys = pks
            .map(|pk| {
                let pkcs8 = pem::parse(pk).expect("failed to parse pem");
                RSAPublicKey::from_pkcs8(&pkcs8.contents)
                    .expect("failed to parse pkcs8")
            })
            .collect();

        Self::new(public_keys)
    }
}

impl EJPubKey for DistributedRSAPubKey {
    fn encrypt(&self, message: String) -> String {
        message
    }

    fn dencrypt(&self, message: String) -> String {
        message
    }
}