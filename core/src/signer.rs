use crate::crypto::RSAPubKey;


use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter, EncryptedMessage, Unblinder };
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};

use serde::Deserialize;

use crate::utils;


//thread_local!(static ODB: RefCell<Option<FBSSigner<RSAPubKey>>> = RefCell::new(None)); 

#[repr(C)]
pub struct Signer {
    signer: FBSSigner<RSAPubKey>
}

impl Signer {
    pub fn new(signer_privkey: String, signer_pubkey: String, judge_pubkey: String) -> Self {
        let signer_privkey = pem::parse(signer_privkey).expect("failed to parse pem");
        let signer_privkey = RSAPrivateKey::from_pkcs1(&signer_privkey.contents).expect("failed to parse pkcs8");

        let signer_pubkey = pem::parse(signer_pubkey).expect("failed to parse pem");
        let signer_pubkey = RSAPublicKey::from_pkcs8(&signer_pubkey.contents).expect("failed to parse pkcs8");

        let judge_pubkey = pem::parse(judge_pubkey).expect("failed to parse pem");
        let judge_pubkey = RSAPublicKey::from_pkcs8(&judge_pubkey.contents).expect("failed to parse pkcs8");

        let judge_pubkey = RSAPubKey {
            public_key: judge_pubkey
        };

        let parameters = FBSParameters {
            signer_pubkey: signer_pubkey,
            judge_pubkey: judge_pubkey,
            k: 40,
            id: 10
        };

        Signer {
            signer: FBSSigner::new(parameters, signer_privkey)
        }
    }

    pub fn set_blinded_digest(&mut self, blinded_digest: String) {
        let u64_vec_vec = serde_json::from_str(&blinded_digest);

        let blinded_digest: Vec<BigUint> = u64_vec_vec
            .iter()
            .map(|m| {
                let x = utils::from_u64_vec_le(m);
                BigUint::new(x)
            })
            .collect();
        
        let blinded_digest = BlindedDigest { m: blinded_digest };

        self.signer.set_blinded_digest(blinded_digest);
    }


    pub fn setup_subset(&mut self) -> String {
        let subset = self.signer.setup_subset();
        serde_json::to_string(&subset).unwrap_or("".to_string())
    }

    pub fn check(&mut self, check_parameter: String) -> bool {
        #[derive(Deserialize)]
        struct Parameters {
            part_of_encrypted_message: EncryptedMessage,
            part_of_unblinder: Unblinder_,
            part_of_beta: Vec<u8>
        }
        #[derive(Deserialize)]
        struct Unblinder_ {
            r: Vec<Vec<u64>>
        }

        let p: Parameters = match serde_json::from_str(&check_parameter) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("failed to parse json: {}", e);
                return false;
            }
        };

        let r: Vec<BigUint> = p.part_of_unblinder.r
            .iter()
            .map(|m| {
                let x = utils::from_u64_vec_le(m);
                BigUint::new(x)
            })
            .collect();
        let part_of_unblinder = Unblinder { r };

        let check_parameter = CheckParameter {
            part_of_encrypted_message: p.part_of_encrypted_message,
            part_of_unblinder: part_of_unblinder,
            part_of_beta: p.part_of_beta
        };
        
        self.signer.check(check_parameter).unwrap_or(false)
    }

    pub fn sign(&self) -> String {
        let signature = match self.signer.sign() {
            Some(v) => serde_json::to_string(&v),
            None => {
                eprintln!("failed to sign");
                return "".to_string();
            }
        };

        signature.unwrap_or_else(|e| {
            eprintln!("failed to convert to string: {}", e);
            "".to_string()
        })
    }
}