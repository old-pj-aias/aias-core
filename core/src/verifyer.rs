use crate::crypto::RSAPubKey;
use crate::utils;


use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter, Signature , FBSVerifyer};
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};


pub fn verify(signature: String, message: String, signer_pubkey: String, judge_pubkeys: String) -> bool {
    let is_vailed = false;

    let signature: Signature = serde_json::from_str(&signature).expect("Parsing json error");

    let signer_pubkey = pem::parse(signer_pubkey).expect("failed to parse pem");
    let signer_pubkey = RSAPublicKey::from_pkcs8(&signer_pubkey.contents).expect("failed to parse pkcs8");

    let judge_pubkeys = pem::parse(judge_pubkeys).expect("failed to parse pem");
    let judge_pubkeys = RSAPublicKey::from_pkcs8(&judge_pubkeys.contents).expect("failed to parse pkcs8");

    let judge_pubkeys = RSAPubKey{
        public_key: judge_pubkeys
    };
    
    let parameters = FBSParameters {
        signer_pubkey: signer_pubkey,
        judge_pubkey: judge_pubkeys,
        k: 40,
        id: 10
    };
    
    let verifyer = FBSVerifyer::new(parameters);
    verifyer.verify(signature, message)
}
