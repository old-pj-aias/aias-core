use crate::crypto::{DistributedRSAPrivKey, RSAPubKey};

use fair_blind_signature::{ Signature, Judge };
use serde_json;

use rsa::{RSAPrivateKey, RSAPublicKey};
use std::cell::RefCell; 
use rand::rngs::OsRng;
use fair_blind_signature::EJPrivKey;

thread_local!(static ODB: RefCell<Option<Judge<DistributedRSAPrivKey>>> = RefCell::new(None)); 


pub fn divide_keys(prevkey: String, pubkey: String) -> DistributedRSAPrivKey {
    let mut rng = OsRng;
    let bits = 2048;
    
    let privkey = pem::parse(prevkey).expect("failed to parse pem");
    let privkey = RSAPrivateKey::from_pkcs1(&privkey.contents).expect("failed to parse pkcs1");

    let pubkey = pem::parse(pubkey).expect("failed to parse pem");
    let pubkey = RSAPublicKey::from_pkcs8(&pubkey.contents).expect("failed to parse pkcs8");

    let privkey = DistributedRSAPrivKey::new(&privkey, &pubkey);

    return privkey;
}

pub fn open(signature: String, judge_privkey: DistributedRSAPrivKey) -> Vec<String> {
    let signature : Signature = serde_json::from_str(&signature).unwrap();

    let judge = Judge::new(judge_privkey);
    judge.open(signature.encrypted_id)
}