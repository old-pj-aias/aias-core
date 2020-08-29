use crate::crypto::RSAPubKey;


use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter };
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};


thread_local!(static ODB: RefCell<Option<FBSSigner<RSAPubKey>>> = RefCell::new(None)); 

pub fn new(signer_privkey: String, signer_pubkey: String, judge_pubkey: String) {
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

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        *odb = Some(FBSSigner::new(parameters, signer_privkey));
    }); 
}

pub fn destroy() {
    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut(); 
        *odb = None;
    }); 
}

pub fn set_blinded_digest(blinded_digest: String) {
    let blinded_digest: BlindedDigest = serde_json::from_str(&blinded_digest).expect("Parsing json error");

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let signer = odb.as_mut().unwrap();
        signer.set_blinded_digest(blinded_digest);
    }); 
}


pub fn setup_subset() -> String {
    let mut serialized = "".to_string();

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let signer = odb.as_mut().unwrap();
        let subset = signer.setup_subset();

        serialized = serde_json::to_string(&subset).unwrap();
    });

    serialized
}


pub fn check(check_parameter: String) -> bool {
    let check_parameter: CheckParameter = serde_json::from_str(&check_parameter).expect("Parsing json error");

    let mut is_vailed = false;

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let signer = odb.as_mut().unwrap();
        is_vailed = signer.check(check_parameter);

    });

    is_vailed
}

pub fn sign() -> String {
    let mut serialized = "".to_string();

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let signer = odb.as_mut().unwrap();
        let blind_signature = signer.sign().unwrap();
        serialized = serde_json::to_string(&blind_signature).unwrap();
    });

    serialized
}
