use crate::crypto::RSAPubKey;


use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter, EncryptedMessage, Unblinder };
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};

use serde::Deserialize;

use crate::utils;


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
    let u64_vec_vec = serde_json::from_str(&blinded_digest);

    let blinded_digest: Vec<BigUint> = u64_vec_vec
        .iter()
        .map(|m| {
            let x = utils::from_u64_vec_le(m);
            BigUint::new(x)
        })
        .collect();
     
    let blinded_digest = BlindedDigest { m: blinded_digest };

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

    let p: Parameters = serde_json::from_str(&check_parameter).expect("Parsing json error");

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
     
    let mut is_vailed = false;

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let signer = odb.as_mut().unwrap();
        is_vailed = signer.check(check_parameter).unwrap();

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