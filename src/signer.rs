use crate::crypto::DistributedRSAPubKey;
use crate::utils;

use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter };
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};



thread_local!(static ODB: RefCell<Option<FBSSigner<DistributedRSAPubKey>>> = RefCell::new(None)); 

#[no_mangle]
pub fn new(signer_privkey: *const c_char, signer_pubkey: *const c_char, judge_pubkeys: *const c_char) {
    let signer_privkey = utils::from_c_str(signer_privkey);
    let signer_privkey = pem::parse(signer_privkey).expect("failed to parse pem");
    let signer_privkey = RSAPrivateKey::from_pkcs1(&signer_privkey.contents).expect("failed to parse pkcs8");

    let signer_pubkey = utils::from_c_str(signer_pubkey);
    let signer_pubkey = pem::parse(signer_pubkey).expect("failed to parse pem");
    let signer_pubkey = RSAPublicKey::from_pkcs8(&signer_pubkey.contents).expect("failed to parse pkcs8");

    let judge_pubkeys_str = utils::from_c_str(judge_pubkeys);
    let judge_pubkeys = DistributedRSAPubKey::from_json(judge_pubkeys_str);

    let parameters = FBSParameters {
        signer_pubkey: signer_pubkey,
        judge_pubkey: judge_pubkeys,
        k: 40,
        id: 10
    };

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        *odb = Some(FBSSigner::new(parameters, signer_privkey));
    }); 
}

#[no_mangle]
pub fn destroy() {
    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut(); 
        *odb = None;
    }); 
}

#[no_mangle]
pub fn set_blinded_digest(blinded_digest: *const c_char) {
    let blinded_digest = utils::from_c_str(blinded_digest);
    let blinded_digest: BlindedDigest = serde_json::from_str(&blinded_digest).expect("Parsing json error");

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let signer = odb.as_mut().unwrap();
        signer.set_blinded_digest(blinded_digest);
    }); 
}


#[no_mangle]
pub fn setup_subset() -> *mut c_char {
    let mut serialized = "".to_string();

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let signer = odb.as_mut().unwrap();
        let subset = signer.setup_subset();

        serialized = serde_json::to_string(&subset).unwrap();
    });

    utils::to_c_str(serialized)
}


#[no_mangle]
pub fn check(check_parameter: *const c_char) -> bool {
    let check_parameter = utils::from_c_str(check_parameter);
    let check_parameter: CheckParameter = serde_json::from_str(&check_parameter).expect("Parsing json error");

    let mut is_vailed = false;

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let signer = odb.as_mut().unwrap();
        is_vailed = signer.check(check_parameter).unwrap();

    });

    is_vailed
}

#[no_mangle]
pub fn sign() -> *mut c_char {
    let mut serialized = "".to_string();

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let signer = odb.as_mut().unwrap();
        let blind_signature = signer.sign().unwrap();
        serialized = serde_json::to_string(&blind_signature).unwrap();
    });

    utils::to_c_str(serialized)
}