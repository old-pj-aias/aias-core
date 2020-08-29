use crate::crypto::{DistributedRSAPubKey, MyRSAPubkey};
use crate::utils;


use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter };
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};


thread_local!(static ODB: RefCell<Option<FBSSender<MyRSAPubkey>>> = RefCell::new(None)); 

pub fn new(signer_pubkey: String, judge_pubkeys: String) {
    let signer_pubkey = pem::parse(signer_pubkey).expect("failed to parse pem");
    let signer_pubkey = RSAPublicKey::from_pkcs8(&signer_pubkey.contents).expect("failed to parse pkcs8");

    let judge_pubkeys = pem::parse(judge_pubkeys).expect("failed to parse pem");
    let judge_pubkeys = RSAPublicKey::from_pkcs8(&judge_pubkeys.contents).expect("failed to parse pkcs8");
    let judge_pubkey = MyRSAPubkey {public_key: judge_pubkeys};

    let parameters = FBSParameters {
        signer_pubkey,
        judge_pubkey,
        k: 40,
        id: 10
    };

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        *odb = Some(FBSSender::new(parameters));
    }); 
}

pub fn destroy() {
    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut(); 
        *odb = None;
    }); 
}

pub fn blind(message: String) -> String {
    let mut serialized = "".to_string();

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let sender = odb.as_mut().unwrap();
        let (digest, _ , _, _) = sender.blind(message).unwrap();

        serialized = serde_json::to_string(&digest).unwrap();
    });

    serialized
}

pub fn set_subset(subset: String) {
    let subset: Subset = serde_json::from_str(&subset).expect("Parsing json error");

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let sender = odb.as_mut().unwrap();
        
        sender.set_subset(subset);
    });
}

pub fn generate_check_parameters() -> String {
    let mut serialized = "".to_string();

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let sender = odb.as_mut().unwrap();
       
        let check_parameters = sender.generate_check_parameter().unwrap();
        serialized = serde_json::to_string(&check_parameters).unwrap();
    });

    serialized
}

pub fn unblind(blind_signature: String) -> String {
    let blind_signature: BlindSignature = serde_json::from_str(&blind_signature).expect("Parsing json error");

    let mut serialized = "".to_string();

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let sender = odb.as_mut().unwrap();
       
        let signature = sender.unblind(blind_signature).unwrap();
        serialized = serde_json::to_string(&signature).unwrap();
    });

    serialized
}

#[no_mangle]
pub extern fn new_ios(signer_pubkey: *const c_char, judge_pubkeys: *const c_char) {
    let signer_pubkey = utils::from_c_str(signer_pubkey);
    let judge_pubkeys = utils::from_c_str(judge_pubkeys);

    new(signer_pubkey, judge_pubkeys);
}

#[no_mangle]
pub extern fn blind_ios(to: *const c_char) -> *mut c_char{
    let recipient = utils::from_c_str(to);
    let result = blind(recipient.to_string());
    utils::to_c_str(result)
}

#[no_mangle]
pub extern fn set_subset_ios(to: *const c_char) {
    let recipient = utils::from_c_str(to);
    set_subset(recipient.to_string());
}

#[no_mangle]
pub extern fn generate_check_parameter_ios() -> *mut c_char{
    let result = generate_check_parameters();
    utils::to_c_str(result)
}

#[no_mangle]
pub extern fn unblind_ios(to: *const c_char) -> *mut c_char{
    let recipient = utils::from_c_str(to);
    let result = unblind(recipient);
    CString::new(result).unwrap().into_raw()
}
