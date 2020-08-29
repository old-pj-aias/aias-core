use crate::crypto::RSAPubKey;
use crate::utils;


use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter, Signature , FBSVerifyer};
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};

thread_local!(static ODB: RefCell<Option<FBSVerifyer<RSAPubKey>>> = RefCell::new(None)); 



#[no_mangle]
pub fn new_verifyer(signer_pubkey: *const c_char, judge_pubkeys: *const c_char) {
    let signer_pubkey = utils::from_c_str(signer_pubkey);
    let signer_pubkey = pem::parse(signer_pubkey).expect("failed to parse pem");
    let signer_pubkey = RSAPublicKey::from_pkcs8(&signer_pubkey.contents).expect("failed to parse pkcs8");

    let judge_pubkeys = utils::from_c_str(judge_pubkeys);
    let judge_pubkeys = pem::parse(judge_pubkeys).expect("failed to parse pem");
    let judge_pubkeys = RSAPublicKey::from_pkcs8(&judge_pubkeys.contents).expect("failed to parse pkcs8");

    let judge_pubkeys = RSAPubKey{
        public_key: judge_pubkeys
    };
    
    // let judge_pubkeys = MyRSAPubkey::from_json(judge_pubkeys_str);

    let parameters = FBSParameters {
        signer_pubkey: signer_pubkey,
        judge_pubkey: judge_pubkeys,
        k: 40,
        id: 10
    };

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        *odb = Some(FBSVerifyer::new(parameters));
    });
}

#[no_mangle]
pub fn destroy_verifyer() {
    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut(); 
        *odb = None;
    }); 
}


#[no_mangle]
pub fn verify(signature: *const c_char, message: *const c_char) -> bool {
    let mut is_vailed = false;

    let message = utils::from_c_str(message);
    
    let signature = utils::from_c_str(signature);
    let signature: Signature = serde_json::from_str(&signature).expect("Parsing json error");

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let verifyer = odb.as_mut().unwrap();
       
        is_vailed = verifyer.verify(signature, message);
    });

    is_vailed
}
