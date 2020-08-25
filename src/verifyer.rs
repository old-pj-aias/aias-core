use crate::crypto::TestCipherPubkey;
use crate::utils;


use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter, Signature , FBSVerifyer};
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};

thread_local!(static ODB: RefCell<Option<FBSVerifyer<TestCipherPubkey>>> = RefCell::new(None)); 



#[no_mangle]
pub fn new_verifyer(signer_pubkey: String) {
    let signer_pubkey = pem::parse(signer_pubkey).expect("failed to parse pem");
    let signer_pubkey = RSAPublicKey::from_pkcs8(&signer_pubkey.contents).expect("failed to parse pkcs8");

    let judge_pubkey = TestCipherPubkey {};

    let parameters = FBSParameters {
        signer_pubkey: signer_pubkey,
        judge_pubkey: judge_pubkey,
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
pub fn verify(signature: String, message: String) -> bool {
    let mut is_vailed = false;
    let signature: Signature = serde_json::from_str(&signature).expect("Parsing json error");

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let verifyer = odb.as_mut().unwrap();
       
        is_vailed = verifyer.clone().verify(signature, message).unwrap();
    });

    is_vailed
}