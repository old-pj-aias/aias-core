use crate::crypto::TestCipherPubkey;
use crate::utils;

use std::os::raw::c_char;
use std::ffi::{CString, CStr};

use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest, BlindSignature, Subset, FBSSigner, CheckParameter };
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};



thread_local!(static ODB: RefCell<Option<FBSSigner<TestCipherPubkey>>> = RefCell::new(None)); 

#[no_mangle]
pub fn new() {
    let mut rng = OsRng;
    let bits = 2048;
    let signer_privkey = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let signer_pubkey = RSAPublicKey::from(&signer_privkey);

    let judge_pubkey = TestCipherPubkey {};

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

#[no_mangle]
pub fn destroy() {
    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut(); 
        *odb = None;
    }); 
}

#[no_mangle]
pub fn set_blinded_digest(blinded_digest: String) {
    let blinded_digest: BlindedDigest = serde_json::from_str(&blinded_digest).expect("Parsing json error");

    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut();
        let signer = odb.as_mut().unwrap();
        signer.set_blinded_digest(blinded_digest);
    }); 
}


#[no_mangle]
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
