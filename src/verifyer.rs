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
pub fn new_verifyer() {
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