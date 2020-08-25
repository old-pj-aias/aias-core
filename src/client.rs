use std::os::raw::{c_char};
use std::ffi::{CString, CStr};

use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender};
use std::cell::RefCell; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};



struct TestCipherPubkey {}

impl EJPubKey for TestCipherPubkey {
    fn encrypt(&self, message: String) -> String {
        return message;
    }

    fn dencrypt(&self, message: String) -> String {
        return message;
    }
}

thread_local!(static ODB: RefCell<Option<FBSSender<TestCipherPubkey>>> = RefCell::new(None)); 

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
        let mut odb = odb_cell.borrow_mut().as_mut(); 
        odb = Some(&mut FBSSender::new(parameters));
    }); 
}

pub fn destroy() {
    ODB.with(|odb_cell| { 
        let mut odb = odb_cell.borrow_mut().as_mut(); 
        odb = None;
    }); 
}


#[no_mangle]
pub extern fn init_aias_ios(){
    new();
}

#[no_mangle]
pub extern fn init_aias_ios_free() {
    destroy();
}


#[test]
fn test_init_and_destroy() {
    new();
    destroy();
}
