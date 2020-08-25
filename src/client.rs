use std::os::raw::{c_char};
use std::ffi::{CString, CStr};

use fair_blind_signature::{EJPubKey, FBSParameters, FBSSender, BlindedDigest};
use std::cell::{RefCell, RefMut}; 

use rand::rngs::OsRng;
use rsa::{BigUint, PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts};


#[derive(Clone)]
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
        let mut odb  = odb_cell.borrow_mut().as_mut().unwrap().clone();
        let (digest, _ , _, _) = odb.blind("".to_string()).unwrap();

        serialized = serde_json::to_string(&digest).unwrap();
    });

    serialized
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
    blind("aaa".to_string());
    destroy();
}
