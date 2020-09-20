use crate::crypto::RSAPubKey;
use crate::signer::ReadyParams;
use crate::DEFAULT_K;

use fair_blind_signature::{BlindSignature, FBSParameters, FBSSender, Subset};

use std::cell::RefCell;

use rsa::RSAPublicKey;

thread_local!(static ODB: RefCell<Option<FBSSender<RSAPubKey>>> = RefCell::new(None));

pub fn new(signer_pubkey: String, judge_pubkeys: String, id: u32) {
    let signer_pubkey = pem::parse(signer_pubkey).expect("failed to parse pem");
    let signer_pubkey =
        RSAPublicKey::from_pkcs8(&signer_pubkey.contents).expect("failed to parse pkcs8");

    let judge_pubkey = pem::parse(judge_pubkeys).expect("failed to parse pem");
    let judge_pubkey =
        RSAPublicKey::from_pkcs8(&judge_pubkey.contents).expect("failed to parse pkcs8");
    let judge_pubkey = RSAPubKey {
        public_key: judge_pubkey,
    };

    let k = DEFAULT_K;

    let parameters = FBSParameters {
        signer_pubkey,
        judge_pubkey,
        k,
        id,
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
    let digest = ODB.with(|odb_cell| {
        let mut odb = odb_cell.borrow_mut();
        let sender = odb.as_mut().unwrap();
        let (digest, _, _, _) = sender.blind(message).unwrap();

        digest
    });

    serde_json::to_string(&digest).unwrap()
}

pub fn generate_ready_parameters(message: String, judge_pubkey: String) -> String {
    let digest = ODB.with(|odb_cell| {
        let mut odb = odb_cell.borrow_mut();
        let sender = odb.as_mut().unwrap();
        let (digest, _, _, _) = sender.blind(message).unwrap();

        digest
    });

    let params = ReadyParams {
        judge_pubkey,
        blinded_digest: digest,
    };

    serde_json::to_string(&params).unwrap()
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
    let check_parameters = ODB.with(|odb_cell| {
        let mut odb = odb_cell.borrow_mut();
        let sender = odb.as_mut().unwrap();

        sender.generate_check_parameter().unwrap()
    });

    serde_json::to_string(&check_parameters).unwrap()
}

pub fn unblind(blind_signature: String) -> String {
    let blind_signature: BlindSignature =
        serde_json::from_str(&blind_signature).expect("Parsing json error");

    let signature = ODB.with(|odb_cell| {
        let mut odb = odb_cell.borrow_mut();
        let sender = odb.as_mut().unwrap();

        sender.unblind(blind_signature).unwrap()
    });

    serde_json::to_string(&signature).unwrap()
}
