use std::os::raw::{c_char, c_int};

use aias_core::{verifyer, utils};

pub fn verify(signature: *const c_char, message: *const c_char, signer_pubkey: *const c_char, judge_pubkey: *const c_char) -> c_int {
    let signature_str = utils::from_c_str(signature);
    let message_str = utils::from_c_str(message);
    let signer_pubkey_str = utils::from_c_str(signer_pubkey);
    let judge_pubkey_str = utils::from_c_str(judge_pubkey);

    if verifyer::verify(signature_str, message_str, signer_pubkey_str, judge_pubkey_str) {
        1
    } else {
        0
    }
}