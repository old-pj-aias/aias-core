use std::ffi::{CString, CStr};
use std::os::raw::c_char;

use aias_core::utils;
use aias_core::signer::Signer;


#[no_mangle]
pub extern "C" fn new(signer_privkey: *const c_char, signer_pubkey: *const c_char, judge_pubkey: *const c_char) -> Signer {
    let signer_privkey = utils::from_c_str(signer_privkey);
    let signer_pubkey = utils::from_c_str(signer_pubkey);
    let judge_pubkey = utils::from_c_str(judge_pubkey);

    Signer::new(signer_privkey, signer_pubkey, judge_pubkey)
}

#[no_mangle]
pub extern "C" fn destroy(signer: Signer) {
}

#[no_mangle]
pub extern "C" fn set_blinded_digest(signer: &mut Signer, blinded_digest: *const c_char) {
    let blinded_digest = utils::from_c_str(blinded_digest);
    signer.set_blinded_digest(blinded_digest);
}


#[no_mangle]
pub extern "C" fn setup_subset(signer: &mut Signer, ) -> *mut c_char {
    let serialized = signer.setup_subset();

    utils::to_c_str(serialized)
}


#[no_mangle]
pub extern "C" fn check(signer: &mut Signer, check_parameter: *const c_char) -> bool {
    let check_parameter = utils::from_c_str(check_parameter);

    signer.check(check_parameter)
}

#[no_mangle]
pub extern "C" fn sign(signer: &mut Signer) -> *mut c_char {
    let serialized = signer.sign();

    utils::to_c_str(serialized)
}