use std::os::raw::{c_char, c_uint};
use std::ffi::{CString, CStr};

use aias_core::{sender, utils};

mod tests;


#[no_mangle]
pub extern fn new_ios(signer_pubkey: *const c_char, judge_pubkeys: *const c_char, id: c_uint) {
    let signer_pubkey = utils::from_c_str(signer_pubkey);
    let judge_pubkeys = utils::from_c_str(judge_pubkeys);
    let id = id as u32;

    sender::new(signer_pubkey, judge_pubkeys, id);
}

#[no_mangle]
pub extern fn blind_ios(to: *const c_char) -> *mut c_char {
    let recipient = utils::from_c_str(to);

    let result = sender::blind(recipient.to_string());
    utils::to_c_str(result)
}

#[no_mangle]
pub extern fn generate_ready_parameter_ios(to: *const c_char, judge_pubkey: *const c_char) -> *mut c_char{
    let recipient = utils::from_c_str(to);
    let pk = utils::from_c_str(judge_pubkey);

    let result = sender::generate_ready_parameters(recipient.to_string(), pk.to_string());
    utils::to_c_str(result)
}

#[no_mangle]
pub extern fn set_subset_ios(to: *const c_char) {
    let recipient = utils::from_c_str(to);
    sender::set_subset(recipient.to_string());
}

#[no_mangle]
pub extern fn generate_check_parameter_ios() -> *mut c_char{
    let result = sender::generate_check_parameters();
    utils::to_c_str(result)
}

#[no_mangle]
pub extern fn unblind_ios(to: *const c_char) -> *mut c_char{
    let recipient = utils::from_c_str(to);
    let result = sender::unblind(recipient);
    CString::new(result).unwrap().into_raw()
}

#[no_mangle]
pub extern fn destroy_ios() {
    sender::destroy();
}