use std::ffi::{CString, CStr};
use std::os::raw::c_char;


pub fn get_c_string(to: *const c_char) -> String{
    let c_str = unsafe { CStr::from_ptr(to) };
    match c_str.to_str() {
        Err(_) => "".to_string(),
        Ok(string) => string.to_string(),
    }
}

pub fn free(s: *mut c_char) {
    unsafe {
        if s.is_null() { return }
        CString::from_raw(s)
    };
}

