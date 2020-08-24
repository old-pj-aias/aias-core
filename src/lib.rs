use std::os::raw::{c_char};
use std::ffi::{CString, CStr};
use rand::Rng;

#[no_mangle]
pub extern fn rust_greeting(to: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(to) };
    let recipient = match c_str.to_str() {
        Err(_) => "there",
        Ok(string) => string,
    };

    let mut rng = rand::thread_rng();
    let random_int = rng.gen_range(0, 100);
    let random_str = format!("rand int: {}\n", random_int);

    CString::new(random_str + recipient).unwrap().into_raw()
}

#[no_mangle]
pub extern fn rust_greeting_free(s: *mut c_char) {
    unsafe {
        if s.is_null() { return }
        CString::from_raw(s)
    };
}

#[test]
fn test_rust_greeting() {
    let c_str = CString::new("Hello, world!").unwrap().into_raw();
    let to = rust_greeting(c_str);
    let c_str = unsafe { CStr::from_ptr(to) };
    let recipient = c_str.to_str().unwrap();
    println!("{}", recipient);
}
