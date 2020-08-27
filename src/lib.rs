mod utils;
mod crypto;
mod sender;
mod signer;
mod verifyer;
mod tests;

use jni::objects::{JClass, JString};
use jni::JNIEnv;
use jni::sys::jstring;

#[no_mangle]
pub extern "system" fn Java_com_aias_aias_Aias_new(env: JNIEnv,
                                             class: JClass,
                                             input: JString) {
    let input: String = 
        env.get_string(input).expect("Couldn't get java string!").into();

    sender::new(input);
 }

