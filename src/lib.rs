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

#[no_mangle]
pub extern "system" fn Java_com_aias_aias_Aias_blind(env: JNIEnv,
                                             class: JClass,
                                             input: JString) -> jstring {
    let input: String = 
        env.get_string(input).expect("Couldn't get java string!").into();

    let output = sender::blind(input);

    let output = env.new_string(output)
        .expect("Couldn't create java string!");

    output.into_inner()
 }

 #[no_mangle]
pub extern "system" fn Java_com_aias_aias_Aias_setSubset(env: JNIEnv,
                                             class: JClass,
                                             input: JString) {
    let input: String = 
        env.get_string(input).expect("Couldn't get java string!").into();

    sender::set_subset(input);
 }

