use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

use aias_core::sender;

#[no_mangle]
pub extern "system" fn Java_com_aias_aias_Aias_new(
    env: JNIEnv,
    class: JClass,
    input1: JString,
    input2: JString,
    input3: JString,
) {
    let input1: String = env
        .get_string(input1)
        .expect("Couldn't get java string!")
        .into();
    let input2: String = env
        .get_string(input2)
        .expect("Couldn't get java string!")
        .into();
    let input3: String = env
        .get_string(input3)
        .expect("Couldn't get java string!")
        .into();
    let id: u32 = input3.parse().expect("failed to parse id (u32)");

    sender::new(input1, input2, id);
}

#[no_mangle]
pub extern "system" fn Java_com_aias_aias_Aias_ready(
    env: JNIEnv,
    class: JClass,
    input1: JString,
    input2: JString,
) -> jstring {
    let input1: String = env
        .get_string(input1)
        .expect("Couldn't get java string!")
        .into();

    let input2: String = env
        .get_string(input2)
        .expect("Couldn't get java string!")
        .into();

    let result = sender::generate_ready_parameters(input1, input2);

    let output = env
        .new_string(result)
        .expect("Couldn't create java string!");

    output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_aias_aias_Aias_setSubset(
    env: JNIEnv,
    class: JClass,
    input: JString,
) {
    let input: String = env
        .get_string(input)
        .expect("Couldn't get java string!")
        .into();

    sender::set_subset(input);
}

#[no_mangle]
pub extern "system" fn Java_com_aias_aias_Aias_generateCheckParameter(
    env: JNIEnv,
    class: JClass,
) -> jstring {
    let output = sender::generate_check_parameters();
    let output = env
        .new_string(output)
        .expect("Couldn't create java string!");

    output.into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_aias_aias_Aias_unblind(
    env: JNIEnv,
    class: JClass,
    input: JString,
) -> jstring {
    let input = env
        .get_string(input)
        .expect("Couldn't get java string!")
        .into();

    let output = sender::unblind(input);
    let output = env
        .new_string(output)
        .expect("Couldn't create java string!");

    output.into_inner()
}
