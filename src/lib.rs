// mod wrapper;

extern crate core;

mod wrapper;

use libc::c_char;
use std::ffi::CString;
use std::slice;
use hex_literal::hex;

use schnorrkel::{KEYPAIR_LENGTH, SECRET_KEY_LENGTH};

use schnorrkel::{ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey, Signature, SIGNATURE_LENGTH, signing_context};
fn to_u8_slice(pointer: *const u8, len: usize) -> Vec<u8> {
    let data_slice = unsafe {
        assert!(!pointer.is_null());
        slice::from_raw_parts(pointer, len)
    };
    data_slice.to_vec()
}

#[no_mangle]
pub extern "C" fn my_free(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        CString::from_raw(s)
    };
}

#[no_mangle]
pub extern "C" fn sign(
    message_p: *const u8, message_len: usize,
    seed_p: *const u8, seed_len: usize,
) ->  *mut c_char {

    // // let seed = to_u8_slice(seed_p, seed_len);
    // let seed = [200, 250, 3, 83, 47, 178, 46, 225, 247, 246, 144, 139, 156, 2, 180, 231, 36, 131, 240, 219, 214, 110, 76, 212, 86, 184, 243, 76, 98, 48, 184, 73];
    // // let keypair = wrapper::__keypair_from_seed(seed.as_slice());
    // let mini_key: MiniSecretKey = MiniSecretKey::from_bytes(&seed)
    //     .expect("32 bytes can always build a key; qed");
    // let s = mini_key.expand(ExpansionMode::Ed25519);
    // let private = s.to_bytes();
    // let public = s.to_public().to_bytes();
    //
    // let message = [104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100];
    // let mut signature = wrapper::__sign(&public, &private, &message);
    // signature.as_mut_ptr()


    // let context = signing_context(b"substrate");
    // let message = to_u8_slice(message_p, message_len);
    // let signature: Signature = keypair.sign(context.bytes(message.as_slice()));
    // let sig_bytes = signature.to_bytes();
    // let ptr = signature.to_bytes().as_mut_ptr();
    // std::mem::forget(sig_bytes);
    // ptr

    let seed = hex!("c8fa03532fb22ee1f7f6908b9c02b4e72483f0dbd66e4cd456b8f34c6230b849");
    let keypair = wrapper::sr25519_keypair_from_seed(&seed);
    let private = &keypair[0..SECRET_KEY_LENGTH];
    let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

    let message = hex!("68656c6c6f2c20776f726c64");
    let mut signature = wrapper::__sign(&public, &private, &message);
    println!("{:?}", signature);
    let s = hex::encode(signature.to_vec());
    let c_str = CString::new(s).unwrap();
    c_str.into_raw()

    // let ptr = signature.as_mut_ptr();
    // std::mem::forget(signature);
    // ptr
}
