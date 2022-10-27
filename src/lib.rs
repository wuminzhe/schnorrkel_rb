// modified from: https://github.com/paritytech/schnorrkel-js/blob/master/src/lib.rs

extern crate core;

mod wrapper;
use wrapper::*;

use libc::c_char;
use std::ffi::{CStr, CString};
use schnorrkel::{KEYPAIR_LENGTH, SECRET_KEY_LENGTH};

// hex str pointer -> string
fn hex_pointer_to_string(s: *const c_char) -> String {
    let c_str = unsafe {
        assert!(!s.is_null());
        CStr::from_ptr(s)
    };
    c_str.to_str().unwrap().to_owned()
}

fn hex_pointer_to_vecu8(s: *const c_char) -> Vec<u8> {
    hex::decode(hex_pointer_to_string(s)).unwrap()
}

fn u8a_to_hex_pointer(u8a: &[u8]) -> *mut c_char {
    let s = hex::encode(u8a.to_vec());
    let c_str = CString::new(s).unwrap();
    c_str.into_raw()
}

#[no_mangle]
pub extern "C" fn free_s(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        CString::from_raw(s)
    };
}

/// Perform a derivation on a secret
///
/// * secret: hex pointer of 64 bytes
/// * cc: hex pointer of 32 bytes
///
/// returned vector the derived keypair as hex pointer of 96 bytes
#[no_mangle]
pub extern "C" fn derive_keypair_hard(pair_p: *const c_char, cc_p: *const c_char) -> *mut c_char {
    let pair = hex_pointer_to_vecu8(pair_p);
    let cc = hex_pointer_to_vecu8(cc_p);
    let d = __derive_keypair_hard(pair.as_slice(), cc.as_slice());
    u8a_to_hex_pointer(&d)
}

/// Perform a derivation on a secret
///
/// * secret: UIntArray with 64 bytes
/// * cc: UIntArray with 32 bytes
///
/// returned vector the derived keypair as a array of 96 bytes
#[no_mangle]
pub fn derive_keypair_soft(pair_p: *const c_char, cc_p: *const c_char) -> *mut c_char {
    let pair = hex_pointer_to_vecu8(pair_p);
    let cc = hex_pointer_to_vecu8(cc_p);
    let d = __derive_keypair_soft(pair.as_slice(), cc.as_slice());
    u8a_to_hex_pointer(&d)
}

/// Sign a message
///
/// The combination of both public and private key must be provided.
/// This is effectively equivalent to a keypair.
///
/// * public: UIntArray with 32 element
/// * private: UIntArray with 64 element
/// * message: Arbitrary length hex pointer
///
/// * returned vector is the signature consisting of 64 bytes.
/// Sign a message
///
/// The combination of both public and private key must be provided.
/// This is effectively equivalent to a keypair.
///
/// * public: UIntArray with 32 element
/// * private: UIntArray with 64 element
/// * message: Arbitrary length UIntArray
///
/// * returned vector is the signature consisting of 64 bytes.
#[no_mangle]
pub fn sign(public_p: *const c_char, private_p: *const c_char, message_p: *const c_char) -> *mut c_char {
    let public = hex_pointer_to_vecu8(public_p);
    let private = hex_pointer_to_vecu8(private_p);
    let message = hex_pointer_to_vecu8(message_p);
    let signature = __sign(public.as_slice(), private.as_slice(), message.as_slice());
    u8a_to_hex_pointer(&signature)
}

/// Verify a message and its corresponding against a public key;
///
/// * signature: UIntArray with 64 element
/// * message: Arbitrary length UIntArray
/// * pubkey: UIntArray with 32 element
#[no_mangle]
pub fn verify(signature_p: *const c_char, message_p: *const c_char, pubkey_p: *const c_char) -> bool {
    let signature = hex_pointer_to_vecu8(signature_p);
    let pubkey = hex_pointer_to_vecu8(pubkey_p);
    let message = hex_pointer_to_vecu8(message_p);
    __verify(signature.as_slice(), message.as_slice(), pubkey.as_slice())
}

/// Generate a secret key (aka. private key) from a seed phrase.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the private key consisting of 64 bytes.
#[no_mangle]
pub fn secret_from_seed(seed_p: *const c_char) -> *mut c_char {
    let seed = hex_pointer_to_vecu8(seed_p);
    let secret = __secret_from_seed(seed.as_slice());
    u8a_to_hex_pointer(&secret)
}

/// Generate a key pair. .
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (64 bytes)
/// followed by the public key (32) bytes.
#[no_mangle]
pub fn keypair_from_seed(seed_p: *const c_char) -> *mut c_char {
    let seed = hex_pointer_to_vecu8(seed_p);
    let keypair = __keypair_from_seed(seed.as_slice());
    u8a_to_hex_pointer(&keypair)
}

#[no_mangle]
pub extern "C" fn sign_by_seed(message_p: *const c_char, seed_p: *const c_char) -> *mut c_char {
    let seed = hex_pointer_to_vecu8(seed_p);
    let keypair = wrapper::__keypair_from_seed(seed.as_slice());
    let private = &keypair[0..SECRET_KEY_LENGTH];
    let public = &keypair[SECRET_KEY_LENGTH..KEYPAIR_LENGTH];

    let message = hex_pointer_to_vecu8(message_p);
    let signature = wrapper::__sign(&public, &private, &message);
    // println!("{:?}", signature);
    u8a_to_hex_pointer(&signature)
}
