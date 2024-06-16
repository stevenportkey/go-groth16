use crate::utils::{
    do_prove, do_verify, load_context, ret_or_err, serialize, write_to_buffer, ProvingContext,
};
use std::ffi::CStr;

#[no_mangle]
pub unsafe extern "C" fn groth16_verify_bn254(
    vk: *const cty::c_char,
    proving_output: *const cty::c_char,
) -> cty::c_int {
    let vk = unsafe { CStr::from_ptr(vk).to_str() };
    let proving_output = unsafe { CStr::from_ptr(proving_output).to_str() };
    match (vk, proving_output) {
        (Ok(vk), Ok(proving_output)) => match do_verify(vk, proving_output) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(err) => {
                println!("{}", err);
                -2
            }
        },
        _ => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn load_context_bn254(
    wasm_path: *const cty::c_char,
    r1cs_path: *const cty::c_char,
    zkey_path: *const cty::c_char,
) -> *mut ProvingContext {
    let wasm_path = unsafe { CStr::from_ptr(wasm_path).to_str() };
    let r1cs_path = unsafe { CStr::from_ptr(r1cs_path).to_str() };
    let zkey_path = unsafe { CStr::from_ptr(zkey_path).to_str() };
    match (wasm_path, r1cs_path, zkey_path) {
        (Ok(wasm_path), Ok(r1cs_path), Ok(zkey_path)) => {
            ret_or_err(load_context(wasm_path, r1cs_path, zkey_path))
        }
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn verifying_key_size_bn254(ctx: Option<&mut ProvingContext>) -> cty::c_int {
    match ctx {
        Some(ctx) => {
            let vk = ctx.verifying_key_in_hex();
            vk.len() as i32
        }
        _ => -1,
    }
}

#[no_mangle]
pub extern "C" fn export_verifying_key_bn254(
    ctx: Option<&mut ProvingContext>,
    buf: *mut cty::c_char,
    max_len: cty::c_int,
) -> cty::c_int {
    match ctx {
        Some(ctx) => {
            let vk = ctx.verifying_key_in_hex();
            write_to_buffer(&vk, buf, max_len)
        }
        _ => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn prove_bn254(
    ctx: Option<&mut ProvingContext>,
    input: *const cty::c_char,
    buf: *mut cty::c_char,
    max_len: cty::c_int,
) -> cty::c_int {
    let input = unsafe { CStr::from_ptr(input).to_str() };
    match (ctx, input) {
        (Some(ctx), Ok(input)) => match do_prove(ctx, input) {
            Ok((pub_inputs, proof)) => match serialize(pub_inputs, proof) {
                Ok(output) => write_to_buffer(&output, buf, max_len),
                Err(_) => -1,
            },
            Err(_) => -1,
        },
        _ => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn free_context_bn254(state: *mut ProvingContext) {
    assert!(!state.is_null());
    let _ = Box::from_raw(state); // Rust auto-drops it
}
