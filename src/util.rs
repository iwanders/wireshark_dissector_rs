/*
Wireshark often expects const char* strings to exist indefinitely... So here we build a container for those strings.
Such that if we require the same string in various places, we don't end up leaking that string over and over.
*/

// The following does this pretty egantly;
// Can we do away with this string container now?
// let field.name = "kdljfslkdf\0"
// std::ffi::CStr::from_bytes_with_nul_unchecked(field.name.as_bytes()).as_ptr()

use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::Mutex;

// Need to tell that it's safe to move between threads, otherwise we can't lazy_static it.
struct ThreadSafeStringHolder {
    v: *const i8,
}
unsafe impl Send for ThreadSafeStringHolder {}

lazy_static! {
    static ref STRING_STORAGE: Mutex<Vec<ThreadSafeStringHolder>> = Mutex::new(vec![]);
}

// Then we can make this function that returns
pub fn perm_string(input: &str) -> &CStr {
    for stored_string in STRING_STORAGE.lock().unwrap().iter() {
        unsafe {
            if CStr::from_ptr(stored_string.v).to_str().unwrap() == input {
                return CStr::from_ptr(stored_string.v);
            }
        }
    }
    let to_add = CString::new(input).unwrap().into_raw();
    STRING_STORAGE
        .lock()
        .unwrap()
        .push(ThreadSafeStringHolder { v: to_add });
    return perm_string(input);
}

#[allow(dead_code)]
pub fn perm_string_ptr(input: &str) -> *const c_char {
    return perm_string(input).as_ptr();
}

//https://stackoverflow.com/a/55323803
use std::ptr;
trait AsMutPtr<T> {
    fn as_mut_ptr(&mut self) -> *mut T;
}

impl<'a, T> AsMutPtr<T> for Option<&'a mut T> {
    fn as_mut_ptr(&mut self) -> *mut T {
        match self {
            Some(v) => *v,
            None => {
                println!("Its a nullptr :( ");
                ptr::null_mut()
            }
        }
    }
}
