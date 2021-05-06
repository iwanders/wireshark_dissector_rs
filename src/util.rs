/*
Wireshark often expects const char* strings to exist indefinitely... So here we build a container for those strings.
Such that if we require the same string in various places, we don't end up leaking that string over and over.
*/

use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;

static mut STRING_STORAGE: Option<Vec<*const i8>> = Some(Vec::new());

// Then we can make this function that returns
pub fn perm_string(input: &str) -> &CStr {
    let mut container_tmp: Option<Vec<*const i8>>;

    // Move our string storage from the static global to our local container.
    unsafe {
        container_tmp = Some(STRING_STORAGE.take().unwrap());
    }

    let mut result : Option<*const i8> = None;

    for stored_string in container_tmp.as_mut().unwrap().iter() {
        unsafe {
            if CStr::from_ptr(*stored_string).to_str().unwrap() == input {
                result = Some(*stored_string);
                break;
            }
        }
    }
    if result.is_some()
    {
        unsafe { STRING_STORAGE = Some(container_tmp.unwrap());
        return CStr::from_ptr(result.unwrap());
        }
    }
    
    let to_add = CString::new(input).unwrap().into_raw();
    container_tmp.as_mut().unwrap().push(to_add);
    unsafe { STRING_STORAGE = Some(container_tmp.unwrap());}
    return perm_string(input);
}

#[allow(dead_code)]
pub fn perm_string_ptr(input: &str) -> *const c_char {
    return perm_string(input).as_ptr();
}
