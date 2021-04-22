// https://doc.rust-lang.org/nomicon/ffi.html
extern crate libc;

#[no_mangle]
static plugin_version: [libc::c_char;  4] = [50, 46, 54, 0];  // "2.6"
#[no_mangle]
static plugin_release: [libc::c_char;  4] = [50, 46, 54, 0];  // "2.6"


mod wireshark;

use std::ffi::CStr;
use std::ffi::CString;
// https://doc.rust-lang.org/std/ffi/struct.CStr.html


extern "C" fn proto_register_hello()
{
    println!("proto_register_hello");
    let cstr = CString::new("hello").unwrap();
    unsafe 
    {
        wireshark::proto_register_protocol(cstr.as_ptr(), cstr.as_ptr(), cstr.as_ptr());
    }
    //~ proto_hello = proto_register_protocol("Wireshark Hello Plugin", "Hello WS", "hello_ws");
    //~ handle_hello = create_dissector_handle(dissect_hello, proto_hello);
    //~ register_postdissector(handle_hello);
}

extern "C" fn proto_reg_handoff_hello()
{
    println!("proto_reg_handoff_hello");
}

//~ static mut five : Box<MaybeUninit<wireshark::proto_plugin>>;
//~ static mut five: Box<wireshark::proto_plugin> = Box::new(Default::default());

use std::ptr;

#[no_mangle]
pub fn plugin_register() {
    println!("plugin_register");
    let cstr = CString::new("hello").unwrap();
    unsafe 
    {
        wireshark::g_print(cstr.as_ptr());  // Yas, we're in business!
        //~ five = Default::default();
        let mut five: Box<wireshark::proto_plugin> = Box::new(Default::default());
        //~ let mut plug : wireshark::proto_plugin = Default::default();
        five.register_protoinfo = Some(proto_register_hello);
        five.register_handoff = Some(proto_reg_handoff_hello);
        wireshark::proto_register_plugin(Box::leak(five)); // This kinda sucks lol.
        //~ wireshark::proto_register_plugin(&plug);
    }
}