// https://doc.rust-lang.org/nomicon/ffi.html
extern crate libc;


#[macro_use]
extern crate lazy_static;
#[no_mangle]
static plugin_version: [libc::c_char;  4] = [50, 46, 54, 0];  // "2.6"
#[no_mangle]
static plugin_release: [libc::c_char;  4] = [50, 46, 54, 0];  // "2.6"


mod util;
mod wireshark;

use std::ffi::CStr;
use std::ffi::CString;
// https://doc.rust-lang.org/std/ffi/struct.CStr.html

//https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-g723.c

extern "C" fn dissect_hello(tvb: *mut wireshark::tvbuff_t, packet_info: *mut wireshark::packet_info, tree: *mut wireshark::proto_tree, data: *mut libc::c_void) -> u32
{
    unsafe
    {
        println!("Dissector hello called!");
        let proto_hello: i32 = -1;
        wireshark::proto_tree_add_protocol_format(tree, proto_hello, tvb, 0, -1, util::perm_string_ptr("This is Hello version %s, a Wireshark postdissector plugin prototype"), plugin_version);
        return wireshark::tvb_reported_length(tvb) as u32;
    }
    return 0;
}


extern "C" fn proto_register_hello()
{
    println!("proto_register_hello");
    //~ let cstr = CString::new("hello").unwrap();

    let cstr = util::perm_string("hello");
    unsafe 
    {
        wireshark::proto_register_protocol(util::perm_string_ptr("The thingy"), cstr.as_ptr(), cstr.as_ptr());


        let proto_hello: i32 = -1;
        let z = wireshark::create_dissector_handle(Some(dissect_hello), proto_hello);
        println!("Proto hello: {:?}", proto_hello);
        wireshark::register_postdissector(z);
    }
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


