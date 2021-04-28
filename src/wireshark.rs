// https://gitlab.com/wireshark/wireshark/-/blob/master/doc/README.dissector
// https://www.wireshark.org/docs/wsdg_html/#ChDissectDetails
// /usr/include/wireshark/epan

// https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/epan/dissectors/packet-usb.c
// https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/epan/dissectors/packet-usb-hid.c
// 1.5 Constructing the protocol tree; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/doc/README.dissector#L713

// 1.5.1 Field Registration; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/doc/README.dissector#L1270
// 1.7 Calling other dissectors; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/doc/README.dissector#L2471

// THis seems useful?
// https://stackoverflow.com/a/55323693

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::dissector;
use crate::util;

use bitflags::bitflags;
bitflags! {
#[repr(C)]
pub struct Encoding: u32 {
    const BIG_ENDIAN = 0x00000000;
    const LITTLE_ENDIAN = 0x80000000;
    const STR_NUM = 0x01000000;
    const STR_HEX = 0x02000000;
    const STRING = 0x03000000;
    const STR_MASK = 0x0000FFFE;
}
}

bitflags! {
#[repr(C)]
pub struct FieldDisplay: i32 {
    const BASE_NONE = 0;
    const BASE_DEC = 1;
    const BASE_HEX = 2;
    const BASE_OCT = 3;
}
}

#[repr(C)]
pub struct proto_plugin {
    pub register_protoinfo: Option<extern "C" fn()>, /* routine to call to register protocol information */
    pub register_handoff: Option<extern "C" fn()>, /* routine to call to register protocol information */
}

impl Default for proto_plugin {
    fn default() -> Self {
        proto_plugin {
            register_protoinfo: None,
            register_handoff: None,
        }
    }
}

#[repr(C)]
pub struct dissector_handle {
    _private: [u8; 0],
}
type dissector_handle_t = *mut dissector_handle;
#[repr(C)]
pub struct tvbuff_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct packet_info {
    _private: [u8; 0],
}

// Hmm, packet_info is enormous, but we have to reach into it for column info. Let skip that for now.

#[repr(C)]
pub struct proto_tree {
    _private: [u8; 0],
}
#[repr(C)]
pub struct proto_item {
    _private: [u8; 0],
}

type dissector_t = Option<
    extern "C" fn(*mut tvbuff_t, *mut packet_info, *mut proto_tree, *mut libc::c_void) -> u32,
>;
//typedef struct capture_dissector_handle* capture_dissector_handle_t;

//'hf' is short for 'header field'
#[repr(C)]
#[allow(dead_code)]
pub enum hf_ref_type {
    NONE,
    INDIRECT,
    DIRECT,
}
impl Default for hf_ref_type {
    fn default() -> Self {
        hf_ref_type::NONE
    }
}
unsafe impl Send for hf_ref_type {}

#[repr(C)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum ftenum {
    NONE,	/* used for text labels with no value */
    PROTOCOL,
    BOOLEAN,	/* TRUE and FALSE come from <glib.h> */
    CHAR,	/* 1-octet character as 0-255 */
    UINT8,
    UINT16,
    UINT24,	/* really a UINT32, but displayed as 6 hex-digits if FD_HEX*/
    UINT32,
    UINT40,	/* really a UINT64, but displayed as 10 hex-digits if FD_HEX*/
    UINT48,	/* really a UINT64, but displayed as 12 hex-digits if FD_HEX*/
    UINT56,	/* really a UINT64, but displayed as 14 hex-digits if FD_HEX*/
    UINT64,
    INT8,
    INT16,
    INT24,	/* same as for UINT24 */
    INT32,
    INT40, /* same as for UINT40 */
    INT48, /* same as for UINT48 */
    INT56, /* same as for UINT56 */
    INT64,
}

impl Default for ftenum {
    fn default() -> Self {
        ftenum::NONE
    }
}

unsafe impl Send for ftenum {}

#[repr(C)]
pub struct header_field_info {
    pub name: *const libc::c_char,
    pub abbrev: *const libc::c_char,
    pub type_: ftenum,
    pub display: FieldDisplay,
    pub strings: *const libc::c_char, // actually void ptr
    pub bitmask: u64,
    pub blurb: *const libc::c_char,

    //
    pub id: i32,
    pub parent: i32,
    pub ref_type: hf_ref_type,
    pub same_name_pref_id: i32,
    pub same_name_next: *mut header_field_info,
}
impl Default for header_field_info {
    fn default() -> Self {
        header_field_info {
            name: 0 as *const libc::c_char,
            abbrev: 0 as *const libc::c_char,
            type_: Default::default(),
            display: FieldDisplay::BASE_NONE,
            strings: 0 as *const libc::c_char,
            bitmask: Default::default(),
            blurb: 0 as *const libc::c_char,
            id: Default::default(),
            parent: Default::default(),
            ref_type: Default::default(),
            same_name_pref_id: Default::default(),
            same_name_next: 0 as *mut header_field_info,
        }
    }
}

impl From<dissector::PacketField> for header_field_info {
    fn from(field: dissector::PacketField) -> Self {
        //~ unsafe {
        header_field_info {
            name: util::perm_string_ptr(field.name),
            abbrev: util::perm_string_ptr(field.abbrev),
            type_: field.field_type.into(),
            display: field.display.into(),
            ..Default::default()
        }
        //~ }
    }
}

#[repr(C)]
pub struct hf_register_info {
    pub p_id: *mut i32,            // written to by register() function
    pub hfinfo: header_field_info, // < the field info to be registered
}
impl Default for hf_register_info {
    fn default() -> Self {
        hf_register_info {
            p_id: 0 as *mut i32,
            hfinfo: Default::default(),
        }
    }
}

#[link(name = "wireshark")]
extern "C" {
    pub fn tvb_reported_length(tvb: *const tvbuff_t) -> i32;

    pub fn proto_tree_add_protocol_format(
        tree: *mut proto_tree,
        hfindex: i32,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        format: *const libc::c_char,
        ...
    ) -> *mut proto_item;

    pub fn proto_tree_add_item(
        tree: *mut proto_tree,
        hfindex: i32,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_int(
        tree: *mut proto_tree,
        hfindex: i32,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut i32
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_uint64(
        tree: *mut proto_tree,
        hfindex: i32,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut u64
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_uint(
        tree: *mut proto_tree,
        hfindex: i32,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut u32
    ) -> *mut proto_item;

    pub fn proto_register_protocol(
        name: *const libc::c_char,
        short_name: *const libc::c_char,
        filter_name: *const libc::c_char,
    ) -> i32;
    pub fn proto_register_plugin(plugin: *const proto_plugin);

    pub fn create_dissector_handle(dissector: dissector_t, proto: i32) -> dissector_handle_t;
    pub fn register_postdissector(handle: dissector_handle_t);

    pub fn proto_register_field_array(parent: i32, hf: *mut hf_register_info, num_records: i32);
    pub fn proto_register_subtree_array();

    // This is technically not from wireshark, it's from gtk.
    //~ let cstr = CString::new("hello").unwrap();
    //~ wireshark::g_print(cstr.as_ptr()); // Yas, we're in business!
    pub fn g_print(string: *const libc::c_char);

}
