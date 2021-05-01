
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use super::ftypes::ftenum;
use super::tvbuff::tvbuff_t;


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
pub struct proto_tree {
    _private: [u8; 0],
}
#[repr(C)]
pub struct proto_item {
    _private: [u8; 0],
}

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

/*
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
}*/


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



#[link(name = "wireshark")]
extern "C" {

    pub fn proto_register_protocol(
        name: *const libc::c_char,
        short_name: *const libc::c_char,
        filter_name: *const libc::c_char,
    ) -> i32;
    pub fn proto_register_plugin(plugin: *const proto_plugin);


    pub fn proto_register_field_array(parent: i32, hf: *mut hf_register_info, num_records: i32);

    pub fn proto_item_add_subtree(ti: *mut proto_item, ett_id: i32) -> *mut proto_tree;

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
        retval: *mut i32,
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_uint64(
        tree: *mut proto_tree,
        hfindex: i32,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut u64,
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_uint(
        tree: *mut proto_tree,
        hfindex: i32,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut u32,
    ) -> *mut proto_item;

    pub fn proto_register_subtree_array();

}