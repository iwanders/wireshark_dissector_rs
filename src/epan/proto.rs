
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use super::ftypes::ftenum;
use super::tvbuff::tvbuff_t;

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum Encoding
{
    BIG_ENDIAN = 0x00000000,
    LITTLE_ENDIAN = 0x80000000,
    STR_NUM = 0x01000000,
    STR_HEX = 0x02000000,
    STRING = 0x03000000,
    STR_MASK = 0x0000FFFE,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum FieldDisplay
{
    BASE_NONE = 0,
    BASE_DEC = 1,
    BASE_HEX = 2,
    BASE_OCT = 3,
}

#[repr(C)]
#[allow(dead_code)]
#[derive(Debug)]
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

#[derive(Debug)]
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

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct HFIndex(pub i32);

#[derive(Debug)]
#[repr(C)]
pub struct hf_register_info {
    pub p_id: *mut HFIndex,            // written to by register() function
    pub hfinfo: header_field_info, // < the field info to be registered
}
impl Default for hf_register_info {
    fn default() -> Self {
        hf_register_info {
            p_id: 0 as *mut HFIndex,
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
        hfindex: HFIndex,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        format: *const libc::c_char,
        ...
    ) -> *mut proto_item;

    pub fn proto_tree_add_item(
        tree: *mut proto_tree,
        hfindex: HFIndex,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_int(
        tree: *mut proto_tree,
        hfindex: HFIndex,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut i32,
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_uint64(
        tree: *mut proto_tree,
        hfindex: HFIndex,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut u64,
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_uint(
        tree: *mut proto_tree,
        hfindex: HFIndex,
        tvb: *mut tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut u32,
    ) -> *mut proto_item;

    pub fn proto_register_subtree_array();

}