// Copyright 2021-2021, Ivor Wanders and the wireshark_dissector_rs contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use super::ftypes::ftenum;
use super::ftypes::fvalue_t;
use super::glib::GPtrArray;
use super::tvbuff::tvbuff_t;

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum Encoding {
    BIG_ENDIAN = 0x00000000,
    LITTLE_ENDIAN = 0x80000000,
    STR_NUM = 0x01000000,
    STR_HEX = 0x02000000,
    STRING = 0x03000000,
    STR_MASK = 0x0000FFFE,
}

#[repr(i32)]
#[derive(Clone, Copy, Debug)]
pub enum FieldDisplay {
    /* Integral types */
    BASE_NONE = 0,
    BASE_DEC = 1,
    BASE_HEX = 2,
    BASE_OCT = 3,
    BASE_DEC_HEX = 4,
    BASE_HEX_DEC = 5,
    BASE_CUSTOM = 6,
    /* Float types */
        //~ BASE_FLOAT = BASE_NONE, /*< decimal-format float */

    /* String types */
        //~ STR_ASCII    = BASE_NONE,   /*< shows non-printable ASCII characters as C-style escapes */
        /* XXX, support for format_text_wsp() ? */
    STR_UNICODE = 7, /*< shows non-printable UNICODE characters as \\uXXXX (XXX for now non-printable characters display depends on UI) */

    /* Byte separators */
    SEP_DOT = 8,    /*< hexadecimal bytes with a period (.) between each byte */
    SEP_DASH = 9,   /*< hexadecimal bytes with a dash (-) between each byte */
    SEP_COLON = 10, /*< hexadecimal bytes with a colon (:) between each byte */
    SEP_SPACE = 11, /*< hexadecimal bytes with a space between each byte */

    /* Address types */
    BASE_NETMASK = 12, /*< Used for IPv4 address that shouldn't be resolved (like for netmasks) */

    /* Port types */
    BASE_PT_UDP = 13,  /*< UDP port */
    BASE_PT_TCP = 14,  /*< TCP port */
    BASE_PT_DCCP = 15, /*< DCCP port */
    BASE_PT_SCTP = 16, /*< SCTP port */

    /* OUI types */
    BASE_OUI = 17, /*< OUI resolution */
}
impl FieldDisplay {
    pub const BASE_FLOAT: FieldDisplay = FieldDisplay::BASE_NONE;
    pub const STR_UNICODE: FieldDisplay = FieldDisplay::BASE_NONE;
}
impl From<&FieldDisplay> for i32 {
    fn from(z: &FieldDisplay) -> Self {
        *z as i32
    }
}
impl From<i32> for FieldDisplay {
    fn from(z: i32) -> Self {
        match z & 0xff {
            0 => FieldDisplay::BASE_NONE,
            1 => FieldDisplay::BASE_DEC,
            2 => FieldDisplay::BASE_HEX,
            3 => FieldDisplay::BASE_OCT,
            4 => FieldDisplay::BASE_DEC_HEX,
            5 => FieldDisplay::BASE_HEX_DEC,
            6 => FieldDisplay::BASE_CUSTOM,
            7 => FieldDisplay::STR_UNICODE,
            8 => FieldDisplay::SEP_DOT,
            9 => FieldDisplay::SEP_DASH,
            10 => FieldDisplay::SEP_COLON,
            11 => FieldDisplay::SEP_SPACE,
            12 => FieldDisplay::BASE_NETMASK,
            13 => FieldDisplay::BASE_PT_UDP,
            14 => FieldDisplay::BASE_PT_TCP,
            15 => FieldDisplay::BASE_PT_DCCP,
            16 => FieldDisplay::BASE_PT_SCTP,
            17 => FieldDisplay::BASE_OUI,
            _ => FieldDisplay::BASE_NONE,
        }
    }
}

#[repr(i32)]
#[derive(Clone, Copy, Debug)]
pub enum FieldDisplayFlags {
    /* Following constants have to be ORed with a field_display_e when dissector
     * want to use specials value-string MACROs for a header_field_info */
    RANGE_STRING = 0x0100,
    EXT_STRING = 0x0200,
    VAL64_STRING = 0x0400,
    ALLOW_ZERO = 0x0800,  /*< Display <none> instead of <MISSING> for zero sized byte array */
    UNIT_STRING = 0x1000, /*< Add unit text to the field value */
    NO_DISPLAY_VALUE = 0x2000, /*< Just display the field name with no value.  Intended for
                          byte arrays or header fields above a subtree */
    PROTOCOL_INFO = 0x4000, /*< protocol_t in [FIELDCONVERT].  Internal use only. */
    SPECIAL_VALS = 0x8000,  /*< field will not display "Unknown" if value_string match is not found */
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

/// Opaque proto_tree struct
#[repr(C)]
pub struct proto_tree {
    _private: [u8; 0],
}
/// Opaque proto_item struct
#[repr(C)]
pub struct proto_item {
    _private: [u8; 0],
}

/// Opaque protocol_t struct
#[repr(C)]
pub struct protocol_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct header_field_info {
    pub name: *const libc::c_char,
    pub abbrev: *const libc::c_char,
    pub type_: ftenum,
    pub display: libc::c_int,
    pub strings: *const libc::c_void,
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
            display: (&FieldDisplay::BASE_NONE).into(),
            strings: 0 as *const libc::c_char as *const libc::c_void,
            bitmask: 0,
            blurb: 0 as *const libc::c_char,
            id: -1,
            parent: 0,
            ref_type: hf_ref_type::NONE,
            same_name_pref_id: -1,
            same_name_next: 0 as *mut header_field_info,
        }
    }
}

// printing everything causes segfaults?? :/
use core::fmt::Debug;
impl Debug for header_field_info {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use std::ffi::CStr;
        write!(f, "header_field_info {{ ")?;
        unsafe {
            match CStr::from_ptr(self.name).to_str() {
                Ok(t) => {
                    write!(f, "name: {:?}, ", t)?;
                }
                Err(_) => {
                    write!(f, "name: 0x0, ")?;
                }
            }
            match CStr::from_ptr(self.abbrev).to_str() {
                Ok(t) => {
                    write!(f, "abbrev: {:?}, ", t)?;
                }
                Err(_) => write!(f, "abbrev: 0x0, ")?,
            }
        }
        write!(f, "type_: {:?}, ", self.type_)?;
        //~ write!(f, "display: {:?}", self.display);
        //~ write!(f, "strings: {:?}", self.strings);
        //~ write!(f, "bitmask: {:?}", self.bitmask);
        //~ write!(f, "blurb: {:?}", self.blurb);
        write!(f, "id: {:?}, ", self.id)?;
        write!(f, "parent: {:?}", self.parent)?;
        //~ write!(f, "same_name_pref_id: {:?}", self.same_name_pref_id);
        //~ write!(f, "same_name_next: {:?}", self.same_name_next);
        write!(f, "}}")
    }
}
/*
*/

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
/// HF index, this should NEVER be instantiated by the user, they are returned by proto_register_field_array.
pub struct HFIndex(pub i32);

#[derive(Debug)]
#[repr(C)]
pub struct hf_register_info {
    pub p_id: *mut HFIndex,        // written to by register() function
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

const ITEM_LABEL_LENGTH: usize = 240;
#[derive(Debug)]
#[repr(C)]
pub struct item_label_t {
    representation: [libc::c_char; ITEM_LABEL_LENGTH],
}

#[derive(Debug)]
#[repr(C)]
pub struct field_info {
    pub hfinfo: *const header_field_info,
    /**< pointer to registered field information */
    pub start: i32,
    /**< current start of data in field_info.ds_tvb */
    pub length: i32,
    /**< current data length of item in field_info.ds_tvb */
    pub appendix_start: i32,
    /**< start of appendix data */
    pub appendix_length: i32,
    /**< length of appendix data */
    pub tree_type: i32,
    /**< one of ETT_ or -1 */
    pub flags: u32,
    /**< bitfield like FI_GENERATED, ... */
    pub rep: *const item_label_t,
    /**< string for GUI tree */
    pub ds_tvb: *mut tvbuff_t,
    /**< data source tvbuff */
    pub value: fvalue_t,
}

#[repr(C)]
pub struct proto_plugin {
    pub register_protoinfo: Option<extern "C" fn()>, /* routine to call to register protocol information */
    pub register_handoff: Option<extern "C" fn()>,   /* routine to call to register protocol information */
}

impl Default for proto_plugin {
    fn default() -> Self {
        proto_plugin {
            register_protoinfo: None,
            register_handoff: None,
        }
    }
}

/// ETT index, this should NEVER be instantiated by the user, they are returned by proto_register_subtree_array.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct ETTIndex(pub i32);

#[link(name = "wireshark")]
extern "C" {

    // proto register
    pub fn proto_register_protocol(
        name: *const libc::c_char,
        short_name: *const libc::c_char,
        filter_name: *const libc::c_char,
    ) -> i32;
    pub fn proto_register_plugin(plugin: *const proto_plugin);
    pub fn proto_register_field_array(parent: i32, hf: *mut hf_register_info, num_records: i32);

    pub fn proto_register_subtree_array(indices: *mut *mut ETTIndex, num_indices: i32);

    // Proto tree
    pub fn proto_tree_add_protocol_format(
        tree: *mut proto_tree,
        hfindex: HFIndex,
        tvb: *const tvbuff_t,
        start: i32,
        length: i32,
        format: *const libc::c_char,
        ...
    ) -> *mut proto_item;

    pub fn proto_tree_add_item(
        tree: *mut proto_tree,
        hfindex: HFIndex,
        tvb: *const tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_int(
        tree: *mut proto_tree,
        hfindex: HFIndex,
        tvb: *const tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut i32,
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_uint64(
        tree: *mut proto_tree,
        hfindex: HFIndex,
        tvb: *const tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut u64,
    ) -> *mut proto_item;

    pub fn proto_tree_add_item_ret_uint(
        tree: *mut proto_tree,
        hfindex: HFIndex,
        tvb: *const tvbuff_t,
        start: i32,
        length: i32,
        encoding: Encoding,
        retval: *mut u32,
    ) -> *mut proto_item;

    pub fn proto_tree_add_bits_item(
        tree: *mut proto_tree,
        hfindex: HFIndex,
        tvb: *const tvbuff_t,
        bit_offset: i32,
        no_of_bits: i32,
        encoding: Encoding,
    ) -> *mut proto_item;

    // Proto item functions below
    pub fn proto_item_set_text(ti: *mut proto_item, text: *const libc::c_char);
    pub fn proto_item_append_text(ti: *mut proto_item, text: *const libc::c_char);
    pub fn proto_item_prepend_text(ti: *mut proto_item, text: *const libc::c_char);
    pub fn proto_item_add_subtree(ti: *mut proto_item, ett_id: ETTIndex) -> *mut proto_tree;

    // Introspection
    pub fn proto_all_finfos(tree: *mut proto_tree) -> *mut GPtrArray;
}
