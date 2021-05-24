// Copyright 2021-2021, Ivor Wanders and the wireshark_dissector_rs contributors
// SPDX-License-Identifier: GPL-2.0-or-later

use super::packet_info::packet_info;
use super::proto::proto_tree;
use super::proto::protocol_t;
use super::range::epan_range;
use super::tvbuff::tvbuff_t;

#[repr(C)]
pub struct dissector_handle {
    _private: [u8; 0],
}
type dissector_handle_t = *mut dissector_handle;

type dissector_t = Option<extern "C" fn(*mut tvbuff_t, *mut packet_info, *mut proto_tree, *mut libc::c_void) -> i32>;

type heur_dissector_t =
    Option<extern "C" fn(*mut tvbuff_t, *mut packet_info, *mut proto_tree, *mut libc::c_void) -> bool>;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum heuristic_enable_e {
    HEURISTIC_DISABLE,
    HEURISTIC_ENABLE,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct heur_dtbl_entry_t {
    dissector: heur_dissector_t,
    protocol: *mut protocol_t,         /* this entry's protocol */
    list_name: *const libc::c_char,    /* the list name this entry is in the list of */
    display_name: *const libc::c_char, /* the string used to present heuristic to user */
    short_name: *const libc::c_char,   /* string used for "internal" use to uniquely identify heuristic */
    pub enabled: bool,
}

#[link(name = "wireshark")]
extern "C" {
    pub fn register_postdissector(handle: dissector_handle_t);
    pub fn dissector_add_uint(abbrev: *const libc::c_char, pattern: u32, handle: dissector_handle_t);
    pub fn dissector_add_uint_range(abbrev: *const libc::c_char, range: *const epan_range, handle: dissector_handle_t);
    //~ pub fn dissector_add_string(name: *const libc::c_char, pattern: *const libc::c_char, handle: dissector_handle_t);
    pub fn dissector_add_for_decode_as(name: *const libc::c_char, handle: dissector_handle_t);

    pub fn create_dissector_handle(dissector: dissector_t, proto: i32) -> dissector_handle_t;

    pub fn heur_dissector_add(
        name: *const libc::c_char,
        dissector: heur_dissector_t,
        display_name: *const libc::c_char,
        internal_name: *const libc::c_char,
        proto: i32,
        enable: heuristic_enable_e,
    );
    pub fn find_heur_dissector_by_unique_short_name(short_name: *const libc::c_char) -> *mut heur_dtbl_entry_t;
}
