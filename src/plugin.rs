// Copyright 2021-2021, Ivor Wanders and the wireshark_dissector_rs contributors
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::dissector;
use crate::epan;
use crate::util;

use crate::dissector::Dissector;

fn string_container_to_perm(v: &dissector::StringContainer) -> *const libc::c_char {
    match v {
        dissector::StringContainer::StaticStr(s) => util::perm_string_ptr(&s),
        dissector::StringContainer::String(s) => util::perm_string_ptr(&s),
    }
}

impl From<&Box<dyn epan::HeaderFieldInfo>> for epan::proto::header_field_info {
    fn from(hfi: &Box<dyn epan::HeaderFieldInfo>) -> Self {
        // If we have strings, we need to build that struct and leak it explicitly.
        let strings_input = hfi.strings();
        let mut strings_output = 0 as *const libc::c_char as *const libc::c_void;
        if let Some(v) = strings_input
        {
            let mut string_entries: Box<Vec<epan::value_string::value_string>> = Box::new(Vec::new());
            // string_entries.resize(v.len(), Default::default());
            for (i, s) in v.iter()
            {
                string_entries.push(epan::value_string::value_string{
                    value: *i,
                    string: util::perm_string_ptr(&s),
                })
            }
            
            let value_str_ptr = (&string_entries[0]) as *const epan::value_string::value_string;
            // now, transmute that pointer to the const char*
            strings_output = unsafe {std::mem::transmute::<*const epan::value_string::value_string, *const libc::c_void>(value_str_ptr)};
            Box::leak(string_entries);
        }
        epan::proto::header_field_info {
            name: util::perm_string_ptr(&hfi.name()),
            abbrev: util::perm_string_ptr(&hfi.abbrev()),
            type_: hfi.feature_type(),
            display: hfi.display_type(),
            strings: strings_output,
            // pub bitmask: u64,
            // pub blurb: *const libc::c_char,

            //
            // pub id: i32,
            // pub parent: i32,
            // pub ref_type: hf_ref_type,
            // pub same_name_pref_id: i32,
            // pub same_name_next: *mut header_field_info,
            ..Default::default()
        }

    }
}


use std::rc::Rc;
// Global state
static mut DISSECTOR_PTR: Option<Rc<dyn Dissector>> = None;
static mut HF_ENTRIES: Option<Vec<epan::proto::hf_register_info>> = None;
static mut PROTO_ID: i32 = -1; // Todo? change into a newtype.

/// Actual implementation of setup that stores the passed in dissector into the global singleton.
pub fn setup<T: 'static + Dissector>(d: Rc<T>) {
    unsafe {
        // Register our two global functions.
        let mut plugin_handle_box: Box<epan::proto::proto_plugin> = Box::new(Default::default());
        plugin_handle_box.register_protoinfo = Some(proto_register_protoinfo);
        plugin_handle_box.register_handoff = Some(proto_register_handoff);
        let ptr_to_plugin = Box::leak(plugin_handle_box); // Need this to persist, but we don't ever need it anymore
        epan::proto::proto_register_plugin(ptr_to_plugin);

        // store the dissector we got handed in.
        DISSECTOR_PTR = Some(d);
    }
}

/// Global dissection function that retrieves the dissector from the singleton, calls dissect and returns it.
extern "C" fn dissect_protocol_function(
    tvb: *mut epan::tvbuff::tvbuff_t,
    _packet_info: *mut epan::packet_info::packet_info,
    tree: *mut epan::proto::proto_tree,
    _data: *mut libc::c_void,
) -> i32 {
    // Create our nice safe wrappers
    let mut proto: epan::ProtoTree = unsafe { epan::ProtoTree::from_ptr(tree) };
    let mut tvb: epan::TVB = unsafe { epan::TVB::from_ptr(tvb) };

    // A temporary to hold the,  we retrieve from a mutable static, so it's unsafe.
    let dissector_tmp = unsafe { &DISSECTOR_PTR.as_ref().unwrap() };

    // Call the dissector.
    let used_bytes = dissector_tmp.dissect(&mut proto, &mut tvb);

    // Return how much bytes we consumed.
    return used_bytes as i32;
}

/// Global heuristic dissector function.
extern "C" fn heuristic_dissector_function(
    tvb: *mut epan::tvbuff::tvbuff_t,
    _packet_info: *mut epan::packet_info::packet_info,
    tree: *mut epan::proto::proto_tree,
    _data: *mut libc::c_void,
) -> bool {
    // A temporary to hold the,  we retrieve from a mutable static, so it's unsafe.
    let dissector_tmp = unsafe { &DISSECTOR_PTR.as_ref().unwrap() };

    // Make our objects and invoke the heuristic dissector method.
    let mut proto: epan::ProtoTree = unsafe { epan::ProtoTree::from_ptr(tree) };
    let mut tvb: epan::TVB = unsafe { epan::TVB::from_ptr(tvb) };

    let applies = dissector_tmp.heuristic_dissect(&mut proto, &mut tvb);

    return applies;
}

/// Global function to register our protocol.
extern "C" fn proto_register_protoinfo() {
    // We're only called once, ensure we have our HF entries setup.
    unsafe {
        HF_ENTRIES = Some(Vec::new());
    }

    let dissector_tmp = unsafe { Rc::<dyn Dissector + 'static>::get_mut(DISSECTOR_PTR.as_mut().unwrap()).unwrap() };

    // Make a vector to hold the HFIndex entries.
    let mut field_ids: Vec<epan::proto::HFIndex> = Vec::new();

    // Obtain the fields we are about to register.
    let mut fields_input = dissector_tmp.get_fields();
    unsafe {
        // Register our protocol names and abbreviation.
        let (full_name, short_name, filter_name) = dissector_tmp.get_protocol_name();
        PROTO_ID = epan::proto::proto_register_protocol(
            util::perm_string_ptr(full_name),
            util::perm_string_ptr(short_name),
            util::perm_string_ptr(filter_name),
        );

        // ok, here we get to make our header fields array, and then we can pass that to wireshark.
        let hf_fields = &mut HF_ENTRIES.as_mut().unwrap();

        // Now, build the struct we're going to pass to wireshark.
        field_ids.resize(fields_input.len(), epan::proto::HFIndex(-1));
        for i in 0..fields_input.len() {
            hf_fields.push(epan::proto::hf_register_info {
                p_id: &mut field_ids[i],
                hfinfo: (&fields_input[i]).into(),
            });
        }

        // pass our struct to wireshark.
        let rawptr = &mut hf_fields[0] as *mut epan::proto::hf_register_info;
        epan::proto::proto_register_field_array(PROTO_ID, rawptr, hf_fields.len() as i32);
    }

    // And, then we assembly the return struct.
    let hf_indices = fields_input.drain(..).enumerate().map(|(i, v)| {
        (v, field_ids[i])
    }).collect::<Vec<(Box<dyn epan::HeaderFieldInfo>, epan::proto::HFIndex)>>();

    // Pass the now usable indices back to the dissector.
    dissector_tmp.set_field_indices(hf_indices);

    // And, then lastly, we create the tree indices.
    let desired_count = dissector_tmp.get_tree_count();
    if desired_count != 0 {
        let mut ett_indices: Vec<epan::proto::ETTIndex> = Vec::new();
        ett_indices.resize(desired_count, epan::proto::ETTIndex(-1));
        let mut ett_index_vector: Vec<*mut epan::proto::ETTIndex> = Vec::new();
        for i in 0..desired_count {
            ett_index_vector.push(&mut ett_indices[i] as *mut epan::proto::ETTIndex);
        }
        unsafe {
            // now, we can pass this vector to register the ETTIndices we want.
            epan::proto::proto_register_subtree_array(
                &mut ett_index_vector[0] as *mut *mut epan::proto::ETTIndex,
                desired_count as i32,
            );
        }

        dissector_tmp.set_tree_indices(ett_indices);
    }
}

/// Global handoff function to register the dissector.
extern "C" fn proto_register_handoff() {
    // A handoff routine associates a protocol handler with the protocol’s traffic. It consists of two major steps:
    // The first step is to create a dissector handle, which is a handle associated with the protocol and the function called to do the actual dissecting.
    // The second step is to register the dissector handle so that traffic associated with the protocol calls the dissector.

    unsafe {
        let dissector_tmp = &DISSECTOR_PTR.as_ref().unwrap();

        let dissector_handle = epan::packet::create_dissector_handle(Some(dissect_protocol_function), PROTO_ID);

        for registration in dissector_tmp.get_registration() {
            match registration {
                // Register as a post dissector
                dissector::Registration::Post {} => {
                    epan::packet::register_postdissector(dissector_handle);
                }
                // Register in a specific table with an integer.
                dissector::Registration::UInt { abbrev, pattern } => {
                    epan::packet::dissector_add_uint(util::perm_string_ptr(abbrev), pattern, dissector_handle);
                }

                // Register in a specific table with ranges of integers.
                dissector::Registration::UIntRange { abbrev, ranges } => {
                    let mut input: epan::range::epan_range = Default::default();
                    for i in 0..ranges.len() {
                        input.ranges[i].low = ranges[i].0;
                        input.ranges[i].high = ranges[i].1;
                    }
                    input.nranges = input.ranges.len() as u32;

                    epan::packet::dissector_add_uint_range(
                        util::perm_string_ptr(abbrev),
                        &input as *const epan::range::epan_range,
                        dissector_handle,
                    );
                }

                // Register for decode as functionality.
                dissector::Registration::DecodeAs { abbrev } => {
                    epan::packet::dissector_add_for_decode_as(util::perm_string_ptr(abbrev), dissector_handle);
                }

                // Register as a heuristic dissector.
                dissector::Registration::Heuristic {
                    table,
                    display_name,
                    internal_name,
                    enabled,
                } => {
                    epan::packet::heur_dissector_add(
                        util::perm_string_ptr(table),
                        Some(heuristic_dissector_function),
                        util::perm_string_ptr(display_name),
                        util::perm_string_ptr(internal_name),
                        PROTO_ID,
                        if enabled {
                            epan::packet::heuristic_enable_e::HEURISTIC_ENABLE
                        } else {
                            epan::packet::heuristic_enable_e::HEURISTIC_DISABLE
                        },
                    );
                }
            }
        }
    }
}
