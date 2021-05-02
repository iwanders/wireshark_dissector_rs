use crate::dissector;
use crate::epan;
use crate::util;

use crate::dissector::Dissector;
use crate::dissector::PacketField;

// Global state
static mut DISSECTOR_PTR: Option<Box<dyn Dissector>> = None;
static mut HF_ENTRIES: Option<Vec<epan::proto::hf_register_info>> = None;
static mut PROTO_ID: i32 = -1;

/// Pass the dissector for setup.
pub fn setup(d: Box<dyn Dissector>) {
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

extern "C" fn dissect_protocol_function(
    tvb: *mut epan::tvbuff::tvbuff_t,
    _packet_info: *mut epan::packet_info::packet_info,
    tree: *mut epan::proto::proto_tree,
    _data: *mut libc::c_void,
) -> u32 {
    let mut dissector_tmp: Option<Box<dyn Dissector>>;

    // Move our dissector pointer, from a mutable static, so this is unsafe.
    unsafe {
        dissector_tmp = Some(DISSECTOR_PTR.take().unwrap());
    }

    // Create our nice safe wrappers
    let mut proto: epan::ProtoTree = epan::ProtoTree::from_ptr(tree);
    let mut tvb: epan::TVB = epan::TVB::from_ptr(tvb);

    // Call the dissector.
    let used_bytes = dissector_tmp
        .as_mut()
        .unwrap()
        .dissect(&mut proto, &mut tvb);

    // Move the pointer back.
    unsafe {
        DISSECTOR_PTR = Some(dissector_tmp.unwrap());
    }

    // Return how much bytes we consumed.
    return used_bytes as u32;
}

extern "C" fn proto_register_protoinfo() {
    // We're only called once, ensure we have our HF entries setup.
    unsafe {
        HF_ENTRIES = Some(Vec::new());
    }
    let mut dissector_tmp_option: Option<Box<dyn Dissector>>;

    // Move the pointer to our object.
    unsafe {
        dissector_tmp_option = Some(DISSECTOR_PTR.take().unwrap());
    }

    {
        let dissector_tmp = dissector_tmp_option.as_mut().unwrap();

        // Make a vector to hold the HFIndex entries.
        let mut field_ids: Vec<epan::proto::HFIndex> = Vec::new();
        // Obtain the fields we are about to register.
        let fields_input = dissector_tmp.get_fields();
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
                    hfinfo: fields_input[i].into(),
                });
            }

            // pass our struct to wireshark.
            let rawptr = &mut hf_fields[0] as *mut epan::proto::hf_register_info;
            epan::proto::proto_register_field_array(PROTO_ID, rawptr, hf_fields.len() as i32);
        }

        // And, then we assembly the return struct.
        let mut hfindices: Vec<(PacketField, epan::proto::HFIndex)> = Vec::new();
        for i in 0..field_ids.len() {
            hfindices.push((fields_input[i], field_ids[i]));
        }

        // Pass the now usable indices back to the dissector.
        dissector_tmp.set_field_indices(hfindices);
    }

    // Store our pointer again.
    unsafe {
        DISSECTOR_PTR = Some(dissector_tmp_option.unwrap());
    }
}

extern "C" fn proto_register_handoff() {
    // A handoff routine associates a protocol handler with the protocol’s traffic. It consists of two major steps:
    // The first step is to create a dissector handle, which is a handle associated with the protocol and the function called to do the actual dissecting.
    // The second step is to register the dissector handle so that traffic associated with the protocol calls the dissector.
    println!("proto_reg_handoff_hello");

    let mut dissector_tmp_option: Option<Box<dyn Dissector>>;
    unsafe {
        dissector_tmp_option = Some(DISSECTOR_PTR.take().unwrap());
    }

    unsafe {
        let dissector_tmp = dissector_tmp_option.as_mut().unwrap();

        let dissector_handle =
            epan::packet::create_dissector_handle(Some(dissect_protocol_function), PROTO_ID);

        for registration in dissector_tmp.get_registration() {
            match registration {
                dissector::Registration::Post {} => {
                    epan::packet::register_postdissector(dissector_handle);
                }
                dissector::Registration::UInt { abbrev, pattern } => {
                    epan::packet::dissector_add_uint(
                        util::perm_string_ptr(abbrev),
                        pattern,
                        dissector_handle,
                    );
                }

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

                dissector::Registration::DecodeAs { abbrev } => {
                    epan::packet::dissector_add_for_decode_as(
                        util::perm_string_ptr(abbrev),
                        dissector_handle,
                    );
                }
            }
        }
    }

    unsafe {
        DISSECTOR_PTR = Some(dissector_tmp_option.unwrap());
    }
}

#[no_mangle]
static plugin_version: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"
#[no_mangle]
static plugin_release: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"
