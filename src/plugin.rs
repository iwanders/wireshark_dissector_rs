use crate::dissector;
use crate::epan;
use crate::util;

/*
    After placing an item, dissect_protocol_function for registered protocols (including our own protocol) may be called
    but we have already taken the dissector out of the DISSECTOR_PTR global, so we don't have a dissector to work with
    and we can't do anything. Popping all bytes from the tvb, or none doesn't help.

    This ONLY happens because the usb dissector is bad and forces us to be re-entrant. TCP works fine, stacktrace from
    the usb crash we get:

   1: wireshark_dissector_rs::plugin::dissect_protocol_function
             at <snip>/plugin.rs:53:13
   2: call_dissector_through_handle
             at /tmp/wireshark-master/epan/packet.c:720
   3: call_dissector_work
             at /tmp/wireshark-master/epan/packet.c:813
   4: dissector_try_uint_new
             at /tmp/wireshark-master/epan/packet.c:1413
   5: try_dissect_next_protocol
             at /tmp/wireshark-master/epan/dissectors/packet-usb.c:3552
   6: dissect_usb_setup_request
             at /tmp/wireshark-master/epan/dissectors/packet-usb.c:3871
   7: dissect_usb_common
             at /tmp/wireshark-master/epan/dissectors/packet-usb.c:5175
   8: dissect_win32_usb
             at /tmp/wireshark-master/epan/dissectors/packet-usb.c:5327
   9: call_dissector_through_handle
             at /tmp/wireshark-master/epan/packet.c:720
  10: call_dissector_work
             at /tmp/wireshark-master/epan/packet.c:813
  11: dissect_frame
             at /tmp/wireshark-master/epan/dissectors/packet-frame.c:788
  12: call_dissector_through_handle
             at /tmp/wireshark-master/epan/packet.c:720
  13: call_dissector_work
             at /tmp/wireshark-master/epan/packet.c:813
  14: call_dissector_with_data
             at /tmp/wireshark-master/epan/packet.c:3246
  15: dissect_record
             at /tmp/wireshark-master/epan/packet.c:594
  16: epan_dissect_run_with_taps
             at /tmp/wireshark-master/epan/epan.c:607
  17: add_packet_to_packet_list
             at /tmp/wireshark-master/file.c:1201
  18: read_record
             at /tmp/wireshark-master/file.c:1297
  19: cf_read

*/


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

    // Create our nice safe wrappers
    let mut proto: epan::ProtoTree = unsafe { epan::ProtoTree::from_ptr(tree) };
    let mut tvb: epan::TVB = unsafe { epan::TVB::from_ptr(tvb) };

    // A temporary to hold the dissector.
    let mut dissector_tmp: Option<Box<dyn Dissector>>;

    // Move our dissector pointer, from a mutable static, so this is unsafe.
    unsafe {
        if !DISSECTOR_PTR.is_some() {
            //~ return 0;
            panic!("Trying to obtain the dissector while it's in use.");
        }
        dissector_tmp = Some(DISSECTOR_PTR.take().unwrap());
    }


    // Call the dissector.
    let used_bytes = dissector_tmp.as_mut().unwrap().dissect(&mut proto, &mut tvb);

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

    // Store our pointer again.
    unsafe {
        DISSECTOR_PTR = Some(dissector_tmp_option.unwrap());
    }
}

extern "C" fn proto_register_handoff() {
    // A handoff routine associates a protocol handler with the protocol’s traffic. It consists of two major steps:
    // The first step is to create a dissector handle, which is a handle associated with the protocol and the function called to do the actual dissecting.
    // The second step is to register the dissector handle so that traffic associated with the protocol calls the dissector.

    let mut dissector_tmp_option: Option<Box<dyn Dissector>>;
    unsafe {
        dissector_tmp_option = Some(DISSECTOR_PTR.take().unwrap());
    }

    unsafe {
        let dissector_tmp = dissector_tmp_option.as_mut().unwrap();

        let dissector_handle = epan::packet::create_dissector_handle(Some(dissect_protocol_function), PROTO_ID);

        for registration in dissector_tmp.get_registration() {
            match registration {
                dissector::Registration::Post {} => {
                    epan::packet::register_postdissector(dissector_handle);
                }
                dissector::Registration::UInt { abbrev, pattern } => {
                    epan::packet::dissector_add_uint(util::perm_string_ptr(abbrev), pattern, dissector_handle);
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
                    epan::packet::dissector_add_for_decode_as(util::perm_string_ptr(abbrev), dissector_handle);
                }
            }
        }
    }

    unsafe {
        DISSECTOR_PTR = Some(dissector_tmp_option.unwrap());
    }
}
