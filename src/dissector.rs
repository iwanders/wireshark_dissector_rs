

use crate::util;
use crate::epan;

//-------------------------------------------------

/// The trait the dissector must adhere to.
pub trait Dissector {
    /// This function must return a vector of all the possible fields the dissector will end up using.
    fn get_fields(self: &Self) -> Vec<PacketField>;

    /// After the fields are registered, this function is called to provide the new HFIndices that should be used
    /// to refer to the registered fields.
    fn set_field_indices(self: &mut Self, hfindices: Vec<(PacketField, epan::proto::HFIndex)>);

    /// Called when there is somethign to dissect.
    fn dissect(self: &mut Self, proto: &mut epan::ProtoTree, tvb: &mut epan::TVB);

    /// Full name, short_name, filter_name
    fn get_protocol_name(self: &Self) -> (&'static str, &'static str, &'static str);

    fn get_registration(self: &Self) -> Vec<Registration> {
        return vec![Registration::Post];
    }
}


//-------------------------------------------------
pub type FieldType = epan::ftypes::ftenum;
pub type FieldDisplay = epan::proto::FieldDisplay;

/// Specification for a field that can be displayed.
#[derive(Debug, Copy, Clone)]
pub struct PacketField {
    pub name: &'static str,
    pub abbrev: &'static str,
    pub field_type: FieldType,
    pub display: FieldDisplay,
}


impl From<PacketField> for epan::proto::header_field_info {
    fn from(field: PacketField) -> Self {
        //~ unsafe {
        epan::proto::header_field_info {
            name: util::perm_string_ptr(field.name),
            abbrev: util::perm_string_ptr(field.abbrev),
            type_: field.field_type.into(),
            display: field.display.into(),
            ..Default::default()
        }
        //~ }
    }
}

/// Something that is displayable in the ui, extra abstraction on top of PacketField atm, such that we can
/// dynamically update the text or something later...
pub trait DisplayItem {
    fn get_field(&self) -> PacketField;
}

// https://rust-lang.github.io/rfcs/0418-struct-variants.html
// This is so fancy
pub enum Registration {
    Post, // called after every frame's dissection.
    UInt { abbrev: &'static str, pattern: u32 },
    UIntRange{abbrev: &'static str, ranges: Vec<(u32, u32)>},
    DecodeAs { abbrev: &'static str },
}

use std::rc::Rc;
// We know that wireshark will ensure only one thread accesses the disector, I think... make this static thing to
// hold our dissector object.
struct UnsafeDissectorHolder {
    ptr: Rc<dyn Dissector>,

    // The things below are usually static members in wireshark plugins.
    proto_id: i32,
    field_ids: Vec<epan::proto::HFIndex>,
    fields_input: Vec<PacketField>,
    fields_wireshark: Vec<epan::proto::hf_register_info>,
    plugin_handle: *mut epan::proto::proto_plugin,
}
unsafe impl Sync for UnsafeDissectorHolder {}
unsafe impl Send for UnsafeDissectorHolder {}
impl UnsafeDissectorHolder {
    fn new(ptr: Rc<dyn Dissector>) -> Self {
        UnsafeDissectorHolder {
            ptr: ptr,
            proto_id: -1,
            fields_input: Vec::new(),
            field_ids: Vec::new(),
            fields_wireshark: Vec::new(),
            plugin_handle: 0 as *mut epan::proto::proto_plugin,
        }
    }
}

// Our global static dissector struct to hold our state in the plugin.
static mut STATIC_DISSECTOR: Option<UnsafeDissectorHolder> = None;

/// Entry point to provide the dissector the the plugin.
pub fn setup(d: Rc<dyn Dissector>) {
    // Assign the dissector to be called sequentially.
    unsafe {
        // Make our global state
        STATIC_DISSECTOR = Some(UnsafeDissectorHolder::new(d));

        // Then, make the plugin handle and bind the functions.
        let state = &mut STATIC_DISSECTOR.as_mut().unwrap();

        let mut plugin_handle_box: Box<epan::proto::proto_plugin> = Box::new(Default::default());
        plugin_handle_box.register_protoinfo = Some(proto_register_protoinfo);
        plugin_handle_box.register_handoff = Some(proto_register_handoff);
        state.plugin_handle = Box::leak(plugin_handle_box); // Need this to persist, but we don't ever need it anymore
        epan::proto::proto_register_plugin(state.plugin_handle);
    }
}

static mut dissector_ptr : Option<*mut dyn Dissector> = None;
pub fn setup2(d: Box<dyn Dissector>)
{
    unsafe
    {
        dissector_ptr = Some(Box::leak(d));
        let mut plugin_handle_box: Box<epan::proto::proto_plugin> = Box::new(Default::default());
        plugin_handle_box.register_protoinfo = Some(proto_register_protoinfo);
        plugin_handle_box.register_handoff = Some(proto_register_handoff);
        let ptr_to_plugin = Box::leak(plugin_handle_box); // Need this to persist, but we don't ever need it anymore
        epan::proto::proto_register_plugin(ptr_to_plugin);
    }
}



extern "C" fn dissect_protocol_function(
    tvb: *mut epan::tvbuff::tvbuff_t,
    packet_info: *mut epan::packet_info::packet_info,
    tree: *mut epan::proto::proto_tree,
    _data: *mut libc::c_void,
) -> u32 {

    //~ let dissector: Option<Rc<dyn Dissector>>;
    let mut dissector_tmp : Option<Box<dyn Dissector>> = None;

    // Copy our dissector pointer
    unsafe {
        //~ let state = &mut STATIC_DISSECTOR.as_mut().unwrap();
        //~ dissector = Some(Rc::clone(&state.ptr));
        dissector_tmp = Some(Box::from_raw(dissector_ptr.unwrap()));
    }
    // Let the dissector do its thing!

    let mut proto: epan::ProtoTree = epan::ProtoTree::from_ptr(tree);
    let mut tvb: epan::TVB = epan::TVB::from_ptr(tvb);
    dissector_tmp.as_mut().unwrap().dissect(&mut proto, &mut tvb);

    unsafe {
        dissector_ptr = Some(Box::leak(dissector_tmp.unwrap()));
    }
    return tvb.reported_length() as u32;
}

static mut hf_entries : Option<Vec<epan::proto::hf_register_info>> = None;
static mut proto_id : i32 = -1;

extern "C" fn proto_register_protoinfo() {
    println!("proto_register_hello");

    let mut dissector_tmp_option : Option<Box<dyn Dissector>> = None;

    unsafe {
        hf_entries = Some(Vec::new());
    }

    unsafe {
        dissector_tmp_option = Some(Box::from_raw(dissector_ptr.unwrap()));
    }
    {
        let dissector_tmp = dissector_tmp_option.as_mut().unwrap();

        let mut field_ids: Vec<epan::proto::HFIndex> = Vec::new();
        unsafe {
            //~ let state = &mut STATIC_DISSECTOR.as_mut().unwrap(); // less wordy.

            let (full_name, short_name, filter_name) = dissector_tmp.get_protocol_name();
            proto_id = epan::proto::proto_register_protocol(
                util::perm_string_ptr(full_name),
                util::perm_string_ptr(short_name),
                util::perm_string_ptr(filter_name),
            );
            println!("Proto proto_int: {:?}", proto_id);

            // ok, here we get to make our header fields array, and then we can pass that to wireshark.
            let fields = &mut hf_entries.as_mut().unwrap();
            let fields_input = dissector_tmp.get_fields();
            println!(
                "Registering {} fields in the protocol register.",
                fields_input.len()
            );
            
            field_ids.resize(fields_input.len(), epan::proto::HFIndex(-1));
            for i in 0..fields_input.len() {
                fields.push(epan::proto::hf_register_info {
                    p_id: &mut field_ids[i],
                    hfinfo: fields_input[i].into(),
                });
            }
            println!("state.fields_wireshark: {:?}", fields);
            let rawptr = &mut fields[0] as *mut epan::proto::hf_register_info;
            epan::proto::proto_register_field_array(proto_id, rawptr, fields.len() as i32);
        
            //fn set_field_indices(self: &Self, hfindices: Vec<(PacketField, epan::proto::HFIndex)>);
            let mut hfindices : Vec<(PacketField, epan::proto::HFIndex)> = Vec::new();
            for i in 0..fields.len()
            {
                hfindices.push((fields_input[i], field_ids[i]));
            }
            println!("fields: {:?}", fields);
            dissector_tmp.set_field_indices(hfindices);
        }
    }

    unsafe {
        dissector_ptr = Some(Box::leak(dissector_tmp_option.unwrap()));
    }
}

extern "C" fn proto_register_handoff() {
    // A handoff routine associates a protocol handler with the protocol’s traffic. It consists of two major steps:
    // The first step is to create a dissector handle, which is a handle associated with the protocol and the function called to do the actual dissecting.
    // The second step is to register the dissector handle so that traffic associated with the protocol calls the dissector.
    println!("proto_reg_handoff_hello");

    let mut dissector_tmp_option : Option<Box<dyn Dissector>> = None;
    unsafe
    {
        dissector_tmp_option = Some(Box::from_raw(dissector_ptr.unwrap()));
    }

    unsafe {
        let dissector_tmp = dissector_tmp_option.as_mut().unwrap();
        //~ let state = &mut STATIC_DISSECTOR.as_mut().unwrap(); // less wordy.
        

        let dissector_handle =
            epan::packet::create_dissector_handle(Some(dissect_protocol_function), proto_id);

        for registration in dissector_tmp.get_registration() {
            match registration {
                Registration::Post {} => {
                    epan::packet::register_postdissector(dissector_handle);
                }
                Registration::UInt { abbrev, pattern } => {
                    epan::packet::dissector_add_uint(
                        util::perm_string_ptr(abbrev),
                        pattern,
                        dissector_handle,
                    );
                }

                Registration::UIntRange { abbrev, ranges } => {
                    println!("Ranges...");
                    let mut input : epan::range::epan_range = Default::default();
                    for i in 0..ranges.len()
                    {
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

                Registration::DecodeAs { abbrev } => {
                    epan::packet::dissector_add_for_decode_as(
                        util::perm_string_ptr(abbrev),
                        dissector_handle,
                    );
                }
            }
        }

        // usb makes a table;     product_to_dissector = register_dissector_table("usb.product",   "USB product",  proto_usb, FT_UINT32, BASE_HEX);
    }

    unsafe {
        dissector_ptr = Some(Box::leak(dissector_tmp_option.unwrap()));
    }
}

#[no_mangle]
static plugin_version: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"
#[no_mangle]
static plugin_release: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"
