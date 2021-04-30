//-------------------------------------------------
/// The object we interact with when perfoming a dissection, allows querying the data and visualising it.
pub trait Dissection {
    // peeks
    fn peek_u8(self: &mut Self) -> Option<u8>;
    fn peek(self: &mut Self) -> &[u8]; // The one peek method to rule them all...

    // Manual advance
    fn advance(self: &mut Self, amount: usize);

    // Adds display and advanced by this amount.
    fn dissect_i8(self: &mut Self, field: &str) -> i8;
    fn dissect_i16(self: &mut Self, field: &str) -> i16;
    fn dissect_i32(self: &mut Self, field: &str) -> i32;

    fn dissect_u8(self: &mut Self, field: &str) -> u8;
    fn dissect_u16(self: &mut Self, field: &str) -> u16;
    fn dissect_u32(self: &mut Self, field: &str) -> u32;
    fn dissect_u64(self: &mut Self, field: &str) -> u64;

    fn dissect_proto(self: &mut Self, item: &str);

    //~ fn get_display_item(self: &mut Self, item: &str) -> &dyn DisplayItem;
    fn get_field(self: &mut Self, item: &str) -> &PacketField;

    // Disect based on the input display item.
    fn dissect(self: &mut Self, field: &str) {
        let item = self.get_field(field);
        match item.field_type {
            FieldType::PROTOCOL => {
                self.dissect_proto(field);
            }

            FieldType::INT8 => {
                self.dissect_i8(field);
            }
            FieldType::INT16 => {
                self.dissect_i16(field);
            }
            FieldType::INT32 => {
                self.dissect_i32(field);
            }

            FieldType::UINT8 => {
                self.dissect_u8(field);
            }
            FieldType::UINT16 => {
                self.dissect_u16(field);
            }
            FieldType::UINT32 => {
                self.dissect_u32(field);
            }
            FieldType::UINT64 => {
                self.dissect_u64(field);
            }
            _ => {}
        }
    }
}

//-------------------------------------------------

/// The trait the dissector must adhere to.
pub trait Dissector {
    /// This function must return a vector of all the possible fields the dissector will end up using.
    fn get_fields(self: &Self) -> Vec<PacketField>;

    /// Called when there is somethign to dissect.
    fn dissect(self: &Self, dissection: &mut dyn Dissection);

    /// Full name, short_name, filter_name
    fn get_protocol_name(self: &Self) -> (&'static str, &'static str, &'static str);

    fn get_registration(self: &Self) -> Vec<Registration> {
        return vec![Registration::Post];
    }
}

/// Trivial implementation for a DisplayItem.
//~ pub struct DisplayItemField {
//~ pub field: PacketField,
//~ }
//~ impl DisplayItem for DisplayItemField {
//~ fn get_field(self: &Self) -> PacketField {
//~ return self.field;
//~ }
//~ }
//~ /// Function to convert a PacketField into a DisplayItemField
//~ pub fn field_to_display(thing: PacketField) -> DisplayItemField {
//~ return DisplayItemField { field: thing };
//~ }

//-------------------------------------------------
pub type FieldType = wireshark::ftenum;
pub type FieldDisplay = wireshark::FieldDisplay;

/// Specification for a field that can be displayed.
#[derive(Debug, Copy, Clone)]
pub struct PacketField {
    pub name: &'static str,
    pub abbrev: &'static str,
    pub field_type: FieldType,
    pub display: FieldDisplay,
}
impl PacketField {
    //~ pub fn display(self: &Self) -> DisplayItemField {
    //~ DisplayItemField { field: *self }
    //~ }
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
    field_ids: Vec<i32>,
    fields_input: Vec<PacketField>,
    fields_wireshark: Vec<wireshark::hf_register_info>,
    plugin_handle: *mut wireshark::proto_plugin,
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
            plugin_handle: 0 as *mut wireshark::proto_plugin,
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

        let mut plugin_handle_box: Box<wireshark::proto_plugin> = Box::new(Default::default());
        plugin_handle_box.register_protoinfo = Some(proto_register_protoinfo);
        plugin_handle_box.register_handoff = Some(proto_register_handoff);
        state.plugin_handle = Box::leak(plugin_handle_box); // Need this to persist, but we don't ever need it anymore
        wireshark::proto_register_plugin(state.plugin_handle);
    }
}

use crate::util;
use crate::wireshark;

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-g723.c

/// The implementation of Dissection that will interface with wireshark.
struct EpanDissection {
    // Wireshark stuff
    pub tvb: *mut wireshark::tvbuff_t,
    pub packet_info: *mut wireshark::packet_info,
    pub tree: *mut wireshark::proto_tree,

    // Our own stuff
    pub pos: usize,
    pub field_ids: Vec<i32>,
    pub fields_input: Vec<PacketField>,
}

impl EpanDissection {
    fn find_field(self: &Self, item: &str) -> usize {
        for i in 0..self.fields_input.len() {
            if item == self.fields_input[i].name {
                return i;
            }
        }
        // panic!?
        panic!("Could not find field id for {}.", item);
    }
    /// Helper to find the hf index this display item is associated with.
    fn find_field_wireshark_id(self: &Self, item: &str) -> i32 {
        return self.field_ids[self.find_field(item)];
    }
}

impl EpanDissection {
    fn dissect_u32(self: &mut Self, item: &str, size: usize) -> u32 {
        let field_id = self.find_field_wireshark_id(item);
        let mut retval: u32 = 0;
        unsafe {
            wireshark::proto_tree_add_item_ret_uint(
                self.tree,
                field_id,
                self.tvb,
                self.pos as i32,
                size as i32,
                wireshark::Encoding::BIG_ENDIAN,
                &mut retval as *mut u32,
            );
        }
        self.pos += size;
        return retval;
    }
    fn dissect_u64(self: &mut Self, item: &str, size: usize) -> u64 {
        let field_id = self.find_field_wireshark_id(item);
        let mut retval: u64 = 0;
        unsafe {
            wireshark::proto_tree_add_item_ret_uint64(
                self.tree,
                field_id,
                self.tvb,
                self.pos as i32,
                size as i32,
                wireshark::Encoding::BIG_ENDIAN,
                &mut retval as *mut u64,
            );
        }
        self.pos += size;
        return retval;
    }

    fn dissect_i32(self: &mut Self, item: &str, size: usize) -> i32 {
        let field_id = self.find_field_wireshark_id(item);
        let mut retval: i32 = 0;
        unsafe {
            wireshark::proto_tree_add_item_ret_int(
                self.tree,
                field_id,
                self.tvb,
                self.pos as i32,
                size as i32,
                wireshark::Encoding::BIG_ENDIAN,
                &mut retval as *mut i32,
            );
        }
        self.pos += size;
        return retval;
    }
}

impl Dissection for EpanDissection {
    fn get_field(self: &mut Self, item: &str) -> &PacketField {
        let item_id = self.find_field(item);
        return &self.fields_input[item_id as usize];
    }

    fn dissect_proto(self: &mut Self, item: &str) {
        let field_id = self.find_field_wireshark_id(item);
        unsafe {
            wireshark::proto_tree_add_item(
                self.tree,
                field_id,
                self.tvb,
                self.pos as i32,
                0 as i32,
                wireshark::Encoding::BIG_ENDIAN,
            );
        }
        self.pos += 0;
    }

    fn peek_u8(self: &mut Self) -> Option<u8>
    {
        return None;
    }

    fn peek(self: &mut Self) -> &[u8]
    {
        unsafe
        {
            // docs use gint available = tvb_reported_length_remaining(tvb, offset);
            let available_length = wireshark::tvb_reported_length_remaining(self.tvb, self.pos as i32);
            let data_ptr = wireshark::tvb_get_ptr(self.tvb, self.pos as i32, available_length as i32);
            return std::slice::from_raw_parts(data_ptr, available_length as usize);
        };
    }

    fn dissect_i8(self: &mut Self, item: &str) -> i8 {
        self.dissect_i32(item, std::mem::size_of::<i8>()) as i8
    }

    fn dissect_i16(self: &mut Self, item: &str) -> i16 {
        self.dissect_i32(item, std::mem::size_of::<i16>()) as i16
    }
    fn dissect_i32(self: &mut Self, item: &str) -> i32 {
        self.dissect_i32(item, std::mem::size_of::<i32>()) as i32
    }

    fn dissect_u8(self: &mut Self, item: &str) -> u8 {
        self.dissect_u32(item, std::mem::size_of::<u8>()) as u8
    }

    fn dissect_u16(self: &mut Self, item: &str) -> u16 {
        self.dissect_u32(item, std::mem::size_of::<u16>()) as u16
    }

    fn dissect_u32(self: &mut Self, item: &str) -> u32 {
        self.dissect_u32(item, std::mem::size_of::<u32>()) as u32
    }

    fn dissect_u64(self: &mut Self, item: &str) -> u64 {
        self.dissect_u64(item, std::mem::size_of::<u64>()) as u64
    }

    fn advance(self: &mut Self, amount: usize) {
        self.pos += amount;
    }
}

extern "C" fn dissect_protocol_function(
    tvb: *mut wireshark::tvbuff_t,
    packet_info: *mut wireshark::packet_info,
    tree: *mut wireshark::proto_tree,
    _data: *mut libc::c_void,
) -> u32 {
    // Construct our dissection wrapper
    let mut dissection: EpanDissection = EpanDissection {
        tvb: tvb,
        tree: tree,
        packet_info: packet_info,

        pos: 0,
        fields_input: Vec::new(),
        field_ids: Vec::new(),
    };

    let dissector: Option<Rc<dyn Dissector>>;

    // Copy our dissector pointer
    unsafe {
        let state = &mut STATIC_DISSECTOR.as_mut().unwrap();
        dissector = Some(Rc::clone(&state.ptr));
        dissection.fields_input = state.fields_input.clone();
        dissection.field_ids = state.field_ids.clone();
    }
    // Let the dissector do its thing!
    dissector.unwrap().dissect(&mut dissection);

    unsafe {
        return wireshark::tvb_reported_length(tvb) as u32;
    }
}

extern "C" fn proto_register_protoinfo() {
    println!("proto_register_hello");

    unsafe {
        let state = &mut STATIC_DISSECTOR.as_mut().unwrap(); // less wordy.

        let (full_name, short_name, filter_name) = state.ptr.get_protocol_name();
        state.proto_id = wireshark::proto_register_protocol(
            util::perm_string_ptr(full_name),
            util::perm_string_ptr(short_name),
            util::perm_string_ptr(filter_name),
        );
        println!("Proto proto_int: {:?}", state.proto_id);

        // ok, here we get to make our header fields array, and then we can pass that to wireshark.
        let fields = state.ptr.get_fields();
        state.fields_input = state.ptr.get_fields();
        println!(
            "Registering {} fields in the protocol register.",
            fields.len()
        );
        state.field_ids.resize(fields.len(), -1);
        for i in 0..fields.len() {
            state.fields_wireshark.push(wireshark::hf_register_info {
                p_id: &mut state.field_ids[i] as *mut i32,
                hfinfo: fields[i].into(),
            });
        }

        let rawptr = &mut state.fields_wireshark[0] as *mut wireshark::hf_register_info;
        wireshark::proto_register_field_array(state.proto_id, rawptr, fields.len() as i32);
    }
}

extern "C" fn proto_register_handoff() {
    // A handoff routine associates a protocol handler with the protocol’s traffic. It consists of two major steps:
    // The first step is to create a dissector handle, which is a handle associated with the protocol and the function called to do the actual dissecting.
    // The second step is to register the dissector handle so that traffic associated with the protocol calls the dissector.
    println!("proto_reg_handoff_hello");
    unsafe {
        let state = &mut STATIC_DISSECTOR.as_mut().unwrap(); // less wordy.
        let dissector_handle =
            wireshark::create_dissector_handle(Some(dissect_protocol_function), state.proto_id);

        for registration in state.ptr.get_registration() {
            match registration {
                Registration::Post {} => {
                    wireshark::register_postdissector(dissector_handle);
                }
                Registration::UInt { abbrev, pattern } => {
                    wireshark::dissector_add_uint(
                        util::perm_string_ptr(abbrev),
                        pattern,
                        dissector_handle,
                    );
                }

                Registration::UIntRange { abbrev, ranges } => {
                    println!("Ranges...");
                    let mut input : wireshark::epan_range = Default::default();
                    for i in 0..ranges.len()
                    {
                        input.ranges[i].low = ranges[i].0;
                        input.ranges[i].high = ranges[i].1;
                    }
                    input.nranges = input.ranges.len() as u32;

                    wireshark::dissector_add_uint_range(
                        util::perm_string_ptr(abbrev),
                        &input as *const wireshark::epan_range,
                        dissector_handle,
                    );
                }

                Registration::DecodeAs { abbrev } => {
                    wireshark::dissector_add_for_decode_as(
                        util::perm_string_ptr(abbrev),
                        dissector_handle,
                    );
                }
            }
        }

        // usb makes a table;     product_to_dissector = register_dissector_table("usb.product",   "USB product",  proto_usb, FT_UINT32, BASE_HEX);
    }
}

#[no_mangle]
static plugin_version: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"
#[no_mangle]
static plugin_release: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"
