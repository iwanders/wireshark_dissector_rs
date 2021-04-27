
//-------------------------------------------------
/// The object we interact with when perfoming a dissection, allows querying the data and visualising it.
pub trait Dissection {
    // peeks
    fn peek_u8(self: &mut Self) -> u8;

    // Manual advance
    fn advance(self: &mut Self, amount: usize);

    // Adds display and advanced by this amount.
    fn dissect_u8(self: &mut Self, item: &dyn DisplayItem) -> u8;
    fn dissect_u16(self: &mut Self, item: &dyn DisplayItem) -> u16;

    fn dissect(self: &mut Self, item: &dyn DisplayItem)
    {
        match item.get_field().field_type
        {
            FieldType::UINT8 => {self.dissect_u8(item);},
            FieldType::UINT16 => {self.dissect_u16(item);}
            _ => {}
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct DissectionTest {
    pub pos: usize,
}
impl Dissection for DissectionTest {
    fn peek_u8(self: &mut Self) -> u8 {
        return self.pos as u8;
    }

    fn dissect_u8(self: &mut Self, _item: &dyn DisplayItem) -> u8 {
        println!("Displaying u8");
        let val = self.pos as u8;
        self.pos += 1;
        return val;
    }
    fn dissect_u16(self: &mut Self, _item: &dyn DisplayItem) -> u16 {
        println!("Displaying u16");
        let val = self.pos as u16;
        self.pos += 1;
        return val;
    }
    fn advance(self: &mut Self, amount: usize)
    {
        self.pos += amount;
    }
}

#[test]
fn it_works() {
    let mut z: DissectionTest = DissectionTest { pos: 0 };
    let peeked_u8 = z.peek_u8();
    println!("Peeked {}", peeked_u8);

    const FIELD1: PacketField = PacketField {
        name: "protoname",
        abbrev: "proto.main",
        field_type: FieldType::PROTOCOL,
        display: FieldDisplay::NONE,
    };
    z.dissect_u8(&field_to_display(FIELD1));
    println!("Peeked {}", z.peek_u8());
}

//-------------------------------------------------


/// The trait the dissector must adhere to.
pub trait Dissector {

    /// This function must return a vector of all the possible fields the dissector will end up using.
    fn get_fields(self: &Self) -> Vec<PacketField>;

    /// Called when there is somethign to dissect.
    fn dissect(self: &Self, dissection: &mut dyn Dissection);
}

/// Trivial implementation for a DisplayItem.
pub struct DisplayItemField {
    pub field: PacketField,
}
impl DisplayItem for DisplayItemField {
    fn get_field(self: &Self) -> PacketField {
        return self.field;
    }
}
/// Function to convert a PacketField into a DisplayItemField
pub fn field_to_display(thing: PacketField) -> DisplayItemField {
    return DisplayItemField { field: thing };
}



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
    pub fn display(self: &Self) -> DisplayItemField {
        DisplayItemField { field: *self }
    }
}


/// Something that is displayable in the ui, extra abstraction on top of PacketField atm, such that we can
/// dynamically update the text or something later...
pub trait DisplayItem {
    fn get_field(&self) -> PacketField;
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
        state.plugin_handle = Box::leak(plugin_handle_box); // Need this to persist....
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
    /// Helper to find the hf index this display item is associated with.
    fn find_field(self: &Self, item: &dyn DisplayItem) -> i32 {
        for i in 0..self.fields_input.len() {
            if item.get_field().name == self.fields_input[i].name {
                return self.field_ids[i];
            }
        }
        // panic!?
        return 0 as i32;
    }

}

impl EpanDissection {
    fn dissect_u(self: &mut Self, item: &dyn DisplayItem, size: usize) -> u64
    {
        let field_id = self.find_field(item);
        unsafe {
            wireshark::proto_tree_add_item(
                self.tree,
                field_id,
                self.tvb,
                self.pos as i32,
                size as i32,
                wireshark::Encoding::BIG_ENDIAN,
            );
        }
        self.pos += size;
        return 0;
    }
}


impl Dissection for EpanDissection {
    fn peek_u8(self: &mut Self) -> u8 {
        return 0 as u8;
    }

    
    fn dissect_u8(self: &mut Self, item: &dyn DisplayItem) -> u8 {
        self.dissect_u(item, std::mem::size_of::<u8>()) as u8
    }

    fn dissect_u16(self: &mut Self, item: &dyn DisplayItem) -> u16 {
        self.dissect_u(item, std::mem::size_of::<u16>()) as u16
    }

    fn advance(self: &mut Self, amount: usize)
    {
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

    let cstr = util::perm_string("hello");

    unsafe {
        let state = &mut STATIC_DISSECTOR.as_mut().unwrap(); // less wordy.

        let proto_int = wireshark::proto_register_protocol(
            util::perm_string_ptr("The thingy"),
            cstr.as_ptr(),
            cstr.as_ptr(),
        );
        println!("Proto proto_int: {:?}", proto_int);

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

        let z = wireshark::create_dissector_handle(Some(dissect_protocol_function), state.proto_id);
        println!("state.proto_id {:?}", state.proto_id);
        wireshark::register_postdissector(z);

        let rawptr = &mut state.fields_wireshark[0] as *mut wireshark::hf_register_info;
        wireshark::proto_register_field_array(proto_int, rawptr, fields.len() as i32);
    }
}

extern "C" fn proto_register_handoff() {
    println!("proto_reg_handoff_hello");
}

#[no_mangle]
static plugin_version: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"
#[no_mangle]
static plugin_release: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"
