pub trait PacketDisplay {
    fn display(self: &Self, item: dyn DisplayItem);
}

// A trait for things that can dissect data.
pub trait Dissector {
    fn get_fields(self: &Self) -> Vec<PacketField>;
    fn dissect(
        self: &Self,
        display: &dyn PacketDisplay, /* something that we can pass display entities into */
        bytes: &[u8],            /* Something with bytes? */
    );
    fn foo(self: &mut Self);
}

#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum FieldType {
    PROTOCOL,
    U8,
}
#[derive(Debug, Copy, Clone)]
#[allow(dead_code)]
pub enum FieldDisplay {
    NONE,
    DEC,
    HEX,
}

#[derive(Debug, Copy, Clone)]
pub struct PacketField {
    pub name: &'static str,
    pub abbrev: &'static str,
    pub field_type: FieldType,
    pub display: FieldDisplay,
}

// Something that is displayable in the ui.
pub trait DisplayItem {
    fn get_field(&self) -> PacketField;
}

struct DisplayU8 {
    field: PacketField,
}
impl DisplayItem for DisplayU8 {
    fn get_field(&self) -> PacketField {
        return self.field;
    }
}

// We know that wireshark will ensure only one thread accesses the disector, I think... make this static thing to
// hold our dissector object.
struct UnsafeDissectorHolder {
    ptr: Box<dyn Dissector>,
    field_ids: Vec<i32>,
    fields: Vec<wireshark::hf_register_info>,
}
unsafe impl Sync for UnsafeDissectorHolder {}
unsafe impl Send for UnsafeDissectorHolder {}
impl UnsafeDissectorHolder {
    fn new(ptr: Box<dyn Dissector>) -> Self {
        UnsafeDissectorHolder {
            ptr: ptr,
            field_ids: Vec::new(),
            fields: Vec::new(),
        }
    }
}

static mut STATIC_DISSECTOR: Option<UnsafeDissectorHolder> = None;

pub fn setup(d: Box<dyn Dissector>) {
    // Assign the dissector to be called sequentially.
    unsafe {
        STATIC_DISSECTOR = Some(UnsafeDissectorHolder::new(d));
    }
}

#[no_mangle]
static plugin_version: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"
#[no_mangle]
static plugin_release: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"

use std::ffi::CString;
// https://doc.rust-lang.org/std/ffi/struct.CStr.html

use crate::util;
use crate::wireshark;

// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-g723.c

//~ static mut PROTO_HELLO_HF: i32 = 0;
//~ static mut proto_hello_hf2: i32 = 0;

extern "C" fn dissect_hello(
    tvb: *mut wireshark::tvbuff_t,
    _packet_info: *mut wireshark::packet_info,
    tree: *mut wireshark::proto_tree,
    _data: *mut libc::c_void,
) -> u32 {
    unsafe {
        let state = &mut STATIC_DISSECTOR.as_mut().unwrap(); // less wordy.
        //~ STATIC_DISSECTOR.as_mut().unwrap().ptr.foo();
        //~ println!("Dissector hello called!");
        //~ let proto_hello: i32 = -1;
        let _proto_item = wireshark::proto_tree_add_protocol_format(
            tree,
            state.field_ids[0],
            tvb,
            0,
            0,
            util::perm_string_ptr(
                "This is Hello version, a Wireshark postdissector plugin %d prototype",
            ),
            3,
        );
        let _thing = wireshark::proto_tree_add_item(
            tree,
            state.field_ids[1],
            tvb,
            0,
            1,
            wireshark::Encoding::STR_HEX,
        );

        return wireshark::tvb_reported_length(tvb) as u32;
    }
}

//https://stackoverflow.com/a/55323803
trait AsMutPtr<T> {
    fn as_mut_ptr(&mut self) -> *mut T;
}

impl<'a, T> AsMutPtr<T> for Option<&'a mut T> {
    fn as_mut_ptr(&mut self) -> *mut T {
        match self {
            Some(v) => *v,
            None => {
                println!("Its a nullptr :( ");
                ptr::null_mut()
            }
        }
    }
}

extern "C" fn proto_register_hello() {
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
        println!(
            "Registering {} fields in the protocol register.",
            fields.len()
        );
        state.field_ids.resize(fields.len(), -1);
        for i in 0..fields.len() {
            state.fields.push(wireshark::hf_register_info {
                p_id: &mut state.field_ids[i] as *mut i32,
                hfinfo: fields[i].into(),
            });
        }

        let proto_hello: i32 = -1;
        let z = wireshark::create_dissector_handle(Some(dissect_hello), proto_hello);
        println!("Proto hello: {:?}", proto_hello);
        wireshark::register_postdissector(z);
        //~ let p = hf[0].data.map_or_else(ptr::null, |x| x);
        //~ unsafe { ffi_call(p) }
        let rawptr = &mut state.fields[0] as *mut wireshark::hf_register_info;
        //~ println!("rawptr hello: {:?}", rawptr);
        //~ println!("hf[0].data.thing: {}", hf[0].data.is_some());
        wireshark::proto_register_field_array(proto_int, rawptr, 2);
        //~ proto_hello_hf = state.field_ids[0];
        //~ proto_hello_hf2 = state.field_ids[1];
    }
    //~ register_postdissector(handle_hello);
}

extern "C" fn proto_reg_handoff_hello() {
    println!("proto_reg_handoff_hello");
}

//~ static mut five : Box<MaybeUninit<wireshark::proto_plugin>>;
//~ static mut five: Box<wireshark::proto_plugin> = Box::new(Default::default());

use std::ptr;

#[no_mangle]
pub fn plugin_register_worker() {
    //~ println!("Size of my new bitmask: {}",  std::mem::size_of::<wireshark::Encoding>());

    println!("plugin_register");
    let cstr = CString::new("hello").unwrap();
    unsafe {
        wireshark::g_print(cstr.as_ptr()); // Yas, we're in business!
                                           //~ five = Default::default();
        let mut five: Box<wireshark::proto_plugin> = Box::new(Default::default());
        //~ let mut plug : wireshark::proto_plugin = Default::default();
        five.register_protoinfo = Some(proto_register_hello);
        five.register_handoff = Some(proto_reg_handoff_hello);
        //~ five.register_handoff = Some(|| { proto_reg_handoff_hello() });
        wireshark::proto_register_plugin(Box::leak(five)); // This kinda sucks lol.
                                                           //~ wireshark::proto_register_plugin(&plug);
    }
}
