// https://doc.rust-lang.org/nomicon/ffi.html

// We can probably hook; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/epan/dissectors/packet-usb.c#L3516-L3518
extern crate bitflags;
extern crate libc;

#[macro_use]
extern crate lazy_static;

pub mod dissector;
pub mod util;
pub mod wireshark;

// Lift these to make it less verbose.
type FieldType = dissector::FieldType;
type FieldDisplay = dissector::FieldDisplay;

struct MyDissector {}
impl MyDissector {
    const FIELD1: dissector::PacketField = dissector::PacketField {
        name: "protoname",
        abbrev: "proto.main",
        field_type: FieldType::PROTOCOL,
        display: FieldDisplay::NONE,
    };
    const FIELD2: dissector::PacketField = dissector::PacketField {
        name: "first byte",
        abbrev: "proto.byte0",
        field_type: FieldType::U8,
        display: FieldDisplay::HEX,
    };
    const FIELD3: dissector::PacketField = dissector::PacketField {
        name: "second byte",
        abbrev: "proto.byte1",
        field_type: FieldType::U8,
        display: FieldDisplay::HEX,
    };
}

impl dissector::Dissector for MyDissector {
    fn get_fields(self: &Self) -> Vec<dissector::PacketField> {
        println!("lib side get_fields");
        let mut f = Vec::new();
        f.push(MyDissector::FIELD1);
        f.push(MyDissector::FIELD2);
        f.push(MyDissector::FIELD3);
        return f;
    }

    fn dissect(self: &Self, dissection: &mut dyn dissector::Dissection) {
        dissection.display_u8(&dissector::field_to_display(MyDissector::FIELD1));
        dissection.advance(5);
        dissection.display_u8(&dissector::field_to_display(MyDissector::FIELD2));
        dissection.display_u8(&dissector::field_to_display(MyDissector::FIELD3));
        // do cool rust things, pass entities into the display.

        //~ match p.parseU8(MyDissector::FIELD1)
        //~ {
        //~ 0x20 => {
        //~ // it's clearly a 'thing';
        //~ p.parseU8(MyDissector::FIELD2)
        //~ }
        //~ }
    }
}

// This function is the main entry point where we can do our setup.
#[no_mangle]
pub fn plugin_register() {
    use std::rc::Rc;
    let z = Rc::new(MyDissector {});
    dissector::setup(z);
}
