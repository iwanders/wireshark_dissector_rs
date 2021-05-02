// https://doc.rust-lang.org/nomicon/ffi.html

/*
Todo:
    - display trees
    - derivable structs such that they implement a dissector or something... wouldn't that be cool?
*/

// We can probably hook; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/epan/dissectors/packet-usb.c#L3516-L3518
extern crate bitflags;
extern crate libc;

#[macro_use]
extern crate lazy_static;

pub mod dissector;
pub mod util;

pub mod epan;
//~ pub mod wireshark;

// Lift these to make it less verbose.
type FieldType = dissector::FieldType;
type FieldDisplay = dissector::FieldDisplay;

struct MyDissector {}
impl MyDissector {
    const FIELD1: dissector::PacketField = dissector::PacketField {
        name: "protoname",
        abbrev: "proto.main",
        field_type: FieldType::PROTOCOL,
        display: FieldDisplay::BASE_NONE,
    };
    const FIELD2: dissector::PacketField = dissector::PacketField {
        name: "first byte",
        abbrev: "proto.byte0",
        field_type: FieldType::UINT8,
        display: FieldDisplay::BASE_HEX,
    };
    const FIELD3: dissector::PacketField = dissector::PacketField {
        name: "second byte",
        abbrev: "proto.byte1",
        field_type: FieldType::UINT16,
        display: FieldDisplay::BASE_HEX,
    };
    const FIELD32: dissector::PacketField = dissector::PacketField {
        name: "uint32 byte",
        abbrev: "proto.byte3",
        field_type: FieldType::UINT32,
        display: FieldDisplay::BASE_HEX,
    };
    const FIELD64: dissector::PacketField = dissector::PacketField {
        name: "uint64 byte",
        abbrev: "proto.byte4",
        field_type: FieldType::UINT64,
        display: FieldDisplay::BASE_HEX,
    };
}
impl MyDissector
{

    fn dissect_displaylight(self: &Self, dissection: &mut dyn dissector::Dissection) 
    {
        dissection.dissect(&MyDissector::FIELD2.name);
        dissection.advance(3);
        dissection.dissect(&MyDissector::FIELD2.name);
        dissection.dissect(&MyDissector::FIELD2.name);
    }
}

impl dissector::Dissector for MyDissector {
    fn get_fields(self: &Self) -> Vec<dissector::PacketField> {
        println!("lib side get_fields");
        let mut f = Vec::new();
        f.push(MyDissector::FIELD1);
        f.push(MyDissector::FIELD2);
        f.push(MyDissector::FIELD3);
        f.push(MyDissector::FIELD32);
        f.push(MyDissector::FIELD64);
        return f;
    }

    fn dissect(self: &Self, dissection: &mut dyn dissector::Dissection) {
        return self.dissect_displaylight(dissection);
        let current = dissection.peek();
        println!("current: {:?}", current);
        dissection.dissect(&MyDissector::FIELD1.name);
        dissection.advance(5);
        dissection.dissect(&MyDissector::FIELD2.name);
        dissection.dissect(&MyDissector::FIELD3.name);
        dissection.dissect(&MyDissector::FIELD32.name);
        dissection.dissect(&MyDissector::FIELD64.name);
        // do cool rust things, pass entities into the display.
    }

    fn get_protocol_name(self: &Self) -> (&'static str, &'static str, &'static str) {
        return ("This is a test protocol", "testproto", "testproto");
    }

    fn get_registration(self: &Self) -> Vec<dissector::Registration> {
        return vec![
            //~ dissector::Registration::Post,
            dissector::Registration::DecodeAs {
                abbrev: "usb.product"
            },
            dissector::Registration::UInt {
                abbrev: "usb.product",
                pattern: 0x15320226
            },
            dissector::Registration::UInt {
                abbrev: "usb.device",
                pattern: 0x00030003
            },
            //~ dissector::Registration::UIntRange {
                //~ abbrev: "usb.product",
                //~ ranges: vec![(0x15320000, 0x1532FFFF)]
            //~ },
        ];
    }
}

// This function is the main entry point where we can do our setup.
#[no_mangle]
pub fn plugin_register() {
    use std::rc::Rc;
    let z = Rc::new(MyDissector {});
    dissector::setup(z);
}
