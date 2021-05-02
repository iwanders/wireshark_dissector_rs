// https://doc.rust-lang.org/nomicon/ffi.html

/*
Todo:
    - display trees
    - derivable structs such that they implement a dissector or something... wouldn't that be cool?
*/

// We can probably hook; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/epan/dissectors/packet-usb.c#L3516-L3518
extern crate libc;

#[macro_use]
extern crate lazy_static;

pub mod dissector;
pub mod plugin;
pub mod util;

pub mod epan;
//~ pub mod wireshark;

// Lift these to make it less verbose.
type FieldType = dissector::FieldType;
type FieldDisplay = dissector::FieldDisplay;

struct MyDissector {
    field_mapping: Vec<(dissector::PacketField, epan::proto::HFIndex)>,
}
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
impl MyDissector {
    fn get_id(self: &Self, desired_field: &dissector::PacketField) -> epan::proto::HFIndex {
        for (field, index) in &self.field_mapping {
            if field.name == desired_field.name {
                return *index;
            }
        }
        panic!("Couldn't find field id for {:?}", desired_field);
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

    fn set_field_indices(self: &mut Self, hfindices: Vec<(dissector::PacketField, epan::proto::HFIndex)>) {
        self.field_mapping = hfindices;
    }

    fn dissect(self: &mut Self, proto: &mut epan::ProtoTree, tvb: &mut epan::TVB) -> usize {
        //~ return self.dissect_displaylight(dissection);
        //~ println!("bytes: {:?}", tvb.bytes(0));
        proto.add_item(
            self.get_id(&MyDissector::FIELD2),
            tvb,
            0,
            1,
            epan::proto::Encoding::BIG_ENDIAN,
        );
        proto.add_item(
            self.get_id(&MyDissector::FIELD3),
            tvb,
            1,
            2,
            epan::proto::Encoding::BIG_ENDIAN,
        );
        tvb.reported_length()
    }

    fn get_protocol_name(self: &Self) -> (&'static str, &'static str, &'static str) {
        return ("This is a test protocol", "testproto", "testproto");
    }

    fn get_registration(self: &Self) -> Vec<dissector::Registration> {
        // usb makes a table;     product_to_dissector = register_dissector_table("usb.product",   "USB product",  proto_usb, FT_UINT32, BASE_HEX);
        return vec![
            //~ dissector::Registration::Post,
            dissector::Registration::DecodeAs { abbrev: "usb.product" },
            dissector::Registration::UInt {
                abbrev: "usb.product",
                pattern: 0x15320226,
            },
            dissector::Registration::UInt {
                abbrev: "usb.device",
                pattern: 0x00030003,
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
    let z = Box::new(MyDissector {
        field_mapping: Vec::new(),
    });
    plugin::setup(z);
}
