// Copyright 2021-2021, Ivor Wanders and the wireshark_dissector_rs contributors
// SPDX-License-Identifier: GPL-2.0-or-later

extern crate wireshark_dissector_rs;

use wireshark_dissector_rs::dissector::{self, FieldDisplay, FieldType};
use wireshark_dissector_rs::epan::{self, proto::Encoding, HeaderFieldInfo};

// Need something to identify the tree foldouts by.
#[repr(usize)]
enum TreeIdentifier {
    Main,
    FirstElements,
    Last, // This allows us to cast this to an usize to get the number of tree identifiers.
}

/// Our dissector, just needs to hold the HFIndicers and ETTIndices.
struct MyDissector {
    field_mapping: Vec<(Box<dyn HeaderFieldInfo>, epan::proto::HFIndex)>,
    tree_indices: Vec<epan::proto::ETTIndex>,
    fields_made_at_runtime: Vec<ExtendedHeaderFieldInfo>,
}

/// We can also make more custom header field infos
#[derive(Debug, Clone)]
struct ExtendedHeaderFieldInfo
{
    info: dissector::BasicHeaderFieldInfo,
    strings: epan::HeaderFieldStrings,
    blurb: Option<String>,
}

impl epan::HeaderFieldInfo for ExtendedHeaderFieldInfo {
    fn name(&self) -> String {
        (&self.info as &dyn epan::HeaderFieldInfo).name()
    }
    fn abbrev(&self) -> String {
        (&self.info as &dyn epan::HeaderFieldInfo).abbrev()
    }
    fn feature_type(&self) -> epan::ftypes::ftenum {
        (&self.info as &dyn epan::HeaderFieldInfo).feature_type()
    }
    fn display_type(&self) -> epan::proto::FieldDisplay {
        (&self.info as &dyn epan::HeaderFieldInfo).display_type()
    }
    fn strings(&self) -> epan::HeaderFieldStrings {
        self.strings.clone()
    }
    fn blurb(&self) -> Option<String> {
        self.blurb.clone()
    }
}


impl MyDissector {
    /// BasicHeaderFieldInfo for the main root element of our dissection.
    const FIELD1: dissector::BasicHeaderFieldInfo = dissector::BasicHeaderFieldInfo {
        name: dissector::StringContainer::StaticStr("protoname"),
        abbrev: dissector::StringContainer::StaticStr("proto.main"),
        field_type: FieldType::PROTOCOL,
        display: FieldDisplay::BASE_NONE,
    };

    /// BasicHeaderFieldInfo for a first byte, represented as hexadecimal.
    const FIELD2: dissector::BasicHeaderFieldInfo = dissector::BasicHeaderFieldInfo {
        name: dissector::StringContainer::StaticStr("first byte"),
        abbrev: dissector::StringContainer::StaticStr("proto.byte0"),
        field_type: FieldType::UINT8,
        display: FieldDisplay::BASE_HEX,
    };

    /// The above is pretty verbose with that string container... so we also support:
    const FIELD3: dissector::BasicHeaderFieldInfo =
        dissector::BasicHeaderFieldInfo::fixed("second byte", "proto.byte1", FieldType::UINT16, FieldDisplay::BASE_HEX);

    /// Field to represent a signed 32 bit integer.
    const FIELD32: dissector::BasicHeaderFieldInfo = dissector::BasicHeaderFieldInfo {
        name: dissector::StringContainer::StaticStr("uint32 byte"),
        abbrev: dissector::StringContainer::StaticStr("proto.byte3"),
        field_type: FieldType::INT32,
        display: FieldDisplay::BASE_DEC,
    };

    /// Field to represent an unsigned 64 bit integer as hexadecimal.
    const FIELD64: dissector::BasicHeaderFieldInfo = dissector::BasicHeaderFieldInfo {
        name: dissector::StringContainer::StaticStr("uint64 byte"),
        abbrev: dissector::StringContainer::StaticStr("proto.byte4"),
        field_type: FieldType::UINT64,
        display: FieldDisplay::BASE_HEX,
    };

    const BITFIELD: dissector::BasicHeaderFieldInfo = dissector::BasicHeaderFieldInfo::fixed(
        "A bitfield",
        "proto.bitfield1",
        FieldType::UINT16,
        FieldDisplay::BASE_DEC,
    );
}

impl MyDissector {
    /// Helper function to retrieve the HFIndex that's associated to one of the BasicHeaderFieldInfos we used during setup.
    fn get_id(self: &Self, desired_field: &dyn HeaderFieldInfo) -> epan::proto::HFIndex {
        for (field, index) in &self.field_mapping {
            if field.name().as_str() == desired_field.name().as_str() {
                return *index;
            }
        }
        panic!("Couldn't find field id for {:?}", desired_field);
    }

    /// Helper function to retrieve the ETTIndex associated to a particular tree identifier.
    fn get_tree_id(self: &Self, identifier: TreeIdentifier) -> epan::proto::ETTIndex {
        match identifier {
            TreeIdentifier::Main => return self.tree_indices[0],
            TreeIdentifier::FirstElements => return self.tree_indices[1],
            TreeIdentifier::Last => {
                panic!("Retrieved incorrect TreeIdentifier value.");
            }
        };
    }

    fn new() -> MyDissector {
        // Look, it's using runtime Strings. we can still only do the creation of the fields once... but it allows
        // composing things.
        let runtime_defined_field = ExtendedHeaderFieldInfo{
            info: dissector::BasicHeaderFieldInfo {
                name: dissector::StringContainer::String(String::from("runtime.field")),
                abbrev: dissector::StringContainer::String(String::from("proto.runtime.field1")),
                field_type: FieldType::UINT16,
                display: FieldDisplay::BASE_HEX,
            },
            blurb: None,
            strings: epan::HeaderFieldStrings::None,
        };

        let field_with_strings = ExtendedHeaderFieldInfo{
            info: dissector::BasicHeaderFieldInfo {
                name: dissector::StringContainer::String(String::from("runtime.field.with_strings")),
                abbrev: dissector::StringContainer::String(String::from("proto.runtime.with_strings")),
                field_type: FieldType::UINT8,
                display: FieldDisplay::BASE_HEX,
            },
            blurb: Some("This is the blurb.".to_string()),
            strings: epan::HeaderFieldStrings::ValueString(vec![(0, "Zero".to_string()),
                               (1, "One".to_string()),
                               (2, "Two".to_string()),
                               (3, "Three".to_string()),
                             ]),
        };

        let field_with_strings64 = ExtendedHeaderFieldInfo{
            info: dissector::BasicHeaderFieldInfo {
                name: dissector::StringContainer::String(String::from("runtime.field.with_strings64")),
                abbrev: dissector::StringContainer::String(String::from("proto.runtime.with_strings64")),
                field_type: FieldType::UINT64,
                display: FieldDisplay::BASE_HEX,
            },
            blurb: Some("This is the blurb.".to_string()),
            strings: epan::HeaderFieldStrings::Value64String(vec![(0, "Zero".to_string()),
                               (1, "One".to_string()),
                               (2, "Two".to_string()),
                               (3, "Three".to_string()),
                             ]),
        };

        let with_strings_range = ExtendedHeaderFieldInfo{
            info: dissector::BasicHeaderFieldInfo {
                name: dissector::StringContainer::String(String::from("runtime.field.with_strings_range")),
                abbrev: dissector::StringContainer::String(String::from("proto.runtime.with_strings_range")),
                field_type: FieldType::UINT32,
                display: FieldDisplay::BASE_HEX,
            },
            blurb: Some("This is the blurb.".to_string()),
            strings: epan::HeaderFieldStrings::RangeString(vec![((0, 5), "Few".to_string()),
                               ((5, 1<<16), "Many".to_string()),
                               ((1<<16, 0xFFFFFFFF), "Lots".to_string()),
                             ]),
        };

        MyDissector {
            field_mapping: Vec::new(),
            tree_indices: Vec::new(),
            fields_made_at_runtime: vec![runtime_defined_field, field_with_strings,
                                        field_with_strings64,
                                        with_strings_range]
        }
    }
}

impl dissector::Dissector for MyDissector {
    /// This function is called during setup, it must provide all BasicHeaderFieldInfos we may end up using for registration.
    fn get_fields(self: &Self) -> Vec<Box<dyn HeaderFieldInfo>> {
        let mut f = Vec::new();
        f.push(MyDissector::FIELD1.as_boxed());
        f.push(MyDissector::FIELD2.as_boxed());
        f.push(MyDissector::FIELD3.as_boxed());
        f.push(MyDissector::FIELD32.as_boxed());
        f.push(MyDissector::FIELD64.as_boxed());
        f.push(MyDissector::BITFIELD.as_boxed());

        for i in 0..self.fields_made_at_runtime.len() {
            f.push(Box::new(self.fields_made_at_runtime[i].clone()));
        }
        return f;
    }

    /// This function is called after registering the fields retrieved from [`get_fields()`], it stores the indieces.
    fn set_field_indices(self: &mut Self, hfindices: Vec<(Box<dyn HeaderFieldInfo>, epan::proto::HFIndex)>) {
        self.field_mapping = hfindices;
    }

    /// This function is called during setup, it should return how many tree foldouts should be registered.
    fn get_tree_count(self: &Self) -> usize {
        return TreeIdentifier::Last as usize;
    }

    /// This function is called after the tree foldouts have been registered, the provided indices should be used to
    /// create subtree foldouts.
    fn set_tree_indices(self: &mut Self, ett_indices: Vec<epan::proto::ETTIndex>) {
        self.tree_indices = ett_indices;
    }

    /// The main dissection function, this is called whenever we are to dissect something.
    fn dissect(self: &Self, proto: &mut epan::ProtoTree, tvb: &mut epan::TVB) -> usize {
        // Usually, we want to use an offset and increment it as we progress through the packet.
        let mut offset = 0;

        // We can now add items to the dissection, for example dissect the first byte as a Field2 value;
        let mut item_entry = proto.add_item(self.get_id(&MyDissector::FIELD2), tvb, offset, 1, Encoding::BIG_ENDIAN);

        // And below that, we could add a subtree, using one of our tree identifiers:
        let mut fold_thing = item_entry.add_subtree(self.get_tree_id(TreeIdentifier::Main));

        // We can add an item to this subtree
        fold_thing.add_item(
            self.get_id(&MyDissector::FIELD3),
            tvb,
            offset + 1,
            2,
            Encoding::BIG_ENDIAN,
        );
        offset += 2;

        // Add the bitfield
        fold_thing.add_bits_item(
            self.get_id(&MyDissector::BITFIELD),
            tvb,
            (offset + 2) * 8 + 3, // In bits from the start of the buffer
            4,
            Encoding::BIG_ENDIAN,
        );

        // We can use the _ret_something flavour to also return a value;
        let (mut item, retval) = fold_thing.add_item_ret_int(
            self.get_id(&MyDissector::FIELD32),
            tvb,
            offset + 1,
            4,
            Encoding::BIG_ENDIAN,
        );

        // Test a runtime field, just to ensure the dynamic strings don't... segfault.
        fold_thing.add_item(
            self.get_id(&self.fields_made_at_runtime[0]),
            tvb,
            offset + 1,
            2,
            Encoding::BIG_ENDIAN,
        );

        // Add the item with the enums.
        fold_thing.add_item(
            self.get_id(&self.fields_made_at_runtime[1]),
            tvb,
            offset + 10,
            2,
            Encoding::BIG_ENDIAN,
        );


        // Add the item with the 64 bit enums.
        fold_thing.add_item(
            self.get_id(&self.fields_made_at_runtime[2]),
            tvb,
            offset + 10,
            8,
            Encoding::BIG_ENDIAN,
        );

        // add the item with the range
        fold_thing.add_item(
            self.get_id(&self.fields_made_at_runtime[3]),
            tvb,
            offset + 14,
            4,
            Encoding::BIG_ENDIAN,
        );


        // And we can prepend text if the returned value is even.
        if retval % 2 == 0 {
            item.prepend_text("foo");
        }

        // Or add our second foldout.
        let mut more_folds = item.add_subtree(self.get_tree_id(TreeIdentifier::FirstElements));
        more_folds.add_item(self.get_id(&MyDissector::FIELD64), tvb, offset, 1, Encoding::BIG_ENDIAN);

        tvb.reported_length()
    }

    /// This function is called during setup to retrieve the name used for the protocol we are dissecting.
    fn get_protocol_name(self: &Self) -> (&'static str, &'static str, &'static str) {
        return ("This is a test protocol", "testproto", "testproto");
    }

    /// This function is called during setup to register our dissector handler for particular dissector tables.
    fn get_registration(self: &Self) -> Vec<dissector::Registration> {
        return vec![
            dissector::Registration::Post,
            //~ dissector::Registration::DecodeAs { abbrev: "tcp.port" },
            //~ dissector::Registration::DecodeAs { abbrev: "usb.product" },
            //~ dissector::Registration::UInt {
            //~ abbrev: "usb.product",
            //~ pattern: 0x15320226,
            //~ },
            //~ dissector::Registration::UInt {
            //~ abbrev: "udp.dstport",
            //~ pattern: 8995,
            //~ },
            //~ dissector::Registration::UInt {
            //~ abbrev: "udp.port",
            //~ pattern: 69,
            //~ },
            //~ dissector::Registration::UInt {
            //~ abbrev: "usb.device",
            //~ pattern: 0x00030003,
            //~ },
        ];
    }
}

use std::rc::Rc;

/// This function is the main entry point for the plugin. It's the only symbol called automatically.
#[no_mangle]
pub fn plugin_register() {
    let z = Rc::new(MyDissector::new());
    dissector::setup(z);
}

// And we need these public symbols to tell wireshark we are a plugin that's made for the right version.
#[no_mangle]
static plugin_version: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"
#[no_mangle]
static plugin_release: [libc::c_char; 4] = [50, 46, 54, 0]; // "2.6"

// Later versions of wireshark also want these integers.
#[no_mangle]
static plugin_want_major: u32 = 2;
#[no_mangle]
static plugin_want_minor: u32 = 6;
