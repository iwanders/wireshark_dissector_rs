use crate::epan;
use crate::util;

//-------------------------------------------------

/// The trait the dissector must adhere to.
pub trait Dissector {
    /// This function must return a vector of all the possible fields the dissector will end up using.
    fn get_fields(self: &Self) -> Vec<PacketField>;

    /// After the fields are registered, this function is called to provide the new HFIndices that should be used
    /// to refer to the registered fields.
    fn set_field_indices(self: &mut Self, hfindices: Vec<(PacketField, epan::proto::HFIndex)>);

    /// Called when there is something to dissect, so probably called for every packet. This function must return how
    /// many bytes it used from the tvb.
    fn dissect(self: &mut Self, proto: &mut epan::ProtoTree, tvb: &mut epan::TVB) -> usize;

    /// Full name, short_name, filter_name
    fn get_protocol_name(self: &Self) -> (&'static str, &'static str, &'static str);

    /// This method should return a list that describes how this dissector's should be registered.
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
        epan::proto::header_field_info {
            name: util::perm_string_ptr(field.name),
            abbrev: util::perm_string_ptr(field.abbrev),
            type_: field.field_type.into(),
            display: field.display.into(),
            ..Default::default()
        }
    }
}

// https://rust-lang.github.io/rfcs/0418-struct-variants.html
// This is so fancy
pub enum Registration {
    Post, // called after every frame's dissection.
    UInt {
        abbrev: &'static str,
        pattern: u32,
    },
    UIntRange {
        abbrev: &'static str,
        ranges: Vec<(u32, u32)>,
    },
    DecodeAs {
        abbrev: &'static str,
    },
}
