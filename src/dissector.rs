use crate::epan;
use crate::util;

use core::fmt::Debug;
/// The trait the dissector must adhere to.
pub trait Dissector {
    /// This function must return a vector of all the possible fields the dissector will end up using.
    fn get_fields(self: &Self) -> Vec<PacketField>;

    /// After the fields are registered, this function is called to provide the new HFIndices that should be used
    /// to refer to the registered fields.
    fn set_field_indices(self: &mut Self, hf_indices: Vec<(PacketField, epan::proto::HFIndex)>);

    /// Called when there is something to dissect, so probably called for every packet. This function must return how
    /// many bytes it used from the tvb.
    fn dissect(self: &mut Self, proto: &mut epan::ProtoTree, tvb: &mut epan::TVB) -> usize;

    /// Full name, short_name, filter_name
    fn get_protocol_name(self: &Self) -> (&'static str, &'static str, &'static str);

    /// This method should return a list that describes how this dissector's should be registered.
    fn get_registration(self: &Self) -> Vec<Registration> {
        return vec![Registration::Post];
    }

    /// This function should return the number of tree foldouts to register.
    fn get_tree_count(self: &Self) -> usize {
        return 0;
    }

    /// This function is called after registering the tree foldouts, the provides ETTIndices can be used to add the
    /// subtree elements to protocol items.
    fn set_tree_indices(self: &mut Self, _ett_indices: Vec<epan::proto::ETTIndex>) {}

    fn heuristic_applies(self: &mut Self, _proto: &mut epan::ProtoTree, _tvb: &mut epan::TVB) -> bool {
        false
    }
}
impl Debug for dyn Dissector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Dissector{{{}}}", self.get_protocol_name().0)
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
/// Enum to specify when to invoke this dissector.
pub enum Registration {
    /// Register as a postdissector, this calls `register_postdissector`.
    Post,
    /// Register an field abbreviation and a integer value, this calls `dissector_add_uint`, this for example allows
    /// registering based on a port, or based on an USB device id.
    UInt { abbrev: &'static str, pattern: u32 },
    /// Register based on a field abbreviation and a range of integers. (At the moment hardcoded limit to 100 ranges).
    UIntRange {
        abbrev: &'static str,
        ranges: Vec<(u32, u32)>,
    },
    /// Register this dissector for manual 'decode as' functionality.
    DecodeAs { abbrev: &'static str },
    /// As a heuristic dissector, uses the names from get_protocol_name() for registration.
    Heuristic {
        table: &'static str,
        display_name: &'static str,
        internal_name: &'static str,
        enabled: bool,
    },
}
