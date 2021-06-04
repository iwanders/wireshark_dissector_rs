// Copyright 2021-2021, Ivor Wanders and the wireshark_dissector_rs contributors
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::epan;
use crate::plugin;
extern crate libc;
use core::fmt::Debug;

/// The trait the dissector must adhere to.
///
/// During the protocol registration, the [`Dissector::get_fields()`] method is invoked and those fields are registered for
/// display in wireshark. After registration, the [`Dissector::set_field_indices()`] method is called with the [`PacketField`] elements
/// that were retrieved from [`Dissector::get_fields()`], paired with the [`epan::proto::HFIndex`] values that should be used when
/// display dissection results in the protocol tree.
///
/// Besides the fields, the dissector also needs to register the subtree foldouts that it will use. During the setup the
/// [`Dissector::get_tree_count()`] method will be called, which should return the number of foldouts to register. After registration
/// the [`Dissector::set_tree_indices()`] method is called with a vector of indices to be used.
///
/// The final step of protocol registration, during the handoff is registering the dissector to be called on packets.
/// The desired registrations need to be returned from [`Dissector::get_registration()`], see Registration for more information.
///
/// Whenever the dissector is invoked, it's [`Dissector::dissect()`] (or [`Dissector::heuristic_dissect()`]) method will be called with the
/// protocol tree and data buffer.
pub trait Dissector {
    /// This function must return a vector of all the possible fields the dissector will end up using.
    fn get_fields(self: &Self) -> Vec<PacketField>;

    /// After the fields are registered, this function is called to provide the new [`epan::proto::HFIndex`] that should be used
    /// to refer to the registered fields.
    fn set_field_indices(self: &mut Self, hf_indices: Vec<(PacketField, epan::proto::HFIndex)>);

    /// Called when there is something to dissect, so probably called for every packet. This function must return how
    /// many bytes it used from the tvb.
    fn dissect(self: &Self, _proto: &mut epan::ProtoTree, _tvb: &mut epan::TVB) -> usize {
        0
    }

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

    /// This function is called after registering the tree foldouts, the provides [`epan::proto::ETTIndex`] can be used to add the
    /// subtree elements to protocol items.
    fn set_tree_indices(self: &mut Self, _ett_indices: Vec<epan::proto::ETTIndex>) {}

    /// This function is called when using a heuristic dissection.
    fn heuristic_dissect(self: &Self, _proto: &mut epan::ProtoTree, _tvb: &mut epan::TVB) -> bool {
        false
    }
}

//-------------------------------------------------
pub type FieldType = epan::ftypes::ftenum;
pub type FieldDisplay = epan::proto::FieldDisplay;

/// A type to allow both dynamic string creation as well as static strings, such that PacketField
/// can be used for CONST class members, as well as for dynamically generated names.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StringContainer {
    StaticStr(&'static str),
    String(String),
}

impl StringContainer {
    pub fn as_str(&self) -> &str {
        match self {
            StringContainer::String(s) => &s.as_str(),
            StringContainer::StaticStr(s) => s,
        }
    }
}

// Implement comparison operator against string slice.
impl std::cmp::PartialEq<&str> for StringContainer {
    fn eq(&self, other: &&str) -> bool {
        match self {
            StringContainer::String(s) => &s.as_str() == other,
            StringContainer::StaticStr(s) => s == other,
        }
    }
}

/// Specification for a field that can be displayed, simpler form of field_info on the C side.
// todo: Should we consolidate this (somehow?!) with epan::HeaderFieldInfo's wrapper for inspection?
#[derive(Debug, Clone)]
pub struct PacketField {
    /// This is the name as displayed for this field. (`Field Name`).
    pub name: StringContainer,
    /// This is the abbreviation / internal name of the field (`proto.field_name`).
    pub abbrev: StringContainer,
    /// This denotes the type of field.
    pub field_type: FieldType,
    /// This specifies how the field should be represented.
    pub display: FieldDisplay,
}

impl PacketField {
    pub const fn fixed(name: &'static str, abbrev: &'static str, field_type: FieldType, display: FieldDisplay) -> Self {
        PacketField {
            name: StringContainer::StaticStr(name),
            abbrev: StringContainer::StaticStr(abbrev),
            field_type: field_type,
            display: display,
        }
    }
}

// https://rust-lang.github.io/rfcs/0418-struct-variants.html
// This is so fancy
/// Specifies how to register this dissector.
pub enum Registration {
    /// Register as a postdissector, this calls `register_postdissector`, it is always ran, after all all other dissectors.
    Post,
    /// Register an field abbreviation and a integer value, this calls `dissector_add_uint`, this for example allows
    /// registering based on a port, or based on an USB device id.
    UInt {
        /// The table to register for.
        abbrev: &'static str,
        /// The value in this table to register.
        pattern: u32,
    },
    /// Register based on a field abbreviation and a range of integers.
    UIntRange {
        /// The table to register for.
        abbrev: &'static str,
        /// The value min-max ranges to register for.
        ranges: Vec<(u32, u32)>,
    },
    /// Register this dissector for manual 'decode as' functionality.
    DecodeAs {
        /// The table to register for.
        abbrev: &'static str,
    },
    /// As a heuristic dissector for the provided table and using display names from this.
    Heuristic {
        /// The table to register for.
        table: &'static str,
        /// Display name for this heuristic dissector
        display_name: &'static str,
        /// Internal name to use for the heuristic dissector.
        internal_name: &'static str,
        /// Does the heuristic dissector start enabled?
        enabled: bool,
    },
}

use std::rc::Rc;
/// Pass the dissector for setup, this is the main entry function that registers the plugin.
///
/// Currently, the one dissector that's handed in is stored in a global static. During setup we use it as a mutable
/// after setup it will be immutable and multiple threads from wireshark may interact with it.
pub fn setup<T: 'static + Dissector>(d: Rc<T>) {
    plugin::setup(d);
}
