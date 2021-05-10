//! This crate attempts to provide a safe way for writing wireshark dissectors in Rust.
//! Please refer to [`dissector::Dissector`], that's the main entry-point for users.
extern crate libc;

/// Provides the trait and types a user created dissector must use.
pub mod dissector;

/// Provides bindings to the functions found in wireshark's epan headers. The root of the module holds safe wrappers
/// for some of the types. File structure mirrors that of the wireshark headers.
pub mod epan;

/// This module exposes a single plugin method and holds several C functions that are registered and subsequently call
/// into the Dissector object the user provided.
mod plugin;

// Utility module to make persistent C strings.
mod util;
