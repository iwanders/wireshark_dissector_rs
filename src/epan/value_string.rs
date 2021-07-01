// Copyright 2021-2021, Ivor Wanders and the wireshark_dissector_rs contributors
// SPDX-License-Identifier: GPL-2.0-or-later

// value_string.h holds quite some flavours of this.

// Default value_string
#[repr(C)]
#[derive(Copy, Debug, Clone)]
pub struct value_string {
    pub value: libc::c_uint,
    pub string: *const libc::c_char,
}

impl Default for value_string{
    fn default() -> value_string
    {
        value_string { value: 0, string: 0 as *const libc::c_char}
    }
}
