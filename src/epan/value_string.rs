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

// Same as value string, but then with 64 bit integer.
#[repr(C)]
#[derive(Copy, Debug, Clone)]
pub struct value64_string {
    pub value: libc::c_ulong,
    pub string: *const libc::c_char,
}

impl Default for value64_string{
    fn default() -> value64_string
    {
        value64_string { value: 0, string: 0 as *const libc::c_char}
    }
}

// Use a range for each string.
#[repr(C)]
#[derive(Copy, Debug, Clone)]
pub struct value_range_string {
    pub value_min: libc::c_uint,
    pub value_max: libc::c_uint,
    pub string: *const libc::c_char,
}

impl Default for value_range_string{
    fn default() -> value_range_string
    {
        value_range_string { value_min: 0, value_max: 0, string: 0 as *const libc::c_char}
    }
}
