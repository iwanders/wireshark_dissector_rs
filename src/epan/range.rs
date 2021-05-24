// Copyright 2021-2021, Ivor Wanders and the wireshark_dissector_rs contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct range_admin_t {
    pub low: u32,
    pub high: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct epan_range {
    pub nranges: u32,
    pub ranges: [range_admin_t; 100], // Need https://blog.rust-lang.org/2021/02/26/const-generics-mvp-beta.html so badly...
}
impl Default for epan_range {
    fn default() -> epan_range {
        epan_range {
            nranges: 0,
            ranges: [range_admin_t { low: 0, high: 0 }; 100],
        }
    }
}
