// Copyright 2021-2021, Ivor Wanders and the wireshark_dissector_rs contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#[derive(Debug)]
#[repr(C)]
pub struct GPtrArray {
    // actually defined as a single pointer, but index macro shows its a
    // list of void pointers behind a pointer.
    pdata: *mut *mut libc::c_void,
    len: u32,
}
impl GPtrArray {
    pub fn len(self: &Self) -> usize {
        return self.len as usize;
    }
    pub unsafe fn index(self: &Self, index: isize) -> *mut libc::c_void {
        // This is actually a macro in the code.
        // #define    g_ptr_array_index(array,index_) ((array)->pdata)[index_]
        return *(self.pdata).offset(index);
    }
}

#[link(name = "glib-2.0")]
extern "C" {
    pub fn g_ptr_array_free(array: *mut GPtrArray, free_seg: bool);
}
