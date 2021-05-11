#[repr(C)]
pub struct tvbuff_t {
    _private: [u8; 0],
}

#[link(name = "wireshark")]
extern "C" {
    // This function comes with the fatest warning ever...
    pub fn tvb_get_ptr(tvb: *const tvbuff_t, offset: i32, length: i32) -> *const u8;

    // Get reported length of buffer:
    pub fn tvb_reported_length(tvb: *const tvbuff_t) -> u32;
    pub fn tvb_reported_length_remaining(tvb: *const tvbuff_t, offset: i32) -> i32;


    /** Returns target for convenience. Does not suffer from possible
     * expense of tvb_get_ptr(), since this routine is smart enough
     * to copy data in chunks if the request range actually exists in
     * different "real" tvbuffs. This function assumes that the target
     * memory is already allocated; it does not allocate or free the
     * target memory. */
    pub fn tvb_memcpy(tvb: *const tvbuff_t, target: *mut libc::c_void, offset: i32, length: usize) -> *mut libc::c_void;
}
