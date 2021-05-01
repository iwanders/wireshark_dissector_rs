
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
    pub fn tvb_reported_length_remaining(tvb: *const tvbuff_t, offset: i32) -> u32;

}
