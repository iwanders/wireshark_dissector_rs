
#[repr(C)]
pub struct dissector_handle {
    _private: [u8; 0],
}
type dissector_handle_t = *mut dissector_handle;


type dissector_t = Option<
    extern "C" fn(*mut tvbuff_t, *mut packet_info, *mut proto_tree, *mut libc::c_void) -> u32,
>;

#[link(name = "wireshark")]
extern "C" {
    pub fn register_postdissector(handle: dissector_handle_t);
    pub fn dissector_add_uint(
        abbrev: *const libc::c_char,
        pattern: u32,
        handle: dissector_handle_t,
    );
    pub fn dissector_add_uint_range(abbrev: *const libc::c_char, range: *const epan_range, handle: dissector_handle_t);
    //~ pub fn dissector_add_string(name: *const libc::c_char, pattern: *const libc::c_char, handle: dissector_handle_t);
    pub fn dissector_add_for_decode_as(name: *const libc::c_char, handle: dissector_handle_t);

    pub fn create_dissector_handle(dissector: dissector_t, proto: i32) -> dissector_handle_t;
}
