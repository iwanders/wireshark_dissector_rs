
// https://gitlab.com/wireshark/wireshark/-/blob/master/doc/README.dissector
// /usr/include/wireshark/epan


#[repr(C)]
pub struct proto_plugin {
    pub register_protoinfo: Option<extern "C" fn()>,/* routine to call to register protocol information */
    pub register_handoff: Option<extern "C" fn()>,/* routine to call to register protocol information */
}

impl Default for proto_plugin {
    fn default() -> Self {
        proto_plugin {
            register_protoinfo: None,
            register_handoff: None,
        }
    }
}

#[repr(C)] pub struct dissector_handle { _private: [u8; 0] }
type dissector_handle_t = *mut dissector_handle;
#[repr(C)] pub struct tvbuff_t { _private: [u8; 0] }
#[repr(C)] pub struct packet_info { _private: [u8; 0] }
type pinfo = packet_info;
#[repr(C)] pub struct proto_tree { _private: [u8; 0] }
#[repr(C)] pub struct proto_item { _private: [u8; 0] }


type dissector_t = Option<extern "C" fn(*mut tvbuff_t, *mut packet_info, *mut proto_tree, *mut libc::c_void) -> u32>;


//typedef struct capture_dissector_handle* capture_dissector_handle_t;

#[link(name = "wireshark")]
extern {
    pub fn tvb_reported_length(tvb : *const tvbuff_t) -> i32;

    pub fn proto_tree_add_protocol_format(tree : *mut proto_tree, hfindex: i32, tvb: *mut tvbuff_t, start: i32, length: i32, format: *const libc::c_char, ...) -> *mut proto_item;

    pub fn proto_register_protocol(name: *const libc::c_char, short_name: *const libc::c_char, filter_name: *const libc::c_char);
    pub fn proto_register_plugin(plugin: *const proto_plugin);

    pub fn create_dissector_handle(dissector : dissector_t, proto: i32) -> dissector_handle_t;
    pub fn register_postdissector(handle: dissector_handle_t);
    pub fn g_print(string: *const libc::c_char);
}

