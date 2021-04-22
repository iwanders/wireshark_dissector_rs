
// https://gitlab.com/wireshark/wireshark/-/blob/master/doc/README.dissector
// /usr/include/wireshark/epan


#[repr(C)]
pub struct proto_plugin {
    //~ pub register_protoinfo: *mut libc::c_void,/* routine to call to register protocol information */
    pub register_protoinfo: Option<extern "C" fn()>,/* routine to call to register protocol information */
    pub register_handoff: Option<extern "C" fn()>,/* routine to call to register protocol information */
}

pub fn nop(){}

impl Default for proto_plugin {
    fn default() -> Self {
        proto_plugin {
            register_protoinfo: None,
            register_handoff: None,
        }
    }
}


#[link(name = "wireshark")]
extern {
    pub fn proto_register_protocol(name: *const libc::c_char, short_name: *const libc::c_char, filter_name: *const libc::c_char);
    pub fn proto_register_plugin(plugin: *const proto_plugin);

    pub fn g_print(string: *const libc::c_char);
}

