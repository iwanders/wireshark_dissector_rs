use core::fmt::Debug;

#[repr(C)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum ftenum {
    NONE, /* used for text labels with no value */
    PROTOCOL,
    BOOLEAN, /* TRUE and FALSE come from <glib.h> */
    CHAR,    /* 1-octet character as 0-255 */
    UINT8,
    UINT16,
    UINT24, /* really a UINT32, but displayed as 6 hex-digits if FD_HEX*/
    UINT32,
    UINT40, /* really a UINT64, but displayed as 10 hex-digits if FD_HEX*/
    UINT48, /* really a UINT64, but displayed as 12 hex-digits if FD_HEX*/
    UINT56, /* really a UINT64, but displayed as 14 hex-digits if FD_HEX*/
    UINT64,
    INT8,
    INT16,
    INT24, /* same as for UINT24 */
    INT32,
    INT40, /* same as for UINT40 */
    INT48, /* same as for UINT48 */
    INT56, /* same as for UINT56 */
    INT64,
    IEEE_11073_SFLOAT,
    IEEE_11073_FLOAT,
    FLOAT,
    DOUBLE,
    ABSOLUTE_TIME,
    RELATIVE_TIME,
    STRING,      /* counted string, with no null terminator */
    STRINGZ,     /* null-terminated string */
    UINT_STRING, /* counted string, with count being the first part of the value */
    ETHER,
    BYTES,
    UINT_BYTES,
    IPv4,
    IPv6,
    IPXNET,
    FRAMENUM, /* a UINT32, but if selected lets you go to frame with that number */
    GUID,     /* GUID, UUID */
    OID,      /* OBJECT IDENTIFIER */
    EUI64,
    AX25,
    VINES,
    REL_OID, /* RELATIVE-OID */
    SYSTEM_ID,
    STRINGZPAD, /* null-padded string */
    FCWWN,
    STRINGZTRUNC, /* null-truncated string */
    NUM_TYPES,    /* last item number plus one */
}

impl Default for ftenum {
    fn default() -> Self {
        ftenum::NONE
    }
}

unsafe impl Send for ftenum {}

#[repr(C)]
pub struct ftype_t {
    _private: [u8; 0],
}

#[repr(C)]
pub union fvalue_t_value_union {
    /* Put a few basic types in here */
    uinteger: u32,
    sinteger: i32,
    integer64: u64,
    uinteger64: u64,
    sinteger64: i64,
    floating: f64,
    string: *const libc::c_char,
    ustring: *const libc::c_char,
    bytes: *const libc::c_char,

    //~ ipv4_addr_and_mask	ipv4;
    //~ ipv6_addr_and_prefix	ipv6;
    //~ e_guid_t		guid;
    //~ nstime_t		time;
    //~ protocol_value_t 	protocol;
    //~ guint16			sfloat_ieee_11073;
    //~ guint32			float_ieee_11073;
    _size: [u8; 24], // determined with sizeof from C.
}

impl Debug for fvalue_t_value_union {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "fvalue_t_value_union")
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct fvalue_t {
    pub ftype: *const ftype_t,
    pub value: fvalue_t_value_union,

    /* The following is provided for private use
     * by the fvalue. */
    fvalue_gboolean1: bool,
}

#[link(name = "wireshark")]
extern "C" {
    pub fn fvalue_type_ftenum(fv: *const fvalue_t) -> ftenum;

    pub fn fvalue_get_uinteger(fv: *const fvalue_t) -> u32;
    pub fn fvalue_get_sinteger(fv: *const fvalue_t) -> i32;
    pub fn fvalue_get_uinteger64(fv: *const fvalue_t) -> u64;
    pub fn fvalue_get_sinteger64(fv: *const fvalue_t) -> i64;
    pub fn fvalue_get_floating(fv: *const fvalue_t) -> f64;

    pub fn fvalue_get(fv: *const fvalue_t) -> *const libc::c_void;

    //~ pub fn fvalue_type_name(fv: *const fvalue_t) -> *const libc::c_char;  // Doesn't exist after linking...?
    //~ pub fn fvalue_length(fv: *const fvalue_t) -> u32;  // likewise, doesn't exist after linking? odd
}
