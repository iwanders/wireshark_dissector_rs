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
}

impl Default for ftenum {
    fn default() -> Self {
        ftenum::NONE
    }
}

unsafe impl Send for ftenum {}
