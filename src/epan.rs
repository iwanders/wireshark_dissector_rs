// https://www.wireshark.org/docs/wsdg_html/#ChDissectDetails
// /usr/include/wireshark/epan

// https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/epan/dissectors/packet-usb.c
// https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/epan/dissectors/packet-usb-hid.c
// 1.5 Constructing the protocol tree; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/doc/README.dissector#L713

// 1.5.1 Field Registration; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/doc/README.dissector#L1270
// 1.7 Calling other dissectors; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/doc/README.dissector#L2471
// 1.7.1 Dissector Tables; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/doc/README.dissector#L2540

// 1.5.2 Adding Items and Values to the Protocol Tree. https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/doc/README.dissector#L1351

// Reassembly 2.7.2 Modifying the pinfo struct; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/doc/README.dissector#L3472
// Yeah, that doesn't work for USB packets... gg.
// https://doc.rust-lang.org/nomicon/ffi.html

// We can probably hook; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/epan/dissectors/packet-usb.c#L3516-L3518

// This seems useful?
// https://stackoverflow.com/a/55323693

#![allow(non_camel_case_types)]
#![allow(dead_code)]

// These files follow the same structure as the header files.
pub mod ftypes;
pub mod glib;
pub mod packet;
pub mod packet_info;
pub mod proto;
pub mod range;
pub mod tvbuff;

/*
   Dissector
       get_fields()
       get_tree()
       get_protocol_name()
       get_registration()

   ProtoTree
       add_**(field_index, tvb, pos, len, encoding, ....) -> returns ProtoItem
       add_boolean(field_index,tvb, start,
       add_item_ret_uint64 -> returns (ProtoItem, u64)

   PacketInfo?
       Lets ignore for now.

   TVB
       // Raw peeking into the buffer.

   ProtoItem
       // Things like:
       proto_item_set_text(proto_item *ti, const char *format, ...) G_GNUC_PRINTF(2,3);
       proto_item_add_subtree(tree_index) -> ProtoTree



    Todo: switch from pointers to references with proper lifetime if that's possible?
*/

/// Wrapper around the fvalue_t found in the FieldInfo struct
pub struct FValue<'a> {
    value: &'a ftypes::fvalue_t,
}
impl FValue<'_> {
    /// Create the FValue from the input argument.
    pub unsafe fn from(v: &ftypes::fvalue_t) -> FValue {
        // This may even be safe??
        return FValue { value: v };
    }

    /// Obtain the enum that represents the type of data held by the value.
    pub fn ftenum(&self) -> ftypes::ftenum {
        unsafe { ftypes::fvalue_type_ftenum(self.value as *const ftypes::fvalue_t) }
    }

    /// Retrieve an unsigned integer, should only be called if ftenum returns an integer-type.
    pub fn get_uinteger(&self) -> u32 {
        unsafe { ftypes::fvalue_get_uinteger(self.value as *const ftypes::fvalue_t) }
    }

    /// Retrieve an unsigned integer, should only be called if ftenum returns an signed integer-type.
    pub fn get_sinteger(&self) -> i32 {
        unsafe { ftypes::fvalue_get_sinteger(self.value as *const ftypes::fvalue_t) }
    }

    /// Retrieve an unsigned 64 bit integer, should only be called if ftenum returns an 64 bit integer-type.
    pub fn get_uinteger64(&self) -> u64 {
        unsafe { ftypes::fvalue_get_uinteger64(self.value as *const ftypes::fvalue_t) }
    }

    /// Retrieve an unsigned 64 bit signed integer, should only be called if ftenum returns an 64 bit signed integer-type.
    pub fn get_sinteger64(&self) -> i64 {
        unsafe { ftypes::fvalue_get_sinteger64(self.value as *const ftypes::fvalue_t) }
    }

    /// Retrieve an floating point value, should only be called if ftenum returns an a floating point type.
    pub fn get_floating(&self) -> f64 {
        unsafe { ftypes::fvalue_get_floating(self.value as *const ftypes::fvalue_t) }
    }

    /*
    pub fn get_length(&self) -> usize
    {
        unsafe
        {
            ftypes::fvalue_length(self.value as *const ftypes::fvalue_t) as usize
        }
    }

    pub fn get(self: &Self) -> &[u8] {
        unsafe {
            let data_ptr = ftypes::fvalue_get(self.value as *const ftypes::fvalue_t) as *const u8;
            return std::slice::from_raw_parts(data_ptr, self.get_length());
        };
    }
    */
}
impl Debug for FValue<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FValue<'_> {{ ")?;
        write!(f, "type: \"{:?}\", ", self.ftenum())?;
        match self.ftenum() {
            ftypes::ftenum::UINT8 => write!(f, "value: {:?}", self.get_uinteger())?,
            ftypes::ftenum::UINT16 => write!(f, "value: {:?}", self.get_uinteger())?,
            ftypes::ftenum::UINT32 => write!(f, "value: {:?}", self.get_uinteger())?,
            ftypes::ftenum::INT8 => write!(f, "value: {:?}", self.get_sinteger())?,
            ftypes::ftenum::INT16 => write!(f, "value: {:?}", self.get_sinteger())?,
            ftypes::ftenum::INT32 => write!(f, "value: {:?}", self.get_sinteger())?,
            //~ ftypes::ftenum::BYTES => write!(f, "value: {:?}", self.get())?,
            _ => write!(f, "value: ...")?,
        }
        write!(f, "}}")
    }
}

/// Struct to represent header field information, serves as a read only wrapper around the `header_field_info` C struct.
pub struct HeaderFieldInfo {
    hfi: *const proto::header_field_info,
}
impl HeaderFieldInfo {
    /// Function to make this structure from a raw pointer.
    pub unsafe fn from_ptr(header_field_info: *const proto::header_field_info) -> HeaderFieldInfo {
        if (header_field_info.is_null()) {
            panic!("HeaderFieldInfo from nullptr.");
        }
        return HeaderFieldInfo { hfi: header_field_info };
    }

    /// Retrieve the pretty field name
    pub fn name(self: &Self) -> &str {
        use std::ffi::CStr;
        unsafe {
            match CStr::from_ptr((*self.hfi).name).to_str() {
                Ok(t) => t,
                Err(_) => "",
            }
        }
    }

    /// Retrieve the field abbreviation.
    pub fn abbrev(self: &Self) -> &str {
        use std::ffi::CStr;
        unsafe {
            match CStr::from_ptr((*self.hfi).abbrev).to_str() {
                Ok(t) => t,
                Err(_) => "",
            }
        }
    }

    /// Obtain the field type enum.
    pub fn type_(self: &Self) -> ftypes::ftenum {
        unsafe {
            return (*self.hfi).type_;
        }
    }

    /// Obtain the field display enum.
    pub fn display(self: &Self) -> proto::FieldDisplay {
        unsafe {
            return (*self.hfi).display;
        }
    }
}
use core::fmt::Debug;
impl Debug for HeaderFieldInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HeaderFieldInfo {{ ")?;
        write!(f, "name: \"{}\", ", self.name())?;
        write!(f, "abbrev: \"{}\", ", self.abbrev())?;
        write!(f, "type_: {:?}, ", self.type_())?;
        //~ write!(f, "display: {:?}", self.display())?;  // This segfaults, somewhere in 'gimli'.
        write!(f, "}}")
    }
}

/// Struct to represent field information, serves as a wrapper around the `field_info` C struct.
pub struct FieldInfo {
    fi: *const proto::field_info,
}

impl FieldInfo {
    /// Function to make this structure from a raw pointer.
    pub unsafe fn from_ptr(field_info: *const proto::field_info) -> FieldInfo {
        if (field_info.is_null()) {
            panic!("Field Info from nullptr.");
        }
        return FieldInfo { fi: field_info };
    }

    /// Obtain the header field info for this field.
    pub fn hfinfo(self: &Self) -> Result<HeaderFieldInfo, &'static str> {
        unsafe {
            if ((*self.fi).hfinfo.is_null()) {
                return Err("No hfinfo provided");
            }
            return Ok(HeaderFieldInfo::from_ptr((*self.fi).hfinfo));
        }
    }

    /// current start of data in field_info.ds_tvb
    pub fn start(self: &Self) -> i32 {
        unsafe { (*self.fi).start }
    }

    /// current data length of item in field_info.ds_tvb
    pub fn length(self: &Self) -> i32 {
        unsafe { (*self.fi).length }
    }

    /// data source tvbuff
    pub fn ds_tvb(self: &Self) -> Option<TVB> {
        unsafe {
            if ((*self.fi).ds_tvb.is_null()) {
                return None;
            }
            return Some(TVB::from_ptr((*self.fi).ds_tvb));
        }
    }

    pub fn value(self: &Self) -> FValue {
        unsafe { FValue::from(&(*self.fi).value) }
    }
}
impl Debug for FieldInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FieldInfo {{ ")?;
        write!(f, "hfinfo: \"{:?}\", ", self.hfinfo())?;
        write!(f, "start: \"{:?}\", ", self.start())?;
        write!(f, "length: \"{:?}\", ", self.length())?;
        write!(f, "value: \"{:?}\", ", self.value())?;
        write!(f, "}}")
    }
}

/// Struct to represent a protocol tree, serves as a wrapper around the `proto_tree_*` C functions.
pub struct ProtoTree {
    tree: *mut proto::proto_tree,
}

impl ProtoTree {
    /// Function to make this structure from a raw pointer.
    pub unsafe fn from_ptr(tree: *mut proto::proto_tree) -> ProtoTree {
        return ProtoTree { tree: tree };
    }

    /// Add an item to a proto_tree, using the text label registered to that item.
    /// The item is extracted from the tvbuff handed to it.
    pub fn add_item(
        self: &mut Self,
        hfindex: proto::HFIndex,
        tvb: &mut TVB,
        start: usize,
        length: usize,
        encoding: proto::Encoding,
    ) -> ProtoItem {
        unsafe {
            ProtoItem {
                item: proto::proto_tree_add_item(self.tree, hfindex, tvb.into(), start as i32, length as i32, encoding),
            }
        }
    }

    /// Add an integer data item to a proto_tree, using the text label registered to that item.
    /// The item is extracted from the tvbuff handed to it, and the retrieved
    /// value is also returned to so the caller gets it back for other uses.
    pub fn add_item_ret_int(
        self: &mut Self,
        hfindex: proto::HFIndex,
        tvb: &mut TVB,
        start: usize,
        length: usize,
        encoding: proto::Encoding,
    ) -> (ProtoItem, i32) {
        let mut retval: i32 = 0;
        unsafe {
            return (
                ProtoItem {
                    item: proto::proto_tree_add_item_ret_int(
                        self.tree,
                        hfindex,
                        tvb.into(),
                        start as i32,
                        length as i32,
                        encoding,
                        &mut retval as *mut i32,
                    ),
                },
                retval,
            );
        }
    }

    pub fn all_finfos(self: &mut Self) -> Vec<FieldInfo> {
        let mut res: Vec<FieldInfo> = Vec::new();

        // see wslua_field.c function wslua_all_field_infos
        if (self.tree.is_null())
        // Not too sure when this happens... tree seems to be null when first invoked?
        {
            return res;
        }
        unsafe {
            let fields = proto::proto_all_finfos(self.tree);
            for i in 0..(*fields).len() {
                let field =
                    std::mem::transmute::<*mut libc::c_void, *const proto::field_info>((*fields).index(i as isize));
                res.push(FieldInfo::from_ptr(field));
            }
            glib::g_ptr_array_free(fields, true);
            // The field info's actually stay in scope, as they are part of the proto datastructure.
            // the lua part also persists them after they're gone.
        }
        return res;
    }
}

use std::ffi::CString;

/// Struct to represent a protocol item, serves as a wrapper around the `proto_item_*` C functions.
pub struct ProtoItem {
    item: *mut proto::proto_item,
}
impl From<&mut ProtoItem> for *mut proto::proto_item {
    fn from(field: &mut ProtoItem) -> Self {
        return field.item;
    }
}

impl ProtoItem {
    /// Replace text of item after it already has been created.
    pub fn set_text(self: &mut Self, text: &str) {
        let to_add = CString::new(text).unwrap().into_raw();
        unsafe {
            proto::proto_item_set_text(self.item.into(), to_add);
            // and clean up the string again.
            let _ = CString::from_raw(to_add);
        }
    }

    /// Append to text of item after it has already been created.
    pub fn append_text(self: &mut Self, text: &str) {
        let to_add = CString::new(text).unwrap().into_raw();
        unsafe {
            proto::proto_item_append_text(self.item.into(), to_add);
            let _ = CString::from_raw(to_add);
        }
    }

    /// Prepend to text of item after it has already been created.
    pub fn prepend_text(self: &mut Self, text: &str) {
        let to_add = CString::new(text).unwrap().into_raw();
        unsafe {
            proto::proto_item_prepend_text(self.item.into(), to_add);
            let _ = CString::from_raw(to_add);
        }
    }

    pub fn add_subtree(self: &mut Self, ett_id: proto::ETTIndex) -> ProtoTree {
        unsafe { ProtoTree::from_ptr(proto::proto_item_add_subtree(self.item.into(), ett_id)) }
    }
}
/// Struct to represent a Testy Virtual Buffer, serves as a wrapper around the `tvb_*` C functions.
pub struct TVB {
    tvb: *mut tvbuff::tvbuff_t,
}
impl TVB {
    /// Create this structure from a raw pointer.
    pub unsafe fn from_ptr(tvb: *mut tvbuff::tvbuff_t) -> TVB {
        return TVB { tvb: tvb };
    }

    /// Function to create a byte slice that can be used to access the data from the tvb.
    /// This comes with the following disclaimer in the header:
    ///
    /// This function is possibly expensive, temporarily allocating
    /// another copy of the packet data. Furthermore, it's dangerous because once
    /// this pointer is given to the user, there's no guarantee that the user will
    /// honor the 'length' and not overstep the boundaries of the buffer.
    ///
    /// If you're thinking of using tvb_get_ptr, STOP WHAT YOU ARE DOING
    /// IMMEDIATELY. Go take a break. Consider that tvb_get_ptr hands you
    /// a raw, unprotected pointer that you can easily use to create a
    /// security vulnerability or otherwise crash Wireshark. Then consider
    /// that you can probably find a function elsewhere in this file that
    /// does exactly what you want in a much more safe and robust manner.
    pub fn remaining_bytes(self: &mut Self, offset: usize) -> &[u8] {
        unsafe {
            let mut available_length = tvbuff::tvb_reported_length_remaining(self.tvb, offset as i32);
            if available_length < 0 {
                available_length = 0;
            }
            let data_ptr = tvbuff::tvb_get_ptr(self.tvb, offset as i32, available_length as i32);
            return std::slice::from_raw_parts(data_ptr, available_length as usize);
        };
    }

    /// Get reported length of buffer.
    pub fn reported_length(self: &mut Self) -> usize {
        unsafe {
            return tvbuff::tvb_reported_length(self.tvb) as usize;
        }
    }

    /// Computes bytes of reported packet data to end of buffer, from offset
    /// (which can be negative, to indicate bytes from end of buffer). Function
    /// returns 0 if offset is either at the end of the buffer or out of bounds.
    /// No exception is thrown.
    pub fn reported_length_remaining(self: &mut Self, offset: usize) -> i32 {
        unsafe {
            return tvbuff::tvb_reported_length_remaining(self.tvb, offset as i32);
        }
    }
}

impl From<&mut TVB> for *mut tvbuff::tvbuff_t {
    fn from(field: &mut TVB) -> Self {
        return field.tvb;
    }
}
