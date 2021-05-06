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

// This seems useful?
// https://stackoverflow.com/a/55323693

#![allow(non_camel_case_types)]
#![allow(dead_code)]

// These files follow the same structure as the header files.
pub mod ftypes;
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


*/
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



impl ProtoItem
{
    /// Replace text of item after it already has been created.
    pub fn set_text(self: &mut Self, text: &str)
    {
        let to_add = CString::new(text).unwrap().into_raw();
        unsafe
        {
            proto::proto_item_set_text(self.item.into(), to_add);
            // and clean up the string again.
            let _ = CString::from_raw(to_add);
        }
    }

    /// Append to text of item after it has already been created.
    pub fn append_text(self: &mut Self, text: &str)
    {
        let to_add = CString::new(text).unwrap().into_raw();
        unsafe
        {
            proto::proto_item_append_text(self.item.into(), to_add);
            let _ = CString::from_raw(to_add);
        }
    }

    /// Prepend to text of item after it has already been created.
    pub fn prepend_text(self: &mut Self, text: &str)
    {
        let to_add = CString::new(text).unwrap().into_raw();
        unsafe
        {
            proto::proto_item_prepend_text(self.item.into(), to_add);
            let _ = CString::from_raw(to_add);
        }
    }

    pub fn add_subtree(self: &mut Self, ett_id: proto::ETTIndex) -> ProtoTree
    {
        unsafe { ProtoTree::from_ptr( proto::proto_item_add_subtree(self.item.into(), ett_id)) }
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
    pub fn bytes(self: &mut Self, offset: usize) -> &[u8] {
        unsafe {
            let mut available_length = tvbuff::tvb_reported_length_remaining(self.tvb, offset as i32);
            if available_length < 0
            {
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
    pub fn tvb_reported_length_remaining(self: &mut Self, offset: usize) -> i32 {
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
