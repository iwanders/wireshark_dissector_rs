#[repr(C)]
pub struct packet_info {
    _private: [u8; 0],
}
// Hmm, packet_info is enormous, but we have to reach into it for column info. Let skip that for now.
