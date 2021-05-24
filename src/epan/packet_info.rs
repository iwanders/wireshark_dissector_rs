// Copyright 2021-2021, Ivor Wanders and the wireshark_dissector_rs contributors
// SPDX-License-Identifier: GPL-2.0-or-later

#[repr(C)]
pub struct packet_info {
    _private: [u8; 0],
}
// Hmm, packet_info is enormous, but we have to reach into it for column info. Let skip that for now.
