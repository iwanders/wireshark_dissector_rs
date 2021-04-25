// https://doc.rust-lang.org/nomicon/ffi.html


// We can probably hook; https://github.com/wireshark/wireshark/blob/ebfbf958f6930b2dad486b33277470e8368dc111/epan/dissectors/packet-usb.c#L3516-L3518
extern crate libc;
extern crate bitflags;

#[macro_use]
extern crate lazy_static;

mod util;
mod wireshark;
mod dissector;

struct MyDissector
{
}

impl dissector::Dissector for MyDissector
{
    fn dissect(self: &Self, display: &dissector::PacketDisplay, bytes: &[u8])
    {
        // do cool rust things, pass entities into the display.v
    }
    fn foo(self: &Self)
    {
        println!("yes, things.");
    }
}


// This function is the main entry point where we can do our setup.
#[no_mangle]
pub fn plugin_register()
{
    dissector::plugin_register_worker();

    let z = Box::new(MyDissector{});
    dissector::setup(z);
}
