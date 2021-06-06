wireshark_dissector_rs
======================

This crate attempts to provide a safe way for writing [Wireshark](https://www.wireshark.org/) dissectors in Rust. It is
incomplete; it doesn't provide the full feature set Wireshark provides to dissectors. It was not created to be a full
binding for writing dissectors in Rust, instead I just implemented what I needed for some reverse engineering. It's
written by someone who's inexperienced with Rust, so there may be some non idiomatic things.

Because of the way Wireshark works, it is necessary to register the field and protocol foldouts before any dissection
takes place. This is obviously unchanged, and because of that it still makes dissectors rather verbose. See the
[dummy example](/../master/examples/dummy.rs) dissector. For the full documentation checkout this repo and run
`cargo doc`, start with the `Dissector` trait.

Usage
-----
Use `cargo doc` to build the documentation, the public interface is reasonably well documented. For
an example dissector take a look at the example directory. That example is pretty boring, but it
should serve as a good starting point to make your own dissector.

This crate is used in my [huntsman](https://github.com/iwanders/huntsman) project, where this
crate is used to perform a dissection by traversing over a tree of field definitions. It provides a
more elaborate example and shows how one could create a dissector without manually specifying all
the fields to be dissected.

License
------
It's a derivative work of Wireshark and links against it, [therefore](https://wiki.wireshark.org/Lua#Beware_the_GPL) it
is licensed GPL-2-or-later.
