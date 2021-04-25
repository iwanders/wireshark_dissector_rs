fn main() {
    println!("cargo:rustc-link-lib=wireshark");
    println!("cargo:rustc-link-lib=glib-2.0");
}
