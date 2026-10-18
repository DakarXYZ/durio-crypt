//! `uniffi-bindgen` pinned to the library's uniffi version (CR-13): the
//! Kotlin bindings are generated from the built library (`--library`).

fn main() {
    uniffi::uniffi_bindgen_main()
}
