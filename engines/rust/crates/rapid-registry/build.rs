fn main() {
    // macOS needs `-undefined dynamic_lookup` for a Python extension cdylib built by plain cargo.
    #[cfg(feature = "python")]
    pyo3_build_config::add_extension_module_link_args();
}
