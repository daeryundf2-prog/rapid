// macOS extension modules resolve libpython symbols at import time
// (`-undefined dynamic_lookup`); no-op on other targets and without `python`.
fn main() {
    #[cfg(feature = "python")]
    pyo3_build_config::add_extension_module_link_args();
}
