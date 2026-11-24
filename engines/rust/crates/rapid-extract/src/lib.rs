//! Opt-in Rust engine for the native E01 -> NTFS file extraction of
//! `rapidtriage.core.e01_native` (selected with `RAPIDTRIAGE_E01_EXTRACT_ENGINE=rust`).
//! Python keeps opening the image (pyewf or a raw file) and passes that handle in; this crate
//! walks NTFS and writes the recovered tree in one call per image.

pub mod extract;
pub mod lznt1;
pub mod ntfs;

#[cfg(feature = "python")]
mod py;

/// Contract version checked by `rapidtriage.core.e01_extract_engine`.
pub const ABI_VERSION: u32 = 1;
