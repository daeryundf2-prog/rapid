//! rapid-ntfs: a Rust port of RapidTriage's native NTFS metadata parsers.
//!
//! Mirrors, field for field, the Python reference in
//! `rapidtriage/artifacts/windows/filesystem.py`:
//!
//! * [`mft::parse_mft_record_headers`] <- `parse_mft_record_headers` (FILE record
//!   scan, slot geometry, update-sequence fixup, attribute decode);
//! * [`usn::parse_usn_record_scan`] <- `parse_usn_record_scan` (USN_RECORD v2/v3/v4
//!   window scan with resume cursors).
//!
//! Results are [`value::Value`] trees shaped like the Python dicts so the PyO3
//! layer (`--features python`, module `rapid_ntfs_native`) can hand them to the
//! existing consumers unchanged. Fields the port deliberately leaves out are
//! listed in `docs/architecture/rapid-ntfs.md`.

pub mod bytes;
pub mod filetime;
pub mod flags;
pub mod mft;
pub mod usn;
pub mod value;

#[cfg(feature = "python")]
mod py;
