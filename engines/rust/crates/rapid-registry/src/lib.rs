//! Windows registry hive (regf) reader for rapidtriage.
//!
//! This crate is a faithful port of the hive-reading layer in
//! `rapidtriage/artifacts/windows/registry.py` (`NativeRegistryHive`, the free-cell allocator
//! walk and the UTF-16LE string pivot). It intentionally reproduces the Python reader's
//! tolerance rules, error counters and text decoding so both engines emit identical rows; the
//! Python side selects it with `RAPIDTRIAGE_REGISTRY_ENGINE=rust`.

pub mod hive;
#[cfg(feature = "python")]
mod py;
pub mod scan;
pub mod text;

/// Bumped whenever the Python-facing contract of the extension changes; the Python loader
/// refuses (and falls back from) an extension built for a different contract.
pub const ABI_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::hive::{child_components, ErrorJournal, Geometry, Hive, KeyWalk, ValueData};
    use super::scan::{free_cell_candidates, utf16le_strings, FreeCellKind};

    /// Minimal one-hbin hive builder (cells are appended; offsets are hbin-relative).
    struct Builder {
        cells: Vec<u8>,
    }

    impl Builder {
        fn new() -> Self {
            Self { cells: Vec::new() }
        }

        fn alloc(&mut self, payload: &[u8], free: bool) -> u32 {
            let mut size = 4 + payload.len();
            size += (8 - size % 8) % 8;
            let offset = 32 + self.cells.len() as u32;
            let raw = if free { size as i32 } else { -(size as i32) };
            self.cells.extend_from_slice(&raw.to_le_bytes());
            self.cells.extend_from_slice(payload);
            self.cells
                .resize(self.cells.len() + size - 4 - payload.len(), 0);
            offset
        }

        fn patch(&mut self, cell: u32, field: usize, value: u32) {
            let position = cell as usize - 32 + 4 + field;
            self.cells[position..position + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn nk(&mut self, name: &str, parent: u32, free: bool) -> u32 {
            let mut body = vec![0u8; 0x4C];
            body[0..2].copy_from_slice(b"nk");
            body[2..4].copy_from_slice(&0x20u16.to_le_bytes());
            body[4..12].copy_from_slice(&133_930_492_691_655_237u64.to_le_bytes());
            body[0x10..0x14].copy_from_slice(&parent.to_le_bytes());
            body[0x1C..0x20].copy_from_slice(&u32::MAX.to_le_bytes());
            body[0x28..0x2C].copy_from_slice(&u32::MAX.to_le_bytes());
            body[0x48..0x4A].copy_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(name.as_bytes());
            self.alloc(&body, free)
        }

        fn vk(&mut self, name: &str, value_type: u32, data: &[u8]) -> u32 {
            let (size_field, data_field) = if data.len() <= 4 {
                let mut inline = [0u8; 4];
                inline[..data.len()].copy_from_slice(data);
                (0x8000_0000 | data.len() as u32, u32::from_le_bytes(inline))
            } else {
                (data.len() as u32, self.alloc(data, false))
            };
            let mut body = vec![0u8; 20];
            body[0..2].copy_from_slice(b"vk");
            body[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
            body[4..8].copy_from_slice(&size_field.to_le_bytes());
            body[8..12].copy_from_slice(&data_field.to_le_bytes());
            body[12..16].copy_from_slice(&value_type.to_le_bytes());
            body[16..18].copy_from_slice(&1u16.to_le_bytes());
            body.extend_from_slice(name.as_bytes());
            self.alloc(&body, false)
        }

        fn build(self, root: u32) -> Vec<u8> {
            let mut hbin_size = 32 + self.cells.len();
            hbin_size += (4096 - hbin_size % 4096) % 4096;
            let mut blob = vec![0u8; 4096 + hbin_size];
            blob[0..4].copy_from_slice(b"regf");
            blob[24..28].copy_from_slice(&5u32.to_le_bytes());
            blob[36..40].copy_from_slice(&root.to_le_bytes());
            blob[40..44].copy_from_slice(&(hbin_size as u32).to_le_bytes());
            blob[4096..4100].copy_from_slice(b"hbin");
            blob[4104..4108].copy_from_slice(&(hbin_size as u32).to_le_bytes());
            blob[4096 + 32..4096 + 32 + self.cells.len()].copy_from_slice(&self.cells);
            blob
        }
    }

    fn sample_hive() -> Vec<u8> {
        let mut builder = Builder::new();
        let root = builder.nk("ROOT", 0, false);
        let child = builder.nk("Select", root, false);
        let current = builder.vk("Current", 4, &1u32.to_le_bytes());
        let path_value = builder.vk(
            "Path",
            1,
            "C:\\Temp\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let values = builder.alloc(
            &[current.to_le_bytes(), path_value.to_le_bytes()].concat(),
            false,
        );
        builder.patch(child, 0x24, 2);
        builder.patch(child, 0x28, values);
        let mut list = b"lh".to_vec();
        list.extend_from_slice(&1u16.to_le_bytes());
        list.extend_from_slice(&child.to_le_bytes());
        list.extend_from_slice(&[0; 4]);
        let list = builder.alloc(&list, false);
        builder.patch(root, 0x14, 1);
        builder.patch(root, 0x1C, list);
        builder.nk("DeletedKey", child, true);
        builder.build(root)
    }

    #[test]
    fn walks_keys_values_and_free_cells() {
        let blob = sample_hive();
        let hive = Hive::new(&blob, Geometry::from_data(&blob));
        let mut errors = ErrorJournal::new();
        let root = hive
            .key_at(hive.geometry.root_cell_offset, &mut errors)
            .expect("root");
        assert_eq!(root.name, "ROOT");
        let mut walk = KeyWalk::new((Vec::new(), root));
        let mut seen = Vec::new();
        while let Some((parts, key)) = walk.next_entry(&hive, &mut errors, child_components) {
            seen.push((parts.join("\\"), key.name.clone()));
        }
        assert_eq!(
            seen,
            vec![
                (String::new(), "ROOT".to_string()),
                ("Select".to_string(), "Select".to_string())
            ]
        );
        assert!(errors.is_empty());

        let select = hive
            .subkeys_of(
                1,
                hive.key_at(hive.geometry.root_cell_offset, &mut errors)
                    .unwrap()
                    .subkey_list_offset,
                &mut errors,
            )
            .remove(0);
        let values = hive.values(&select, &mut errors);
        assert_eq!(values.len(), 2);
        assert_eq!(
            hive.value_data(&values[0], &mut errors),
            ValueData::Integer(1)
        );
        assert_eq!(
            hive.value_data(&values[1], &mut errors),
            ValueData::Text("C:\\Temp".to_string())
        );
        assert_eq!(hive.value_data_allocated(&values[1]), Some(true));
        assert_eq!(hive.value_data_allocated(&values[0]), None);

        let (candidates, stats) = free_cell_candidates(&hive);
        assert_eq!(candidates.len(), 1);
        assert!(
            matches!(&candidates[0].kind, FreeCellKind::Key(cell) if cell.name == "DeletedKey")
        );
        assert_eq!(stats.get("allocated_nk"), 2);
        assert_eq!(stats.get("free_nk"), 1);
        assert_eq!(stats.get("hbin_count"), 1);
    }

    #[test]
    fn misaligned_and_out_of_bounds_cells_are_journaled() {
        let blob = sample_hive();
        let hive = Hive::new(&blob, Geometry::from_data(&blob));
        let mut errors = ErrorJournal::new();
        assert!(hive.key_at(3, &mut errors).is_none());
        assert!(hive.key_at(0x7FFF_FFF8, &mut errors).is_none());
        assert!(hive.key_at(0, &mut errors).is_none());
        assert_eq!(
            errors,
            vec!["misaligned-cell-offset", "cell-offset-out-of-bounds"]
        );
    }

    #[test]
    fn utf16_strings_scan_both_alignments() {
        let mut blob: Vec<u8> = "\0Hello world\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        blob.insert(0, 0);
        blob.extend("Again text".encode_utf16().flat_map(u16::to_le_bytes));
        let strings = utf16le_strings(&blob, 4, 250);
        assert!(strings.contains(&"Hello world".to_string()));
        assert!(strings.contains(&"Again text".to_string()));
    }
}
