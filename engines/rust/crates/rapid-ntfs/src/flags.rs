// Flag and name tables copied from filesystem.py in the same order, so the
// decoded name lists come out in the order Python's dict iteration gives.

pub const USN_REASON_FLAGS: &[(u32, &str)] = &[
    (0x0000_0001, "DATA_OVERWRITE"),
    (0x0000_0002, "DATA_EXTEND"),
    (0x0000_0004, "DATA_TRUNCATION"),
    (0x0000_0010, "NAMED_DATA_OVERWRITE"),
    (0x0000_0020, "NAMED_DATA_EXTEND"),
    (0x0000_0040, "NAMED_DATA_TRUNCATION"),
    (0x0000_0100, "FILE_CREATE"),
    (0x0000_0200, "FILE_DELETE"),
    (0x0000_0400, "EA_CHANGE"),
    (0x0000_0800, "SECURITY_CHANGE"),
    (0x0000_1000, "RENAME_OLD_NAME"),
    (0x0000_2000, "RENAME_NEW_NAME"),
    (0x0000_4000, "INDEXABLE_CHANGE"),
    (0x0000_8000, "BASIC_INFO_CHANGE"),
    (0x0001_0000, "HARD_LINK_CHANGE"),
    (0x0002_0000, "COMPRESSION_CHANGE"),
    (0x0004_0000, "ENCRYPTION_CHANGE"),
    (0x0008_0000, "OBJECT_ID_CHANGE"),
    (0x0010_0000, "REPARSE_POINT_CHANGE"),
    (0x0020_0000, "STREAM_CHANGE"),
    (0x8000_0000, "CLOSE"),
];

pub const USN_SOURCE_INFO_FLAGS: &[(u32, &str)] = &[
    (0x0000_0001, "DATA_MANAGEMENT"),
    (0x0000_0002, "AUXILIARY_DATA"),
    (0x0000_0004, "REPLICATION_MANAGEMENT"),
    (0x0000_0008, "CLIENT_REPLICATION_MANAGEMENT"),
];

pub const NTFS_FILE_ATTRIBUTE_NAMES: &[(u32, &str)] = &[
    (0x0000_0001, "READONLY"),
    (0x0000_0002, "HIDDEN"),
    (0x0000_0004, "SYSTEM"),
    (0x0000_0010, "DIRECTORY"),
    (0x0000_0020, "ARCHIVE"),
    (0x0000_0040, "DEVICE"),
    (0x0000_0080, "NORMAL"),
    (0x0000_0100, "TEMPORARY"),
    (0x0000_0400, "REPARSE_POINT"),
    (0x0000_0800, "COMPRESSED"),
    (0x0000_1000, "OFFLINE"),
    (0x0000_4000, "ENCRYPTED"),
];

const MFT_ATTRIBUTE_TYPE_NAMES: &[(u64, &str)] = &[
    (0x10, "$STANDARD_INFORMATION"),
    (0x20, "$ATTRIBUTE_LIST"),
    (0x30, "$FILE_NAME"),
    (0x40, "$OBJECT_ID"),
    (0x50, "$SECURITY_DESCRIPTOR"),
    (0x60, "$VOLUME_NAME"),
    (0x70, "$VOLUME_INFORMATION"),
    (0x80, "$DATA"),
    (0x90, "$INDEX_ROOT"),
    (0xA0, "$INDEX_ALLOCATION"),
    (0xB0, "$BITMAP"),
    (0xC0, "$REPARSE_POINT"),
    (0xD0, "$EA_INFORMATION"),
    (0xE0, "$EA"),
    (0x100, "$LOGGED_UTILITY_STREAM"),
];

pub fn flag_names(value: u64, names: &[(u32, &str)]) -> Vec<String> {
    names
        .iter()
        .filter(|(flag, _)| value & u64::from(*flag) != 0)
        .map(|(_, name)| (*name).to_string())
        .collect()
}

pub fn unknown_flag_mask(value: u64, names: &[(u32, &str)]) -> u64 {
    let known = names
        .iter()
        .fold(0u64, |acc, (flag, _)| acc | u64::from(*flag));
    value & !known
}

pub fn attribute_type_name(attribute_type: u64) -> String {
    MFT_ATTRIBUTE_TYPE_NAMES
        .iter()
        .find(|(code, _)| *code == attribute_type)
        .map_or_else(
            || format!("0x{attribute_type:08x}"),
            |(_, name)| (*name).to_string(),
        )
}

pub fn file_name_namespace(namespace: u64) -> String {
    match namespace {
        0 => "POSIX".to_string(),
        1 => "WIN32".to_string(),
        2 => "DOS".to_string(),
        3 => "WIN32_AND_DOS".to_string(),
        other => other.to_string(),
    }
}
