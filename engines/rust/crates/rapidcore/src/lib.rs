use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const ARTIFACT_SCHEMA_VERSION: &str = "ArtifactRecordV1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceRef {
    pub case_id: String,
    pub source_id: String,
    pub source_path: String,
    pub offset: Option<u64>,
    pub length: Option<u64>,
    #[serde(default)]
    pub hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactRecordV1 {
    pub schema: String,
    pub artifact_id: String,
    pub artifact_family: String,
    pub artifact_type: String,
    pub parser: String,
    pub parser_version: String,
    pub source: SourceRef,
    pub confidence: f64,
    pub validation_required: bool,
    pub commercial_grade_ready: bool,
    #[serde(default)]
    pub commercial_grade_blockers: Vec<String>,
    #[serde(default)]
    pub legal_limitations: Vec<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, serde_json::Value>,
}

impl ArtifactRecordV1 {
    pub fn noop(case_id: String, source_id: String, source_path: String) -> Self {
        let artifact_id = format!("{}:{}:noop:0", case_id, source_id);
        Self {
            schema: ARTIFACT_SCHEMA_VERSION.to_string(),
            artifact_id,
            artifact_family: "worker-health".to_string(),
            artifact_type: "noop-worker-record".to_string(),
            parser: "rapid-worker-noop".to_string(),
            parser_version: env!("CARGO_PKG_VERSION").to_string(),
            source: SourceRef {
                case_id,
                source_id,
                source_path,
                offset: None,
                length: None,
                hashes: BTreeMap::new(),
            },
            confidence: 1.0,
            validation_required: false,
            commercial_grade_ready: false,
            commercial_grade_blockers: vec![
                "noop-parser-is-worker-contract-test-only".to_string(),
                "real-parser-validation-required".to_string(),
            ],
            legal_limitations: vec![
                "This noop record proves worker connectivity only; it is not forensic evidence."
                    .to_string(),
            ],
            fields: BTreeMap::new(),
        }
    }

    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn file_inventory(
        case_id: String,
        source_id: String,
        source_path: String,
        file_path: &Path,
        size_bytes: u64,
        modified_unix_seconds: Option<u64>,
    ) -> Self {
        let mut fields = BTreeMap::new();
        let path_text = file_path.to_string_lossy().to_string();
        fields.insert(
            "path".to_string(),
            serde_json::Value::String(path_text.clone()),
        );
        fields.insert(
            "size_bytes".to_string(),
            serde_json::Value::from(size_bytes),
        );
        if let Some(value) = modified_unix_seconds {
            fields.insert(
                "modified_unix_seconds".to_string(),
                serde_json::Value::from(value),
            );
        }
        let stable_path_hash = stable_fnv1a64(&path_text);
        Self {
            schema: ARTIFACT_SCHEMA_VERSION.to_string(),
            artifact_id: format!("{}:{}:file-inventory:{:016x}", case_id, source_id, stable_path_hash),
            artifact_family: "file-system".to_string(),
            artifact_type: "file-inventory-record".to_string(),
            parser: "rapid-worker-file-inventory".to_string(),
            parser_version: env!("CARGO_PKG_VERSION").to_string(),
            source: SourceRef {
                case_id,
                source_id,
                source_path,
                offset: None,
                length: Some(size_bytes),
                hashes: BTreeMap::new(),
            },
            confidence: 0.9,
            validation_required: false,
            commercial_grade_ready: false,
            commercial_grade_blockers: vec![
                "hashing-and-filesystem-specific-metadata-not-yet-complete".to_string(),
                "large-case-corpus-validation-required".to_string(),
            ],
            legal_limitations: vec![
                "File inventory metadata alone does not prove user intent, execution, or content meaning.".to_string(),
            ],
            fields,
        }
    }

    pub fn evtx_inventory(
        case_id: String,
        source_id: String,
        source_path: String,
        file_path: &Path,
        size_bytes: u64,
        signature_valid: bool,
        major_version: u16,
        minor_version: u16,
        next_record_identifier: u64,
    ) -> Self {
        let path_text = file_path.to_string_lossy().to_string();
        let mut fields = BTreeMap::new();
        fields.insert(
            "path".to_string(),
            serde_json::Value::String(path_text.clone()),
        );
        fields.insert(
            "size_bytes".to_string(),
            serde_json::Value::from(size_bytes),
        );
        fields.insert(
            "signature_valid".to_string(),
            serde_json::Value::from(signature_valid),
        );
        fields.insert(
            "major_version".to_string(),
            serde_json::Value::from(major_version),
        );
        fields.insert(
            "minor_version".to_string(),
            serde_json::Value::from(minor_version),
        );
        fields.insert(
            "next_record_identifier".to_string(),
            serde_json::Value::from(next_record_identifier),
        );
        fields.insert(
            "recommended_validation".to_string(),
            serde_json::Value::String("cross-validate with EvtxECmd, Hayabusa, Chainsaw, or Velociraptor before report-grade use".to_string()),
        );
        Self {
            schema: ARTIFACT_SCHEMA_VERSION.to_string(),
            artifact_id: format!(
                "{}:{}:evtx-inventory:{:016x}",
                case_id,
                source_id,
                stable_fnv1a64(&path_text)
            ),
            artifact_family: "windows-eventlog".to_string(),
            artifact_type: "eventlog-file".to_string(),
            parser: "rapid-worker-evtx-inventory".to_string(),
            parser_version: env!("CARGO_PKG_VERSION").to_string(),
            source: SourceRef {
                case_id,
                source_id,
                source_path,
                offset: Some(0),
                length: Some(size_bytes),
                hashes: BTreeMap::new(),
            },
            confidence: if signature_valid { 0.86 } else { 0.2 },
            validation_required: true,
            commercial_grade_ready: false,
            commercial_grade_blockers: vec![
                "evtx-inventory-only-no-record-decoding".to_string(),
                "provider-message-resource-rendering-not-implemented".to_string(),
                "cross-tool-validation-required".to_string(),
            ],
            legal_limitations: vec![
                "EVTX inventory confirms a candidate log file; event-level conclusions require record parsing and independent validation.".to_string(),
            ],
            fields,
        }
    }

    pub fn evtx_chunk(
        case_id: String,
        source_id: String,
        source_path: String,
        file_path: &Path,
        chunk_offset: u64,
        chunk_index: u64,
        first_record_number: u64,
        last_record_number: u64,
        first_record_id: u64,
        last_record_id: u64,
        last_record_offset: u32,
        free_space_offset: u32,
        signature_valid: bool,
    ) -> Self {
        let path_text = file_path.to_string_lossy().to_string();
        let mut fields = BTreeMap::new();
        fields.insert(
            "path".to_string(),
            serde_json::Value::String(path_text.clone()),
        );
        fields.insert(
            "chunk_offset".to_string(),
            serde_json::Value::from(chunk_offset),
        );
        fields.insert(
            "chunk_index".to_string(),
            serde_json::Value::from(chunk_index),
        );
        fields.insert(
            "first_record_number".to_string(),
            serde_json::Value::from(first_record_number),
        );
        fields.insert(
            "last_record_number".to_string(),
            serde_json::Value::from(last_record_number),
        );
        fields.insert(
            "first_record_id".to_string(),
            serde_json::Value::from(first_record_id),
        );
        fields.insert(
            "last_record_id".to_string(),
            serde_json::Value::from(last_record_id),
        );
        fields.insert(
            "last_record_offset".to_string(),
            serde_json::Value::from(last_record_offset),
        );
        fields.insert(
            "free_space_offset".to_string(),
            serde_json::Value::from(free_space_offset),
        );
        fields.insert(
            "signature_valid".to_string(),
            serde_json::Value::from(signature_valid),
        );
        Self {
            schema: ARTIFACT_SCHEMA_VERSION.to_string(),
            artifact_id: format!(
                "{}:{}:evtx-chunk:{:016x}:{}",
                case_id,
                source_id,
                stable_fnv1a64(&path_text),
                chunk_offset
            ),
            artifact_family: "windows-eventlog".to_string(),
            artifact_type: "eventlog-chunk".to_string(),
            parser: "rapid-worker-evtx-record-headers".to_string(),
            parser_version: env!("CARGO_PKG_VERSION").to_string(),
            source: SourceRef {
                case_id,
                source_id,
                source_path,
                offset: Some(chunk_offset),
                length: Some(65536),
                hashes: BTreeMap::new(),
            },
            confidence: if signature_valid { 0.82 } else { 0.25 },
            validation_required: true,
            commercial_grade_ready: false,
            commercial_grade_blockers: vec![
                "chunk-crc-validation-not-yet-implemented-in-rust-worker".to_string(),
                "cross-tool-validation-required".to_string(),
            ],
            legal_limitations: vec![
                "EVTX chunk metadata is a structural pivot and is not enough to prove event content.".to_string(),
            ],
            fields,
        }
    }

    pub fn evtx_record_header(
        case_id: String,
        source_id: String,
        source_path: String,
        file_path: &Path,
        record_offset: u64,
        declared_size: u32,
        trailing_size: u32,
        record_id: u64,
        timestamp_filetime: u64,
        chunk_offset: Option<u64>,
        chunk_index: Option<u64>,
        binxml_status: String,
        binxml_model: serde_json::Value,
        message_rendering: serde_json::Value,
        recovery_status: String,
        allocation_status: String,
        caution_labels: Vec<String>,
    ) -> Self {
        let path_text = file_path.to_string_lossy().to_string();
        let mut fields = BTreeMap::new();
        fields.insert(
            "path".to_string(),
            serde_json::Value::String(path_text.clone()),
        );
        fields.insert(
            "record_offset".to_string(),
            serde_json::Value::from(record_offset),
        );
        fields.insert(
            "declared_size".to_string(),
            serde_json::Value::from(declared_size),
        );
        fields.insert(
            "trailing_size".to_string(),
            serde_json::Value::from(trailing_size),
        );
        fields.insert(
            "trailing_size_valid".to_string(),
            serde_json::Value::from(trailing_size == declared_size),
        );
        fields.insert("record_id".to_string(), serde_json::Value::from(record_id));
        fields.insert(
            "timestamp_filetime".to_string(),
            serde_json::Value::from(timestamp_filetime),
        );
        if let Some(value) = chunk_offset {
            fields.insert("chunk_offset".to_string(), serde_json::Value::from(value));
        }
        if let Some(value) = chunk_index {
            fields.insert("chunk_index".to_string(), serde_json::Value::from(value));
        }
        fields.insert(
            "binxml_status".to_string(),
            serde_json::Value::String(binxml_status),
        );
        fields.insert("binxml_model".to_string(), binxml_model);
        fields.insert("message_rendering".to_string(), message_rendering);
        fields.insert(
            "recovery_status".to_string(),
            serde_json::Value::String(recovery_status),
        );
        fields.insert(
            "allocation_status".to_string(),
            serde_json::Value::String(allocation_status),
        );
        fields.insert(
            "caution_labels".to_string(),
            serde_json::Value::Array(
                caution_labels
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        Self {
            schema: ARTIFACT_SCHEMA_VERSION.to_string(),
            artifact_id: format!(
                "{}:{}:evtx-record-header:{:016x}:{}",
                case_id,
                source_id,
                stable_fnv1a64(&path_text),
                record_offset
            ),
            artifact_family: "windows-eventlog".to_string(),
            artifact_type: "eventlog-event".to_string(),
            parser: "rapid-worker-evtx-record-headers".to_string(),
            parser_version: env!("CARGO_PKG_VERSION").to_string(),
            source: SourceRef {
                case_id,
                source_id,
                source_path,
                offset: Some(record_offset),
                length: Some(u64::from(declared_size)),
                hashes: BTreeMap::new(),
            },
            confidence: if trailing_size == declared_size {
                0.74
            } else {
                0.45
            },
            validation_required: true,
            commercial_grade_ready: false,
            commercial_grade_blockers: vec![
                "record-header-only-no-binxml-decoding".to_string(),
                "full-binxml-object-model-validation-required".to_string(),
                "provider-message-resource-rendering-not-implemented".to_string(),
                "cross-tool-validation-required".to_string(),
            ],
            legal_limitations: vec![
                "EVTX record headers identify candidate event records; event content and meaning require BinXML decoding and message rendering.".to_string(),
            ],
            fields,
        }
    }
}

fn stable_fnv1a64(value: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_record_has_commercial_gate_fields() {
        let record = ArtifactRecordV1::noop(
            "CASE-1".to_string(),
            "SRC-1".to_string(),
            "/evidence".to_string(),
        );

        assert_eq!(record.schema, ARTIFACT_SCHEMA_VERSION);
        assert_eq!(record.parser, "rapid-worker-noop");
        assert!(!record.commercial_grade_ready);
        assert!(!record.commercial_grade_blockers.is_empty());
    }

    #[test]
    fn file_inventory_record_preserves_size_and_path() {
        let record = ArtifactRecordV1::file_inventory(
            "CASE-1".to_string(),
            "SRC-1".to_string(),
            "/evidence".to_string(),
            Path::new("/evidence/a.txt"),
            123,
            Some(42),
        );

        assert_eq!(record.artifact_type, "file-inventory-record");
        assert!(record
            .artifact_id
            .starts_with("CASE-1:SRC-1:file-inventory:"));
        assert_eq!(record.source.length, Some(123));
        assert_eq!(record.fields["size_bytes"], serde_json::Value::from(123));
    }

    #[test]
    fn file_inventory_id_is_stable_for_same_path() {
        let first = ArtifactRecordV1::file_inventory(
            "CASE-1".to_string(),
            "SRC-1".to_string(),
            "/evidence".to_string(),
            Path::new("/evidence/a.txt"),
            123,
            None,
        );
        let second = ArtifactRecordV1::file_inventory(
            "CASE-1".to_string(),
            "SRC-1".to_string(),
            "/evidence".to_string(),
            Path::new("/evidence/a.txt"),
            456,
            None,
        );

        assert_eq!(first.artifact_id, second.artifact_id);
    }

    #[test]
    fn evtx_inventory_discloses_validation_limits() {
        let record = ArtifactRecordV1::evtx_inventory(
            "CASE-1".to_string(),
            "SRC-1".to_string(),
            "/evidence/System.evtx".to_string(),
            Path::new("/evidence/System.evtx"),
            4096,
            true,
            3,
            1,
            42,
        );

        assert_eq!(record.artifact_family, "windows-eventlog");
        assert_eq!(record.artifact_type, "eventlog-file");
        assert!(record.validation_required);
        assert!(!record.commercial_grade_ready);
        assert_eq!(
            record.fields["signature_valid"],
            serde_json::Value::from(true)
        );
    }

    #[test]
    fn evtx_record_header_has_record_offsets_and_limits() {
        let record = ArtifactRecordV1::evtx_record_header(
            "CASE-1".to_string(),
            "SRC-1".to_string(),
            "/evidence/System.evtx".to_string(),
            Path::new("/evidence/System.evtx"),
            4096,
            88,
            88,
            123,
            132456789,
            Some(4096),
            Some(0),
            "not-decoded".to_string(),
            serde_json::json!({"status":"not-decoded"}),
            serde_json::json!({"status":"unresolved-provider-template"}),
            "recoverable-record-header".to_string(),
            "allocated-or-live-record".to_string(),
            vec!["do-not-report-without-binxml-validation".to_string()],
        );

        assert_eq!(record.artifact_type, "eventlog-event");
        assert_eq!(record.fields["record_id"], serde_json::Value::from(123));
        assert!(record.validation_required);
        assert!(!record.commercial_grade_ready);
    }

    #[test]
    fn evtx_chunk_has_boundary_fields() {
        let record = ArtifactRecordV1::evtx_chunk(
            "CASE-1".to_string(),
            "SRC-1".to_string(),
            "/evidence/System.evtx".to_string(),
            Path::new("/evidence/System.evtx"),
            4096,
            0,
            1,
            2,
            100,
            101,
            600,
            700,
            true,
        );

        assert_eq!(record.artifact_type, "eventlog-chunk");
        assert_eq!(
            record.fields["free_space_offset"],
            serde_json::Value::from(700)
        );
        assert!(record.validation_required);
    }
}
