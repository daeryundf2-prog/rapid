use serde_json::Value;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn evtx_records_known_answer_outputs_chunk_and_record_rows() {
    let root = std::env::temp_dir().join(format!(
        "rapid-worker-known-answer-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let logs = root
        .join("Windows")
        .join("System32")
        .join("winevt")
        .join("Logs");
    fs::create_dir_all(&logs).unwrap();
    fs::write(logs.join("System.evtx"), known_answer_evtx()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rapid-worker"))
        .args([
            "parse",
            "--kind",
            "evtx-records",
            "--source",
            root.to_str().unwrap(),
            "--case-id",
            "CASE-KA",
            "--source-id",
            "SRC-KA",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["artifact_type"], "eventlog-chunk");
    assert_eq!(rows[0]["fields"]["first_record_id"], 301);
    assert_eq!(rows[1]["artifact_type"], "eventlog-event");
    assert_eq!(rows[1]["fields"]["record_id"], 301);
    assert_eq!(rows[1]["fields"]["binxml_status"], "object-model-decoded");
    assert_eq!(
        rows[1]["fields"]["message_rendering"]["status"],
        "builtin-preview"
    );
    assert_eq!(
        rows[1]["fields"]["message_rendering"]["rendered_preview"],
        "PowerShell"
    );
    assert_eq!(
        rows[1]["fields"]["recovery_status"],
        "recoverable-record-header"
    );

    fs::remove_dir_all(root).ok();
}

fn known_answer_evtx() -> Vec<u8> {
    let mut blob = vec![0u8; 4096 + 65536];
    blob[0..8].copy_from_slice(b"ElfFile\0");
    let chunk = 4096usize;
    blob[chunk..chunk + 8].copy_from_slice(b"ElfChnk\0");
    blob[chunk + 8..chunk + 16].copy_from_slice(&1u64.to_le_bytes());
    blob[chunk + 16..chunk + 24].copy_from_slice(&1u64.to_le_bytes());
    blob[chunk + 24..chunk + 32].copy_from_slice(&301u64.to_le_bytes());
    blob[chunk + 32..chunk + 40].copy_from_slice(&301u64.to_le_bytes());
    blob[chunk + 40..chunk + 44].copy_from_slice(&512u32.to_le_bytes());
    blob[chunk + 44..chunk + 48].copy_from_slice(&700u32.to_le_bytes());

    let text = "PowerShell"
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    let mut payload = vec![0x0f, 0x01, 0x01, 0x00, 0x05, 0x01];
    payload.extend_from_slice(&(text.len() as u16).to_le_bytes());
    payload.extend_from_slice(&text);
    payload.push(0x00);

    let record = chunk + 512;
    let record_size = (24 + payload.len() + 4) as u32;
    blob[record..record + 4].copy_from_slice(b"**\0\0");
    blob[record + 4..record + 8].copy_from_slice(&record_size.to_le_bytes());
    blob[record + 8..record + 16].copy_from_slice(&301u64.to_le_bytes());
    blob[record + 16..record + 24].copy_from_slice(&132456789u64.to_le_bytes());
    blob[record + 24..record + 24 + payload.len()].copy_from_slice(&payload);
    blob[record + record_size as usize - 4..record + record_size as usize]
        .copy_from_slice(&record_size.to_le_bytes());
    blob
}
