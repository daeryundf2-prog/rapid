use rapidcore::ArtifactRecordV1;
use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::UNIX_EPOCH;

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    if args.is_empty() || args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_help();
        return Ok(());
    }
    if args == ["--version"] || args == ["version"] {
        println!("rapid-worker {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.first().map(String::as_str) != Some("parse") {
        return Err(format!("unsupported command: {}", args[0]));
    }
    let options = ParseOptions::from_args(&args[1..])?;
    if options.kind == "noop" {
        let record = ArtifactRecordV1::noop(options.case_id, options.source_id, options.source);
        println!("{}", record.to_json_line().map_err(|err| err.to_string())?);
        return Ok(());
    }
    if options.kind == "file-inventory" {
        return emit_file_inventory(options);
    }
    if options.kind == "evtx-inventory" {
        return emit_evtx_inventory(options);
    }
    if options.kind == "evtx-records" {
        return emit_evtx_records(options);
    }
    Err(format!("unsupported parser kind: {}", options.kind))
}

fn print_help() {
    println!(
        "rapid-worker\n\nCommands:\n  --version\n  parse --kind noop --source PATH [--case-id CASE] [--source-id SOURCE]\n  parse --kind file-inventory --source PATH [--case-id CASE] [--source-id SOURCE] [--max-records N]\n  parse --kind evtx-inventory --source PATH [--case-id CASE] [--source-id SOURCE] [--max-records N]\n  parse --kind evtx-records --source PATH [--case-id CASE] [--source-id SOURCE] [--max-records N]"
    );
}

#[derive(Debug, Clone, PartialEq)]
struct ParseOptions {
    kind: String,
    source: String,
    case_id: String,
    source_id: String,
    max_records: usize,
}

impl ParseOptions {
    fn from_args(args: &[String]) -> Result<Self, String> {
        let mut kind = String::new();
        let mut source = String::new();
        let mut case_id = "CASE".to_string();
        let mut source_id = "SOURCE".to_string();
        let mut max_records = 100_000usize;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--kind" => {
                    index += 1;
                    kind = args.get(index).cloned().ok_or("--kind requires a value")?;
                }
                "--source" => {
                    index += 1;
                    source = args
                        .get(index)
                        .cloned()
                        .ok_or("--source requires a value")?;
                }
                "--case-id" => {
                    index += 1;
                    case_id = args
                        .get(index)
                        .cloned()
                        .ok_or("--case-id requires a value")?;
                }
                "--source-id" => {
                    index += 1;
                    source_id = args
                        .get(index)
                        .cloned()
                        .ok_or("--source-id requires a value")?;
                }
                "--max-records" => {
                    index += 1;
                    let raw = args.get(index).ok_or("--max-records requires a value")?;
                    max_records = raw
                        .parse::<usize>()
                        .map_err(|_| "--max-records must be a positive integer")?;
                    if max_records == 0 {
                        return Err("--max-records must be greater than zero".to_string());
                    }
                }
                value => return Err(format!("unknown parse option: {value}")),
            }
            index += 1;
        }
        if kind.is_empty() {
            return Err("--kind is required".to_string());
        }
        if source.is_empty() {
            return Err("--source is required".to_string());
        }
        Ok(Self {
            kind,
            source,
            case_id,
            source_id,
            max_records,
        })
    }
}

fn emit_file_inventory(options: ParseOptions) -> Result<(), String> {
    let root = PathBuf::from(&options.source);
    let root_metadata = fs::symlink_metadata(&root)
        .map_err(|err| format!("source is not accessible: {}: {err}", root.display()))?;
    if !root_metadata.is_dir() && !root_metadata.is_file() {
        return Err(format!(
            "source must be a regular file or directory: {}",
            root.display()
        ));
    }
    let mut stack = vec![root.clone()];
    let mut emitted = 0usize;
    while let Some(path) = stack.pop() {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            if let Ok(entries) = fs::read_dir(&path) {
                let mut children: Vec<PathBuf> =
                    entries.flatten().map(|entry| entry.path()).collect();
                children.sort();
                for child in children.into_iter().rev() {
                    stack.push(child);
                }
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        emitted += 1;
        let modified = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|value| value.as_secs());
        let record = ArtifactRecordV1::file_inventory(
            options.case_id.clone(),
            options.source_id.clone(),
            options.source.clone(),
            path.as_path(),
            metadata.len(),
            modified,
        );
        println!("{}", record.to_json_line().map_err(|err| err.to_string())?);
        if emitted >= options.max_records {
            break;
        }
    }
    Ok(())
}

fn emit_evtx_inventory(options: ParseOptions) -> Result<(), String> {
    let root = PathBuf::from(&options.source);
    let root_metadata = fs::symlink_metadata(&root)
        .map_err(|err| format!("source is not accessible: {}: {err}", root.display()))?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    if root_metadata.is_file() {
        candidates.push(root.clone());
    } else if root_metadata.is_dir() {
        collect_evtx_paths(&root, &mut candidates, options.max_records)?;
    } else {
        return Err(format!(
            "source must be a regular file or directory: {}",
            root.display()
        ));
    }
    candidates.sort();
    let mut emitted = 0usize;
    for path in candidates.into_iter().take(options.max_records) {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|err| format!("failed to read metadata for {}: {err}", path.display()))?;
        if !metadata.is_file() {
            continue;
        }
        let header = read_evtx_header(&path)?;
        let record = ArtifactRecordV1::evtx_inventory(
            options.case_id.clone(),
            options.source_id.clone(),
            options.source.clone(),
            path.as_path(),
            metadata.len(),
            header.signature_valid,
            header.major_version,
            header.minor_version,
            header.next_record_identifier,
        );
        println!("{}", record.to_json_line().map_err(|err| err.to_string())?);
        emitted += 1;
        if emitted >= options.max_records {
            break;
        }
    }
    Ok(())
}

fn emit_evtx_records(options: ParseOptions) -> Result<(), String> {
    let paths = evtx_candidate_paths(&options)?;
    let mut emitted = 0usize;
    for path in paths {
        if emitted >= options.max_records {
            break;
        }
        for item in parse_evtx_file_streaming(&path, options.max_records - emitted)? {
            match item {
                EvtxParsedItem::Chunk(chunk) => {
                    let record = ArtifactRecordV1::evtx_chunk(
                        options.case_id.clone(),
                        options.source_id.clone(),
                        options.source.clone(),
                        path.as_path(),
                        chunk.offset,
                        chunk.index,
                        chunk.first_record_number,
                        chunk.last_record_number,
                        chunk.first_record_id,
                        chunk.last_record_id,
                        chunk.last_record_offset,
                        chunk.free_space_offset,
                        chunk.signature_valid,
                    );
                    println!("{}", record.to_json_line().map_err(|err| err.to_string())?);
                }
                EvtxParsedItem::Record(record_header) => {
                    let record = ArtifactRecordV1::evtx_record_header(
                        options.case_id.clone(),
                        options.source_id.clone(),
                        options.source.clone(),
                        path.as_path(),
                        record_header.offset,
                        record_header.declared_size,
                        record_header.trailing_size,
                        record_header.record_id,
                        record_header.timestamp_filetime,
                        record_header.chunk_offset,
                        record_header.chunk_index,
                        record_header.binxml_status,
                        record_header.binxml_model,
                        record_header.message_rendering,
                        record_header.recovery_status,
                        record_header.allocation_status,
                        record_header.caution_labels,
                    );
                    println!("{}", record.to_json_line().map_err(|err| err.to_string())?);
                }
            }
            emitted += 1;
            if emitted >= options.max_records {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn evtx_candidate_paths(options: &ParseOptions) -> Result<Vec<PathBuf>, String> {
    let root = PathBuf::from(&options.source);
    let root_metadata = fs::symlink_metadata(&root)
        .map_err(|err| format!("source is not accessible: {}: {err}", root.display()))?;
    let mut candidates: Vec<PathBuf> = Vec::new();
    if root_metadata.is_file() {
        candidates.push(root.clone());
    } else if root_metadata.is_dir() {
        collect_evtx_paths(&root, &mut candidates, options.max_records)?;
    } else {
        return Err(format!(
            "source must be a regular file or directory: {}",
            root.display()
        ));
    }
    candidates.sort();
    Ok(candidates)
}

fn collect_evtx_paths(
    root: &Path,
    output: &mut Vec<PathBuf>,
    max_records: usize,
) -> Result<(), String> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        if output.len() >= max_records {
            break;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            let mut children: Vec<PathBuf> = match fs::read_dir(&path) {
                Ok(entries) => entries.flatten().map(|entry| entry.path()).collect(),
                Err(_) => continue,
            };
            children.sort();
            for child in children.into_iter().rev() {
                stack.push(child);
            }
            continue;
        }
        if metadata.is_file()
            && path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or("")
                .eq_ignore_ascii_case("evtx")
        {
            output.push(path);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
struct EvtxHeader {
    signature_valid: bool,
    major_version: u16,
    minor_version: u16,
    next_record_identifier: u64,
}

fn read_evtx_header(path: &Path) -> Result<EvtxHeader, String> {
    let mut file =
        fs::File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut header = [0u8; 4096];
    let bytes_read = file
        .read(&mut header)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    Ok(EvtxHeader {
        signature_valid: bytes_read >= 8 && &header[0..8] == b"ElfFile\0",
        minor_version: read_u16_le(&header, 38),
        major_version: read_u16_le(&header, 40),
        next_record_identifier: read_u64_le(&header, 24),
    })
}

#[derive(Debug, Clone, PartialEq)]
struct EvtxChunkHeader {
    offset: u64,
    index: u64,
    signature_valid: bool,
    first_record_number: u64,
    last_record_number: u64,
    first_record_id: u64,
    last_record_id: u64,
    last_record_offset: u32,
    free_space_offset: u32,
}

#[derive(Debug, Clone, PartialEq)]
struct EvtxRecordHeader {
    offset: u64,
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
}

#[derive(Debug, Clone, PartialEq)]
enum EvtxParsedItem {
    Chunk(EvtxChunkHeader),
    Record(EvtxRecordHeader),
}

#[derive(Debug, Clone, PartialEq)]
struct BinXmlToken {
    offset: usize,
    token: u8,
    kind: String,
}

#[derive(Debug, Clone, PartialEq)]
struct BinXmlDecodedValue {
    value_type: String,
    text: String,
    json_value: serde_json::Value,
    raw_hex: String,
    end_offset: usize,
}

#[cfg(test)]
fn parse_evtx_chunks(blob: &[u8]) -> Vec<EvtxChunkHeader> {
    const FILE_HEADER_SIZE: usize = 4096;
    const CHUNK_SIZE: usize = 65536;
    const CHUNK_SIGNATURE: &[u8; 8] = b"ElfChnk\0";
    let mut output = Vec::new();
    if blob.len() < FILE_HEADER_SIZE + CHUNK_SIGNATURE.len() {
        return output;
    }
    let mut offset = FILE_HEADER_SIZE;
    let mut index = 0u64;
    while offset + CHUNK_SIGNATURE.len() <= blob.len() {
        if &blob[offset..offset + CHUNK_SIGNATURE.len()] == CHUNK_SIGNATURE {
            output.push(EvtxChunkHeader {
                offset: offset as u64,
                index,
                signature_valid: true,
                first_record_number: read_u64_le(blob, offset + 8),
                last_record_number: read_u64_le(blob, offset + 16),
                first_record_id: read_u64_le(blob, offset + 24),
                last_record_id: read_u64_le(blob, offset + 32),
                last_record_offset: read_u32_le(blob, offset + 40),
                free_space_offset: read_u32_le(blob, offset + 44),
            });
            index += 1;
            offset += CHUNK_SIZE;
            continue;
        }
        offset += 1;
    }
    output
}

fn parse_evtx_file_streaming(path: &Path, max_items: usize) -> Result<Vec<EvtxParsedItem>, String> {
    const FILE_HEADER_SIZE: u64 = 4096;
    const CHUNK_SIZE: usize = 65536;
    let mut file =
        fs::File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    if metadata.len() <= FILE_HEADER_SIZE {
        return Ok(Vec::new());
    }
    file.seek(SeekFrom::Start(FILE_HEADER_SIZE))
        .map_err(|err| format!("failed to seek {}: {err}", path.display()))?;
    let mut items = Vec::new();
    let mut chunk_index = 0u64;
    let mut absolute_offset = FILE_HEADER_SIZE;
    loop {
        let mut chunk_blob = vec![0u8; CHUNK_SIZE];
        let bytes_read = file
            .read(&mut chunk_blob)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        chunk_blob.truncate(bytes_read);
        if let Some(chunk) = parse_evtx_chunk_header_at(&chunk_blob, absolute_offset, chunk_index) {
            items.push(EvtxParsedItem::Chunk(chunk.clone()));
            if items.len() >= max_items {
                break;
            }
            for record in parse_evtx_record_headers_in_chunk(&chunk_blob, &chunk) {
                items.push(EvtxParsedItem::Record(record));
                if items.len() >= max_items {
                    break;
                }
            }
            if items.len() >= max_items {
                break;
            }
        }
        if bytes_read < CHUNK_SIZE {
            break;
        }
        chunk_index += 1;
        absolute_offset += CHUNK_SIZE as u64;
    }
    Ok(items)
}

fn parse_evtx_chunk_header_at(
    blob: &[u8],
    absolute_offset: u64,
    index: u64,
) -> Option<EvtxChunkHeader> {
    const CHUNK_SIGNATURE: &[u8; 8] = b"ElfChnk\0";
    if blob.len() < CHUNK_SIGNATURE.len() || &blob[0..CHUNK_SIGNATURE.len()] != CHUNK_SIGNATURE {
        return None;
    }
    Some(EvtxChunkHeader {
        offset: absolute_offset,
        index,
        signature_valid: true,
        first_record_number: read_u64_le(blob, 8),
        last_record_number: read_u64_le(blob, 16),
        first_record_id: read_u64_le(blob, 24),
        last_record_id: read_u64_le(blob, 32),
        last_record_offset: read_u32_le(blob, 40),
        free_space_offset: read_u32_le(blob, 44),
    })
}

fn parse_evtx_record_headers_in_chunk(
    blob: &[u8],
    chunk: &EvtxChunkHeader,
) -> Vec<EvtxRecordHeader> {
    const RECORD_MAGIC: &[u8; 4] = b"**\0\0";
    const RECORD_HEADER_SIZE: usize = 24;
    const MAX_RECORD_SIZE: u32 = 16 * 1024 * 1024;
    let mut output = Vec::new();
    let mut offset = 0usize;
    while offset + RECORD_HEADER_SIZE <= blob.len() {
        let relative = match find_bytes(&blob[offset..], RECORD_MAGIC) {
            Some(value) => value,
            None => break,
        };
        offset += relative;
        let declared_size = read_u32_le(blob, offset + 4);
        if declared_size < RECORD_HEADER_SIZE as u32 || declared_size > MAX_RECORD_SIZE {
            offset += RECORD_MAGIC.len();
            continue;
        }
        let end = offset.saturating_add(declared_size as usize);
        if end > blob.len() {
            offset += RECORD_MAGIC.len();
            continue;
        }
        let trailing_size = read_u32_le(blob, end - 4);
        let payload_start = offset + RECORD_HEADER_SIZE;
        let payload_end = end.saturating_sub(4);
        let payload = if payload_start <= payload_end {
            &blob[payload_start..payload_end]
        } else {
            &[]
        };
        let binxml_model = parse_binxml_object_model(payload);
        let message_rendering = render_evtx_message_preview(&binxml_model);
        let absolute_record_offset = chunk.offset as usize + offset;
        let allocation_status = evtx_allocation_status(absolute_record_offset, Some(chunk));
        let recovery_status =
            evtx_recovery_status(trailing_size == declared_size, &allocation_status);
        let caution_labels =
            evtx_caution_labels(&recovery_status, &allocation_status, &binxml_model);
        output.push(EvtxRecordHeader {
            offset: absolute_record_offset as u64,
            declared_size,
            trailing_size,
            record_id: read_u64_le(blob, offset + 8),
            timestamp_filetime: read_u64_le(blob, offset + 16),
            chunk_offset: Some(chunk.offset),
            chunk_index: Some(chunk.index),
            binxml_status: binxml_model_status(&binxml_model),
            binxml_model,
            message_rendering,
            recovery_status,
            allocation_status,
            caution_labels,
        });
        offset = end;
    }
    output
}

#[cfg(test)]
fn parse_evtx_record_headers(blob: &[u8]) -> Vec<EvtxRecordHeader> {
    const RECORD_MAGIC: &[u8; 4] = b"**\0\0";
    const RECORD_HEADER_SIZE: usize = 24;
    const MAX_RECORD_SIZE: u32 = 16 * 1024 * 1024;
    let chunks = parse_evtx_chunks(blob);
    let mut output = Vec::new();
    let mut offset = 0usize;
    while offset + RECORD_HEADER_SIZE <= blob.len() {
        let relative = match find_bytes(&blob[offset..], RECORD_MAGIC) {
            Some(value) => value,
            None => break,
        };
        offset += relative;
        let declared_size = read_u32_le(blob, offset + 4);
        if declared_size < RECORD_HEADER_SIZE as u32 || declared_size > MAX_RECORD_SIZE {
            offset += RECORD_MAGIC.len();
            continue;
        }
        let end = offset.saturating_add(declared_size as usize);
        if end > blob.len() {
            offset += RECORD_MAGIC.len();
            continue;
        }
        let trailing_size = read_u32_le(blob, end - 4);
        let payload_start = offset + RECORD_HEADER_SIZE;
        let payload_end = end.saturating_sub(4);
        let payload = if payload_start <= payload_end {
            &blob[payload_start..payload_end]
        } else {
            &[]
        };
        let binxml_model = parse_binxml_object_model(payload);
        let message_rendering = render_evtx_message_preview(&binxml_model);
        let chunk = chunk_for_record(offset, &chunks);
        let allocation_status = evtx_allocation_status(offset, chunk);
        let recovery_status =
            evtx_recovery_status(trailing_size == declared_size, &allocation_status);
        let caution_labels =
            evtx_caution_labels(&recovery_status, &allocation_status, &binxml_model);
        output.push(EvtxRecordHeader {
            offset: offset as u64,
            declared_size,
            trailing_size,
            record_id: read_u64_le(blob, offset + 8),
            timestamp_filetime: read_u64_le(blob, offset + 16),
            chunk_offset: evtx_chunk_offset_for_record(offset),
            chunk_index: evtx_chunk_index_for_record(offset),
            binxml_status: binxml_model_status(&binxml_model),
            binxml_model,
            message_rendering,
            recovery_status,
            allocation_status,
            caution_labels,
        });
        offset = end;
    }
    output
}

#[cfg(test)]
fn chunk_for_record<'a>(
    record_offset: usize,
    chunks: &'a [EvtxChunkHeader],
) -> Option<&'a EvtxChunkHeader> {
    chunks.iter().find(|chunk| {
        let start = chunk.offset as usize;
        let end = start.saturating_add(65536);
        record_offset >= start && record_offset < end
    })
}

fn evtx_allocation_status(record_offset: usize, chunk: Option<&EvtxChunkHeader>) -> String {
    let Some(chunk) = chunk else {
        return "unknown-no-valid-chunk-header".to_string();
    };
    let relative = record_offset.saturating_sub(chunk.offset as usize) as u32;
    if chunk.free_space_offset > 0 && relative >= chunk.free_space_offset {
        return "slack-or-deleted-record-candidate".to_string();
    }
    if chunk.last_record_offset > 0 && relative > chunk.last_record_offset {
        return "after-last-record-candidate".to_string();
    }
    "allocated-or-live-record".to_string()
}

fn evtx_recovery_status(trailing_size_valid: bool, allocation_status: &str) -> String {
    if !trailing_size_valid {
        return "corrupt-record-candidate".to_string();
    }
    if allocation_status == "slack-or-deleted-record-candidate"
        || allocation_status == "after-last-record-candidate"
    {
        return "slack-or-deleted-record-candidate".to_string();
    }
    "recoverable-record-header".to_string()
}

fn evtx_caution_labels(
    recovery_status: &str,
    allocation_status: &str,
    binxml_model: &serde_json::Value,
) -> Vec<String> {
    let mut labels = vec!["do-not-report-without-binxml-validation".to_string()];
    if recovery_status != "recoverable-record-header" {
        labels.push("do-not-report-without-independent-validation".to_string());
        labels.push(recovery_status.to_string());
    }
    if allocation_status != "allocated-or-live-record" {
        labels.push(allocation_status.to_string());
    }
    if binxml_model_status(binxml_model) == "not-decoded" {
        labels.push("binxml-not-decoded".to_string());
    }
    labels.sort();
    labels.dedup();
    labels
}

fn parse_binxml_object_model(payload: &[u8]) -> serde_json::Value {
    if payload.is_empty() {
        return serde_json::json!({
            "status": "not-decoded",
            "reason": "empty-record-payload",
            "tokens": [],
            "nodes": [],
            "warnings": []
        });
    }
    if payload[0] != 0x0f {
        return serde_json::json!({
            "status": "not-decoded",
            "reason": "missing-fragment-header",
            "first_byte": payload[0],
            "tokens": [],
            "nodes": [],
            "warnings": []
        });
    }
    let mut tokens: Vec<BinXmlToken> = Vec::new();
    let mut nodes: Vec<serde_json::Value> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut offset = 0usize;
    let mut stack: Vec<String> = Vec::new();
    let mut last_attribute: Option<(String, String)> = None;
    while offset < payload.len() && tokens.len() < 1024 {
        let token = payload[offset];
        let kind = binxml_token_kind(token).to_string();
        tokens.push(BinXmlToken {
            offset,
            token,
            kind: kind.clone(),
        });
        match token & 0xbf {
            0x00 => {
                break;
            }
            0x0f => {
                if offset + 4 > payload.len() {
                    warnings.push(format!("truncated-fragment-header:{offset}"));
                    break;
                }
                nodes.push(serde_json::json!({
                    "node_type": "fragment_header",
                    "offset": offset,
                    "major_version": payload[offset + 1],
                    "minor_version": payload[offset + 2],
                    "flags": payload[offset + 3]
                }));
                offset += 4;
                continue;
            }
            0x01 => {
                let (name, after_name) = read_binxml_name(payload, offset + 7);
                if name.is_empty() {
                    warnings.push(format!("truncated-start-element:{offset}"));
                    break;
                }
                let path = if stack.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", stack.join("/"), name)
                };
                nodes.push(serde_json::json!({
                    "node_type": "start_element",
                    "offset": offset,
                    "name": name,
                    "path": path
                }));
                stack.push(name);
                offset = after_name;
                continue;
            }
            0x06 => {
                let (name, after_name) = read_binxml_name(payload, offset + 1);
                if name.is_empty() {
                    warnings.push(format!("truncated-attribute:{offset}"));
                    break;
                }
                let path = if stack.is_empty() {
                    format!("@{name}")
                } else {
                    format!("{}/@{name}", stack.join("/"))
                };
                nodes.push(serde_json::json!({
                    "node_type": "attribute",
                    "offset": offset,
                    "name": name,
                    "path": path
                }));
                last_attribute = Some((name, path));
                offset = after_name;
                continue;
            }
            0x02 => {
                nodes.push(serde_json::json!({
                    "node_type": "close_start_element",
                    "offset": offset,
                    "path": stack.join("/")
                }));
                offset += 1;
                continue;
            }
            0x03 => {
                let name = stack.pop().unwrap_or_default();
                nodes.push(serde_json::json!({
                    "node_type": "empty_element",
                    "offset": offset,
                    "name": name,
                    "path": stack.join("/")
                }));
                offset += 1;
                continue;
            }
            0x04 => {
                let name = stack.pop().unwrap_or_default();
                nodes.push(serde_json::json!({
                    "node_type": "end_element",
                    "offset": offset,
                    "name": name,
                    "path": stack.join("/")
                }));
                offset += 1;
                continue;
            }
            0x05 => {
                let decoded = read_binxml_value(payload, offset);
                let mut path = stack.join("/");
                let mut attribute_name = serde_json::Value::Null;
                if let Some((name, attribute_path)) = last_attribute.take() {
                    path = attribute_path;
                    attribute_name = serde_json::Value::String(name);
                }
                nodes.push(serde_json::json!({
                    "node_type": "value_text",
                    "offset": offset,
                    "path": path,
                    "attribute_name": attribute_name,
                    "text": decoded.text,
                    "value": decoded.json_value,
                    "value_type": decoded.value_type,
                    "raw_hex": decoded.raw_hex
                }));
                offset = decoded.end_offset;
                continue;
            }
            0x0d => {
                if offset + 4 > payload.len() {
                    warnings.push(format!("truncated-substitution:{offset}"));
                    break;
                }
                let substitution_index = read_u16_le(payload, offset + 1);
                let substitution_type = payload[offset + 3];
                nodes.push(serde_json::json!({
                    "node_type": "substitution",
                    "offset": offset,
                    "path": stack.join("/"),
                    "substitution_index": substitution_index,
                    "value_type": binxml_value_type_name(substitution_type),
                    "value_type_raw": format!("0x{substitution_type:02x}")
                }));
                offset += 4;
                continue;
            }
            0x0c => {
                let (node, after_template) = read_binxml_template_instance(payload, offset);
                if let Some(value) = node {
                    nodes.push(value);
                    offset = after_template;
                    continue;
                }
                warnings.push(format!("truncated-template-instance:{offset}"));
                break;
            }
            _ => {
                warnings.push(format!("unsupported-token:0x{token:02x}@{offset}"));
                offset += 1;
            }
        }
    }
    let extracted_fields = extract_binxml_fields(&nodes);
    let status = if nodes.iter().any(|node| {
        node.get("node_type").and_then(|value| value.as_str()) == Some("template_instance")
    }) {
        "template-instance-decoded"
    } else if nodes
        .iter()
        .any(|node| node.get("node_type").and_then(|value| value.as_str()) == Some("value_text"))
    {
        "object-model-decoded"
    } else if nodes.len() > 1 {
        "tokenized-no-values"
    } else {
        "not-decoded"
    };
    serde_json::json!({
        "status": status,
        "token_count": tokens.len(),
        "extracted_fields": extracted_fields,
        "tokens": tokens.iter().take(256).map(|item| serde_json::json!({
            "offset": item.offset,
            "token": item.token,
            "kind": item.kind
        })).collect::<Vec<_>>(),
        "nodes": nodes.into_iter().take(256).collect::<Vec<_>>(),
        "warnings": warnings
    })
}

fn binxml_model_status(model: &serde_json::Value) -> String {
    model
        .get("status")
        .and_then(|value| value.as_str())
        .unwrap_or("not-decoded")
        .to_string()
}

fn binxml_token_kind(token: u8) -> &'static str {
    match token & 0xbf {
        0x00 => "end-of-stream",
        0x01 => "start-element",
        0x02 => "close-start-element",
        0x03 => "empty-element",
        0x04 => "end-element",
        0x05 => "value-text",
        0x06 => "attribute",
        0x0c => "template-instance",
        0x0d => "substitution",
        0x0f => "fragment-header",
        _ => "unsupported",
    }
}

fn read_binxml_name(blob: &[u8], offset: usize) -> (String, usize) {
    if offset + 4 > blob.len() {
        return (String::new(), blob.len());
    }
    let first = read_u16_le(blob, offset) as usize;
    let second = read_u16_le(blob, offset + 2) as usize;
    let (char_count, start) = if first == 0 && second > 0 {
        (second, offset + 4)
    } else {
        (first, offset + 2)
    };
    let end = start.saturating_add(char_count.saturating_mul(2));
    if end > blob.len() {
        return (String::new(), blob.len());
    }
    let mut units = Vec::with_capacity(char_count);
    let mut cursor = start;
    while cursor + 1 < end {
        units.push(u16::from_le_bytes([blob[cursor], blob[cursor + 1]]));
        cursor += 2;
    }
    let after_nul = if end + 2 <= blob.len() && blob[end] == 0 && blob[end + 1] == 0 {
        end + 2
    } else {
        end
    };
    (String::from_utf16_lossy(&units), after_nul)
}

fn read_binxml_value(blob: &[u8], offset: usize) -> BinXmlDecodedValue {
    if offset + 2 > blob.len() {
        return decoded_value("truncated", "", serde_json::Value::Null, &[], blob.len());
    }
    let value_type = blob[offset + 1];
    let value_type_name = binxml_value_type_name(value_type);
    match value_type {
        0x01 => {
            if offset + 4 > blob.len() {
                return decoded_value("truncated", "", serde_json::Value::Null, &[], blob.len());
            }
            let raw_len = read_u16_le(blob, offset + 2) as usize;
            let start = offset + 4;
            let preferred_end = start.saturating_add(raw_len.saturating_mul(2));
            let fallback_end = start.saturating_add(raw_len);
            let end =
                if preferred_end <= blob.len() && looks_like_binxml_boundary(blob, preferred_end) {
                    preferred_end
                } else if fallback_end <= blob.len() {
                    fallback_end
                } else {
                    blob.len()
                };
            let text = utf16le_lossy(&blob[start..end]);
            decoded_value(
                value_type_name,
                &text,
                serde_json::Value::String(text.clone()),
                &blob[start..end],
                end,
            )
        }
        0x02 => decode_fixed_string(blob, offset, 1, value_type_name, |bytes| {
            serde_json::Value::from(i8::from_le_bytes([bytes[0]]) as i64)
        }),
        0x03 => decode_fixed_string(blob, offset, 1, value_type_name, |bytes| {
            serde_json::Value::from(bytes[0] as u64)
        }),
        0x04 => decode_fixed_string(blob, offset, 2, value_type_name, |bytes| {
            serde_json::Value::from(i16::from_le_bytes([bytes[0], bytes[1]]) as i64)
        }),
        0x05 => decode_fixed_string(blob, offset, 2, value_type_name, |bytes| {
            serde_json::Value::from(u16::from_le_bytes([bytes[0], bytes[1]]) as u64)
        }),
        0x06 => decode_fixed_string(blob, offset, 4, value_type_name, |bytes| {
            serde_json::Value::from(
                i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64
            )
        }),
        0x07 | 0x08 => decode_fixed_string(blob, offset, 4, value_type_name, |bytes| {
            serde_json::Value::from(
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
            )
        }),
        0x09 => decode_fixed_string(blob, offset, 8, value_type_name, |bytes| {
            serde_json::Value::from(i64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        }),
        0x0a => decode_fixed_string(blob, offset, 8, value_type_name, |bytes| {
            serde_json::Value::from(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        }),
        0x0b => decode_fixed_string(blob, offset, 4, value_type_name, |bytes| {
            serde_json::Value::from(
                f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f64
            )
        }),
        0x0c => decode_fixed_string(blob, offset, 8, value_type_name, |bytes| {
            serde_json::Value::from(f64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        }),
        0x0d => decode_fixed_string(blob, offset, 4, value_type_name, |bytes| {
            serde_json::Value::from(
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != 0,
            )
        }),
        0x0e => decode_length_prefixed_bytes(blob, offset, value_type_name, |bytes| {
            serde_json::Value::String(hex_bytes(bytes))
        }),
        0x0f => decode_fixed_string(blob, offset, 16, value_type_name, |bytes| {
            serde_json::Value::String(format_guid(bytes))
        }),
        0x11 => decode_fixed_string(blob, offset, 8, value_type_name, |bytes| {
            let filetime = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            serde_json::Value::String(filetime_to_iso8601(filetime))
        }),
        0x12 => decode_fixed_string(blob, offset, 16, value_type_name, |bytes| {
            serde_json::json!({
                "system_time_raw_hex": hex_bytes(bytes),
                "year": u16::from_le_bytes([bytes[0], bytes[1]]),
                "month": u16::from_le_bytes([bytes[2], bytes[3]]),
                "day_of_week": u16::from_le_bytes([bytes[4], bytes[5]]),
                "day": u16::from_le_bytes([bytes[6], bytes[7]]),
                "hour": u16::from_le_bytes([bytes[8], bytes[9]]),
                "minute": u16::from_le_bytes([bytes[10], bytes[11]]),
                "second": u16::from_le_bytes([bytes[12], bytes[13]]),
                "milliseconds": u16::from_le_bytes([bytes[14], bytes[15]])
            })
        }),
        0x13 => {
            let start = offset + 2;
            let Some(length) = sid_length(blob, start) else {
                return decoded_value("truncated", "", serde_json::Value::Null, &[], blob.len());
            };
            let end = start + length;
            let sid = format_sid(&blob[start..end]);
            decoded_value(
                value_type_name,
                &sid,
                serde_json::Value::String(sid.clone()),
                &blob[start..end],
                end,
            )
        }
        _ => {
            let start = offset + 2;
            let end = blob.len().min(start + 16);
            decoded_value(
                value_type_name,
                &hex_bytes(&blob[start..end]),
                serde_json::Value::String(hex_bytes(&blob[start..end])),
                &blob[start..end],
                end,
            )
        }
    }
}

fn binxml_value_type_name(value_type: u8) -> &'static str {
    match value_type {
        0x01 => "StringType",
        0x02 => "Int8Type",
        0x03 => "UInt8Type",
        0x04 => "Int16Type",
        0x05 => "UInt16Type",
        0x06 => "Int32Type",
        0x07 => "UInt32Type",
        0x08 => "HexInt32Type",
        0x09 => "Int64Type",
        0x0a => "UInt64Type",
        0x0b => "Real32Type",
        0x0c => "Real64Type",
        0x0d => "BoolType",
        0x0e => "BinaryType",
        0x0f => "GuidType",
        0x11 => "FileTimeType",
        0x12 => "SysTimeType",
        0x13 => "SidType",
        _ => "UnsupportedType",
    }
}

fn decoded_value(
    value_type: &str,
    text: &str,
    json_value: serde_json::Value,
    raw: &[u8],
    end_offset: usize,
) -> BinXmlDecodedValue {
    BinXmlDecodedValue {
        value_type: value_type.to_string(),
        text: text.to_string(),
        json_value,
        raw_hex: hex_bytes(raw),
        end_offset,
    }
}

fn decode_fixed_string<F>(
    blob: &[u8],
    offset: usize,
    byte_len: usize,
    value_type: &str,
    decode: F,
) -> BinXmlDecodedValue
where
    F: Fn(&[u8]) -> serde_json::Value,
{
    let start = offset + 2;
    let end = start.saturating_add(byte_len);
    if end > blob.len() {
        return decoded_value("truncated", "", serde_json::Value::Null, &[], blob.len());
    }
    let value = decode(&blob[start..end]);
    let text = json_scalar_to_text(&value);
    decoded_value(value_type, &text, value, &blob[start..end], end)
}

fn decode_length_prefixed_bytes<F>(
    blob: &[u8],
    offset: usize,
    value_type: &str,
    decode: F,
) -> BinXmlDecodedValue
where
    F: Fn(&[u8]) -> serde_json::Value,
{
    if offset + 4 > blob.len() {
        return decoded_value("truncated", "", serde_json::Value::Null, &[], blob.len());
    }
    let byte_len = read_u16_le(blob, offset + 2) as usize;
    let start = offset + 4;
    let end = start.saturating_add(byte_len);
    if end > blob.len() {
        return decoded_value("truncated", "", serde_json::Value::Null, &[], blob.len());
    }
    let value = decode(&blob[start..end]);
    let text = json_scalar_to_text(&value);
    decoded_value(value_type, &text, value, &blob[start..end], end)
}

fn json_scalar_to_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => String::new(),
        _ => value.to_string(),
    }
}

fn utf16le_lossy(bytes: &[u8]) -> String {
    let mut units = Vec::new();
    let mut cursor = 0usize;
    while cursor + 1 < bytes.len() {
        units.push(u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]));
        cursor += 2;
    }
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string()
}

fn looks_like_binxml_boundary(blob: &[u8], offset: usize) -> bool {
    if offset >= blob.len() {
        return true;
    }
    matches!(
        blob[offset] & 0xbf,
        0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x0c | 0x0d | 0x0f
    )
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return hex_bytes(bytes);
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{}-{}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        hex_bytes(&bytes[8..10]),
        hex_bytes(&bytes[10..16])
    )
}

fn sid_length(blob: &[u8], offset: usize) -> Option<usize> {
    if offset + 8 > blob.len() {
        return None;
    }
    let sub_authority_count = blob[offset + 1] as usize;
    let length = 8usize.saturating_add(sub_authority_count.saturating_mul(4));
    if offset + length <= blob.len() {
        Some(length)
    } else {
        None
    }
}

fn format_sid(bytes: &[u8]) -> String {
    if bytes.len() < 8 {
        return hex_bytes(bytes);
    }
    let revision = bytes[0];
    let sub_authority_count = bytes[1] as usize;
    let identifier_authority = bytes[2..8]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let mut parts = vec![format!("S-{revision}-{identifier_authority}")];
    let mut cursor = 8usize;
    for _ in 0..sub_authority_count {
        if cursor + 4 > bytes.len() {
            break;
        }
        parts.push(
            u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ])
            .to_string(),
        );
        cursor += 4;
    }
    parts.join("-")
}

fn filetime_to_iso8601(filetime: u64) -> String {
    const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
    if filetime < FILETIME_UNIX_EPOCH {
        return format!("filetime:{filetime}");
    }
    let unix_seconds = (filetime - FILETIME_UNIX_EPOCH) / 10_000_000;
    format!("unix_seconds:{unix_seconds}")
}

fn read_binxml_template_instance(blob: &[u8], offset: usize) -> (Option<serde_json::Value>, usize) {
    let marker_offset = offset + 1;
    if marker_offset >= blob.len() || blob[marker_offset] != 0xb0 {
        return (None, offset + 1);
    }
    let template_id_start = marker_offset + 1;
    let template_id_end = template_id_start + 16;
    if template_id_end > blob.len() {
        return (None, blob.len());
    }
    let template_id = blob[template_id_start..template_id_end]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("");
    let mut cursor = template_id_end;
    let mut template_body = serde_json::Value::Null;
    let mut template_body_length = 0u32;
    if cursor + 4 <= blob.len() {
        let declared_template_length = read_u32_le(blob, cursor);
        let template_start = cursor + 4;
        let template_end = template_start.saturating_add(declared_template_length as usize);
        if declared_template_length > 0 && template_end <= blob.len() {
            template_body_length = declared_template_length;
            template_body = parse_binxml_object_model(&blob[template_start..template_end]);
            cursor = template_end;
        }
    }
    let value_count = if cursor + 4 <= blob.len() {
        let value = read_u32_le(blob, cursor);
        cursor += 4;
        value
    } else if cursor + 2 <= blob.len() {
        let value = read_u16_le(blob, cursor) as u32;
        cursor += 2;
        value
    } else {
        0
    };
    let mut value_specs = Vec::new();
    let mut values = Vec::new();
    for index in 0..usize::try_from(value_count).unwrap_or(0).min(256) {
        if cursor + 4 > blob.len() {
            break;
        }
        let value_size = read_u16_le(blob, cursor);
        let value_type = blob[cursor + 2];
        let value_start = cursor + 4;
        let value_end = value_start.saturating_add(value_size as usize);
        let decoded = if value_end <= blob.len() {
            decode_template_value(&blob[value_start..value_end], value_type)
        } else {
            decoded_value("truncated", "", serde_json::Value::Null, &[], blob.len())
        };
        value_specs.push(serde_json::json!({
            "index": index,
            "size": value_size,
            "value_type": binxml_value_type_name(value_type),
            "value_type_raw": format!("0x{value_type:02x}")
        }));
        values.push(serde_json::json!({
            "index": index,
            "value_type": decoded.value_type,
            "text": decoded.text,
            "value": decoded.json_value,
            "raw_hex": decoded.raw_hex
        }));
        cursor = if value_end <= blob.len() {
            value_end
        } else {
            blob.len()
        };
    }
    (
        Some(serde_json::json!({
            "node_type": "template_instance",
            "offset": offset,
            "template_id": template_id,
            "template_body_length": template_body_length,
            "template_body": template_body,
            "value_count": value_count,
            "value_specs": value_specs,
            "values": values,
            "decode_status": "template-body-and-values"
        })),
        cursor,
    )
}

fn decode_template_value(bytes: &[u8], value_type: u8) -> BinXmlDecodedValue {
    let mut wrapped = vec![0x05, value_type];
    match value_type {
        0x01 | 0x0e => {
            wrapped.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            wrapped.extend_from_slice(bytes);
        }
        _ => wrapped.extend_from_slice(bytes),
    }
    read_binxml_value(&wrapped, 0)
}

fn extract_binxml_fields(nodes: &[serde_json::Value]) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    let mut event_data = serde_json::Map::new();
    let mut substitutions = Vec::new();
    for node in nodes {
        let node_type = node
            .get("node_type")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if node_type == "value_text" {
            let path = node
                .get("path")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let value = node.get("value").cloned().unwrap_or_else(|| {
                serde_json::Value::String(
                    node.get("text")
                        .and_then(|value| value.as_str())
                        .unwrap_or("")
                        .to_string(),
                )
            });
            promote_binxml_field(&mut fields, &mut event_data, path, value);
        } else if node_type == "substitution" {
            substitutions.push(node.clone());
        } else if node_type == "template_instance" {
            if let Some(template_fields) = node
                .get("template_body")
                .and_then(|value| value.get("extracted_fields"))
                .and_then(|value| value.as_object())
            {
                for (key, value) in template_fields {
                    fields.entry(key.clone()).or_insert_with(|| value.clone());
                }
            }
            if let Some(values) = node.get("values").and_then(|value| value.as_array()) {
                for value in values {
                    substitutions.push(value.clone());
                }
            }
        }
    }
    if !event_data.is_empty() {
        fields.insert(
            "event_data".to_string(),
            serde_json::Value::Object(event_data),
        );
    }
    if !substitutions.is_empty() {
        fields.insert(
            "substitutions".to_string(),
            serde_json::Value::Array(substitutions.into_iter().take(256).collect()),
        );
    }
    serde_json::Value::Object(fields)
}

fn promote_binxml_field(
    fields: &mut serde_json::Map<String, serde_json::Value>,
    event_data: &mut serde_json::Map<String, serde_json::Value>,
    path: &str,
    value: serde_json::Value,
) {
    let normalized = path.trim_matches('/');
    let key = match normalized {
        "Event/System/Provider/@Name" => "provider_name",
        "Event/System/EventID" => "event_id",
        "Event/System/Level" => "level",
        "Event/System/Channel" => "channel",
        "Event/System/Computer" => "computer",
        "Event/System/TimeCreated/@SystemTime" => "system_time",
        "Event/System/Execution/@ProcessID" => "process_id",
        "Event/System/Execution/@ThreadID" => "thread_id",
        "Event/System/Security/@UserID" => "user_sid",
        _ => "",
    };
    if !key.is_empty() {
        fields.insert(key.to_string(), value);
        return;
    }
    if let Some(name) = normalized.strip_prefix("Event/EventData/") {
        if !name.is_empty() {
            event_data.insert(name.to_string(), value);
        }
    }
}

fn render_evtx_message_preview(binxml_model: &serde_json::Value) -> serde_json::Value {
    if let Some(rendered) = render_builtin_event_message(binxml_model) {
        return rendered;
    }
    let mut values = Vec::new();
    collect_binxml_preview_values(binxml_model, &mut values);
    let preview = values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ");
    if preview.is_empty() {
        return serde_json::json!({
            "status": "unresolved-provider-template",
            "renderer": "rapid-worker-provider-message-preview",
            "provider_message_resource_resolved": false,
            "validation_required": true,
            "rendered_preview": "",
            "limitations": [
                "provider-message-resource-not-loaded",
                "binxml-values-insufficient-for-template-rendering"
            ]
        });
    }
    serde_json::json!({
        "status": "builtin-preview",
        "renderer": "rapid-worker-provider-message-preview",
        "provider_message_resource_resolved": false,
        "validation_required": true,
        "rendered_preview": preview,
        "value_count": values.len(),
        "limitations": [
            "provider-message-resource-not-loaded",
            "preview-is-not-report-grade-message"
        ]
    })
}

fn render_builtin_event_message(binxml_model: &serde_json::Value) -> Option<serde_json::Value> {
    let fields = binxml_model
        .get("extracted_fields")
        .and_then(|value| value.as_object())?;
    let event_id = fields.get("event_id").map(json_scalar_to_text)?;
    let provider = fields
        .get("provider_name")
        .map(json_scalar_to_text)
        .unwrap_or_default();
    let channel = fields
        .get("channel")
        .map(json_scalar_to_text)
        .unwrap_or_default();
    let computer = fields
        .get("computer")
        .map(json_scalar_to_text)
        .unwrap_or_default();
    let event_data = fields
        .get("event_data")
        .and_then(|value| value.as_object())
        .cloned()
        .unwrap_or_default();
    let substitutions = fields
        .get("substitutions")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    let message = match event_id.as_str() {
        "4104" => format!(
            "PowerShell script block was recorded. Script={}.",
            first_event_value(
                &event_data,
                &substitutions,
                &["ScriptBlockText", "CommandLine", "Payload"]
            )
        ),
        "4624" => format!(
            "An account successfully logged on. User={}; logon_type={}; source={}.",
            first_event_value(
                &event_data,
                &substitutions,
                &["TargetUserName", "SubjectUserName", "User"]
            ),
            first_event_value(&event_data, &substitutions, &["LogonType"]),
            first_event_value(
                &event_data,
                &substitutions,
                &["IpAddress", "SourceAddress", "SourceIp"]
            )
        ),
        "4688" => format!(
            "A process was created. Process={}; command={}; parent={}.",
            first_event_value(
                &event_data,
                &substitutions,
                &["NewProcessName", "ProcessName", "Image"]
            ),
            first_event_value(
                &event_data,
                &substitutions,
                &["CommandLine", "ProcessCommandLine"]
            ),
            first_event_value(
                &event_data,
                &substitutions,
                &["ParentProcessName", "CreatorProcessName"]
            )
        ),
        "7045" => format!(
            "A service was installed. Service={}; image={}; account={}.",
            first_event_value(&event_data, &substitutions, &["ServiceName"]),
            first_event_value(
                &event_data,
                &substitutions,
                &["ServiceFileName", "ImagePath"]
            ),
            first_event_value(&event_data, &substitutions, &["AccountName", "User"])
        ),
        "1102" => "The audit log was cleared.".to_string(),
        _ => return None,
    };
    Some(serde_json::json!({
        "status": "rendered-builtin-template",
        "renderer": "rapid-worker-builtin-template",
        "provider_message_resource_resolved": false,
        "validation_required": true,
        "rendered_preview": message,
        "message": message,
        "event_id": event_id,
        "provider_name": provider,
        "channel": channel,
        "computer": computer,
        "provenance": {
            "renderer": "rapid-worker-builtin-template",
            "provider_message_resource_resolved": false,
            "native_binxml_status": binxml_model_status(binxml_model),
            "template_value_count": substitutions.len()
        },
        "limitations": [
            "provider-message-resource-not-loaded",
            "builtin-template-is-validation-required",
            "locale-specific-provider-message-not-resolved"
        ]
    }))
}

fn first_event_value(
    event_data: &serde_json::Map<String, serde_json::Value>,
    substitutions: &[serde_json::Value],
    keys: &[&str],
) -> String {
    for key in keys {
        if let Some(value) = event_data.get(*key) {
            let text = json_scalar_to_text(value);
            if !text.is_empty() {
                return text;
            }
        }
    }
    for substitution in substitutions {
        if let Some(text) = substitution.get("text").and_then(|value| value.as_str()) {
            if !text.is_empty() {
                return text.to_string();
            }
        }
    }
    String::new()
}

fn collect_binxml_preview_values(model: &serde_json::Value, output: &mut Vec<String>) {
    if let Some(fields) = model
        .get("extracted_fields")
        .and_then(|value| value.as_object())
    {
        for key in [
            "provider_name",
            "event_id",
            "channel",
            "computer",
            "system_time",
        ] {
            if let Some(value) = fields.get(key) {
                output.push(json_scalar_to_text(value));
            }
        }
        if let Some(event_data) = fields.get("event_data").and_then(|value| value.as_object()) {
            for value in event_data.values().take(32) {
                output.push(json_scalar_to_text(value));
            }
        }
        if let Some(substitutions) = fields
            .get("substitutions")
            .and_then(|value| value.as_array())
        {
            for value in substitutions.iter().take(32) {
                if let Some(text) = value.get("text").and_then(|text| text.as_str()) {
                    output.push(text.to_string());
                }
            }
        }
    }
    if let Some(nodes) = model.get("nodes").and_then(|value| value.as_array()) {
        for node in nodes {
            if node.get("node_type").and_then(|value| value.as_str()) == Some("value_text") {
                if let Some(text) = node.get("text").and_then(|value| value.as_str()) {
                    output.push(text.to_string());
                }
            }
            if let Some(template_body) = node.get("template_body") {
                collect_binxml_preview_values(template_body, output);
            }
            if let Some(values) = node.get("values").and_then(|value| value.as_array()) {
                for value in values {
                    if let Some(text) = value.get("text").and_then(|text| text.as_str()) {
                        output.push(text.to_string());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
fn evtx_chunk_offset_for_record(record_offset: usize) -> Option<u64> {
    const FILE_HEADER_SIZE: usize = 4096;
    const CHUNK_SIZE: usize = 65536;
    if record_offset < FILE_HEADER_SIZE {
        return None;
    }
    let relative = record_offset - FILE_HEADER_SIZE;
    Some((FILE_HEADER_SIZE + (relative / CHUNK_SIZE) * CHUNK_SIZE) as u64)
}

#[cfg(test)]
fn evtx_chunk_index_for_record(record_offset: usize) -> Option<u64> {
    const FILE_HEADER_SIZE: usize = 4096;
    const CHUNK_SIZE: usize = 65536;
    if record_offset < FILE_HEADER_SIZE {
        return None;
    }
    Some(((record_offset - FILE_HEADER_SIZE) / CHUNK_SIZE) as u64)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_u16_le(blob: &[u8], offset: usize) -> u16 {
    if offset + 2 > blob.len() {
        return 0;
    }
    u16::from_le_bytes([blob[offset], blob[offset + 1]])
}

fn read_u32_le(blob: &[u8], offset: usize) -> u32 {
    if offset + 4 > blob.len() {
        return 0;
    }
    u32::from_le_bytes([
        blob[offset],
        blob[offset + 1],
        blob[offset + 2],
        blob[offset + 3],
    ])
}

fn read_u64_le(blob: &[u8], offset: usize) -> u64 {
    if offset + 8 > blob.len() {
        return 0;
    }
    u64::from_le_bytes([
        blob[offset],
        blob[offset + 1],
        blob[offset + 2],
        blob[offset + 3],
        blob[offset + 4],
        blob[offset + 5],
        blob[offset + 6],
        blob[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_noop_options() {
        let args = vec![
            "--kind".to_string(),
            "noop".to_string(),
            "--source".to_string(),
            "/case".to_string(),
            "--case-id".to_string(),
            "CASE-1".to_string(),
            "--source-id".to_string(),
            "SRC-1".to_string(),
        ];

        let parsed = ParseOptions::from_args(&args).unwrap();

        assert_eq!(parsed.kind, "noop");
        assert_eq!(parsed.source, "/case");
        assert_eq!(parsed.case_id, "CASE-1");
        assert_eq!(parsed.source_id, "SRC-1");
        assert_eq!(parsed.max_records, 100_000);
    }

    #[test]
    fn parses_file_inventory_limit() {
        let args = vec![
            "--kind".to_string(),
            "file-inventory".to_string(),
            "--source".to_string(),
            "/case".to_string(),
            "--max-records".to_string(),
            "10".to_string(),
        ];

        let parsed = ParseOptions::from_args(&args).unwrap();

        assert_eq!(parsed.kind, "file-inventory");
        assert_eq!(parsed.max_records, 10);
    }

    #[test]
    fn file_inventory_rejects_missing_source() {
        let options = ParseOptions {
            kind: "file-inventory".to_string(),
            source: "/definitely/missing/rapidforensic/source".to_string(),
            case_id: "CASE".to_string(),
            source_id: "SOURCE".to_string(),
            max_records: 10,
        };

        let error = emit_file_inventory(options).unwrap_err();

        assert!(error.contains("source is not accessible"));
    }

    #[test]
    fn evtx_header_reader_extracts_version_and_next_record_id() {
        let root = env::temp_dir().join(format!("rapid-worker-evtx-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("System.evtx");
        let mut header = vec![0u8; 4096];
        header[0..8].copy_from_slice(b"ElfFile\0");
        header[24..32].copy_from_slice(&42u64.to_le_bytes());
        header[38..40].copy_from_slice(&1u16.to_le_bytes());
        header[40..42].copy_from_slice(&3u16.to_le_bytes());
        fs::write(&path, header).unwrap();

        let parsed = read_evtx_header(&path).unwrap();

        assert!(parsed.signature_valid);
        assert_eq!(parsed.major_version, 3);
        assert_eq!(parsed.minor_version, 1);
        assert_eq!(parsed.next_record_identifier, 42);
        fs::remove_file(path).ok();
        fs::remove_dir(root).ok();
    }

    #[test]
    fn evtx_record_parser_extracts_chunk_and_record_headers() {
        let mut blob = vec![0u8; 4096 + 65536];
        blob[0..8].copy_from_slice(b"ElfFile\0");
        let chunk_offset = 4096;
        blob[chunk_offset..chunk_offset + 8].copy_from_slice(b"ElfChnk\0");
        blob[chunk_offset + 8..chunk_offset + 16].copy_from_slice(&1u64.to_le_bytes());
        blob[chunk_offset + 16..chunk_offset + 24].copy_from_slice(&1u64.to_le_bytes());
        blob[chunk_offset + 24..chunk_offset + 32].copy_from_slice(&300u64.to_le_bytes());
        blob[chunk_offset + 32..chunk_offset + 40].copy_from_slice(&300u64.to_le_bytes());
        blob[chunk_offset + 40..chunk_offset + 44].copy_from_slice(&512u32.to_le_bytes());
        blob[chunk_offset + 44..chunk_offset + 48].copy_from_slice(&600u32.to_le_bytes());
        let record_offset = chunk_offset + 512;
        let record_size = 32u32;
        blob[record_offset..record_offset + 4].copy_from_slice(b"**\0\0");
        blob[record_offset + 4..record_offset + 8].copy_from_slice(&record_size.to_le_bytes());
        blob[record_offset + 8..record_offset + 16].copy_from_slice(&300u64.to_le_bytes());
        blob[record_offset + 16..record_offset + 24].copy_from_slice(&132456789u64.to_le_bytes());
        blob[record_offset + 28..record_offset + 32].copy_from_slice(&record_size.to_le_bytes());

        let chunks = parse_evtx_chunks(&blob);
        let records = parse_evtx_record_headers(&blob);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].free_space_offset, 600);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_id, 300);
        assert_eq!(records[0].declared_size, 32);
        assert_eq!(records[0].trailing_size, 32);
        assert_eq!(records[0].chunk_offset, Some(4096));
        assert_eq!(records[0].chunk_index, Some(0));
        assert_eq!(records[0].binxml_status, "not-decoded");
        assert_eq!(records[0].allocation_status, "allocated-or-live-record");
        assert_eq!(records[0].recovery_status, "recoverable-record-header");
    }

    #[test]
    fn evtx_streaming_parser_reads_chunks_without_whole_file_scan() {
        let root = env::temp_dir().join(format!(
            "rapid-worker-evtx-streaming-test-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("System.evtx");
        let mut blob = vec![0u8; 4096 + 65536];
        blob[0..8].copy_from_slice(b"ElfFile\0");
        let chunk_offset = 4096;
        blob[chunk_offset..chunk_offset + 8].copy_from_slice(b"ElfChnk\0");
        blob[chunk_offset + 24..chunk_offset + 32].copy_from_slice(&400u64.to_le_bytes());
        blob[chunk_offset + 32..chunk_offset + 40].copy_from_slice(&400u64.to_le_bytes());
        blob[chunk_offset + 40..chunk_offset + 44].copy_from_slice(&512u32.to_le_bytes());
        blob[chunk_offset + 44..chunk_offset + 48].copy_from_slice(&700u32.to_le_bytes());
        let record_offset = chunk_offset + 512;
        let record_size = 32u32;
        blob[record_offset..record_offset + 4].copy_from_slice(b"**\0\0");
        blob[record_offset + 4..record_offset + 8].copy_from_slice(&record_size.to_le_bytes());
        blob[record_offset + 8..record_offset + 16].copy_from_slice(&400u64.to_le_bytes());
        blob[record_offset + 16..record_offset + 24].copy_from_slice(&132456789u64.to_le_bytes());
        blob[record_offset + 28..record_offset + 32].copy_from_slice(&record_size.to_le_bytes());
        fs::write(&path, blob).unwrap();

        let limited = parse_evtx_file_streaming(&path, 1).unwrap();
        let full = parse_evtx_file_streaming(&path, 10).unwrap();

        assert_eq!(limited.len(), 1);
        assert!(matches!(limited[0], EvtxParsedItem::Chunk(_)));
        assert_eq!(full.len(), 2);
        assert!(matches!(full[1], EvtxParsedItem::Record(_)));
        fs::remove_file(path).ok();
        fs::remove_dir(root).ok();
    }

    #[test]
    fn evtx_record_parser_labels_slack_and_corrupt_candidates() {
        let mut blob = vec![0u8; 4096 + 65536];
        let chunk_offset = 4096;
        blob[chunk_offset..chunk_offset + 8].copy_from_slice(b"ElfChnk\0");
        blob[chunk_offset + 40..chunk_offset + 44].copy_from_slice(&512u32.to_le_bytes());
        blob[chunk_offset + 44..chunk_offset + 48].copy_from_slice(&600u32.to_le_bytes());
        let record_offset = chunk_offset + 700;
        let record_size = 32u32;
        blob[record_offset..record_offset + 4].copy_from_slice(b"**\0\0");
        blob[record_offset + 4..record_offset + 8].copy_from_slice(&record_size.to_le_bytes());
        blob[record_offset + 8..record_offset + 16].copy_from_slice(&301u64.to_le_bytes());
        blob[record_offset + 16..record_offset + 24].copy_from_slice(&132456789u64.to_le_bytes());
        blob[record_offset + 28..record_offset + 32].copy_from_slice(&31u32.to_le_bytes());

        let records = parse_evtx_record_headers(&blob);

        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].allocation_status,
            "slack-or-deleted-record-candidate"
        );
        assert_eq!(records[0].recovery_status, "corrupt-record-candidate");
        assert!(records[0]
            .caution_labels
            .contains(&"do-not-report-without-independent-validation".to_string()));
    }

    #[test]
    fn binxml_object_model_decodes_fragment_and_value_text() {
        let mut payload = vec![0x0f, 0x01, 0x01, 0x00, 0x05, 0x01];
        let text: Vec<u8> = "PowerShell"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        payload.extend_from_slice(&(text.len() as u16).to_le_bytes());
        payload.extend_from_slice(&text);
        payload.push(0x00);

        let model = parse_binxml_object_model(&payload);

        assert_eq!(
            model["status"],
            serde_json::Value::from("object-model-decoded")
        );
        assert_eq!(
            model["nodes"][0]["node_type"],
            serde_json::Value::from("fragment_header")
        );
        assert_eq!(
            model["nodes"][1]["text"],
            serde_json::Value::from("PowerShell")
        );
        let rendering = render_evtx_message_preview(&model);
        assert_eq!(
            rendering["status"],
            serde_json::Value::from("builtin-preview")
        );
        assert_eq!(
            rendering["rendered_preview"],
            serde_json::Value::from("PowerShell")
        );
        assert_eq!(
            rendering["provider_message_resource_resolved"],
            serde_json::Value::from(false)
        );
    }

    #[test]
    fn binxml_object_model_decodes_template_instance_header() {
        let mut template_body = vec![0x0f, 0x01, 0x01, 0x00];
        template_body.extend_from_slice(&binxml_element(
            "EventData",
            &[binxml_element(
                "CommandLine",
                &[binxml_substitution(0, 0x01)],
            )],
        ));
        template_body.push(0x00);

        let mut payload = vec![0x0f, 0x01, 0x01, 0x00, 0x0c, 0xb0];
        payload.extend_from_slice(&[0x11; 16]);
        payload.extend_from_slice(&(template_body.len() as u32).to_le_bytes());
        payload.extend_from_slice(&template_body);
        payload.extend_from_slice(&1u32.to_le_bytes());
        let command: Vec<u8> = "Get-Process"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        payload.extend_from_slice(&(command.len() as u16).to_le_bytes());
        payload.push(0x01);
        payload.push(0x00);
        payload.extend_from_slice(&command);

        let model = parse_binxml_object_model(&payload);

        assert_eq!(
            model["status"],
            serde_json::Value::from("template-instance-decoded")
        );
        assert_eq!(
            model["nodes"][1]["node_type"],
            serde_json::Value::from("template_instance")
        );
        assert_eq!(model["nodes"][1]["value_count"], serde_json::Value::from(1));
        assert_eq!(
            model["nodes"][1]["values"][0]["text"],
            serde_json::Value::from("Get-Process")
        );
    }

    #[test]
    fn binxml_object_model_promotes_event_system_and_eventdata_fields() {
        let mut payload = vec![0x0f, 0x01, 0x01, 0x00];
        payload.extend_from_slice(&binxml_element(
            "Event",
            &[
                binxml_element(
                    "System",
                    &[
                        binxml_element_with_attributes(
                            "Provider",
                            &[("Name", binxml_value_string("Microsoft-Windows-PowerShell"))],
                            &[],
                        ),
                        binxml_element("EventID", &[binxml_value_string("4104")]),
                        binxml_element("Channel", &[binxml_value_string("PowerShell/Operational")]),
                        binxml_element("Computer", &[binxml_value_string("WIN-01")]),
                        binxml_element_with_attributes(
                            "Execution",
                            &[
                                ("ProcessID", binxml_value_u32(4321)),
                                ("ThreadID", binxml_value_u32(8765)),
                            ],
                            &[],
                        ),
                    ],
                ),
                binxml_element(
                    "EventData",
                    &[binxml_element(
                        "CommandLine",
                        &[binxml_value_string("powershell -enc AAAA")],
                    )],
                ),
            ],
        ));
        payload.push(0x00);

        let model = parse_binxml_object_model(&payload);

        assert_eq!(
            model["extracted_fields"]["provider_name"],
            serde_json::Value::from("Microsoft-Windows-PowerShell")
        );
        assert_eq!(
            model["extracted_fields"]["event_id"],
            serde_json::Value::from("4104")
        );
        assert_eq!(
            model["extracted_fields"]["process_id"],
            serde_json::Value::from(4321)
        );
        assert_eq!(
            model["extracted_fields"]["event_data"]["CommandLine"],
            serde_json::Value::from("powershell -enc AAAA")
        );
        let rendering = render_evtx_message_preview(&model);
        assert_eq!(
            rendering["status"],
            serde_json::Value::from("rendered-builtin-template")
        );
        assert!(rendering["rendered_preview"]
            .as_str()
            .unwrap()
            .contains("powershell -enc AAAA"));
    }

    fn binxml_element(name: &str, children: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![0x01, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00];
        out.extend_from_slice(&binxml_name(name));
        out.push(0x02);
        for child in children {
            out.extend_from_slice(child);
        }
        out.push(0x04);
        out
    }

    fn binxml_element_with_attributes(
        name: &str,
        attributes: &[(&str, Vec<u8>)],
        children: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut out = vec![0x41, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00];
        out.extend_from_slice(&binxml_name(name));
        for (attribute_name, value) in attributes {
            out.push(0x06);
            out.extend_from_slice(&binxml_name(attribute_name));
            out.extend_from_slice(value);
        }
        out.push(0x02);
        for child in children {
            out.extend_from_slice(child);
        }
        out.push(0x04);
        out
    }

    fn binxml_name(value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(value.encode_utf16().count() as u16).to_le_bytes());
        for unit in value.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn binxml_value_string(value: &str) -> Vec<u8> {
        let mut out = vec![0x05, 0x01];
        out.extend_from_slice(&(value.encode_utf16().count() as u16).to_le_bytes());
        for unit in value.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    fn binxml_value_u32(value: u32) -> Vec<u8> {
        let mut out = vec![0x05, 0x08];
        out.extend_from_slice(&value.to_le_bytes());
        out
    }

    fn binxml_substitution(index: u16, value_type: u8) -> Vec<u8> {
        let mut out = vec![0x0d];
        out.extend_from_slice(&index.to_le_bytes());
        out.push(value_type);
        out
    }
}
