// Fast EVTX chunk/record-header scanner for the native acceleration path (R4-1).
//
// This is a structural scanner only: it locates ElfChnk chunks and record
// headers (signature, declared/trailing size, record id, FILETIME timestamp)
// without decoding BinXML payloads. rapid-worker performs full BinXML decoding;
// this index is the cheap pre-scan used to bound downstream parsing.

use serde::Serialize;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const EVTX_FILE_SIGNATURE: &[u8; 8] = b"ElfFile\0";
pub const EVTX_CHUNK_SIGNATURE: &[u8; 8] = b"ElfChnk\0";
pub const EVTX_RECORD_MAGIC: &[u8; 4] = b"**\0\0";
pub const FILE_HEADER_SIZE: u64 = 4096;
pub const CHUNK_SIZE: usize = 65536;
const RECORD_HEADER_SIZE: usize = 24;
const MAX_RECORD_SIZE: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EvtxFileHeader {
    pub signature_valid: bool,
    pub major_version: u16,
    pub minor_version: u16,
    pub next_record_identifier: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EvtxScanChunk {
    pub offset: u64,
    pub index: u64,
    pub first_record_number: u64,
    pub last_record_number: u64,
    pub first_record_id: u64,
    pub last_record_id: u64,
    pub last_record_offset: u32,
    pub free_space_offset: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EvtxScanRecord {
    pub offset: u64,
    pub chunk_offset: u64,
    pub chunk_index: u64,
    pub declared_size: u32,
    pub trailing_size: u32,
    pub trailing_size_valid: bool,
    pub record_id: u64,
    pub timestamp_filetime: u64,
    /// "allocated" when the record sits before the chunk's free-space offset,
    /// "slack" when it is beyond it (deleted/carve candidate).
    pub allocation_status: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EvtxScanResult {
    pub file_header: EvtxFileHeader,
    pub chunks: Vec<EvtxScanChunk>,
    pub records: Vec<EvtxScanRecord>,
    pub truncated: bool,
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
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&blob[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

pub fn read_evtx_file_header(path: &Path) -> Result<EvtxFileHeader, String> {
    let mut file =
        fs::File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut header = [0u8; 4096];
    let bytes_read = file
        .read(&mut header)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    Ok(EvtxFileHeader {
        signature_valid: bytes_read >= 8 && &header[0..8] == EVTX_FILE_SIGNATURE,
        minor_version: read_u16_le(&header, 38),
        major_version: read_u16_le(&header, 40),
        next_record_identifier: read_u64_le(&header, 24),
    })
}

fn scan_chunk_header(blob: &[u8], absolute_offset: u64, index: u64) -> Option<EvtxScanChunk> {
    if blob.len() < EVTX_CHUNK_SIGNATURE.len()
        || &blob[0..EVTX_CHUNK_SIGNATURE.len()] != EVTX_CHUNK_SIGNATURE
    {
        return None;
    }
    Some(EvtxScanChunk {
        offset: absolute_offset,
        index,
        first_record_number: read_u64_le(blob, 8),
        last_record_number: read_u64_le(blob, 16),
        first_record_id: read_u64_le(blob, 24),
        last_record_id: read_u64_le(blob, 32),
        last_record_offset: read_u32_le(blob, 40),
        free_space_offset: read_u32_le(blob, 44),
    })
}

fn scan_record_headers_in_chunk(
    blob: &[u8],
    chunk: &EvtxScanChunk,
    remaining_budget: usize,
) -> Vec<EvtxScanRecord> {
    let mut output = Vec::new();
    let mut offset = 0usize;
    while offset + RECORD_HEADER_SIZE <= blob.len() && output.len() < remaining_budget {
        if &blob[offset..offset + 4] == EVTX_RECORD_MAGIC {
            let declared_size = read_u32_le(blob, offset + 4);
            let next_offset = if declared_size >= RECORD_HEADER_SIZE as u32
                && declared_size <= MAX_RECORD_SIZE
                && offset + declared_size as usize <= blob.len()
            {
                offset + declared_size as usize
            } else {
                offset + 4
            };
            if declared_size >= RECORD_HEADER_SIZE as u32 && declared_size <= MAX_RECORD_SIZE {
                let trailing_size = read_u32_le(blob, offset + declared_size as usize - 4);
                let allocation_status =
                    if chunk.free_space_offset == 0 || (offset as u32) < chunk.free_space_offset {
                        "allocated"
                    } else {
                        "slack"
                    };
                output.push(EvtxScanRecord {
                    offset: chunk.offset + offset as u64,
                    chunk_offset: chunk.offset,
                    chunk_index: chunk.index,
                    declared_size,
                    trailing_size,
                    trailing_size_valid: trailing_size == declared_size,
                    record_id: read_u64_le(blob, offset + 8),
                    timestamp_filetime: read_u64_le(blob, offset + 16),
                    allocation_status: allocation_status.to_string(),
                });
            }
            offset = next_offset;
            continue;
        }
        offset += 1;
    }
    output
}

/// Stream an EVTX file and return chunk + record-header indexes.
///
/// `max_records` bounds memory use; `truncated` is set when the bound is hit.
pub fn scan_evtx(path: &Path, max_records: usize) -> Result<EvtxScanResult, String> {
    let file_header = read_evtx_file_header(path)?;
    let mut file =
        fs::File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    let mut result = EvtxScanResult {
        file_header,
        chunks: Vec::new(),
        records: Vec::new(),
        truncated: false,
    };
    if metadata.len() <= FILE_HEADER_SIZE {
        return Ok(result);
    }
    file.seek(SeekFrom::Start(FILE_HEADER_SIZE))
        .map_err(|err| format!("failed to seek {}: {err}", path.display()))?;
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
        if let Some(chunk) = scan_chunk_header(&chunk_blob, absolute_offset, chunk_index) {
            result.chunks.push(chunk.clone());
            let budget = max_records.saturating_sub(result.records.len());
            for record in scan_record_headers_in_chunk(&chunk_blob, &chunk, budget) {
                result.records.push(record);
            }
            if result.records.len() >= max_records {
                result.truncated = true;
                break;
            }
        }
        if bytes_read < CHUNK_SIZE {
            break;
        }
        chunk_index += 1;
        absolute_offset += CHUNK_SIZE as u64;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_sample(path: &Path) -> (u64, u64) {
        let mut blob = vec![0u8; FILE_HEADER_SIZE as usize + CHUNK_SIZE];
        blob[0..8].copy_from_slice(EVTX_FILE_SIGNATURE);
        blob[24..32].copy_from_slice(&3u64.to_le_bytes());
        let chunk = FILE_HEADER_SIZE as usize;
        blob[chunk..chunk + 8].copy_from_slice(EVTX_CHUNK_SIGNATURE);
        blob[chunk + 8..chunk + 16].copy_from_slice(&1u64.to_le_bytes());
        blob[chunk + 16..chunk + 24].copy_from_slice(&2u64.to_le_bytes());
        blob[chunk + 44..chunk + 48].copy_from_slice(&2048u32.to_le_bytes());
        // record at chunk+64: size 48, id 7, filetime 0xDEADBEEF
        let rec = chunk + 64;
        blob[rec..rec + 4].copy_from_slice(EVTX_RECORD_MAGIC);
        blob[rec + 4..rec + 8].copy_from_slice(&48u32.to_le_bytes());
        blob[rec + 8..rec + 16].copy_from_slice(&7u64.to_le_bytes());
        blob[rec + 16..rec + 24].copy_from_slice(&0xDEADBEEFu64.to_le_bytes());
        blob[rec + 44..rec + 48].copy_from_slice(&48u32.to_le_bytes());
        let mut file = fs::File::create(path).unwrap();
        file.write_all(&blob).unwrap();
        (3, 7)
    }

    #[test]
    fn scan_finds_chunk_and_record() {
        let dir = std::env::temp_dir().join("rapidcore_evtx_test.evtx");
        let (next_id, record_id) = write_sample(&dir);
        let result = scan_evtx(&dir, 1024).unwrap();
        assert!(result.file_header.signature_valid);
        assert_eq!(result.file_header.next_record_identifier, next_id);
        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].record_id, record_id);
        assert!(result.records[0].trailing_size_valid);
        assert_eq!(result.records[0].allocation_status, "allocated");
        let _ = fs::remove_file(&dir);
    }

    #[test]
    fn scan_rejects_short_file() {
        let dir = std::env::temp_dir().join("rapidcore_evtx_short.evtx");
        fs::write(&dir, b"tiny").unwrap();
        let result = scan_evtx(&dir, 1024).unwrap();
        assert!(result.chunks.is_empty());
        assert!(result.records.is_empty());
        let _ = fs::remove_file(&dir);
    }
}
