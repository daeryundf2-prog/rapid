//! EWF v1 (E01 from EnCase 1-7, FTK Imager, ewfacquire; S01) media reader with a decoded-chunk
//! cache and parallel zlib decoding of multi-chunk reads.
//!
//! It only has to be right where it answers: anything it does not recognise makes `open` fail
//! (the caller then reads through pyewf), and a chunk whose stored checksum or inflated size does
//! not match fails the read (the caller re-reads that range through pyewf, so libewf decides).

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use flate2::{Decompress, FlushDecompress, Status};

use crate::ntfs::Res;

const SIGNATURE_V1: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";
const DESCRIPTOR: u64 = 76;
const CACHE_CHUNKS: usize = 1024;
const PARALLEL_MIN_CHUNKS: usize = 8;

type ChunkCache = (HashMap<usize, Arc<Vec<u8>>>, VecDeque<usize>);
type DecodedBatch = Res<Vec<(usize, Vec<u8>)>>;

#[derive(Clone, Copy)]
struct Chunk {
    segment: u16,
    offset: u64,
    stored: u32,
    compressed: bool,
}

pub struct EwfImage {
    segments: Vec<File>,
    chunks: Vec<Chunk>,
    chunk_size: u64,
    media_size: u64,
    threads: usize,
    cache: Mutex<ChunkCache>,
}

fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            let n = file.seek_read(&mut buf[done..], offset + done as u64)?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            done += n;
        }
        Ok(())
    }
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for block in data.chunks(5552) {
        for &byte in block {
            a += byte as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

fn le32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}
fn le64(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

struct Geometry {
    chunk_count: u64,
    chunk_size: u64,
    media_size: u64,
}

impl EwfImage {
    /// Parse the segment set (in order); `Err` for anything this reader does not handle.
    pub fn open(paths: &[PathBuf], threads: usize) -> Res<EwfImage> {
        let mut segments = Vec::new();
        let mut chunks = Vec::new();
        let mut geometry: Option<Geometry> = None;
        for (index, path) in paths.iter().enumerate() {
            let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let length = file.metadata().map_err(|e| e.to_string())?.len();
            let mut header = [0u8; 13];
            read_exact_at(&file, 0, &mut header).map_err(|e| e.to_string())?;
            if &header[..8] != SIGNATURE_V1 {
                return Err("not an EWF v1 segment".into());
            }
            if u16::from_le_bytes([header[9], header[10]]) as usize != index + 1 {
                return Err("segment numbers are not consecutive".into());
            }
            Self::parse_segment(&file, length, index as u16, &mut chunks, &mut geometry)?;
            segments.push(file);
        }
        let geometry = geometry.ok_or("no volume section")?;
        if chunks.len() as u64 != geometry.chunk_count {
            return Err(format!(
                "table lists {} chunks, volume says {}",
                chunks.len(),
                geometry.chunk_count
            ));
        }
        if geometry.chunk_count * geometry.chunk_size < geometry.media_size {
            return Err("chunks do not cover the media".into());
        }
        Ok(EwfImage {
            segments,
            chunks,
            chunk_size: geometry.chunk_size,
            media_size: geometry.media_size,
            threads: threads.max(1),
            cache: Mutex::new((HashMap::new(), VecDeque::new())),
        })
    }

    fn parse_segment(
        file: &File,
        length: u64,
        segment: u16,
        chunks: &mut Vec<Chunk>,
        geometry: &mut Option<Geometry>,
    ) -> Res<()> {
        let mut offset = 13u64;
        let mut data_end: Option<u64> = None;
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 1_000_000 || offset + DESCRIPTOR > length {
                return Err("section chain runs past the segment".into());
            }
            let mut descriptor = [0u8; DESCRIPTOR as usize];
            read_exact_at(file, offset, &mut descriptor).map_err(|e| e.to_string())?;
            if adler32(&descriptor[..72]) != le32(&descriptor, 72) {
                return Err("section descriptor checksum mismatch".into());
            }
            let kind_end = descriptor[..16].iter().position(|&b| b == 0).unwrap_or(16);
            let kind = &descriptor[..kind_end];
            let next = le64(&descriptor, 16);
            let size = le64(&descriptor, 24);
            match kind {
                b"volume" | b"disk" => {
                    let body_len = size.checked_sub(DESCRIPTOR).ok_or("short volume section")?;
                    let mut body = vec![0u8; body_len.min(4096) as usize];
                    read_exact_at(file, offset + DESCRIPTOR, &mut body)
                        .map_err(|e| e.to_string())?;
                    let (chunk_count, sectors_per_chunk, bytes_per_sector, sector_count) =
                        match body.len() {
                            1052 => (
                                le32(&body, 4),
                                le32(&body, 8),
                                le32(&body, 12),
                                le64(&body, 16),
                            ),
                            94 => (
                                le32(&body, 4),
                                le32(&body, 8),
                                le32(&body, 12),
                                le32(&body, 16) as u64,
                            ),
                            other => {
                                return Err(format!("unsupported volume section size {other}"))
                            }
                        };
                    let chunk_size = sectors_per_chunk as u64 * bytes_per_sector as u64;
                    if chunk_size == 0 || chunk_size > 64 << 20 {
                        return Err("unsupported chunk size".into());
                    }
                    *geometry = Some(Geometry {
                        chunk_count: chunk_count as u64,
                        chunk_size,
                        media_size: sector_count * bytes_per_sector as u64,
                    });
                }
                b"sectors" => data_end = Some(offset + size),
                b"table" => {
                    let section_end = offset + size;
                    let mut head = [0u8; 24];
                    read_exact_at(file, offset + DESCRIPTOR, &mut head)
                        .map_err(|e| e.to_string())?;
                    let count = le32(&head, 0) as u64;
                    let base = le64(&head, 8);
                    let mut raw = vec![0u8; (count * 4) as usize];
                    read_exact_at(file, offset + DESCRIPTOR + 24, &mut raw)
                        .map_err(|e| e.to_string())?;
                    let entries: Vec<(u64, bool)> = raw
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|e| {
                            let value = u32::from_le_bytes(*e);
                            (
                                base + (value & 0x7FFF_FFFF) as u64,
                                value & 0x8000_0000 != 0,
                            )
                        })
                        .collect();
                    let end = data_end.take().unwrap_or(section_end);
                    for (i, &(start, compressed)) in entries.iter().enumerate() {
                        let stop = entries.get(i + 1).map(|e| e.0).unwrap_or(end);
                        if stop <= start || stop > length {
                            return Err(
                                "chunk offsets are not increasing (31-bit overflow or damage)"
                                    .into(),
                            );
                        }
                        chunks.push(Chunk {
                            segment,
                            offset: start,
                            stored: (stop - start) as u32,
                            compressed,
                        });
                    }
                }
                _ => {}
            }
            if kind == b"done" || kind == b"next" || next == offset {
                return Ok(());
            }
            if next <= offset {
                return Err("section chain goes backwards".into());
            }
            offset = next;
        }
    }

    pub fn media_size(&self) -> u64 {
        self.media_size
    }

    fn expected_len(&self, index: usize) -> usize {
        let start = index as u64 * self.chunk_size;
        self.chunk_size.min(self.media_size.saturating_sub(start)) as usize
    }

    fn decode(&self, index: usize) -> Res<Vec<u8>> {
        let chunk = self.chunks[index];
        let mut stored = vec![0u8; chunk.stored as usize];
        read_exact_at(
            &self.segments[chunk.segment as usize],
            chunk.offset,
            &mut stored,
        )
        .map_err(|e| e.to_string())?;
        let want = self.chunk_size as usize;
        let data = if chunk.compressed {
            let mut out = Vec::with_capacity(want);
            let mut inflater = Decompress::new(true);
            match inflater.decompress_vec(&stored, &mut out, FlushDecompress::Finish) {
                Ok(Status::StreamEnd) => {}
                _ => return Err(format!("chunk {index}: zlib stream does not end cleanly")),
            }
            out
        } else {
            if stored.len() < 4 {
                return Err(format!("chunk {index}: too short"));
            }
            let (body, checksum) = stored.split_at(stored.len() - 4);
            if adler32(body) != u32::from_le_bytes(checksum.try_into().unwrap()) {
                return Err(format!("chunk {index}: checksum mismatch"));
            }
            body.to_vec()
        };
        if data.len() != want && data.len() != self.expected_len(index) {
            return Err(format!(
                "chunk {index}: {} bytes instead of {want}",
                data.len()
            ));
        }
        Ok(data)
    }

    fn cached(&self, index: usize) -> Option<Arc<Vec<u8>>> {
        self.cache.lock().ok()?.0.get(&index).cloned()
    }

    fn remember(&self, index: usize, data: Arc<Vec<u8>>) {
        if let Ok(mut guard) = self.cache.lock() {
            let (map, order) = &mut *guard;
            if map.insert(index, data).is_none() {
                order.push_back(index);
                while order.len() > CACHE_CHUNKS {
                    if let Some(old) = order.pop_front() {
                        map.remove(&old);
                    }
                }
            }
        }
    }

    /// Up to `len` media bytes at `offset` (short only past the media end), like pyewf `read`.
    pub fn read_at(&self, offset: u64, len: usize) -> Res<Vec<u8>> {
        if offset >= self.media_size || len == 0 {
            return Ok(Vec::new());
        }
        let end = (offset + len as u64).min(self.media_size);
        let first = (offset / self.chunk_size) as usize;
        let last = ((end - 1) / self.chunk_size) as usize;
        let mut parts: Vec<Option<Arc<Vec<u8>>>> = (first..=last).map(|i| self.cached(i)).collect();
        let missing: Vec<usize> = (first..=last)
            .filter(|i| parts[i - first].is_none())
            .collect();
        let keep = last - first < 8;
        if missing.len() >= PARALLEL_MIN_CHUNKS && self.threads > 1 {
            let per = missing.len().div_ceil(self.threads);
            let decoded: Vec<DecodedBatch> = std::thread::scope(|scope| {
                let handles: Vec<_> = missing
                    .chunks(per)
                    .map(|batch| {
                        scope.spawn(move || {
                            batch
                                .iter()
                                .map(|&i| self.decode(i).map(|d| (i, d)))
                                .collect::<Res<Vec<_>>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().unwrap_or_else(|_| Err("decoder panicked".into())))
                    .collect()
            });
            for batch in decoded {
                for (i, data) in batch? {
                    parts[i - first] = Some(Arc::new(data));
                }
            }
        } else {
            for &i in &missing {
                let data = Arc::new(self.decode(i)?);
                if keep {
                    self.remember(i, data.clone());
                }
                parts[i - first] = Some(data);
            }
        }
        let mut out = Vec::with_capacity((end - offset) as usize);
        for (k, part) in parts.into_iter().enumerate() {
            let data = part.expect("every chunk decoded");
            let chunk_start = (first + k) as u64 * self.chunk_size;
            let from = offset.saturating_sub(chunk_start) as usize;
            let to = ((end - chunk_start) as usize).min(data.len());
            if from < to {
                out.extend_from_slice(&data[from..to]);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::adler32;

    #[test]
    fn adler32_known_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(&vec![0xFFu8; 100_000]), {
            let (mut a, mut b) = (1u64, 0u64);
            for _ in 0..100_000 {
                a = (a + 255) % 65521;
                b = (b + a) % 65521;
            }
            ((b << 16) | a) as u32
        });
    }
}
