//! NTFS reader that reproduces dissect.ntfs 3.x behaviour as used by
//! `rapidtriage.core.e01_native`: the same record, attribute, index, data-run and stream
//! semantics, including which malformed inputs fail and where reads come back short.

use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::lznt1;

pub type Res<T> = Result<T, String>;

/// Byte source of the whole media (pyewf handle, raw file, or a test buffer).
pub trait Media {
    /// Up to `len` bytes at `offset`; shorter only at the end of the media.
    fn read_at(&mut self, offset: u64, len: usize) -> Res<Vec<u8>>;
}

const META_BLOCK: u64 = 1 << 20;
const META_BLOCKS_KEPT: usize = 32;

/// `EwfSectorReader(handle, base, size)`: the partition as a zero-based stream.
pub struct Volume<M: Media> {
    media: M,
    base: u64,
    size: u64,
    blocks: HashMap<u64, Rc<Vec<u8>>>,
    order: Vec<u64>,
}

impl<M: Media> Volume<M> {
    pub fn new(media: M, base: u64, size: u64) -> Self {
        Volume {
            media,
            base,
            size,
            blocks: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub fn read(&mut self, offset: i128, len: i128) -> Res<Vec<u8>> {
        if offset < 0 {
            return Err("negative seek position".into());
        }
        if len <= 0 {
            return Ok(Vec::new());
        }
        let offset = offset as u64;
        if offset >= self.size {
            return Ok(Vec::new());
        }
        let want = (len as u128).min((self.size - offset) as u128) as usize;
        self.media.read_at(self.base + offset, want)
    }

    /// Same bytes as `read`, served from 1 MiB blocks; used for MFT records and index buffers.
    pub fn read_cached(&mut self, offset: i128, len: i128) -> Res<Vec<u8>> {
        if offset < 0 || len <= 0 || len as u64 > META_BLOCK {
            return self.read(offset, len);
        }
        let start = offset as u64;
        let block = start - start % META_BLOCK;
        if start + len as u64 > block + META_BLOCK {
            return self.read(offset, len);
        }
        let data = match self.blocks.get(&block) {
            Some(data) => data.clone(),
            None => match self.read(block as i128, META_BLOCK as i128) {
                Ok(bytes) => {
                    let data = Rc::new(bytes);
                    if self.order.len() >= META_BLOCKS_KEPT {
                        let old = self.order.remove(0);
                        self.blocks.remove(&old);
                    }
                    self.order.push(block);
                    self.blocks.insert(block, data.clone());
                    data
                }
                // A failing block (e.g. one corrupt EWF chunk) must not fail unrelated reads.
                Err(_) => return self.read(offset, len),
            },
        };
        let from = (start - block) as usize;
        let to = (from + len as usize).min(data.len());
        Ok(if from < to {
            data[from..to].to_vec()
        } else {
            Vec::new()
        })
    }
}

pub type Run = (Option<i128>, i128);

#[derive(Clone)]
enum Kind {
    Resident(Rc<Vec<u8>>),
    Runlist {
        runs: Vec<Run>,
        offsets: Vec<i128>,
    },
    Compressed {
        cu_blocks: Vec<Vec<Run>>,
        cu_size: i128,
    },
}

/// dissect.util `AlignedStream` subclasses: `RangeStream` (resident), `RunlistStream`,
/// `CompressedRunlistStream`. Reads are position-explicit; the result equals what the
/// Python stream returns for `seek(pos); read(n)`.
#[derive(Clone)]
pub struct Stream {
    kind: Kind,
    pub size: i128,
    align: i128,
    block_size: i128,
    metadata: bool,
}

fn bisect_right(values: &[i128], x: i128) -> usize {
    let (mut lo, mut hi) = (0usize, values.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        if x < values[mid] {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

impl Stream {
    fn resident(bytes: Vec<u8>, size: i128) -> Stream {
        Stream {
            kind: Kind::Resident(Rc::new(bytes)),
            size,
            align: 8192,
            block_size: 1,
            metadata: false,
        }
    }

    fn runlist(runs: Vec<Run>, size: i128, cluster: i128) -> Stream {
        let mut offsets = Vec::new();
        let mut offset: i128 = 0;
        for (_, count) in &runs {
            if offset != 0 {
                offsets.push(offset);
            }
            offset += count;
        }
        Stream {
            kind: Kind::Runlist { runs, offsets },
            size,
            align: cluster,
            block_size: cluster,
            metadata: false,
        }
    }

    fn compressed(runs: Vec<Run>, size: i128, cluster: i128, unit: u8) -> Stream {
        let per_cu: i128 = 1i128 << unit;
        let mut cu_blocks = Vec::new();
        let mut current_runs = Vec::new();
        let mut current = per_cu;
        for (lcn, count) in runs {
            let mut lcn = lcn;
            let mut count = count;
            while count > 0 {
                let used = count.min(current);
                current_runs.push((lcn, used));
                current -= used;
                count -= used;
                if let Some(value) = lcn.as_mut() {
                    *value += used;
                }
                if current == 0 {
                    cu_blocks.push(std::mem::take(&mut current_runs));
                    current = per_cu;
                }
            }
        }
        let cu_size = cluster << unit;
        Stream {
            kind: Kind::Compressed { cu_blocks, cu_size },
            size,
            align: cu_size,
            block_size: cluster,
            metadata: false,
        }
    }

    pub fn for_metadata(mut self) -> Stream {
        self.metadata = true;
        self
    }

    fn volume_read<M: Media>(&self, vol: &mut Volume<M>, offset: i128, len: i128) -> Res<Vec<u8>> {
        if self.metadata {
            vol.read_cached(offset, len)
        } else {
            vol.read(offset, len)
        }
    }

    /// The subclass `_read(offset, length)`.
    fn raw_read<M: Media>(&self, vol: &mut Volume<M>, offset: i128, length: i128) -> Res<Vec<u8>> {
        match &self.kind {
            Kind::Resident(bytes) => {
                let read_len = if self.size != 0 {
                    length.min(self.size - offset)
                } else {
                    length
                };
                if offset < 0 || read_len <= 0 || offset as usize >= bytes.len() {
                    return Ok(Vec::new());
                }
                let from = offset as usize;
                let to = (from as i128 + read_len).min(bytes.len() as i128) as usize;
                Ok(bytes[from..to].to_vec())
            }
            Kind::Runlist { runs, offsets } => {
                let bs = self.block_size;
                let mut out = Vec::new();
                let mut offset = offset;
                let mut length = length;
                let mut run_idx = bisect_right(offsets, offset.div_euclid(bs));
                while length > 0 {
                    if run_idx >= runs.len() {
                        break;
                    }
                    let run_block_pos = if run_idx == 0 {
                        0
                    } else {
                        offsets[run_idx - 1]
                    };
                    let (lcn, count) = runs[run_idx];
                    let run_size = count * bs;
                    let run_pos = offset - run_block_pos * bs;
                    let run_remaining = run_size - run_pos;
                    if run_remaining < 0 {
                        break;
                    }
                    let read_count = (self.size - offset).min(run_remaining.min(length));
                    match lcn {
                        None => {
                            if read_count > 0 {
                                out.resize(out.len() + read_count as usize, 0);
                            }
                        }
                        Some(lcn) => {
                            let start = lcn * bs + run_pos;
                            if start < 0 {
                                return Err("negative seek position".into());
                            }
                            if read_count < 0 {
                                return Err(
                                    "unbounded read past a run (negative read count)".into()
                                );
                            }
                            out.extend(self.volume_read(vol, start, read_count)?);
                        }
                    }
                    offset += read_count;
                    length -= read_count;
                    run_idx += 1;
                }
                Ok(out)
            }
            Kind::Compressed { cu_blocks, cu_size } => {
                let cu_size = *cu_size;
                let mut out = Vec::new();
                let mut cu_block = offset.div_euclid(cu_size);
                let cu_offset = cu_block * cu_size;
                let mut total_remaining = self.size - cu_offset;
                let mut length = length;
                while length > 0 {
                    let block = usize::try_from(cu_block)
                        .ok()
                        .and_then(|i| cu_blocks.get(i))
                        .ok_or_else(|| "compression unit index out of range".to_string())?;
                    let mut buf: Vec<Vec<u8>> = Vec::new();
                    let mut buf_len: i128 = 0;
                    let mut compressed = false;
                    for (lcn, run_count) in block {
                        let Some(lcn) = lcn else {
                            compressed = true;
                            continue;
                        };
                        let run_len = run_count * self.block_size;
                        let start = lcn * self.block_size;
                        if start < 0 {
                            return Err("negative seek position".into());
                        }
                        buf.push(self.volume_read(vol, start, run_len)?);
                        buf_len += run_len;
                        if buf_len == total_remaining {
                            break;
                        }
                    }
                    if buf.is_empty() {
                        out.resize(out.len() + cu_size as usize, 0);
                    } else if compressed {
                        let mut joined: Vec<u8> = buf.concat();
                        joined.extend_from_slice(&[0u8; 64]);
                        let mut data = lznt1::decompress(&joined)
                            .map_err(|_| "Decompression failed".to_string())?;
                        data.truncate(cu_size as usize);
                        out.extend(data);
                    } else {
                        out.extend(buf.concat());
                    }
                    length -= cu_size;
                    total_remaining -= cu_size;
                    cu_block += 1;
                }
                Ok(out)
            }
        }
    }

    /// `AlignedStream.read(n)` after `seek(pos)`.
    pub fn read<M: Media>(&self, vol: &mut Volume<M>, pos: i128, n: i128) -> Res<Vec<u8>> {
        let mut n = n.min(self.size - pos);
        if n <= 0 || self.size <= pos {
            return Ok(Vec::new());
        }
        let align = self.align;
        let mut pos = pos;
        let mut out = Vec::new();
        if pos % align != 0 {
            let pos_align = pos - pos.rem_euclid(align);
            let buf = self.raw_read(vol, pos_align, align)?;
            let buffer_pos = (pos - pos_align) as usize;
            let take = n.min(align - buffer_pos as i128);
            let end = (buffer_pos + take as usize).min(buf.len());
            if buffer_pos < end {
                out.extend_from_slice(&buf[buffer_pos..end]);
            }
            n -= take;
            pos += take;
        }
        if n >= align {
            let len = (n / align) * align;
            out.extend(self.raw_read(vol, pos, len)?);
            pos += len;
            n -= len;
        }
        if n > 0 {
            let buf = self.raw_read(vol, pos, align)?;
            let end = (n as usize).min(buf.len());
            out.extend_from_slice(&buf[..end]);
        }
        Ok(out)
    }
}

fn u16_at(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}
fn u32_at(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
}
fn u64_at(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

pub fn utf16_strict(bytes: &[u8]) -> Res<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err("utf-16-le: truncated data".into());
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16(&units).map_err(|_| "utf-16-le: invalid surrogate".to_string())
}

/// `util.apply_fixup`.
pub fn apply_fixup(raw: &[u8]) -> Res<Vec<u8>> {
    if raw.len() < 6 {
        return Err("fixup header truncated".into());
    }
    let mut data = raw.to_vec();
    let fixup_offset = u16_at(&data, 4) as usize;
    let count = data.len() >> 9;
    if fixup_offset & 1 != 0
        || fixup_offset + (count + 1) * 2 > 512
        || count == 0
        || count * 512 > data.len()
    {
        return Err(format!("Fixup offset out of range: {fixup_offset}"));
    }
    let sample = [data[fixup_offset], data[fixup_offset + 1]];
    for i in 0..count {
        let ptr = i * 512 + 510;
        if data[ptr..ptr + 2] != sample {
            return Err("Fixup mismatch".into());
        }
        let src = fixup_offset + 2 + i * 2;
        data[ptr] = data[src];
        data[ptr + 1] = data[src + 1];
    }
    Ok(data)
}

fn varint(buf: &[u8]) -> Res<i128> {
    let last = *buf.last().ok_or("varint of zero bytes")?;
    if buf.len() > 8 {
        return Err("varint longer than 8 bytes".into());
    }
    let mut padded = [if last & 0x80 != 0 { 0xFF } else { 0 }; 8];
    padded[..buf.len()].copy_from_slice(buf);
    Ok(i64::from_le_bytes(padded) as i128)
}

pub const FILE_NAME_DOS: u8 = 2;
const TAG_SYMLINK: u32 = 0xA000_000C;
const TAG_MOUNT_POINT: u32 = 0xA000_0003;

pub struct FileNameInfo {
    pub flags: u8,
    pub name: String,
    pub parent: u64,
    pub parent_sequence: u16,
}

/// `c_ntfs._FILE_NAME(data.ljust(0x48))`.
pub fn parse_file_name(value: &[u8]) -> Res<FileNameInfo> {
    let mut data = value.to_vec();
    if data.len() < 0x48 {
        data.resize(0x48, 0);
    }
    let length = data[0x40] as usize;
    let end = 0x42 + length * 2;
    if end > data.len() {
        return Err("EOF in FILE_NAME".into());
    }
    Ok(FileNameInfo {
        flags: data[0x41],
        name: utf16_strict(&data[0x42..end])?,
        parent: u32_at(&data, 0) as u64 | ((u16_at(&data, 4) as u64) << 32),
        parent_sequence: u16_at(&data, 6),
    })
}

pub struct ReparseInfo {
    pub tag: u32,
    flags: Option<u32>,
    print_name: Option<Vec<u8>>,
}

fn parse_reparse(value: &[u8]) -> Res<ReparseInfo> {
    if value.len() < 8 {
        return Err("EOF in REPARSE_DATA_BUFFER".into());
    }
    let tag = u32_at(value, 0);
    let data_len = u16_at(value, 4) as usize;
    let data = &value[8..(8 + data_len).min(value.len())];
    let header_len = match tag {
        TAG_SYMLINK => 12,
        TAG_MOUNT_POINT => 8,
        _ => {
            return Ok(ReparseInfo {
                tag,
                flags: None,
                print_name: None,
            })
        }
    };
    if data.len() < header_len {
        return Err("EOF in reparse tag header".into());
    }
    let buffer = &data[header_len..];
    let offset = u16_at(data, 4) as usize;
    let length = u16_at(data, 6) as usize;
    let from = offset.min(buffer.len());
    let to = (offset + length).min(buffer.len());
    Ok(ReparseInfo {
        tag,
        flags: (tag == TAG_SYMLINK).then(|| u32_at(data, 8)),
        print_name: Some(buffer[from..to].to_vec()),
    })
}

/// `_ATTRIBUTE_LIST_ENTRY` segment references, in list order.
fn parse_attribute_list(value: &[u8]) -> Res<Vec<u64>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    loop {
        if offset + 0x1A > value.len() {
            break;
        }
        let record_length = u16_at(value, offset + 4) as usize;
        let name_len = value[offset + 6] as usize;
        let name_end = offset + 0x1A + name_len * 2;
        if name_end > value.len() {
            break;
        }
        utf16_strict(&value[offset + 0x1A..name_end])?;
        if record_length == 0 {
            break;
        }
        out.push(
            u32_at(value, offset + 0x10) as u64 | ((u16_at(value, offset + 0x14) as u64) << 32),
        );
        offset += record_length;
    }
    Ok(out)
}

pub enum Parsed {
    Other,
    FileName(FileNameInfo),
    Reparse(ReparseInfo),
    AttrList(Vec<u64>),
}

pub struct Attr {
    data: Rc<Vec<u8>>,
    offset: usize,
    pub type_code: u32,
    pub resident: bool,
    pub flags: u16,
    name_length: usize,
    name_offset: usize,
    value_length: i128,
    value_offset: usize,
    pub lowest_vcn: u64,
    mapping_offset: usize,
    compression_unit: u8,
    allocated: i128,
    file_size: i128,
    pub parsed: Parsed,
}

impl Attr {
    pub fn name(&self) -> Res<String> {
        let from = (self.offset + self.name_offset).min(self.data.len());
        let to = (from + self.name_length * 2).min(self.data.len());
        utf16_strict(&self.data[from..to])
    }

    fn resident_bytes(&self) -> Vec<u8> {
        let from = self.offset + self.value_offset;
        if from >= self.data.len() || self.value_length <= 0 {
            return Vec::new();
        }
        let to = (from as i128 + self.value_length).min(self.data.len() as i128) as usize;
        self.data[from..to].to_vec()
    }

    pub fn size(&self) -> i128 {
        if self.resident {
            self.value_length
        } else {
            self.file_size
        }
    }

    /// `AttributeHeader.dataruns()`.
    pub fn dataruns(&self) -> Res<Vec<Run>> {
        if self.resident {
            return Err("Resident attributes don't have dataruns".into());
        }
        let data = &self.data;
        let mut pos = self.offset + self.mapping_offset;
        let mut runs = Vec::new();
        let mut current: i128 = 0;
        loop {
            let value = *data.get(pos).ok_or("datarun header past record end")?;
            pos += 1;
            if value == 0 {
                break;
            }
            let size_len = (value & 0xF) as usize;
            let offset_len = (value >> 4) as usize;
            let size_bytes = &data[pos.min(data.len())..(pos + size_len).min(data.len())];
            pos += size_bytes.len();
            let run_size = varint(size_bytes)?;
            if offset_len == 0 {
                runs.push((None, run_size));
            } else {
                let offset_bytes = &data[pos.min(data.len())..(pos + offset_len).min(data.len())];
                pos += offset_bytes.len();
                current += varint(offset_bytes)?;
                runs.push((Some(current), run_size));
            }
        }
        Ok(runs)
    }

    /// `AttributeHeader.open()` for this single attribute.
    fn open_single<M: Media>(&self, ntfs: &Ntfs<M>) -> Res<Stream> {
        if self.resident {
            return Ok(Stream::resident(self.resident_bytes(), self.value_length));
        }
        Ok(Stream::runlist(
            self.dataruns()?,
            self.file_size,
            ntfs.cluster_size,
        ))
    }
}

/// `AttributeMap`: attribute collections per type, in first-seen type order.
#[derive(Default)]
pub struct AttrMap {
    pub groups: Vec<(u32, Vec<Rc<Attr>>)>,
}

impl AttrMap {
    fn add(&mut self, attr: Rc<Attr>) {
        if let Some((_, group)) = self.groups.iter_mut().find(|(t, _)| *t == attr.type_code) {
            group.push(attr);
        } else {
            self.groups.push((attr.type_code, vec![attr]));
        }
    }

    pub fn get(&self, type_code: u32) -> &[Rc<Attr>] {
        self.groups
            .iter()
            .find(|(t, _)| *t == type_code)
            .map(|(_, g)| g.as_slice())
            .unwrap_or(&[])
    }

    /// `AttributeMap.find(name, type)`: case-insensitive name match.
    pub fn find(&self, name: &str, type_code: u32) -> Res<Vec<Rc<Attr>>> {
        let wanted = name.to_lowercase();
        let mut out = Vec::new();
        for attr in self.get(type_code) {
            if attr.name()?.to_lowercase() == wanted {
                out.push(attr.clone());
            }
        }
        Ok(out)
    }
}

/// `AttributeCollection.size()` / `.open()` over the attributes `find` returned.
pub fn collection_size(attrs: &[Rc<Attr>]) -> Res<i128> {
    let first = attrs.first().ok_or("No such stream")?;
    if first.resident {
        return Ok(first.value_length);
    }
    let sorted = sorted_nonresident(attrs);
    Ok(sorted[0].file_size)
}

fn sorted_nonresident(attrs: &[Rc<Attr>]) -> Vec<Rc<Attr>> {
    let mut sorted: Vec<Rc<Attr>> = attrs.iter().filter(|a| !a.resident).cloned().collect();
    sorted.sort_by_key(|a| a.lowest_vcn);
    sorted
}

pub fn collection_open<M: Media>(ntfs: &Ntfs<M>, attrs: &[Rc<Attr>]) -> Res<Stream> {
    let first = attrs.first().ok_or("No such stream")?;
    if first.resident {
        return Ok(Stream::resident(first.resident_bytes(), first.value_length));
    }
    let sorted = sorted_nonresident(attrs);
    let mut runs = Vec::new();
    for attr in &sorted {
        runs.extend(attr.dataruns()?);
    }
    let lead = &sorted[0];
    if lead.flags & 0x00FF != 0 {
        if lead.compression_unit > 32 {
            return Err("compression unit out of range".into());
        }
        return Ok(Stream::compressed(
            runs,
            lead.file_size,
            ntfs.cluster_size,
            lead.compression_unit,
        ));
    }
    let _ = lead.allocated;
    Ok(Stream::runlist(runs, lead.file_size, ntfs.cluster_size))
}

pub struct Record {
    pub segment: u64,
    data: Rc<Vec<u8>>,
    pub flags: u16,
    pub sequence: u16,
    first_attribute: usize,
    attributes: OnceCell<Rc<AttrMap>>,
}

impl Record {
    pub fn is_dir(&self) -> bool {
        self.flags & 0x0002 != 0
    }
}

/// `MftRecord.from_bytes`.
pub fn parse_record(raw: &[u8], segment: u64) -> Res<Record> {
    if raw.len() < 4 || &raw[..4] != b"FILE" {
        return Err("Invalid MFT record Signature".into());
    }
    let data = apply_fixup(raw)?;
    Ok(Record {
        segment,
        flags: u16_at(&data, 0x16),
        sequence: u16_at(&data, 0x10),
        first_attribute: u16_at(&data, 0x14) as usize,
        data: Rc::new(data),
        attributes: OnceCell::new(),
    })
}

pub struct Ntfs<M: Media> {
    pub vol: RefCell<Volume<M>>,
    pub cluster_size: i128,
    cluster_shift: u32,
    pub record_size: i128,
    pub mft: Stream,
}

fn bsf(value: i128) -> u32 {
    if value == 0 {
        0
    } else {
        value.trailing_zeros()
    }
}

pub struct IndexEntry {
    pub file_reference: u64,
    pub length: u16,
    pub key_length: u16,
    pub flags: u16,
    pub buf: Vec<u8>,
}

impl IndexEntry {
    pub fn is_end(&self) -> bool {
        self.flags & 2 != 0 || self.length == 0
    }
    pub fn is_node(&self) -> bool {
        self.flags & 1 != 0
    }
    fn node_vcn(&self) -> Res<i128> {
        if self.buf.len() < 8 {
            return Err("EOF reading node VCN".into());
        }
        Ok(u64_at(&self.buf, self.buf.len() - 8) as i128)
    }
    pub fn segment(&self) -> u64 {
        self.file_reference & 0xFFFF_FFFF_FFFF
    }
}

/// `Index(record, "$I30")`.
pub struct Index {
    root: Stream,
    root_total: i128,
    attribute_type: u32,
    collation: u32,
    buffer_size: i128,
    vcn_shift: u32,
    allocation: Option<Stream>,
}

enum BufferError {
    Eof,
    Broken,
    Fatal(String),
}

enum EntrySource<'a> {
    Root,
    Buffer(&'a [u8]),
}

impl<M: Media> Ntfs<M> {
    /// `NTFS(fh)`: boot sector, then the `$MFT` stream from record 0 (plus attribute-list runs).
    pub fn open(volume: Volume<M>) -> Res<Ntfs<M>> {
        let vol = RefCell::new(volume);
        let boot = vol.borrow_mut().read(0, 512)?;
        if boot.len() < 512 {
            return Err("EOF reading boot sector".into());
        }
        if &boot[3..11] != b"NTFS    " {
            return Err("Invalid NTFS magic".into());
        }
        let sector_size = u16_at(&boot, 0x0B) as i128;
        let spc_raw = boot[0x0D] as i8;
        let spc: i128 = if (spc_raw as u8) > 0x80 {
            shifted(-(spc_raw as i32))?
        } else {
            (spc_raw as u8) as i128
        };
        let cluster_size = spc * sector_size;
        if cluster_size <= 0 {
            return Err("cluster size is zero".into());
        }
        let cpr = boot[0x40] as i8;
        let record_size = if cpr < 0 {
            shifted(-(cpr as i32))?
        } else {
            cpr as i128 * cluster_size
        };
        let mft_lcn = u64_at(&boot, 0x30) as i128;
        let mut ntfs = Ntfs {
            vol,
            cluster_size,
            cluster_shift: bsf(cluster_size),
            record_size,
            mft: Stream::resident(Vec::new(), 0),
        };
        let raw = ntfs
            .vol
            .borrow_mut()
            .read(mft_lcn * cluster_size, record_size)?;
        let record0 = parse_record(&raw, 0)?;
        let base_attrs = ntfs.parse_attributes(&record0, false)?;
        let data = base_attrs.find("", 0x80)?;
        if data.is_empty() {
            return Err("No such stream on $MFT".into());
        }
        ntfs.mft = collection_open(&ntfs, &data)?.for_metadata();
        if let Some(list) = base_attrs.get(0x20).first() {
            if let Parsed::AttrList(segments) = &list.parsed {
                let mut seen = HashSet::from([0u64]);
                for segment in segments.clone() {
                    if segment == 0 || !seen.insert(segment) {
                        continue;
                    }
                    let record = ntfs.mft_record(segment)?;
                    let attrs = ntfs.attributes(&record)?;
                    let mut extra = Vec::new();
                    for (_, group) in &attrs.groups {
                        for attr in group {
                            if attr.type_code == 0x80 {
                                extra.extend(attr.dataruns()?);
                            }
                        }
                    }
                    if let Kind::Runlist { runs, .. } = &ntfs.mft.kind {
                        let mut all = runs.clone();
                        all.extend(extra);
                        ntfs.mft = Stream::runlist(all, ntfs.mft.size, cluster_size).for_metadata();
                    }
                }
            }
        }
        Ok(ntfs)
    }

    pub fn mft_size(&self) -> i128 {
        self.mft.size
    }

    /// `Mft.get(segment)`.
    pub fn mft_record(&self, segment: u64) -> Res<Record> {
        let raw = self.mft.read(
            &mut self.vol.borrow_mut(),
            segment as i128 * self.record_size,
            self.record_size,
        )?;
        parse_record(&raw, segment)
    }

    pub fn attributes(&self, record: &Record) -> Res<Rc<AttrMap>> {
        if let Some(map) = record.attributes.get() {
            return Ok(map.clone());
        }
        let map = Rc::new(self.parse_attributes(record, true)?);
        let _ = record.attributes.set(map.clone());
        Ok(map)
    }

    fn parse_attributes(&self, record: &Record, expand_list: bool) -> Res<AttrMap> {
        self.parse_attributes_depth(record, expand_list, 0)
    }

    fn parse_attributes_depth(
        &self,
        record: &Record,
        expand_list: bool,
        depth: u32,
    ) -> Res<AttrMap> {
        if depth > 32 {
            return Err("attribute list recursion".into());
        }
        let data = &record.data;
        let mut map = AttrMap::default();
        let mut offset = record.first_attribute;
        let mut list_segments: Option<Vec<u64>> = None;
        loop {
            if offset + 0x48 > data.len() {
                break;
            }
            let type_code = u32_at(data, offset);
            if type_code == 0xFFFF_FFFF {
                break;
            }
            let record_length = u32_at(data, offset + 4) as usize;
            if record_length == 0 {
                return Err("Attribute RecordLength is 0 but end not yet reached".into());
            }
            let resident = data[offset + 8] == 0;
            let mut attr = Attr {
                data: data.clone(),
                offset,
                type_code,
                resident,
                flags: u16_at(data, offset + 0x0C),
                name_length: data[offset + 9] as usize,
                name_offset: u16_at(data, offset + 0x0A) as usize,
                value_length: u32_at(data, offset + 0x10) as i128,
                value_offset: u16_at(data, offset + 0x14) as usize,
                lowest_vcn: u64_at(data, offset + 0x10),
                mapping_offset: u16_at(data, offset + 0x20) as usize,
                compression_unit: data[offset + 0x22],
                allocated: u64_at(data, offset + 0x28) as i64 as i128,
                file_size: u64_at(data, offset + 0x30) as i64 as i128,
                parsed: Parsed::Other,
            };
            if matches!(type_code, 0x10 | 0x20 | 0x30 | 0xC0) {
                let stream = attr.open_single(self)?;
                let value = stream.read(&mut self.vol.borrow_mut(), 0, stream.size.max(0))?;
                attr.parsed = match type_code {
                    0x20 => Parsed::AttrList(parse_attribute_list(&value)?),
                    0x30 => Parsed::FileName(parse_file_name(&value)?),
                    0xC0 => Parsed::Reparse(parse_reparse(&value)?),
                    _ => Parsed::Other,
                };
            }
            if let Parsed::AttrList(segments) = &attr.parsed {
                list_segments = Some(segments.clone());
            }
            map.add(Rc::new(attr));
            offset += record_length;
        }
        if let (true, Some(segments)) = (expand_list, list_segments) {
            let mut seen = HashSet::from([record.segment]);
            for segment in segments {
                if segment == 0 || !seen.insert(segment) {
                    continue;
                }
                let ext = self.mft_record(segment)?;
                let ext_attrs = self.parse_attributes_depth(&ext, true, depth + 1)?;
                for (_, group) in ext_attrs.groups {
                    for attr in group {
                        map.add(attr);
                    }
                }
            }
        }
        Ok(map)
    }

    /// `MftRecord.filenames()[0]`: names sorted (stably) by namespace flags.
    pub fn filename(&self, record: &Record) -> Res<Option<String>> {
        let attrs = self.attributes(record)?;
        let mut names: Vec<(u8, String)> = Vec::new();
        for attr in attrs.get(0x30) {
            match &attr.parsed {
                Parsed::FileName(info) => names.push((info.flags, info.name.clone())),
                _ => return Err("FILE_NAME attribute without a parsed value".into()),
            }
        }
        names.sort_by_key(|(flags, _)| *flags);
        Ok(names.into_iter().next().map(|(_, name)| name))
    }

    pub fn data_size(&self, record: &Record) -> Res<i128> {
        let attrs = self.attributes(record)?.find("", 0x80)?;
        collection_size(&attrs)
    }

    pub fn data_stream(&self, record: &Record) -> Res<Stream> {
        let attrs = self.attributes(record)?.find("", 0x80)?;
        collection_open(self, &attrs)
    }

    fn reparse(&self, record: &Record) -> Res<Option<Rc<Attr>>> {
        let attrs = self.attributes(record)?;
        Ok(attrs.get(0xC0).first().cloned())
    }

    fn reparse_tag(&self, record: &Record) -> Res<Option<u32>> {
        match self.reparse(record)? {
            None => Ok(None),
            Some(attr) => match &attr.parsed {
                Parsed::Reparse(info) => Ok(Some(info.tag)),
                _ => Err("reparse attribute without a parsed value".into()),
            },
        }
    }

    /// `MftRecord.reparse_point_record`.
    fn reparse_target(&self, record: &Record) -> Res<Record> {
        let attr = self.reparse(record)?.ok_or("not a reparse point")?;
        let Parsed::Reparse(info) = &attr.parsed else {
            return Err("reparse attribute without a parsed value".into());
        };
        let mut target = match &info.print_name {
            Some(bytes) => utf16_strict(bytes)?,
            None => return Err("no reparse target".into()),
        };
        if info.tag == TAG_SYMLINK && info.flags == Some(1) {
            let full = self
                .full_path(record)?
                .ok_or("no file name for relative reparse point")?;
            target = ntpath_join(&ntpath_dirname(&full), &target);
        }
        if target.is_empty() {
            return Err("no valid reparse target".into());
        }
        let root = self.mft_record(5)?;
        self.get_path(&root, &target)
    }

    /// `MftRecord.full_path()`.
    fn full_path(&self, record: &Record) -> Res<Option<String>> {
        let attrs = self.attributes(record)?;
        let mut paths: Vec<(u8, String)> = Vec::new();
        for attr in attrs.get(0x30) {
            let Parsed::FileName(info) = &attr.parsed else {
                return Err("FILE_NAME attribute without a parsed value".into());
            };
            paths.push((
                info.flags,
                self.get_full_path(&info.name, info.parent, info.parent_sequence),
            ));
        }
        paths.sort_by_key(|(flags, _)| *flags);
        Ok(paths.into_iter().next().map(|(_, p)| p))
    }

    /// `util.get_full_path`.
    fn get_full_path(&self, name: &str, parent: u64, parent_sequence: u16) -> String {
        let mut path = vec![name.to_string()];
        let mut seen = HashSet::new();
        let (mut parent, mut parent_sequence) = (parent, parent_sequence);
        loop {
            if parent == 5 {
                break;
            }
            if !seen.insert(parent) {
                path.push("<recursion>".into());
                break;
            }
            let step = (|| -> Res<Option<(String, u64, u16)>> {
                let record = self.mft_record(parent)?;
                let Some(filename) = self.filename(&record)?.filter(|n| !n.is_empty()) else {
                    return Err("No filename".into());
                };
                if record.sequence != parent_sequence {
                    return Ok(None);
                }
                let attrs = self.attributes(&record)?;
                let Some(Parsed::FileName(first)) = attrs.get(0x30).first().map(|a| &a.parsed)
                else {
                    return Err("No filename".into());
                };
                Ok(Some((filename, first.parent, first.parent_sequence)))
            })();
            match step {
                Ok(Some((filename, next, next_sequence))) => {
                    path.push(filename);
                    parent = next;
                    parent_sequence = next_sequence;
                }
                Ok(None) => {
                    path.push(format!("<broken_reference_0x{parent:x}#{parent_sequence}>"));
                    break;
                }
                Err(_) => {
                    path.push(format!("<unknown_segment_0x{parent:x}>"));
                    break;
                }
            }
        }
        path.reverse();
        path.join("\\")
    }

    pub fn open_index(&self, record: &Record) -> Res<Index> {
        let attrs = self.attributes(record)?;
        let root_attrs = attrs.find("$I30", 0x90)?;
        if root_attrs.is_empty() {
            return Err("No such stream ($I30 INDEX_ROOT)".into());
        }
        let root = collection_open(self, &root_attrs)?;
        let header = root.read(&mut self.vol.borrow_mut(), 0, 0x20)?;
        if header.len() < 0x20 {
            return Err("EOF reading INDEX_ROOT".into());
        }
        let buffer_size = u32_at(&header, 8) as i128;
        let vcn_shift = if self.cluster_size <= buffer_size {
            self.cluster_shift
        } else {
            9
        };
        let alloc_attrs = attrs.find("$I30", 0xA0)?;
        let allocation = if alloc_attrs.is_empty() {
            None
        } else {
            Some(collection_open(self, &alloc_attrs)?.for_metadata())
        };
        Ok(Index {
            root,
            root_total: u32_at(&header, 0x14) as i128,
            attribute_type: u32_at(&header, 0),
            collation: u32_at(&header, 4),
            buffer_size,
            vcn_shift,
            allocation,
        })
    }

    /// `_iter_entries`, keeping the end entry.
    fn iter_entries(
        &self,
        index: &Index,
        source: EntrySource,
        start: i128,
        size: i128,
    ) -> Res<Vec<IndexEntry>> {
        let mut out = Vec::new();
        let max_offset = start + size;
        let mut offset = start;
        while offset < max_offset {
            let header = match source {
                EntrySource::Root => index.root.read(&mut self.vol.borrow_mut(), offset, 0x10)?,
                EntrySource::Buffer(data) => slice_from(data, offset, 0x10),
            };
            if header.len() < 0x10 {
                break;
            }
            let length = u16_at(&header, 8);
            let rest = length as i128 - 0x10;
            let buf = match source {
                EntrySource::Root => {
                    if rest < -1 {
                        return Err("invalid number of bytes to read".into());
                    }
                    let n = if rest == -1 {
                        index.root.size - (offset + 0x10)
                    } else {
                        rest
                    };
                    index
                        .root
                        .read(&mut self.vol.borrow_mut(), offset + 0x10, n)?
                }
                EntrySource::Buffer(data) => {
                    let n = if rest < 0 { data.len() as i128 } else { rest };
                    slice_from(data, offset + 0x10, n)
                }
            };
            let entry = IndexEntry {
                file_reference: u64_at(&header, 0),
                length,
                key_length: u16_at(&header, 10),
                flags: u16_at(&header, 12),
                buf,
            };
            let end = entry.is_end();
            offset += entry.length as i128;
            out.push(entry);
            if end {
                break;
            }
        }
        Ok(out)
    }

    fn root_entries(&self, index: &Index) -> Res<Vec<IndexEntry>> {
        self.iter_entries(index, EntrySource::Root, 0x20, index.root_total)
    }

    fn index_buffer(&self, index: &Index, vcn: i128) -> Result<Vec<IndexEntry>, BufferError> {
        let stream = index
            .allocation
            .as_ref()
            .ok_or(BufferError::Fatal("Index has no index allocation".into()))?;
        if index.buffer_size == 0 {
            return Err(BufferError::Fatal("zero-sized index buffers".into()));
        }
        let buf = stream
            .read(
                &mut self.vol.borrow_mut(),
                vcn << index.vcn_shift,
                index.buffer_size,
            )
            .map_err(BufferError::Fatal)?;
        if buf.len() as i128 != index.buffer_size {
            return Err(BufferError::Eof);
        }
        if &buf[..4] != b"INDX" {
            return Err(BufferError::Broken);
        }
        let data = apply_fixup(&buf).map_err(BufferError::Fatal)?;
        if data.len() < 0x28 {
            return Err(BufferError::Eof);
        }
        let first = u32_at(&data, 0x18) as i128;
        let total = u32_at(&data, 0x1C) as i128;
        self.iter_entries(index, EntrySource::Buffer(&data), first + 0x18, total)
            .map_err(BufferError::Fatal)
    }

    /// `Index.entries()`: root entries, then INDX buffers by VCN until one is short.
    pub fn index_entries(&self, index: &Index) -> Res<Vec<IndexEntry>> {
        let mut out: Vec<IndexEntry> = Vec::new();
        for entry in self.root_entries(index)? {
            if entry.is_end() {
                break;
            }
            out.push(entry);
        }
        if index.allocation.is_some() {
            let mut vcn = 0;
            loop {
                match self.index_buffer(index, vcn) {
                    Ok(entries) => {
                        for entry in entries {
                            if entry.is_end() {
                                break;
                            }
                            out.push(entry);
                        }
                    }
                    Err(BufferError::Broken) => {}
                    Err(BufferError::Eof) => break,
                    Err(BufferError::Fatal(message)) => return Err(message),
                }
                vcn += 1;
            }
        }
        Ok(out)
    }

    /// `MftRecord.listdir(ignore_dos)` keys, in dict insertion order.
    pub fn listdir(&self, record: &Record, ignore_dos: bool) -> Res<Vec<String>> {
        if !record.is_dir() {
            return Err("not a directory".into());
        }
        let index = self.open_index(record)?;
        let mut names = Vec::new();
        let mut seen = HashSet::new();
        for entry in self.index_entries(&index)? {
            if entry.key_length == 0 || index.attribute_type == 0 {
                return Err("index entry without attribute".into());
            }
            if index.attribute_type != 0x30 {
                return Err("index entry attribute is not a FILE_NAME".into());
            }
            let info = parse_file_name(&entry.buf)?;
            if ignore_dos && info.flags == FILE_NAME_DOS {
                continue;
            }
            if seen.insert(info.name.clone()) {
                names.push(info.name);
            }
        }
        Ok(names)
    }

    /// `Index.search(value)` with the `_cmp_filename` collation.
    fn search(&self, index: &Index, value: &str) -> Res<IndexEntry> {
        if index.collation != 1 {
            return Err(format!(
                "No collation function for collation rule: {}",
                index.collation
            ));
        }
        let wanted = value.to_uppercase();
        let mut entries = self.root_entries(index)?;
        let mut levels = 0;
        loop {
            let position = bsearch(&entries, &wanted)?;
            let entry = &entries[position];
            if !entry.is_node()
                || (!entry.is_end() && cmp_filename(entry, &wanted)? == std::cmp::Ordering::Equal)
            {
                break;
            }
            levels += 1;
            if levels > 64 {
                return Err("index search does not terminate".into());
            }
            let vcn = entry.node_vcn()?;
            entries = match self.index_buffer(index, vcn) {
                Ok(entries) => entries,
                Err(BufferError::Eof) => return Err("EOF reading index buffer".into()),
                Err(BufferError::Broken) => return Err("Broken INDX header".into()),
                Err(BufferError::Fatal(message)) => return Err(message),
            };
        }
        let position = bsearch(&entries, &wanted)?;
        let entry = entries.swap_remove(position);
        if entry.is_end() || cmp_filename(&entry, &wanted)? != std::cmp::Ordering::Equal {
            return Err(format!("Value not found: {value}"));
        }
        Ok(entry)
    }

    /// `Mft._get_path(path, root)`.
    pub fn get_path(&self, root: &Record, path: &str) -> Res<Record> {
        let search_path = path.replace('/', "\\");
        let mut node: Option<Record> = None;
        for part in search_path.split('\\') {
            if part.is_empty() {
                continue;
            }
            let mut hops = 0;
            loop {
                let current = node.as_ref().unwrap_or(root);
                match self.reparse_tag(current)? {
                    Some(TAG_SYMLINK) | Some(TAG_MOUNT_POINT) => {
                        hops += 1;
                        if hops > 64 {
                            return Err("reparse point loop".into());
                        }
                        node = Some(self.reparse_target(current)?);
                    }
                    _ => break,
                }
            }
            let current = node.as_ref().unwrap_or(root);
            if !current.is_dir() {
                return Err(format!("Error finding path {path}: not a directory"));
            }
            let index = self.open_index(current)?;
            let entry = self.search(&index, part)?;
            node = Some(self.mft_record(entry.segment())?);
        }
        match node {
            Some(record) => Ok(record),
            None => self.mft_record(root.segment),
        }
    }
}

fn shifted(shift: i32) -> Res<i128> {
    if !(0..63).contains(&shift) {
        return Err(format!("size shift out of range: {shift}"));
    }
    Ok(1i128 << shift)
}

fn slice_from(data: &[u8], offset: i128, len: i128) -> Vec<u8> {
    if offset < 0 || offset as usize >= data.len() || len <= 0 {
        return Vec::new();
    }
    let from = offset as usize;
    let to = (offset + len).min(data.len() as i128) as usize;
    data[from..to].to_vec()
}

/// `_cmp_filename(entry, value)`: Less when `value` sorts before the entry name.
fn cmp_filename(entry: &IndexEntry, value: &str) -> Res<std::cmp::Ordering> {
    let length = *entry.buf.get(64).ok_or("index entry key too short")? as usize;
    let from = 66.min(entry.buf.len());
    let to = (66 + length * 2).min(entry.buf.len());
    let test = utf16_strict(&entry.buf[from..to])?.to_uppercase();
    Ok(value.cmp(test.as_str()))
}

/// `_bsearch`: index of the matching entry or of the first entry above `value`.
fn bsearch(entries: &[IndexEntry], value: &str) -> Res<usize> {
    if entries.is_empty() {
        return Err("search in an empty index node".into());
    }
    let (mut min, mut max) = (0usize, entries.len() - 1);
    while min != max {
        let test = min + (max - min) / 2;
        let entry = &entries[test];
        let result = cmp_filename(entry, value)?;
        if !entry.is_end() && result == std::cmp::Ordering::Greater {
            min = test + 1;
        } else if result == std::cmp::Ordering::Equal {
            return Ok(test);
        } else {
            max = test;
        }
    }
    Ok(min)
}

fn ntpath_split(path: &str) -> (String, String) {
    let (drive, rest) = if path.len() >= 2 && path.as_bytes()[1] == b':' {
        path.split_at(2)
    } else {
        ("", path)
    };
    let cut = rest.rfind(['\\', '/']).map(|i| i + 1).unwrap_or(0);
    let (head, tail) = rest.split_at(cut);
    let trimmed = head.trim_end_matches(['\\', '/']);
    let head = if trimmed.is_empty() { head } else { trimmed };
    (format!("{drive}{head}"), tail.to_string())
}

fn ntpath_dirname(path: &str) -> String {
    ntpath_split(path).0
}

fn ntpath_join(base: &str, target: &str) -> String {
    let absolute =
        target.starts_with(['\\', '/']) || (target.len() >= 2 && target.as_bytes()[1] == b':');
    if absolute || base.is_empty() {
        return target.to_string();
    }
    if base.ends_with(['\\', '/']) {
        format!("{base}{target}")
    } else {
        format!("{base}\\{target}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Mem(Vec<u8>);
    impl Media for Mem {
        fn read_at(&mut self, offset: u64, len: usize) -> Res<Vec<u8>> {
            let from = (offset as usize).min(self.0.len());
            let to = (from + len).min(self.0.len());
            Ok(self.0[from..to].to_vec())
        }
    }

    fn volume(bytes: Vec<u8>) -> Volume<Mem> {
        let size = bytes.len() as u64;
        Volume::new(Mem(bytes), 0, size)
    }

    #[test]
    fn runlist_read_skips_short_runs_like_dissect() {
        let mut vol = volume((0..16u8).flat_map(|b| vec![b; 4]).collect());
        // run 1: cluster 1; run 2: far past the volume (reads come back empty); run 3: cluster 3
        let stream = Stream::runlist(vec![(Some(1), 1), (Some(1000), 1), (Some(3), 1)], 12, 4);
        assert_eq!(
            stream.read(&mut vol, 0, 12).unwrap(),
            vec![1, 1, 1, 1, 3, 3, 3, 3]
        );
        let sparse = Stream::runlist(vec![(Some(2), 1), (None, 1)], 6, 4);
        assert_eq!(
            sparse.read(&mut vol, 0, 100).unwrap(),
            vec![2, 2, 2, 2, 0, 0]
        );
        assert_eq!(sparse.read(&mut vol, 3, 2).unwrap(), vec![2, 0]);
    }

    #[test]
    fn cached_reads_match_direct_reads() {
        let bytes: Vec<u8> = (0..(3 << 20)).map(|i| (i % 251) as u8).collect();
        let mut vol = volume(bytes);
        for (offset, len) in [
            (0i128, 10i128),
            ((1 << 20) - 3, 6),
            (5000, 1 << 20),
            ((3 << 20) - 2, 10),
        ] {
            assert_eq!(
                vol.read_cached(offset, len).unwrap(),
                vol.read(offset, len).unwrap()
            );
        }
    }

    #[test]
    fn dataruns_decode_negative_deltas_and_sparse() {
        let mut data = vec![0u8; 0x48];
        data[0x20] = 0x40;
        data.extend_from_slice(&[0x21, 4, 0x00, 0x01, 0x11, 2, 0xF0, 0x01, 5, 0x00]);
        let attr = Attr {
            data: Rc::new(data),
            offset: 0,
            type_code: 0x80,
            resident: false,
            flags: 0,
            name_length: 0,
            name_offset: 0,
            value_length: 0,
            value_offset: 0,
            lowest_vcn: 0,
            mapping_offset: 0x48,
            compression_unit: 0,
            allocated: 0,
            file_size: 0,
            parsed: Parsed::Other,
        };
        assert_eq!(
            attr.dataruns().unwrap(),
            vec![(Some(256), 4), (Some(240), 2), (None, 5)]
        );
    }

    #[test]
    fn ntpath_helpers() {
        assert_eq!(ntpath_dirname("a\\b\\c"), "a\\b");
        assert_eq!(ntpath_join("a\\b", "x"), "a\\b\\x");
        assert_eq!(ntpath_join("a", "C:\\x"), "C:\\x");
    }
}
