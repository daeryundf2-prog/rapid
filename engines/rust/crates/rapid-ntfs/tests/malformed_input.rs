//! Malformed-input robustness: structured random $MFT / $UsnJrnl blobs (synthetic,
//! seeded) must never panic -- debug builds also trap integer overflow -- and every
//! output cap of the Python reference must hold.

use rapid_ntfs::mft::{parse_mft_record_headers, MFT_RECORD_SCAN_LIMIT};
use rapid_ntfs::usn::parse_usn_record_scan;
use rapid_ntfs::value::Value;

/// xorshift64*: deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }

    fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.next() as u8).collect()
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

fn put(blob: &mut [u8], offset: usize, value: u64, size: usize) {
    if offset + size <= blob.len() {
        blob[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
    }
}

fn attribute(rng: &mut Rng) -> Vec<u8> {
    let wild = rng.next() as u32;
    let attribute_type = rng.pick(&[0x10, 0x20, 0x30, 0x80, 0x80, 0x90, 0x100, 0xFFFF_FFFF, wild]);
    let nonresident = rng.chance(30);
    let body = rng.below(160);
    let length = (24 + body + 7) & !7;
    let mut blob = rng.bytes(length.max(72));
    put(&mut blob, 0, u64::from(attribute_type), 4);
    let wild = rng.next() as u32 as usize;
    let declared = rng.pick(&[length, length, length, 0, 8, 23, length + 8, wild]);
    put(&mut blob, 4, declared as u64, 4);
    blob[8] = u8::from(nonresident);
    blob[9] = rng.pick(&[0, 0, 1, 4, 255]);
    put(&mut blob, 10, rng.pick(&[24, 64, 0, 0xFFFF]) as u64, 2);
    if nonresident {
        put(&mut blob, 32, rng.pick(&[64, 72, 0, 500, 0xFFFF]) as u64, 2);
    } else {
        put(
            &mut blob,
            16,
            rng.pick(&[body as u64, 0, 36, 72, u64::from(u32::MAX)]),
            4,
        );
        put(&mut blob, 20, rng.pick(&[24, 0, 32, 0xFFFF]) as u64, 2);
        if attribute_type == 0x30 {
            put(&mut blob, 24 + 64, rng.pick(&[0, 3, 40, 255]) as u64, 1);
        }
    }
    blob.truncate(length.max(24));
    blob
}

fn mft_record(rng: &mut Rng, size: usize, number: u64) -> Vec<u8> {
    let mut record = vec![0u8; size];
    record[..4].copy_from_slice(b"FILE");
    let sectors = size / 512;
    let usa_offset = rng.pick(&[0x30, 0x30, 0x28, 0, size - 2, 0xFFFF]);
    let usa_count = rng.pick(&[sectors + 1, sectors + 1, 0, 1, sectors + 2, 0xFFFF]);
    let first = rng.pick(&[0x38, 0x38, 0x40, 0, 0x31, size, 0xFFFF]);
    put(&mut record, 0x04, usa_offset as u64, 2);
    put(&mut record, 0x06, usa_count as u64, 2);
    put(&mut record, 0x10, rng.next() & 0xFFFF, 2);
    put(&mut record, 0x14, first as u64, 2);
    put(&mut record, 0x16, rng.next() & 0xFFFF, 2);
    let wild = rng.next() as u32 as usize;
    let allocated = rng.pick(&[size, size, 1024, 2048, 4096, 0, 47, 4097, wild]);
    put(&mut record, 0x1C, allocated as u64, 4);
    let wild = rng.next() & 0xFFFF_FFFF;
    put(
        &mut record,
        0x2C,
        rng.pick(&[number, number, number + 1, wild]),
        4,
    );
    let mut offset = if (0x30..size).contains(&first) {
        first
    } else {
        0x38
    };
    for _ in 0..rng.below(10) {
        let attribute = attribute(rng);
        if offset + attribute.len() > size {
            break;
        }
        record[offset..offset + attribute.len()].copy_from_slice(&attribute);
        offset += attribute.len();
    }
    if rng.chance(80) {
        put(&mut record, offset, 0xFFFF_FFFF, 4);
        offset += 8;
    }
    let wild = rng.next() as u32 as usize;
    let used = rng.pick(&[offset, offset, 0, size, size + 1, wild]);
    put(&mut record, 0x18, used as u64, 4);
    if usa_offset + 2 * sectors + 2 <= size {
        let stamp = rng.next() & 0xFFFF;
        put(&mut record, usa_offset, stamp, 2);
        for sector in 1..=sectors {
            if rng.chance(95) {
                put(&mut record, sector * 512 - 2, stamp, 2);
            }
        }
    }
    record
}

fn mft_blob(rng: &mut Rng) -> Vec<u8> {
    let size = rng.pick(&[1024, 1024, 2048, 4096]);
    let mut blob = Vec::new();
    for _ in 0..1 + rng.below(8) {
        match rng.below(10) {
            0 => blob.extend(vec![0u8; size]),
            1 => {
                let count = rng.below(300);
                blob.extend(rng.bytes(count));
            }
            2 => {
                let other = rng.pick(&[1024, 2048, 4096]);
                blob.extend(mft_record(rng, other, (blob.len() / size) as u64));
            }
            _ => {
                let number = (blob.len() / size) as u64;
                blob.extend(mft_record(rng, size, number));
            }
        }
    }
    for _ in 0..rng.below(40) {
        let position = rng.below(blob.len().max(1));
        if position < blob.len() {
            blob[position] = rng.next() as u8;
        }
    }
    if rng.chance(30) {
        let cut = rng.below(blob.len() + 1);
        blob.truncate(cut);
    }
    if rng.chance(10) {
        blob.extend(b"FILE");
        let count = rng.below(60);
        blob.extend(rng.bytes(count));
    }
    blob
}

fn usn_record(rng: &mut Rng) -> Vec<u8> {
    let major = rng.pick(&[2u16, 2, 3, 4, 4, 1, 5]);
    let minimum = if major == 2 { 60 } else { 76 };
    let payload = rng.below(80);
    let natural = (minimum + payload + 7) & !7;
    let mut record = rng.bytes(natural.max(64));
    let wild = rng.next() as u32 as usize;
    let length = rng.pick(&[natural, natural, natural, 59, 60, 64, 65_536, 65_537, wild]);
    put(&mut record, 0, length as u64, 4);
    put(&mut record, 4, u64::from(major), 2);
    if major == 4 {
        put(
            &mut record,
            60,
            rng.pick(&[0, 1, 3, 64, 65, 0xFFFF]) as u64,
            2,
        );
        put(
            &mut record,
            62,
            rng.pick(&[16, 16, 0, 15, 24, 0xFFFF]) as u64,
            2,
        );
    } else {
        let (length_at, offset_at) = if major == 2 { (56, 58) } else { (72, 74) };
        put(
            &mut record,
            length_at,
            rng.pick(&[payload, payload, 0, payload + 1, 0xFFFF]) as u64,
            2,
        );
        put(
            &mut record,
            offset_at,
            rng.pick(&[minimum, minimum, minimum + 1, 0, 0xFFFF]) as u64,
            2,
        );
    }
    record
}

fn usn_blob(rng: &mut Rng) -> Vec<u8> {
    let mut blob = Vec::new();
    for _ in 0..1 + rng.below(24) {
        match rng.below(10) {
            0 | 1 => blob.extend(vec![0u8; rng.pick(&[1, 2, 3, 4, 5, 13, 60, 4096])]),
            2 => {
                let count = 1 + rng.below(30);
                blob.extend(rng.bytes(count));
            }
            _ => blob.extend(usn_record(rng)),
        }
    }
    for _ in 0..rng.below(20) {
        let position = rng.below(blob.len().max(1));
        if position < blob.len() {
            blob[position] = rng.next() as u8;
        }
    }
    blob
}

fn list<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    match value.get(key) {
        Some(Value::List(items)) => items,
        _ => &[],
    }
}

#[test]
fn corrupted_mft_records_never_panic_and_keep_caps() {
    let mut rng = Rng(0x5EED_0001);
    let mut records = 0;
    for _ in 0..1500 {
        let blob = mft_blob(&mut rng);
        let parsed = parse_mft_record_headers(&blob);
        assert!(parsed.len() <= MFT_RECORD_SCAN_LIMIT);
        for record in &parsed {
            assert!(list(record, "attributes").len() <= 256);
            assert!(list(record, "path_candidates").len() <= 10);
            let timestamps = record
                .get("timestamp_validation")
                .expect("timestamp_validation");
            assert!(list(timestamps, "sources").len() <= 32);
            for data in list(record, "data_attributes") {
                assert!(list(data, "runlist_preview").len() <= 64);
            }
        }
        records += parsed.len();
    }
    assert!(records > 3000, "generator produced only {records} records");
}

#[test]
fn file_magic_spam_is_capped_at_the_scan_limit() {
    let mut blob = Vec::new();
    for _ in 0..MFT_RECORD_SCAN_LIMIT + 700 {
        blob.extend(b"FILE");
        blob.extend([0u8; 44]);
    }
    assert_eq!(parse_mft_record_headers(&blob).len(), MFT_RECORD_SCAN_LIMIT);
}

#[test]
fn corrupted_usn_journals_never_panic_and_keep_caps() {
    let mut rng = Rng(0x5EED_0002);
    let mut records = 0;
    for _ in 0..4000 {
        let blob = usn_blob(&mut rng);
        let limit = rng.pick(&[-1, 0, 1, 3, 5000, 5000, 5000, i64::MAX]);
        let inside = rng.below(blob.len() + 10) as i64;
        let start = rng.pick(&[-7, 0, 0, 0, 1, inside, i64::MAX]);
        let inside = rng.below(blob.len() + 10) as i64;
        let window = rng.pick(&[
            None,
            None,
            None,
            Some(-5),
            Some(0),
            Some(61),
            Some(inside),
            Some(i64::MAX),
        ]);
        let scan = parse_usn_record_scan(&blob, limit, start, window);
        let parsed = list(&scan, "records");
        assert!(parsed.len() as i64 <= limit.max(1));
        let stop = scan
            .get("scan_stop_offset")
            .and_then(Value::as_int)
            .expect("scan_stop_offset");
        for record in parsed {
            let end = record
                .get("record_end_offset")
                .and_then(Value::as_int)
                .expect("record_end_offset");
            assert!(end <= stop);
            assert!(list(record, "v4_extents").len() <= 64);
        }
        records += parsed.len();
    }
    assert!(records > 1500, "generator produced only {records} records");
}
