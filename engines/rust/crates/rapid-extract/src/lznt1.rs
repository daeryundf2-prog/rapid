//! LZNT1 decompression with the exact behaviour of `dissect.util.compression.lznt1.decompress`
//! (the decoder behind dissect.ntfs's compressed streams), including where it stops or fails.

const COMPRESSED_MASK: u16 = 1 << 15;
const SIGNATURE_MASK: u16 = 3 << 12;
const SIZE_MASK: u16 = (1 << 12) - 1;

fn displacement(offset: usize) -> u32 {
    let mut value = offset;
    let mut result = 0;
    while value >= 0x10 {
        value >>= 1;
        result += 1;
    }
    result
}

/// `Err` wherever the Python decoder raises (short header, back-reference before the output
/// start, displacement-table overflow); the caller turns it into the stream's `IOError`.
pub fn decompress(src: &[u8]) -> Result<Vec<u8>, String> {
    let size = src.len();
    let mut pos = 0usize;
    let mut dst: Vec<u8> = Vec::new();
    while pos < size {
        let block_offset = pos;
        let chunk_start = dst.len();
        if pos + 2 > size {
            return Err("lznt1: truncated block header".into());
        }
        let header = u16::from_le_bytes([src[pos], src[pos + 1]]);
        pos += 2;
        if header & SIGNATURE_MASK != SIGNATURE_MASK {
            break;
        }
        let hsize = (header & SIZE_MASK) as usize;
        let block_end = block_offset + hsize + 3;
        if header & COMPRESSED_MASK != 0 {
            while pos < block_end {
                let Some(&tag) = src.get(pos) else {
                    return Err("lznt1: truncated tag".into());
                };
                pos += 1;
                for bit in 0..8 {
                    if pos >= block_end {
                        break;
                    }
                    if tag & (1 << bit) != 0 {
                        if pos + 2 > size {
                            return Err("lznt1: truncated back-reference".into());
                        }
                        let pointer = u16::from_le_bytes([src[pos], src[pos + 1]]);
                        pos += 2;
                        // Python indexes DISPLACEMENT_TABLE[-1] (its last entry) at chunk start.
                        let index = (dst.len() - chunk_start).checked_sub(1).unwrap_or(8191);
                        if index >= 8192 {
                            return Err("lznt1: displacement index out of range".into());
                        }
                        let disp = displacement(index);
                        let symbol_offset = ((pointer >> (12 - disp)) as usize) + 1;
                        let symbol_length = ((pointer & (0xFFF >> disp)) as usize) + 3;
                        if symbol_offset > dst.len() {
                            return Err("lznt1: back-reference before output start".into());
                        }
                        let start = dst.len() - symbol_offset;
                        for i in 0..symbol_length {
                            let byte = dst[start + (i % symbol_offset)];
                            dst.push(byte);
                        }
                    } else {
                        if let Some(&byte) = src.get(pos) {
                            dst.push(byte);
                        }
                        pos = (pos + 1).min(size);
                    }
                }
            }
        } else {
            let end = (pos + hsize + 1).min(size);
            dst.extend_from_slice(&src[pos..end]);
            pos = end;
        }
    }
    Ok(dst)
}

#[cfg(test)]
mod tests {
    use super::decompress;

    #[test]
    fn literal_and_back_reference_chunk() {
        // "abcabcabc": three literals, then a 6-byte copy at displacement 3.
        let body = [0b0000_1000u8, b'a', b'b', b'c', 0x03, 0x20];
        let mut src = vec![];
        src.extend_from_slice(&(0xB000u16 | (body.len() as u16 + 2 - 3)).to_le_bytes());
        src.extend_from_slice(&body);
        src.extend_from_slice(&[0u8; 64]);
        assert_eq!(decompress(&src).unwrap(), b"abcabcabc");
    }

    #[test]
    fn uncompressed_chunk_and_terminator() {
        let mut src = vec![];
        src.extend_from_slice(&(0x3000u16 | (4 - 1)).to_le_bytes());
        src.extend_from_slice(b"wxyz");
        src.extend_from_slice(&[0u8; 8]);
        assert_eq!(decompress(&src).unwrap(), b"wxyz");
    }

    #[test]
    fn back_reference_before_start_fails() {
        let body = [0b0000_0001u8, 0xFF, 0x0F];
        let mut src = vec![];
        src.extend_from_slice(&(0xB000u16 | (body.len() as u16 + 2 - 3)).to_le_bytes());
        src.extend_from_slice(&body);
        assert!(decompress(&src).is_err());
    }
}
