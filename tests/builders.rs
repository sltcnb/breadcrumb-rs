//! Synthetic file builders for the carve tests: one valid, minimal file per
//! supported type, so a carve can be compared byte for byte with what was
//! planted. Mirrors tests/builders.py in the Python implementation.

use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

/// Deterministic filler. Real random bytes make the byte-exact assertions
/// flake: a handler that scans for continuations can read random junk as more
/// file (see the mp3 frame walk).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        // xorshift64*: enough for filler, and reproducible across platforms
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(n);
        out
    }
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() as usize) % (hi - lo)
    }
}

fn be32(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub fn make_png() -> Vec<u8> {
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let chunk = |ctype: &[u8], body: &[u8], out: &mut Vec<u8>| {
        out.extend_from_slice(&be32(body.len() as u32));
        let mut crc_input = ctype.to_vec();
        crc_input.extend_from_slice(body);
        out.extend_from_slice(ctype);
        out.extend_from_slice(body);
        out.extend_from_slice(&be32(crc32(&crc_input)));
    };
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&be32(2));
    ihdr.extend_from_slice(&be32(2));
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(b"IHDR", &ihdr, &mut out);
    let raw = [0u8, 1, 2, 3, 4, 5, 6, 0, 7, 8, 9, 10, 11, 12, 13];
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&raw).unwrap();
    let idat = enc.finish().unwrap();
    chunk(b"IDAT", &idat, &mut out);
    chunk(b"IEND", b"", &mut out);
    out
}

pub fn make_jpeg() -> Vec<u8> {
    let mut out = vec![0xFF, 0xD8, 0xFF, 0xE0];
    let jfif = b"\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00";
    out.extend_from_slice(jfif);
    // SOF0 (len 11: precision, 2x2, one component) then a minimal SOS whose
    // entropy data contains a stuffed FF 00, which must not end the scan.
    out.extend_from_slice(&[
        0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x02, 0x00, 0x02, 0x01, 0x01, 0x11, 0x00,
    ]);
    out.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
    out.extend_from_slice(&[0x12, 0x34, 0xFF, 0x00, 0x56, 0xFF, 0x00, 0x78]);
    out.extend_from_slice(&[0xFF, 0xD9]);
    out
}

pub fn make_gif() -> Vec<u8> {
    let mut out = b"GIF89a".to_vec();
    out.extend_from_slice(&[2, 0, 2, 0, 0x80, 0, 0]); // 2x2, global color table
    out.extend_from_slice(&[0, 0, 0, 0xFF, 0xFF, 0xFF]); // 2-entry palette
    out.extend_from_slice(&[0x21, 0xF9, 0x04, 0, 0, 0, 0, 0]); // graphic control ext
    out.extend_from_slice(&[0x2C, 0, 0, 0, 0, 2, 0, 2, 0, 0]); // image descriptor
    out.push(2); // LZW min code size
    out.extend_from_slice(&[3, 0x44, 0x01, 0x00, 0]); // one sub-block, then terminator
    out.push(0x3B); // trailer
    out
}

pub fn make_bmp() -> Vec<u8> {
    let pixels: Vec<u8> = vec![0xFF; 16];
    let size = 14 + 40 + pixels.len();
    let mut out = b"BM".to_vec();
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // reserved1/2
    out.extend_from_slice(&(54u32).to_le_bytes()); // pixel data offset
    out.extend_from_slice(&(40u32).to_le_bytes()); // DIB header size
    out.extend_from_slice(&(2i32).to_le_bytes());
    out.extend_from_slice(&(2i32).to_le_bytes());
    out.extend_from_slice(&(1u16).to_le_bytes());
    out.extend_from_slice(&(32u16).to_le_bytes());
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&pixels);
    out
}

pub fn make_pdf() -> Vec<u8> {
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\ntrailer\n\
      << /Size 2 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
        .iter()
        .filter(|_| true)
        .copied()
        .collect::<Vec<u8>>()
}

/// Stored (uncompressed) single-entry zip, built by hand so the central
/// directory offsets line up exactly -- `carve_zip` validates that identity.
pub fn zip_with(name: &[u8], body: &[u8]) -> Vec<u8> {
    let crc = crc32(body);
    let mut out = Vec::new();
    let mut local = Vec::new();
    local.extend_from_slice(b"PK\x03\x04");
    local.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // ver, flags, method, time, date
    local.extend_from_slice(&crc.to_le_bytes());
    local.extend_from_slice(&(body.len() as u32).to_le_bytes());
    local.extend_from_slice(&(body.len() as u32).to_le_bytes());
    local.extend_from_slice(&(name.len() as u16).to_le_bytes());
    local.extend_from_slice(&0u16.to_le_bytes());
    local.extend_from_slice(name);
    local.extend_from_slice(body);
    out.extend_from_slice(&local);

    let cd_off = out.len() as u32;
    let mut cd = Vec::new();
    cd.extend_from_slice(b"PK\x01\x02");
    cd.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    cd.extend_from_slice(&crc.to_le_bytes());
    cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
    cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
    cd.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    cd.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    cd.extend_from_slice(name);
    out.extend_from_slice(&cd);

    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

pub fn make_zip() -> Vec<u8> {
    zip_with(b"hello.txt", b"hello breadcrumb")
}

pub fn make_gzip() -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&b"breadcrumb gzip payload ".repeat(200))
        .unwrap();
    enc.finish().unwrap()
}

pub fn make_sqlite() -> Vec<u8> {
    let page_size: usize = 4096;
    let pages: u32 = 3;
    let mut out = b"SQLite format 3\x00".to_vec();
    out.extend_from_slice(&(page_size as u16).to_be_bytes());
    out.extend_from_slice(&[1, 1, 0, 64, 32, 32]); // write/read version, reserved, payload fracs
    out.extend_from_slice(&1u32.to_be_bytes()); // change counter
    out.extend_from_slice(&pages.to_be_bytes()); // page count (offset 28)
    out.resize(page_size * pages as usize, 0);
    out
}

pub fn make_wav() -> Vec<u8> {
    let data: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&((36 + data.len()) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&8000u32.to_le_bytes());
    out.extend_from_slice(&8000u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&data);
    out
}

/// ID3v2 tag + valid MPEG1 Layer III frames (128 kbps, 44100 Hz).
pub fn make_mp3() -> Vec<u8> {
    let tag_body = vec![0u8; 100];
    let n = tag_body.len() as u32;
    let mut out = b"ID3\x03\x00\x00".to_vec();
    out.extend_from_slice(&[
        ((n >> 21) & 0x7F) as u8,
        ((n >> 14) & 0x7F) as u8,
        ((n >> 7) & 0x7F) as u8,
        (n & 0x7F) as u8,
    ]);
    out.extend_from_slice(&tag_body);
    let frame_len = 144 * 128000 / 44100; // 417
    for _ in 0..12 {
        out.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
        out.extend_from_slice(&vec![0u8; frame_len - 4]);
    }
    out
}

pub fn make_ico() -> Vec<u8> {
    let img_hdr: Vec<u8> = {
        let mut v = Vec::new();
        v.extend_from_slice(&40u32.to_le_bytes());
        v.extend_from_slice(&2i32.to_le_bytes());
        v.extend_from_slice(&4i32.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&32u16.to_le_bytes());
        v.extend_from_slice(&[0u8; 24]);
        v
    };
    let mut img = img_hdr;
    img.extend_from_slice(&[0xAB; 16]);
    let mut out = vec![0, 0, 1, 0, 1, 0];
    out.extend_from_slice(&[2, 2, 0, 0]);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&(img.len() as u32).to_le_bytes());
    out.extend_from_slice(&22u32.to_le_bytes()); // data offset
    out.extend_from_slice(&img);
    out
}

pub fn make_evtx() -> Vec<u8> {
    let chunks: u16 = 1;
    let mut out = b"ElfFile\x00".to_vec();
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&chunks.to_le_bytes()); // offset 40
    out.extend_from_slice(&[0u8; 6]);
    out.resize(4096 + 65536 * chunks as usize, 0);
    out
}

pub fn make_hive() -> Vec<u8> {
    let hbins: u32 = 8192;
    let mut out = b"regf".to_vec();
    out.extend_from_slice(&[0u8; 36]);
    out.extend_from_slice(&hbins.to_le_bytes()); // offset 40
    out.extend_from_slice(&[0u8; 4]);
    out.resize(4096 + hbins as usize, 0);
    out
}

pub fn make_bplist() -> Vec<u8> {
    // header | one object | offset table | 32-byte trailer
    let mut out = b"bplist00".to_vec();
    out.push(0x09); // true
    let table_start = out.len() as u64;
    out.push(8); // 1-byte offset table with one entry
    let mut trailer = vec![0u8; 32];
    trailer[6] = 1; // offset size
    trailer[7] = 1; // object ref size
    trailer[8..16].copy_from_slice(&1u64.to_be_bytes()); // num objects
    trailer[16..24].copy_from_slice(&0u64.to_be_bytes()); // top object
    trailer[24..32].copy_from_slice(&table_start.to_be_bytes());
    out.extend_from_slice(&trailer);
    out
}

pub fn make_7z() -> Vec<u8> {
    let payload = vec![0x5Au8; 300];
    let mut out = b"7z\xbc\xaf\x27\x1c".to_vec();
    out.extend_from_slice(&[0, 4]); // version
    out.extend_from_slice(&0u32.to_le_bytes()); // start header CRC
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes()); // next header offset
    out.extend_from_slice(&40u64.to_le_bytes()); // next header size
    out.extend_from_slice(&0u32.to_le_bytes()); // next header CRC
    out.extend_from_slice(&payload);
    out.extend_from_slice(&[0u8; 40]);
    out
}

pub fn make_ogg() -> Vec<u8> {
    fn page(htype: u8, body: &[u8], seq: u32) -> Vec<u8> {
        let nseg = body.len().div_ceil(255);
        let mut out = b"OggS\x00".to_vec();
        out.push(htype);
        out.extend_from_slice(&[0u8; 8]); // granule
        out.extend_from_slice(&1u32.to_le_bytes()); // serial
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]); // checksum (not verified by the carver)
        out.push(nseg as u8);
        let mut left = body.len();
        for _ in 0..nseg {
            let take = left.min(255);
            out.push(take as u8);
            left -= take;
        }
        out.extend_from_slice(body);
        out
    }
    let mut out = page(0x02, b"\x01vorbis-header", 0);
    out.extend_from_slice(&page(0x04, &[0x11; 200], 1)); // 0x04 = end of stream
    out
}

/// Every builder, keyed by the type name the carver reports.
pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("png", make_png()),
        ("jpg", make_jpeg()),
        ("gif", make_gif()),
        ("bmp", make_bmp()),
        ("pdf", make_pdf()),
        ("zip", make_zip()),
        ("gz", make_gzip()),
        ("sqlite", make_sqlite()),
        ("wav", make_wav()),
        ("mp3", make_mp3()),
        ("ico", make_ico()),
        ("evtx", make_evtx()),
        ("hive", make_hive()),
        ("plist", make_bplist()),
        ("7z", make_7z()),
        ("ogg", make_ogg()),
    ]
}
