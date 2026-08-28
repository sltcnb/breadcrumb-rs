#![allow(dead_code)] // shared by several test binaries; each uses a subset

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

/// Minimal OLE2/CFB container: header + FAT + directory + one stream. Real
/// Office 97-2003 files are exactly this shape, just larger; the stream name is
/// what tells the handler whether it is a .doc, .xls, an Outlook .msg, and so on.
pub fn make_ole(stream_name: &str) -> Vec<u8> {
    const SECTOR: usize = 512;
    const FREESECT: u32 = 0xFFFF_FFFF;
    const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
    const FATSECT: u32 = 0xFFFF_FFFD;
    let payload: Vec<u8> = b"office payload ".repeat(20);

    let mut hdr = vec![0u8; SECTOR];
    hdr[0..8].copy_from_slice(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1");
    hdr[24..26].copy_from_slice(&0x003Eu16.to_le_bytes()); // minor version
    hdr[26..28].copy_from_slice(&3u16.to_le_bytes()); // major version
    hdr[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes()); // little-endian
    hdr[30..32].copy_from_slice(&9u16.to_le_bytes()); // 512-byte sectors
    hdr[32..34].copy_from_slice(&6u16.to_le_bytes()); // mini sector shift
    hdr[44..48].copy_from_slice(&1u32.to_le_bytes()); // FAT sector count
    hdr[48..52].copy_from_slice(&1u32.to_le_bytes()); // first directory sector
    hdr[56..60].copy_from_slice(&4096u32.to_le_bytes()); // mini stream cutoff
    hdr[60..64].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
    hdr[68..72].copy_from_slice(&ENDOFCHAIN.to_le_bytes()); // first DIFAT
    for i in 0..109usize {
        let v = if i == 0 { 0u32 } else { FREESECT }; // the FAT lives at sector 0
        hdr[76 + i * 4..80 + i * 4].copy_from_slice(&v.to_le_bytes());
    }

    let data_sectors = payload.len().div_ceil(SECTOR).max(1);
    let mut fat = vec![0xFFu8; SECTOR]; // all FREESECT
    fat[0..4].copy_from_slice(&FATSECT.to_le_bytes());
    fat[4..8].copy_from_slice(&ENDOFCHAIN.to_le_bytes()); // directory sector
    for i in 0..data_sectors {
        let nxt = if i + 1 < data_sectors {
            (3 + i) as u32
        } else {
            ENDOFCHAIN
        };
        fat[8 + i * 4..12 + i * 4].copy_from_slice(&nxt.to_le_bytes());
    }

    let dir_entry = |name: &str, etype: u8, start: u32, size: u64| -> Vec<u8> {
        let mut e = vec![0u8; 128];
        let nb: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let n = nb.len().min(62);
        e[..n].copy_from_slice(&nb[..n]);
        e[64..66].copy_from_slice(&((n + 2) as u16).to_le_bytes());
        e[66] = etype; // 5 = root, 2 = stream
        e[67] = 1; // black
        for o in [68usize, 72, 76] {
            e[o..o + 4].copy_from_slice(&FREESECT.to_le_bytes());
        }
        e[116..120].copy_from_slice(&start.to_le_bytes());
        e[120..128].copy_from_slice(&size.to_le_bytes());
        e
    };
    let mut directory = dir_entry("Root Entry", 5, ENDOFCHAIN, 0);
    directory.extend_from_slice(&dir_entry(stream_name, 2, 2, payload.len() as u64));
    directory.resize(SECTOR, 0);

    let mut out = hdr;
    out.extend_from_slice(&fat);
    out.extend_from_slice(&directory);
    let mut body = payload;
    body.resize(data_sectors * SECTOR, 0);
    out.extend_from_slice(&body);
    out
}

/// Outlook store header (MS-PST 2.2.2.6) padded to its recorded size. Only the
/// fields the carver reads are filled in.
pub fn make_pst(unicode_store: bool, size: usize) -> Vec<u8> {
    let mut hdr = vec![0u8; if unicode_store { 0x4400 } else { 0x1000 }];
    hdr[0..4].copy_from_slice(b"!BDN");
    hdr[8..10].copy_from_slice(&0x4D53u16.to_le_bytes()); // wMagicClient "SM"
    let ver: u16 = if unicode_store { 23 } else { 15 };
    hdr[10..12].copy_from_slice(&ver.to_le_bytes());
    hdr[12..14].copy_from_slice(&19u16.to_le_bytes()); // wVerClient
    hdr[0x0E] = 1;
    hdr[0x0F] = 1;
    if unicode_store {
        hdr[0xB8..0xC0].copy_from_slice(&(size as u64).to_le_bytes()); // ROOT.ibFileEof
    } else {
        hdr[0xA8..0xAC].copy_from_slice(&(size as u32).to_le_bytes());
    }
    hdr.resize(size, 0);
    hdr
}

/// An OLE2 container whose root entry carries a CLSID, which is what says for
/// certain which application wrote it.
pub fn make_ole_clsid(clsid: [u8; 16], stream_name: &str) -> Vec<u8> {
    let mut data = make_ole(stream_name);
    let sector = 1usize << u16::from_le_bytes([data[30], data[31]]);
    let dir_sect = u32::from_le_bytes([data[48], data[49], data[50], data[51]]) as usize;
    let root = (dir_sect + 1) * sector;
    data[root + 80..root + 96].copy_from_slice(&clsid);
    data
}

/// RTF with a nested group, an escaped brace, and a \bin blob whose raw bytes
/// include unbalanced braces -- all three trip a naive brace count.
pub fn make_rtf() -> Vec<u8> {
    let blob = b"}}}{{{";
    let mut out = b"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fnil Arial;}}\n".to_vec();
    out.extend_from_slice(b"\\f0\\fs24 recovered \\{document\\} text\\par\n");
    out.extend_from_slice(b"{\\*\\shppict{\\pict\\pngblip\\bin");
    out.extend_from_slice(blob.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(blob);
    out.extend_from_slice(b"}}\n}");
    out
}

/// Minimal thin Mach-O 64 LE with one segment and a symbol table.
pub fn make_macho() -> Vec<u8> {
    let (seg_fileoff, seg_filesize): (u64, u64) = (0x100, 0x200);
    let mut cmds: Vec<u8> = Vec::new();
    cmds.extend_from_slice(&0x19u32.to_le_bytes()); // LC_SEGMENT_64
    cmds.extend_from_slice(&72u32.to_le_bytes());
    let mut name = b"__TEXT".to_vec();
    name.resize(16, 0);
    cmds.extend_from_slice(&name);
    cmds.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
    cmds.extend_from_slice(&0x1000u64.to_le_bytes()); // vmsize
    cmds.extend_from_slice(&seg_fileoff.to_le_bytes());
    cmds.extend_from_slice(&seg_filesize.to_le_bytes());
    cmds.extend_from_slice(&7u32.to_le_bytes()); // maxprot
    cmds.extend_from_slice(&5u32.to_le_bytes()); // initprot
    cmds.extend_from_slice(&0u32.to_le_bytes()); // nsects
    cmds.extend_from_slice(&0u32.to_le_bytes()); // flags
    cmds.extend_from_slice(&0x02u32.to_le_bytes()); // LC_SYMTAB
    cmds.extend_from_slice(&24u32.to_le_bytes());
    cmds.extend_from_slice(&0x280u32.to_le_bytes()); // symoff
    cmds.extend_from_slice(&4u32.to_le_bytes()); // nsyms
    cmds.extend_from_slice(&0x2C0u32.to_le_bytes()); // stroff
    cmds.extend_from_slice(&0x40u32.to_le_bytes()); // strsize

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&0xFEEDFACFu32.to_le_bytes()); // MH_MAGIC_64
    out.extend_from_slice(&0x0100000Cu32.to_le_bytes()); // cputype x86_64
    out.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
    out.extend_from_slice(&2u32.to_le_bytes()); // filetype MH_EXECUTE
    out.extend_from_slice(&2u32.to_le_bytes()); // ncmds
    out.extend_from_slice(&(cmds.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    out.extend_from_slice(&cmds);
    out.resize(0x300, 0);
    out
}

/// Minimal PE32+ with one section and a certificate table beyond it.
pub fn make_pe(dll: bool) -> Vec<u8> {
    let e_lfanew: u32 = 0x80;
    let opt_size: u16 = 240; // PE32+ optional header with 16 data directories
    let nsections: u16 = 1;
    let sect_raw_ptr: u32 = 0x400;
    let sect_raw_size: u32 = 0x200;
    let cert_off: u32 = 0x600;
    let cert_size: u32 = 0x80;

    let mut out = vec![0u8; e_lfanew as usize];
    out[0..2].copy_from_slice(b"MZ");
    out[60..64].copy_from_slice(&e_lfanew.to_le_bytes());

    let mut pe: Vec<u8> = b"PE\x00\x00".to_vec();
    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // machine x86_64
    pe.extend_from_slice(&nsections.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes()); // timestamp
    pe.extend_from_slice(&0u32.to_le_bytes()); // symbol table
    pe.extend_from_slice(&0u32.to_le_bytes()); // symbol count
    pe.extend_from_slice(&opt_size.to_le_bytes());
    let characteristics: u16 = if dll { 0x2000 } else { 0x0002 };
    pe.extend_from_slice(&characteristics.to_le_bytes());

    let mut opt = vec![0u8; opt_size as usize];
    opt[0..2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
                                                        // data directory 4 (certificate table) lives at 112 for PE32+
    opt[112 + 32..112 + 36].copy_from_slice(&cert_off.to_le_bytes());
    opt[112 + 36..112 + 40].copy_from_slice(&cert_size.to_le_bytes());
    pe.extend_from_slice(&opt);

    let mut sect = vec![0u8; 40];
    sect[..8].copy_from_slice(b".text\x00\x00\x00");
    sect[16..20].copy_from_slice(&sect_raw_size.to_le_bytes());
    sect[20..24].copy_from_slice(&sect_raw_ptr.to_le_bytes());
    pe.extend_from_slice(&sect);

    out.extend_from_slice(&pe);
    out.resize((cert_off + cert_size) as usize, 0);
    out
}

pub fn make_flac() -> Vec<u8> {
    let mut out = b"fLaC".to_vec();
    let streaminfo = vec![0x11u8; 34];
    out.push(0x80); // last metadata block, type 0 (STREAMINFO)
    out.extend_from_slice(&[0, 0, streaminfo.len() as u8]);
    out.extend_from_slice(&streaminfo);
    out.extend_from_slice(&[0xFF, 0xF8]); // frame sync
    out.extend_from_slice(&Rng::new(15).bytes(200));
    out
}

pub fn make_psd() -> Vec<u8> {
    let mut out = b"8BPS".to_vec();
    out.extend_from_slice(&1u16.to_be_bytes()); // version
    out.extend_from_slice(&[0u8; 6]); // reserved
    out.extend_from_slice(&3u16.to_be_bytes()); // channels
    out.extend_from_slice(&4u32.to_be_bytes()); // height
    out.extend_from_slice(&4u32.to_be_bytes()); // width
    out.extend_from_slice(&8u16.to_be_bytes()); // depth
    out.extend_from_slice(&3u16.to_be_bytes()); // colour mode RGB
    for _ in 0..4 {
        out.extend_from_slice(&0u32.to_be_bytes()); // four empty sections
    }
    out.extend_from_slice(&Rng::new(16).bytes(32)); // image data
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
        ("doc", make_ole("WordDocument")),
        ("rtf", make_rtf()),
        ("pst", make_pst(true, 0x8000)),
        ("macho", make_macho()),
        ("exe", make_pe(false)),
    ]
}

/// A compound file whose directory declares a stream far larger than the data
/// actually present: what a carve that stopped short looks like on disk.
pub fn make_ole_truncated(stream_name: &str) -> Vec<u8> {
    let mut d = make_ole(stream_name);
    // Second directory entry, size field: claim a megabyte of content.
    let dir = 512 * 2; // header, FAT, then the directory sector
    let size_at = dir + 128 + 120;
    d[size_at..size_at + 8].copy_from_slice(&(1u64 << 20).to_le_bytes());
    d
}
