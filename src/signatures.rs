//! Signature registry: magic bytes -> carving handler.
//!
//! `precheck` runs against the in-memory scan chunk before a `Window` is
//! opened, to cheaply reject noise from short magics (BM, RIFF, ID3, ftyp).

use crate::handlers::{self, Carve};
use crate::window::Window;

const KB: u64 = 1 << 10;
const MB: u64 = 1 << 20;
const GB: u64 = 1 << 30;

pub type Handler = fn(&mut Window) -> Option<Carve>;
pub type Precheck = fn(&[u8], usize) -> bool;

pub struct Signature {
    pub name: &'static str,
    pub magics: &'static [&'static [u8]],
    pub header_offset: u64,
    pub handler: Handler,
    pub max_size: u64,
    pub precheck: Option<Precheck>,
    pub description: &'static str,
}

fn pre_bmp(buf: &[u8], i: usize) -> bool {
    if i + 26 > buf.len() {
        return true;
    }
    let dib = u32::from_le_bytes([buf[i + 14], buf[i + 15], buf[i + 16], buf[i + 17]]);
    matches!(dib, 12 | 40 | 52 | 56 | 64 | 108 | 124)
}

fn pre_riff(buf: &[u8], i: usize) -> bool {
    if i + 12 > buf.len() {
        return true;
    }
    matches!(&buf[i + 8..i + 12], b"WAVE" | b"AVI " | b"WEBP")
}

fn pre_ftyp(buf: &[u8], i: usize) -> bool {
    if i < 4 {
        return false;
    }
    let size = u32::from_be_bytes([buf[i - 4], buf[i - 3], buf[i - 2], buf[i - 1]]) as u64;
    size == 1 || (8..=0xFF_FFFF).contains(&size)
}

fn pre_id3(buf: &[u8], i: usize) -> bool {
    if i + 10 > buf.len() {
        return true;
    }
    buf[i + 3] < 0x10 && buf[i + 4] < 0x10 && buf[i + 6..i + 10].iter().all(|b| b & 0x80 == 0)
}

pub static SIGNATURES: &[Signature] = &[
    Signature {
        name: "jpg",
        magics: &[b"\xff\xd8\xff"],
        header_offset: 0,
        handler: handlers::carve_jpeg,
        max_size: 64 * MB,
        precheck: None,
        description: "JPEG image",
    },
    Signature {
        name: "png",
        magics: &[b"\x89PNG\r\n\x1a\n"],
        header_offset: 0,
        handler: handlers::carve_png,
        max_size: 64 * MB,
        precheck: None,
        description: "PNG image",
    },
    Signature {
        name: "gif",
        magics: &[b"GIF87a", b"GIF89a"],
        header_offset: 0,
        handler: handlers::carve_gif,
        max_size: 32 * MB,
        precheck: None,
        description: "GIF image",
    },
    Signature {
        name: "bmp",
        magics: &[b"BM"],
        header_offset: 0,
        handler: handlers::carve_bmp,
        max_size: 64 * MB,
        precheck: Some(pre_bmp),
        description: "BMP image",
    },
    Signature {
        name: "tif",
        magics: &[b"II*\x00", b"MM\x00*"],
        header_offset: 0,
        handler: handlers::carve_tiff,
        max_size: 256 * MB,
        precheck: None,
        description: "TIFF image",
    },
    Signature {
        name: "pdf",
        magics: &[b"%PDF-"],
        header_offset: 0,
        handler: handlers::carve_pdf,
        max_size: 128 * MB,
        precheck: None,
        description: "PDF document",
    },
    Signature {
        name: "rtf",
        magics: &[b"{\\rtf"],
        header_offset: 0,
        handler: handlers::carve_rtf,
        max_size: 64 * MB,
        precheck: None,
        description: "Rich Text Format",
    },
    Signature {
        name: "ole",
        magics: &[b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
        header_offset: 0,
        handler: handlers::carve_ole,
        max_size: 64 * MB,
        precheck: None,
        description: "OLE2/CFB: doc, xls, ppt, msg, vsd, msi",
    },
    Signature {
        name: "zip",
        magics: &[b"PK\x03\x04"],
        header_offset: 0,
        handler: handlers::carve_zip,
        max_size: 512 * MB,
        precheck: None,
        description: "ZIP, docx/xlsx/pptx, jar, apk, epub, odf",
    },
    Signature {
        name: "gz",
        magics: &[b"\x1f\x8b\x08"],
        header_offset: 0,
        handler: handlers::carve_gzip,
        max_size: 256 * MB,
        precheck: None,
        description: "gzip",
    },
    Signature {
        name: "7z",
        magics: &[b"7z\xbc\xaf\x27\x1c"],
        header_offset: 0,
        handler: handlers::carve_7z,
        max_size: 4 * GB,
        precheck: None,
        description: "7-Zip",
    },
    Signature {
        name: "sqlite",
        magics: &[b"SQLite format 3\x00"],
        header_offset: 0,
        handler: handlers::carve_sqlite,
        max_size: GB,
        precheck: None,
        description: "SQLite 3 database",
    },
    Signature {
        name: "mp4",
        magics: &[b"ftyp"],
        header_offset: 4,
        handler: handlers::carve_mp4,
        max_size: 4 * GB,
        precheck: Some(pre_ftyp),
        description: "MP4/MOV/HEIC/AVIF/3GP/M4A/M4V",
    },
    Signature {
        name: "riff",
        magics: &[b"RIFF"],
        header_offset: 0,
        handler: handlers::carve_riff,
        max_size: 2 * GB,
        precheck: Some(pre_riff),
        description: "WAV, AVI, WebP",
    },
    Signature {
        name: "mp3",
        magics: &[b"ID3"],
        header_offset: 0,
        handler: handlers::carve_mp3,
        max_size: 256 * MB,
        precheck: Some(pre_id3),
        description: "MP3 (ID3v2-tagged)",
    },
    Signature {
        name: "elf",
        magics: &[b"\x7fELF"],
        header_offset: 0,
        handler: handlers::carve_elf,
        max_size: 256 * MB,
        precheck: None,
        description: "ELF binary",
    },
    Signature {
        name: "ico",
        magics: &[b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"],
        header_offset: 0,
        handler: handlers::carve_ico,
        max_size: 8 * MB,
        precheck: None,
        description: "ICO / CUR",
    },
    Signature {
        name: "ogg",
        magics: &[b"OggS"],
        header_offset: 0,
        handler: handlers::carve_ogg,
        max_size: 512 * MB,
        precheck: None,
        description: "OGG (Vorbis/Opus/Theora)",
    },
    Signature {
        name: "mkv",
        magics: &[b"\x1a\x45\xdf\xa3"],
        header_offset: 0,
        handler: handlers::carve_mkv,
        max_size: 4 * GB,
        precheck: None,
        description: "Matroska / WebM",
    },
    Signature {
        name: "evtx",
        magics: &[b"ElfFile\x00"],
        header_offset: 0,
        handler: handlers::carve_evtx,
        max_size: 256 * MB,
        precheck: None,
        description: "Windows event log",
    },
    Signature {
        name: "hive",
        magics: &[b"regf"],
        header_offset: 0,
        handler: handlers::carve_regf,
        max_size: 256 * MB,
        precheck: None,
        description: "Windows registry hive",
    },
    Signature {
        name: "plist",
        magics: &[b"bplist00"],
        header_offset: 0,
        handler: handlers::carve_bplist,
        max_size: 64 * KB * 1024,
        precheck: None,
        description: "Apple binary plist",
    },
];

/// Friendly aliases accepted by --types.
pub const ALIASES: &[(&str, &str)] = &[
    ("jpeg", "jpg"),
    ("tiff", "tif"),
    ("gzip", "gz"),
    ("mov", "mp4"),
    ("avi", "riff"),
    ("wav", "riff"),
    ("webp", "riff"),
    ("docx", "zip"),
    ("xlsx", "zip"),
    ("pptx", "zip"),
    ("sqlite3", "sqlite"),
    ("db", "sqlite"),
    ("heic", "mp4"),
    ("heif", "mp4"),
    ("avif", "mp4"),
    ("m4a", "mp4"),
    ("m4v", "mp4"),
    ("3gp", "mp4"),
    ("webm", "mkv"),
    ("matroska", "mkv"),
    ("cur", "ico"),
    ("reg", "hive"),
    ("registry", "hive"),
    ("bplist", "plist"),
    ("doc", "ole"),
    ("xls", "ole"),
    ("ppt", "ole"),
    ("msg", "ole"),
    ("vsd", "ole"),
    ("msi", "ole"),
    ("pub", "ole"),
];

/// Named groups for --types, so a document sweep does not mean listing every
/// container an Office file can arrive in.
pub const GROUPS: &[(&str, &[&str])] = &[
    // zip covers docx/xlsx/pptx/odf; ole covers doc/xls/ppt/msg/vsd/msi.
    ("office", &["ole", "zip", "pdf", "rtf"]),
    ("docs", &["ole", "zip", "pdf", "rtf"]),
    ("images", &["jpg", "png", "gif", "bmp", "tif", "ico"]),
    ("media", &["mp4", "riff", "mp3", "mkv", "ogg"]),
    ("archives", &["zip", "gz", "7z"]),
];

/// Parse "jpg,png,..." into signature indices, erroring on unknown names.
pub fn resolve_types(spec: &str) -> Result<Vec<&'static Signature>, String> {
    let mut out: Vec<&'static Signature> = Vec::new();
    for tok in spec.split(',') {
        let tok = tok.trim().to_ascii_lowercase();
        if tok.is_empty() {
            continue;
        }
        let group = GROUPS.iter().find(|(g, _)| *g == tok).map(|(_, m)| *m);
        let names: Vec<&str> = match group {
            Some(members) => members.to_vec(),
            None => vec![ALIASES
                .iter()
                .find(|(a, _)| *a == tok)
                .map(|(_, n)| *n)
                .unwrap_or(tok.as_str())],
        };
        for name in names {
            match SIGNATURES.iter().find(|s| s.name == name) {
                Some(sig) => {
                    if !out.iter().any(|s| s.name == sig.name) {
                        out.push(sig);
                    }
                }
                None => return Err(format!("unknown type {tok:?} (see --list-types)")),
            }
        }
    }
    Ok(out)
}
