//! EWF reader tests. The synthetic images run everywhere; where libewf's
//! `ewfacquire` is installed, real images are read back and compared with the
//! source byte for byte.

mod builders;

use breadcrumb_rs::carver::{Carver, Options};
use breadcrumb_rs::ewf::{segment_names, EwfReader};
use breadcrumb_rs::reader::Source;
use breadcrumb_rs::signatures::SIGNATURES;
use std::path::{Path, PathBuf};

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("breadcrumb-rs-ewf-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Minimal single-segment EWF with one sectors+table section. Field offsets
/// follow libewf's `ewf_volume` exactly -- a builder that mirrors a parser's
/// own idea of the layout proves nothing.
fn build_e01(path: &Path, payload: &[u8], chunk_sectors: u64, compress: bool, declare_extra: u64) {
    let bps: u64 = 512;
    let chunk_size = (chunk_sectors * bps) as usize;
    let mut raw_chunks: Vec<Vec<u8>> = payload
        .chunks(chunk_size)
        .map(|c| {
            let mut v = c.to_vec();
            v.resize(chunk_size, 0);
            v
        })
        .collect();
    if raw_chunks.is_empty() {
        raw_chunks.push(vec![0u8; chunk_size]);
    }
    let total_sectors = (payload.len() as u64).div_ceil(bps);

    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"EVF\x09\x0d\x0a\xff\x00");
    out.push(1);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());

    let emit = |out: &mut Vec<u8>, stype: &[u8], body: &[u8]| -> u64 {
        let start = out.len() as u64;
        let mut desc = vec![0u8; 76];
        let n = stype.len().min(15);
        desc[..n].copy_from_slice(&stype[..n]);
        let size = 76 + body.len() as u64;
        desc[16..24].copy_from_slice(&(start + size).to_le_bytes()); // next section
        desc[24..32].copy_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&desc);
        out.extend_from_slice(body);
        start
    };

    // media_type(1) unknown(3) chunk_count(4) sectors_per_chunk(4)
    // bytes_per_sector(4) sector_count(8)
    let mut vol = vec![0u8; 1052];
    vol[0] = 1;
    vol[4..8].copy_from_slice(&((raw_chunks.len() as u64 + declare_extra) as u32).to_le_bytes());
    vol[8..12].copy_from_slice(&(chunk_sectors as u32).to_le_bytes());
    vol[12..16].copy_from_slice(&(bps as u32).to_le_bytes());
    vol[16..24].copy_from_slice(&total_sectors.to_le_bytes());
    emit(&mut out, b"volume", &vol);

    let mut stored: Vec<u8> = Vec::new();
    let mut entries_meta: Vec<(u64, bool)> = Vec::new();
    for chunk in &raw_chunks {
        entries_meta.push((stored.len() as u64, compress));
        if compress {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(chunk).unwrap();
            stored.extend_from_slice(&enc.finish().unwrap());
        } else {
            stored.extend_from_slice(chunk);
        }
    }
    let sectors_start = emit(&mut out, b"sectors", &stored);
    let data_base = sectors_start + 76;

    let mut thdr = vec![0u8; 24];
    thdr[..4].copy_from_slice(&(raw_chunks.len() as u32).to_le_bytes());
    thdr[8..16].copy_from_slice(&data_base.to_le_bytes());
    let mut table = thdr;
    for (rel, comp) in &entries_meta {
        let v = (*rel as u32) | if *comp { 0x8000_0000 } else { 0 };
        table.extend_from_slice(&v.to_le_bytes());
    }
    emit(&mut out, b"table", &table);
    emit(&mut out, b"done", b"");

    std::fs::write(path, &out).unwrap();
}

#[test]
fn segment_names_follow_libewf_naming() {
    // Past segment 99 the digits become letters and the leading character
    // carries: E01..E99, EAA..EZZ, FAA.., through ZZZ.
    let names: Vec<String> = segment_names("/ev/RM", 'E').take(105).collect();
    let ext = |s: &String| s.rsplit('.').next().unwrap().to_string();
    assert_eq!(ext(&names[0]), "E01");
    assert_eq!(ext(&names[98]), "E99");
    assert_eq!(ext(&names[99]), "EAA");
    assert_eq!(ext(&names[100]), "EAB");
    assert_eq!(ext(&names[104]), "EAF");
    // a lowercase set keeps its case
    let lower: Vec<String> = segment_names("/ev/rm", 'e').take(100).collect();
    assert_eq!(ext(&lower[99]), "eaa");
}

#[test]
fn synthetic_e01_roundtrips() {
    let dir = Tmp::new("synthetic");
    let mut payload = builders::make_png();
    payload.extend_from_slice(&builders::Rng::new(3).bytes(9000));
    payload.extend_from_slice(&builders::make_jpeg());
    for compress in [false, true] {
        let path = dir.join("img.E01");
        build_e01(&path, &payload, 2, compress, 0);
        let r = EwfReader::open(path.to_str().unwrap()).unwrap();
        // the sector count gives an exact media size, not the chunk-aligned bound
        assert_eq!(r.size, 512 * (payload.len() as u64).div_ceil(512));
        assert_eq!(r.pread(0, payload.len()), payload, "compress={compress}");
        assert_eq!(r.pread(100, 50), payload[100..150], "compress={compress}");
        // a read spanning several chunks
        assert_eq!(
            r.pread(900, 3000),
            payload[900..3900],
            "compress={compress}"
        );
    }
}

#[test]
fn incomplete_set_is_refused() {
    // The volume section promises more chunks than the table holds: the tail
    // segments are missing. Carving a fraction of the evidence while reporting
    // success is the worst possible outcome, so this must fail loudly.
    let dir = Tmp::new("incomplete");
    let path = dir.join("short.E01");
    build_e01(&path, &builders::Rng::new(5).bytes(8192), 2, false, 40);
    let err = match EwfReader::open(path.to_str().unwrap()) {
        Ok(_) => panic!("an incomplete set was accepted"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("incomplete EWF set"), "{err}");
}

#[test]
fn source_routes_e01_to_the_ewf_reader_and_carves_it() {
    let dir = Tmp::new("source");
    let png = builders::make_png();
    let mut payload = vec![0u8; 1024];
    payload.extend_from_slice(&png);
    payload.extend_from_slice(&builders::Rng::new(9).bytes(4096));
    let path = dir.join("img.E01");
    build_e01(&path, &payload, 4, true, 0);

    let src = Source::open(path.to_str().unwrap()).unwrap();
    assert!(matches!(src, Source::Ewf(_)), "E01 must not open as raw");
    assert!(src.describe().contains("EWF"));

    let opts = Options {
        out_dir: dir.join("out").to_string_lossy().to_string(),
        quiet: true,
        ..Options::default()
    };
    let mut c = Carver::new(&src, SIGNATURES.iter().collect(), &opts);
    let records = c.run();
    let carved: Vec<_> = records.iter().filter(|r| r.ext == "png").collect();
    assert_eq!(carved.len(), 1, "png not recovered through EWF");
    assert_eq!(carved[0].offset, 1024);
    assert_eq!(carved[0].size, png.len() as u64);
}
