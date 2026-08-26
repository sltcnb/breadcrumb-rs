//! Deep validation.
//!
//! The fixtures are written by other implementations on purpose -- Python's
//! zipfile, gzip and sqlite3 modules, and zlib for the PNG chunk CRCs and pixel
//! stream. A fixture produced by the code under test would agree with it about
//! a wrong CRC or a misplaced field, which is exactly the failure this is meant
//! to catch.

use breadcrumb_rs::validate::{self, Verdict};

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/validate")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Flip one bit somewhere inside the body, past the header.
fn corrupt(mut data: Vec<u8>, at: usize) -> Vec<u8> {
    data[at] ^= 0x40;
    data
}

#[test]
fn crc32_matches_the_reference_values() {
    // The two vectors every CRC-32 implementation is checked against.
    assert_eq!(validate::crc32(b""), 0);
    assert_eq!(validate::crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(validate::crc32(b"The quick brown fox"), 0xB74574DE);
}

#[test]
fn a_real_png_verifies_and_is_tightened_to_its_iend() {
    let png = fixture("valid.png");
    match validate::validate("png", &png) {
        Verdict::Verified(Some(n)) => assert_eq!(n, png.len() as u64),
        other => panic!("valid PNG: {other:?}"),
    }
    // Carving over-reads into whatever follows; validation puts the end back.
    let mut over = png.clone();
    over.extend_from_slice(&[0xAB; 4096]);
    match validate::validate("png", &over) {
        Verdict::Verified(Some(n)) => assert_eq!(n, png.len() as u64, "not tightened"),
        other => panic!("over-read PNG: {other:?}"),
    }
}

#[test]
fn a_png_with_a_flipped_byte_fails_its_chunk_crc() {
    let png = fixture("valid.png");
    // 40 bytes in is inside IDAT, past IHDR.
    assert_eq!(
        validate::validate("png", &corrupt(png.clone(), 60)),
        Verdict::Invalid
    );
    // Truncated before IEND: not a whole file.
    assert_eq!(
        validate::validate("png", &png[..png.len() - 20]),
        Verdict::Invalid
    );
}

#[test]
fn a_real_docx_verifies_and_a_damaged_member_does_not() {
    let docx = fixture("valid.docx");
    assert_eq!(validate::validate("docx", &docx), Verdict::Verified(None));
    assert_eq!(validate::validate("zip", &docx), Verdict::Verified(None));

    // A carve that crossed a fragment boundary keeps the framing but not the
    // member data: this is the case the structure walk cannot see.
    let at = docx.len() / 2;
    assert_eq!(
        validate::validate("docx", &corrupt(docx.clone(), at)),
        Verdict::Invalid,
        "a corrupt member passed validation"
    );
    // Truncated archive: no end-of-central-directory record.
    assert_eq!(
        validate::validate("docx", &docx[..docx.len() - 40]),
        Verdict::Invalid
    );
}

#[test]
fn a_stored_zip_member_is_checked_too() {
    let zip = fixture("stored.zip");
    assert_eq!(validate::validate("zip", &zip), Verdict::Verified(None));
    // Corrupting an uncompressed member breaks only its CRC.
    let at = zip.len() / 3;
    assert_eq!(
        validate::validate("zip", &corrupt(zip, at)),
        Verdict::Invalid
    );
}

#[test]
fn gzip_is_verified_by_a_full_inflate() {
    let gz = fixture("valid.gz");
    assert_eq!(validate::validate("gz", &gz), Verdict::Verified(None));
    assert_eq!(
        validate::validate("gz", &corrupt(gz.clone(), gz.len() / 2)),
        Verdict::Invalid
    );
    // A truncated stream never reaches its stored length and CRC.
    assert_eq!(
        validate::validate("gz", &gz[..gz.len() - 12]),
        Verdict::Invalid
    );
}

#[test]
fn a_real_sqlite_database_matches_its_own_geometry() {
    let db = fixture("valid.sqlite");
    match validate::validate("sqlite", &db) {
        Verdict::Verified(Some(n)) => assert_eq!(n, db.len() as u64),
        other => panic!("valid database: {other:?}"),
    }
    // Over-read: the header's page count says where the database ends.
    let mut over = db.clone();
    over.extend_from_slice(&[0u8; 1000]);
    match validate::validate("sqlite", &over) {
        Verdict::Verified(Some(n)) => assert_eq!(n, db.len() as u64),
        other => panic!("over-read database: {other:?}"),
    }
    // An impossible page size is not a database.
    let mut bad = db.clone();
    bad[16] = 0x00;
    bad[17] = 0x03; // 768: not a power of two
    assert_eq!(validate::validate("sqlite", &bad), Verdict::Invalid);
}

#[test]
fn jpeg_and_gif_report_what_they_can_and_no_more() {
    // JPEG has no checksum: a marker walk can confirm the header and the
    // terminator, and must not claim more than that.
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    jpeg.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
    jpeg.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0, 0, 0, 0, 0, 0]);
    jpeg.extend_from_slice(&[0x11; 64]);
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    assert_eq!(validate::validate("jpg", &jpeg), Verdict::Verified(None));

    let mut no_eoi = jpeg.clone();
    no_eoi.truncate(no_eoi.len() - 2);
    assert_eq!(
        validate::validate("jpg", &no_eoi),
        Verdict::Inconclusive,
        "a missing terminator is uncertainty, not proof of corruption"
    );

    let mut bad_marker = jpeg.clone();
    bad_marker[2] = 0x00; // a segment that does not start with FF
    assert_eq!(validate::validate("jpg", &bad_marker), Verdict::Invalid);

    let mut gif = b"GIF89a".to_vec();
    gif.extend_from_slice(&[0x10, 0, 0x10, 0, 0x80, 0, 0]);
    gif.push(0x3B);
    assert_eq!(validate::validate("gif", &gif), Verdict::Verified(None));
    gif.pop();
    assert_eq!(validate::validate("gif", &gif), Verdict::Invalid);
}

#[test]
fn a_type_without_a_validator_is_left_alone() {
    assert!(!validate::can_validate("rtf"));
    assert_eq!(
        validate::validate("rtf", b"{\\rtf1 hello}"),
        Verdict::Inconclusive
    );
    // ...and one with a validator, handed the wrong bytes, says nothing either.
    assert_eq!(
        validate::validate("png", b"not a png"),
        Verdict::Inconclusive
    );
}

// -- through the carver ----------------------------------------------------

fn carve_with(
    validate: bool,
    drop_failed: bool,
    tag: &str,
) -> (Vec<breadcrumb_rs::carver::Record>, std::path::PathBuf) {
    use breadcrumb_rs::carver::{Carver, Options};
    use breadcrumb_rs::reader::Source;
    use breadcrumb_rs::signatures::resolve_types;

    let good = fixture("valid.docx");
    let mut broken = fixture("valid.docx");
    let at = broken.len() / 2;
    broken[at] ^= 0x40; // a member that will not inflate to its CRC

    // Two documents in one image, with slack between them.
    let mut img = vec![0u8; 4096];
    img.extend_from_slice(&good);
    img.extend_from_slice(&vec![0u8; 4096]);
    img.extend_from_slice(&broken);
    img.extend_from_slice(&vec![0u8; 4096]);

    let mut dir = std::env::temp_dir();
    dir.push(format!("bcrumb-validate-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let img_path = dir.join("disk.dd");
    std::fs::write(&img_path, &img).unwrap();

    let src = Source::open(img_path.to_str().unwrap()).unwrap();
    let opts = Options {
        out_dir: dir.join("out").to_string_lossy().to_string(),
        validate,
        drop_failed,
        ..Default::default()
    };
    let sigs = resolve_types("docx,zip").unwrap();
    let records = Carver::new(&src, sigs, &opts).run();
    (records, dir)
}

#[test]
fn validation_separates_an_intact_document_from_a_damaged_one() {
    let (records, dir) = carve_with(true, false, "keep");
    let verified: Vec<&breadcrumb_rs::carver::Record> =
        records.iter().filter(|r| r.decoded == Some(true)).collect();
    let failed: Vec<&breadcrumb_rs::carver::Record> = records
        .iter()
        .filter(|r| r.decoded == Some(false))
        .collect();
    assert_eq!(
        verified.len(),
        1,
        "one document should decode: {records:#?}"
    );
    // The damaged document is reported at its own offset. It is not skipped
    // over the way a verified carve is, so the archive members inside it are
    // examined too and fail in their turn -- which is right: nothing about
    // those bytes has been established.
    assert!(!failed.is_empty(), "nothing failed to decode: {records:#?}");
    assert_eq!(verified[0].offset, 4096);
    assert_eq!(failed[0].offset, 8770);
    assert_eq!(verified[0].confidence(), "verified");
    assert_eq!(failed[0].confidence(), "failed");
    // The failed one is still on disk: an analyst decides what to do with it.
    assert!(std::path::Path::new(&failed[0].path).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn drop_failed_leaves_only_what_decodes() {
    let (records, dir) = carve_with(true, true, "drop");
    assert_eq!(records.len(), 1, "only the intact document should survive");
    assert_eq!(records[0].decoded, Some(true));
    let written: Vec<std::path::PathBuf> = std::fs::read_dir(dir.join("out/docx"))
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    assert_eq!(
        written.len(),
        1,
        "a rejected carve was still written: {written:?}"
    );
    // What landed on disk is the document, byte for byte.
    assert_eq!(std::fs::read(&written[0]).unwrap(), fixture("valid.docx"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn without_validation_both_documents_look_alike() {
    // The point of --validate: the structure walk cannot tell these apart.
    let (records, dir) = carve_with(false, false, "off");
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.decoded.is_none()));
    assert!(records.iter().all(|r| r.confidence() == "high"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_pdf_is_checked_against_its_own_cross_reference_offset() {
    // Both ways a carved PDF goes wrong, and both were found on live evidence:
    // an end marker belonging to unrelated data further along, and a document
    // whose trailer was overwritten while it sat in free space -- leaving NULs
    // where the offset should be.
    let mut pdf: Vec<u8> = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n".to_vec();
    let xref_at = pdf.len();
    pdf.extend_from_slice(b"xref\n0 1\ntrailer\n<< /Root 1 0 R >>\n");
    pdf.extend_from_slice(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());

    match validate::validate("pdf", &pdf) {
        Verdict::Verified(Some(n)) => assert_eq!(n, pdf.len() as u64),
        other => panic!("a sound PDF: {other:?}"),
    }

    // Trailing bytes are dropped rather than kept.
    let mut over = pdf.clone();
    over.extend_from_slice(&[0x41; 4096]);
    match validate::validate("pdf", &over) {
        Verdict::Verified(Some(n)) => assert_eq!(n, pdf.len() as u64, "not tightened"),
        other => panic!("over-read PDF: {other:?}"),
    }

    // A NUL where the offset belongs: the trailer is gone, which is what an
    // overwritten cluster in free space leaves behind.
    let mut wiped = pdf.clone();
    let at = wiped
        .windows(9)
        .position(|w| w == b"startxref")
        .expect("startxref");
    let eof = wiped
        .windows(5)
        .rposition(|w| w == b"%%EOF")
        .expect("%%EOF");
    for b in wiped[at + 9..eof].iter_mut() {
        *b = 0;
    }
    assert_eq!(validate::validate("pdf", &wiped), Verdict::Invalid);

    // An offset outside the carve, which is what an over-carved PDF looks like:
    // the trailer describes a document larger than the bytes on hand.
    let bad = String::from_utf8_lossy(&pdf)
        .replace(&format!("startxref\n{xref_at}"), "startxref\n99999999")
        .into_bytes();
    assert_eq!(validate::validate("pdf", &bad), Verdict::Invalid);

    // Not a PDF at all: say nothing rather than condemn it.
    assert_eq!(
        validate::validate("pdf", b"just some bytes"),
        Verdict::Inconclusive
    );
}
