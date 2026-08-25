//! Deletion artefacts: $Recycle.Bin/$I records and the $UsnJrnl change journal.
//!
//! The records here are built from the documented structures, not from what the
//! parser happens to read, which is the only way a fixture can catch a wrong
//! field offset:
//!
//!   $I v2:  version u64 @0, original size u64 @8, deletion FILETIME u64 @16,
//!           path length in characters u32 @24, UTF-16LE path @28
//!   $I v1:  same header, then a fixed 260-character path field @24
//!   USN v2: RecordLength @0, Major @4, Minor @6, FileReferenceNumber @8,
//!           ParentFileReferenceNumber @16, Usn @24, TimeStamp @32, Reason @40,
//!           SourceInfo @44, SecurityId @48, FileAttributes @52,
//!           FileNameLength @56, FileNameOffset @58, FileName @60
//!   USN v3: 128-bit references, so Usn @40, TimeStamp @48, Reason @56,
//!           FileNameLength @72, FileNameOffset @74, FileName @76

use breadcrumb_rs::artifacts::{
    self, parse_recycle_i, parse_usn_journal, UsnRecord, USN_REASON_FILE_DELETE,
};

const FILETIME_EPOCH: u64 = 116_444_736_000_000_000;

fn filetime(unix: u64) -> u64 {
    FILETIME_EPOCH + unix * 10_000_000
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn recycle_v2(path: &str, size: u64, when: u64) -> Vec<u8> {
    let mut p = utf16(path);
    p.extend_from_slice(&[0, 0]); // the path field is NUL-terminated
    let mut out = vec![0u8; 28 + p.len()];
    out[0..8].copy_from_slice(&2u64.to_le_bytes());
    out[8..16].copy_from_slice(&size.to_le_bytes());
    out[16..24].copy_from_slice(&filetime(when).to_le_bytes());
    out[24..28].copy_from_slice(&((p.len() / 2) as u32).to_le_bytes());
    out[28..].copy_from_slice(&p);
    out
}

fn recycle_v1(path: &str, size: u64, when: u64) -> Vec<u8> {
    let mut out = vec![0u8; 24 + 520];
    out[0..8].copy_from_slice(&1u64.to_le_bytes());
    out[8..16].copy_from_slice(&size.to_le_bytes());
    out[16..24].copy_from_slice(&filetime(when).to_le_bytes());
    let p = utf16(path);
    out[24..24 + p.len()].copy_from_slice(&p);
    out
}

fn usn(name: &str, reason: u32, when: u64, usn_no: u64, major: u16) -> Vec<u8> {
    let nm = utf16(name);
    let head = if major == 2 { 24 } else { 40 };
    let name_off = head + 36;
    let mut length = name_off + nm.len();
    length += (8 - length % 8) % 8;
    let mut r = vec![0u8; length];
    r[0..4].copy_from_slice(&(length as u32).to_le_bytes());
    r[4..6].copy_from_slice(&major.to_le_bytes());
    r[8..16].copy_from_slice(&0x1234u64.to_le_bytes()); // file reference
    let parent_at = if major == 2 { 16 } else { 24 };
    r[parent_at..parent_at + 8].copy_from_slice(&5u64.to_le_bytes());
    r[head..head + 8].copy_from_slice(&usn_no.to_le_bytes());
    r[head + 8..head + 16].copy_from_slice(&filetime(when).to_le_bytes());
    r[head + 16..head + 20].copy_from_slice(&reason.to_le_bytes());
    r[head + 32..head + 34].copy_from_slice(&(nm.len() as u16).to_le_bytes());
    r[head + 34..head + 36].copy_from_slice(&(name_off as u16).to_le_bytes());
    r[name_off..name_off + nm.len()].copy_from_slice(&nm);
    r
}

fn journal() -> Vec<u8> {
    let mut j = vec![0u8; 4096]; // the journal opens with a sparse hole
    j.extend(usn("created.txt", 0x100, 1_700_000_100, 0x1000, 2));
    j.extend(usn(
        "deleted-one.txt",
        USN_REASON_FILE_DELETE | 0x8000_0000,
        1_700_000_200,
        0x1100,
        2,
    ));
    j.extend(usn(
        "deleted-two.docx",
        USN_REASON_FILE_DELETE,
        1_700_000_300,
        0x1200,
        3,
    ));
    j.extend(usn("renamed.txt", 0x1000, 1_700_000_400, 0x1300, 2));
    j
}

fn parse_all(data: &[u8]) -> Vec<UsnRecord> {
    let mut out = Vec::new();
    parse_usn_journal(data, &mut out);
    out
}

// -- $I --------------------------------------------------------------------

#[test]
fn recycle_v2_gives_the_deletion_time_size_and_original_path() {
    let e = parse_recycle_i(&recycle_v2(
        r"C:\Users\analyste\Documents\evidence.xlsx",
        44_213,
        1_700_000_500,
    ))
    .expect("v2 record refused");
    assert_eq!(e.version, 2);
    assert_eq!(e.deleted, 1_700_000_500);
    assert_eq!(e.size, 44_213);
    assert_eq!(e.path, r"C:\Users\analyste\Documents\evidence.xlsx");
}

#[test]
fn recycle_v1_reads_the_fixed_length_path_field() {
    let e = parse_recycle_i(&recycle_v1(r"D:\old\report.doc", 1024, 1_600_000_000))
        .expect("v1 record refused");
    assert_eq!(e.version, 1);
    assert_eq!(e.path, r"D:\old\report.doc");
    assert_eq!(e.deleted, 1_600_000_000);
}

#[test]
fn a_malformed_recycle_record_is_refused_not_guessed_at() {
    let good = recycle_v2(r"C:\x.txt", 10, 1_700_000_000);
    assert!(parse_recycle_i(&good[..20]).is_none(), "truncated accepted");

    let mut bad_version = good.clone();
    bad_version[0] = 9;
    assert!(
        parse_recycle_i(&bad_version).is_none(),
        "version 9 accepted"
    );

    let mut too_long = good.clone();
    too_long[24..28].copy_from_slice(&99_999u32.to_le_bytes());
    assert!(
        parse_recycle_i(&too_long).is_none(),
        "path running past the end accepted"
    );

    let mut empty_path = good.clone();
    empty_path[28..30].copy_from_slice(&[0, 0]);
    assert!(
        parse_recycle_i(&empty_path).is_none(),
        "empty path accepted"
    );
}

// -- $UsnJrnl --------------------------------------------------------------

#[test]
fn the_journal_is_read_past_its_sparse_hole_in_both_record_versions() {
    let recs = parse_all(&journal());
    let names: Vec<&str> = recs.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "created.txt",
            "deleted-one.txt",
            "deleted-two.docx",
            "renamed.txt"
        ]
    );
    assert_eq!(recs[0].version, (2, 0));
    assert_eq!(recs[2].version, (3, 0), "V3 record not recognised");
    assert_eq!(recs[2].mft_record(), 0x1234);
    assert_eq!(recs[1].timestamp, 1_700_000_200);
    assert_eq!(recs[1].usn, 0x1100);
    let deleted: Vec<&str> = recs
        .iter()
        .filter(|r| r.deleted())
        .map(|r| r.name.as_str())
        .collect();
    assert_eq!(deleted, vec!["deleted-one.txt", "deleted-two.docx"]);
    assert_eq!(
        artifacts::describe_reasons(recs[1].reason),
        "file-delete|close"
    );
    assert_eq!(artifacts::describe_reasons(0x4000_0000), "0x40000000");
    assert_eq!(artifacts::describe_reasons(0), "none");
}

#[test]
fn a_journal_starting_mid_record_resynchronises() {
    // A carved journal rarely starts on a record boundary.
    let full = journal();
    let cut = &full[4096 + 6..];
    let recs = parse_all(cut);
    let names: Vec<&str> = recs.iter().map(|r| r.name.as_str()).collect();
    assert!(
        names.contains(&"deleted-two.docx") && names.contains(&"renamed.txt"),
        "did not resynchronise: {names:?}"
    );
    assert!(
        !names.contains(&"created.txt"),
        "parsed a record it cut into"
    );
}

#[test]
fn a_record_split_across_two_blocks_is_left_for_the_next_one() {
    // Feeding the journal in blocks must not half-parse the record on the seam.
    let full = journal();
    let seam = full.len() - 30;
    let mut recs = Vec::new();
    let consumed = parse_usn_journal(&full[..seam], &mut recs);
    assert!(consumed <= seam);
    assert_eq!(recs.len(), 3, "the split record should not be reported yet");
    let mut rest = full[consumed..seam].to_vec();
    rest.extend_from_slice(&full[seam..]);
    let mut tail = Vec::new();
    parse_usn_journal(&rest, &mut tail);
    assert_eq!(
        tail.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        vec!["renamed.txt"],
        "the carried-over record was lost"
    );
}

#[test]
fn a_record_whose_name_runs_past_its_length_is_skipped() {
    let mut j = usn("victim.txt", USN_REASON_FILE_DELETE, 1_700_000_000, 1, 2);
    j[24 + 32..24 + 34].copy_from_slice(&4000u16.to_le_bytes()); // name length
    j.extend(usn(
        "survivor.txt",
        USN_REASON_FILE_DELETE,
        1_700_000_001,
        2,
        2,
    ));
    let recs = parse_all(&j);
    assert_eq!(
        recs.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
        vec!["survivor.txt"]
    );
}

// -- reporting -------------------------------------------------------------

#[test]
fn the_events_csv_is_sorted_oldest_first_and_quotes_commas() {
    let mut events = artifacts::events_from_usn(&journal(), true);
    events.extend(artifacts::events_from_recycle(
        &recycle_v2(r"C:\a,b\odd,name.txt", 7, 1_600_000_000),
        "$IZZ.txt",
    ));
    let mut path = std::env::temp_dir();
    path.push(format!("bcrumb-events-{}.csv", std::process::id()));
    let p = path.to_string_lossy().to_string();
    let n = artifacts::write_events_csv(&events, &p).unwrap();
    assert_eq!(n, 3);
    let text = std::fs::read_to_string(&p).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "deleted_utc,unix,source,name,size,detail");
    assert!(lines[1].starts_with("2020-09-13 12:26:40,1600000000,$I,"));
    assert!(
        lines[1].contains("\"C:\\a,b\\odd,name.txt\""),
        "comma in a path was not quoted: {}",
        lines[1]
    );
    assert!(lines[2].contains("deleted-one.txt"));
    assert!(lines[3].contains("deleted-two.docx"));
    let _ = std::fs::remove_file(&p);
}

// -- straight off a volume -------------------------------------------------

#[test]
fn artefacts_are_read_from_the_volume_with_their_paths() {
    // The fixture carries $Recycle.Bin/$IAB12CD.xlsx and $Extend/$UsnJrnl:$J,
    // the journal's data behind a sparse hole.
    let img = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join("ntfs_artifacts.img");
    let src = breadcrumb_rs::reader::Source::open(img.to_str().unwrap()).unwrap();
    let found = breadcrumb_rs::ntfs::deletion_events(&src, 0, true, 1 << 20).unwrap();

    let sources: Vec<&str> = found.sources.iter().map(|(p, _)| p.as_str()).collect();
    assert!(
        sources.contains(&"$Recycle.Bin/$IAB12CD.xlsx"),
        "recycle bin record not found: {sources:?}"
    );
    assert!(
        sources.contains(&"$Extend/$UsnJrnl~$J"),
        "change journal not found: {sources:?}"
    );

    let names: Vec<&str> = found.events.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&r"C:\Users\analyste\Documents\evidence.xlsx"));
    assert!(names.contains(&"deleted-one.txt") && names.contains(&"deleted-two.docx"));
    assert!(
        !names.contains(&"created.txt"),
        "a non-deletion reason leaked into the deletions"
    );
    // ...and with --usn-all, the rest of the journal comes too.
    let all = breadcrumb_rs::ntfs::deletion_events(&src, 0, false, 1 << 20).unwrap();
    assert!(all.events.len() > found.events.len());
}
