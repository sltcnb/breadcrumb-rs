//! Partition table parsing and filesystem detection.
//!
//! MBR (including the extended/logical chain), GPT, and Apple Partition Map,
//! plus superblock sniffing at each partition start so `--list-partitions` can
//! summarise a disk and the undelete modes know where to look.

use crate::reader::Source;

#[derive(Debug, Clone)]
pub struct Partition {
    pub index: usize,
    pub scheme: &'static str,
    pub start: u64,
    pub size: u64,
    pub type_id: String,
    pub name: String,
    pub fstype: &'static str,
}

fn u16le(b: &[u8], o: usize) -> u64 {
    if o + 2 > b.len() {
        return 0;
    }
    u16::from_le_bytes([b[o], b[o + 1]]) as u64
}
fn u32le(b: &[u8], o: usize) -> u64 {
    if o + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64
}
fn u64le(b: &[u8], o: usize) -> u64 {
    if o + 8 > b.len() {
        return 0;
    }
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}
fn u32be(b: &[u8], o: usize) -> u64 {
    if o + 4 > b.len() {
        return 0;
    }
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64
}

const MBR_TYPES: &[(u8, &str)] = &[
    (0x01, "FAT12"),
    (0x04, "FAT16"),
    (0x06, "FAT16B"),
    (0x07, "NTFS/exFAT"),
    (0x0B, "FAT32"),
    (0x0C, "FAT32L"),
    (0x0E, "FAT16L"),
    (0x05, "extended"),
    (0x0F, "extended"),
    (0x82, "linux-swap"),
    (0x83, "linux"),
    (0x8E, "linux-lvm"),
    (0xA5, "freebsd"),
    (0xA8, "apple-ufs"),
    (0xAF, "apple-hfs"),
    (0xEE, "gpt-protective"),
    (0xEF, "efi"),
    (0xFD, "linux-raid"),
];

const GPT_TYPES: &[(&str, &str)] = &[
    ("c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "efi-system"),
    ("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", "basic-data"),
    ("0fc63daf-8483-4772-8e79-3d69d8477de4", "linux-fs"),
    ("e6d6d379-f507-44c2-a23c-238f2a3df928", "linux-lvm"),
    ("a19d880f-05fc-4d3b-a006-743f0f84911e", "linux-raid"),
    ("0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "linux-swap"),
    ("933ac7e1-2eb4-4f13-b844-0e14e2aef915", "linux-home"),
    ("48465300-0000-11aa-aa11-00306543ecac", "apple-hfs"),
    ("7c3457ef-0000-11aa-aa11-00306543ecac", "apple-apfs"),
    ("53746f72-6167-11aa-aa11-00306543ecac", "apple-core-storage"),
    ("426f6f74-0000-11aa-aa11-00306543ecac", "apple-boot"),
];

/// Identify the filesystem or encryption container at a byte offset.
pub fn detect_fs(src: &Source, offset: u64) -> &'static str {
    let head = src.pread(offset, 1024);
    if head.len() < 512 {
        return "";
    }
    if &head[3..11] == b"NTFS    " {
        return "ntfs";
    }
    if &head[3..11] == b"EXFAT   " {
        return "exfat";
    }
    if &head[3..11] == b"-FVE-FS-" {
        return "bitlocker";
    }
    if &head[510..512] == b"\x55\xaa" {
        let fs32 = head.len() >= 90 && &head[82..90] == b"FAT32   ";
        let fs16 =
            head.len() >= 62 && matches!(&head[54..62], b"FAT12   " | b"FAT16   " | b"FAT     ");
        if fs32 || fs16 {
            return "fat";
        }
        if matches!(u16le(&head, 11), 512 | 1024 | 2048 | 4096)
            && head[13] != 0
            && u16le(&head, 14) != 0
        {
            return "fat";
        }
    }
    // ext2/3/4 superblock lives 1024 bytes in
    let sb = src.pread(offset + 1024, 512);
    if sb.len() >= 58 && u16le(&sb, 56) == 0xEF53 {
        return "ext";
    }
    // HFS+/HFSX: the volume header is 1024 bytes into the volume, which is
    // past `head` -- reading only the first sector finds nothing.
    if matches!(&head[..4], b"H+\x00\x04" | b"HX\x00\x05")
        || matches!(&sb[..2.min(sb.len())], b"H+" | b"HX")
    {
        return "hfs+";
    }
    if src.pread(offset + 32, 4) == b"NXSB" {
        return "apfs";
    }
    if &head[..6] == b"LUKS\xba\xbe" {
        return "luks";
    }
    ""
}

/// Which undelete mode fits a detected filesystem.
pub fn fs_to_mode(fstype: &str) -> Option<&'static str> {
    Some(match fstype {
        "ntfs" => "ntfs",
        "exfat" | "fat" => "fat",
        "ext" => "ext4",
        "hfs+" => "hfs",
        "apfs" => "apfs",
        _ => return None,
    })
}

/// A 16-byte mixed-endian GUID as its canonical string.
fn guid_le(b: &[u8]) -> String {
    if b.len() < 16 {
        return String::new();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        b[3],
        b[2],
        b[1],
        b[0],
        b[5],
        b[4],
        b[7],
        b[6],
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    )
}

pub fn parse(src: &Source) -> Vec<Partition> {
    let sector0 = src.pread(0, 512);
    if sector0.len() < 512 || &sector0[510..512] != b"\x55\xaa" {
        return parse_apm(src); // could still be an Apple Partition Map disk
    }
    let gpt = parse_gpt(src);
    if !gpt.is_empty() {
        return gpt;
    }
    parse_mbr(src)
}

fn mbr_label(ptype: u8) -> &'static str {
    MBR_TYPES
        .iter()
        .find(|(t, _)| *t == ptype)
        .map(|(_, l)| *l)
        .unwrap_or("")
}

fn parse_mbr(src: &Source) -> Vec<Partition> {
    let sector0 = src.pread(0, 512);
    let mut parts = Vec::new();
    let mut idx = 0usize;
    for i in 0..4usize {
        let e = &sector0[446 + i * 16..446 + (i + 1) * 16];
        let ptype = e[4];
        let lba = u32le(e, 8);
        let count = u32le(e, 12);
        if ptype == 0 || lba == 0 {
            continue;
        }
        if ptype == 0x05 || ptype == 0x0F {
            parts.extend(parse_ebr(src, lba, idx)); // extended: walk the chain
            idx = parts.len();
            continue;
        }
        let off = lba * 512;
        parts.push(Partition {
            index: idx,
            scheme: "mbr",
            start: off,
            size: count * 512,
            type_id: format!("0x{ptype:02X}"),
            name: mbr_label(ptype).to_string(),
            fstype: detect_fs(src, off),
        });
        idx += 1;
    }
    parts
}

fn parse_ebr(src: &Source, ext_lba: u64, start_idx: usize) -> Vec<Partition> {
    let mut parts = Vec::new();
    let mut cur = ext_lba;
    let mut idx = start_idx;
    let mut seen: Vec<u64> = Vec::new();
    while cur != 0 && !seen.contains(&cur) && parts.len() < 128 {
        seen.push(cur);
        let ebr = src.pread(cur * 512, 512);
        if ebr.len() < 512 || &ebr[510..512] != b"\x55\xaa" {
            break;
        }
        let e = &ebr[446..462];
        let (ptype, lba, count) = (e[4], u32le(e, 8), u32le(e, 12));
        if ptype != 0 && lba != 0 {
            let off = (cur + lba) * 512;
            let label = mbr_label(ptype);
            parts.push(Partition {
                index: idx,
                scheme: "mbr",
                start: off,
                size: count * 512,
                type_id: format!("0x{ptype:02X}"),
                name: if label.is_empty() {
                    "logical".into()
                } else {
                    label.into()
                },
                fstype: detect_fs(src, off),
            });
            idx += 1;
        }
        let nxt_lba = u32le(&ebr[462..478], 8);
        cur = if nxt_lba != 0 { ext_lba + nxt_lba } else { 0 };
    }
    parts
}

fn parse_gpt(src: &Source) -> Vec<Partition> {
    let hdr = src.pread(512, 512);
    if hdr.len() < 512 || &hdr[..8] != b"EFI PART" {
        return Vec::new();
    }
    let entry_lba = u64le(&hdr, 72);
    let num = u32le(&hdr, 80);
    let esize = u32le(&hdr, 84);
    if !(1..=1024).contains(&num) || esize < 128 {
        return Vec::new();
    }
    let table = src.pread(entry_lba * 512, (num * esize) as usize);
    let mut parts = Vec::new();
    let mut idx = 0usize;
    for i in 0..num as usize {
        let lo = i * esize as usize;
        if lo + 128 > table.len() {
            break;
        }
        let e = &table[lo..lo + esize as usize];
        let type_guid = guid_le(&e[..16]);
        if type_guid == "00000000-0000-0000-0000-000000000000" {
            continue;
        }
        let first = u64le(e, 32);
        let last = u64le(e, 40);
        let name: String = e[56..128]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .filter_map(|u| char::from_u32(u as u32))
            .collect();
        let label = GPT_TYPES
            .iter()
            .find(|(g, _)| *g == type_guid)
            .map(|(_, l)| l.to_string())
            .unwrap_or_else(|| name.clone());
        let off = first * 512;
        parts.push(Partition {
            index: idx,
            scheme: "gpt",
            start: off,
            size: (last + 1 - first.min(last + 1)) * 512,
            type_id: type_guid,
            name: label,
            fstype: detect_fs(src, off),
        });
        idx += 1;
    }
    parts
}

fn parse_apm(src: &Source) -> Vec<Partition> {
    let blk1 = src.pread(512, 512);
    if blk1.len() < 512 || &blk1[..2] != b"PM" {
        return Vec::new();
    }
    let total = u32be(&blk1, 4).min(64);
    let mut parts = Vec::new();
    for i in 0..total as usize {
        let e = src.pread(512 * (1 + i as u64), 512);
        if e.len() < 512 || &e[..2] != b"PM" {
            break;
        }
        let ascii = |b: &[u8]| -> String {
            b.iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as char)
                .collect()
        };
        let start = u32be(&e, 8) * 512;
        parts.push(Partition {
            index: i,
            scheme: "apm",
            start,
            size: u32be(&e, 12) * 512,
            type_id: ascii(&e[48..80]),
            name: ascii(&e[16..48]),
            fstype: detect_fs(src, start),
        });
    }
    parts
}

pub fn format_table(parts: &[Partition]) -> String {
    if parts.is_empty() {
        return "no partitions found (whole-disk filesystem or unknown scheme)".into();
    }
    let mut lines = vec![format!(
        "{:>2}  {:<6} {:>14} {:>12}  {:<24} {:<10} name",
        "#", "scheme", "start", "size", "type", "fs"
    )];
    for p in parts {
        let size = if p.size > 0 {
            format!("{}M", p.size / (1 << 20))
        } else {
            "?".to_string()
        };
        let type_id: String = p.type_id.chars().take(24).collect();
        lines.push(format!(
            "{:>2}  {:<6} {:>14} {:>12}  {:<24} {:<10} {}",
            p.index, p.scheme, p.start, size, type_id, p.fstype, p.name
        ));
    }
    lines.join("\n")
}
