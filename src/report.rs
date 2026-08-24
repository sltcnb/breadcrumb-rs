//! Derived outputs: CSV, Sleuth Kit bodyfile, timeline, and an HTML report.
//!
//! All four are computed from the same records the manifest holds, so they can
//! be regenerated from a manifest without rescanning.

use crate::carver::Record;
use std::fmt::Write as _;

fn csv_cell(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn csv(records: &[Record]) -> String {
    let mut out =
        String::from("type,ext,offset,size,sha256,validated,confidence,duplicate_of,path\n");
    for r in records {
        let dup = r.duplicate_of.map(|d| d.to_string()).unwrap_or_default();
        let _ = writeln!(
            out,
            "{},{},{},{},{},{},{},{},{}",
            csv_cell(r.kind),
            csv_cell(r.ext),
            r.offset,
            r.size,
            r.sha256,
            // "True"/"False" rather than Rust's lowercase, so a CSV from either
            // implementation diffs cleanly against the other.
            if r.validated { "True" } else { "False" },
            r.confidence(),
            dup,
            csv_cell(&r.path)
        );
    }
    out
}

/// Sleuth Kit body format v3. Carving has no timestamps, so the offset stands
/// in for the inode and the time fields are zero.
pub fn bodyfile(records: &[Record]) -> String {
    let mut out = String::new();
    for r in records {
        let name = if r.path.is_empty() {
            format!("carved_{:#x}.{}", r.offset, r.ext)
        } else {
            r.path.clone()
        };
        let _ = writeln!(
            out,
            "{}|{}|{}|0|0|0|{}|0|0|0|0",
            r.sha256, name, r.offset, r.size
        );
    }
    out
}

/// Timeline rows. Carved files carry no timestamps of their own, so the rows
/// are ordered by offset -- the order the bytes appear on the disk.
pub fn timeline(records: &[Record]) -> String {
    let mut rows: Vec<&Record> = records.iter().collect();
    rows.sort_by_key(|r| r.offset);
    let mut out = String::from("offset,ext,size,sha256,confidence,path\n");
    for r in rows {
        let _ = writeln!(
            out,
            "{},{},{},{},{},{}",
            r.offset,
            csv_cell(r.ext),
            r.size,
            r.sha256,
            r.confidence(),
            csv_cell(&r.path)
        );
    }
    out
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn html(source: &str, source_size: u64, records: &[Record], elapsed: f64) -> String {
    let mut by_ext: Vec<(&str, usize, u64)> = Vec::new();
    for r in records {
        match by_ext.iter_mut().find(|(e, _, _)| *e == r.ext) {
            Some(row) => {
                row.1 += 1;
                row.2 += r.size;
            }
            None => by_ext.push((r.ext, 1, r.size)),
        }
    }
    by_ext.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let total: u64 = records.iter().map(|r| r.size).sum();

    let mut out = String::new();
    out.push_str("<!doctype html><meta charset=\"utf-8\">\n");
    out.push_str("<title>BreadCrumb report</title>\n<style>\n");
    out.push_str(
        "body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:70rem}\
         table{border-collapse:collapse;width:100%;margin:1rem 0}\
         th,td{border-bottom:1px solid #ddd;padding:.35rem .6rem;text-align:left}\
         th{background:#f6f6f6}td.n{text-align:right;font-variant-numeric:tabular-nums}\
         code{background:#f2f2f2;padding:.1rem .3rem}\
         .low{color:#a60}.high{color:#060}\n",
    );
    out.push_str("</style>\n");
    let _ = writeln!(
        out,
        "<h1>BreadCrumb report</h1>\n<p>Source <code>{}</code> ({} bytes) — \
         {} file(s) recovered, {} bytes, in {:.2}s.</p>",
        esc(source),
        source_size,
        records.len(),
        total,
        elapsed
    );

    out.push_str("<h2>By type</h2>\n<table><tr><th>type<th>files<th>bytes</tr>\n");
    for (ext, count, bytes) in &by_ext {
        let _ = writeln!(
            out,
            "<tr><td>{}<td class=n>{}<td class=n>{}</tr>",
            esc(ext),
            count,
            bytes
        );
    }
    out.push_str("</table>\n<h2>Files</h2>\n<table>");
    out.push_str("<tr><th>offset<th>type<th>size<th>confidence<th>sha256<th>path</tr>\n");
    let mut rows: Vec<&Record> = records.iter().collect();
    rows.sort_by_key(|r| r.offset);
    for r in rows {
        let cls = if r.validated { "high" } else { "low" };
        let _ = writeln!(
            out,
            "<tr><td class=n>{:#x}<td>{}<td class=n>{}<td class={}>{}\
             <td><code>{}</code><td>{}</tr>",
            r.offset,
            esc(r.ext),
            r.size,
            cls,
            r.confidence(),
            &r.sha256[..16.min(r.sha256.len())],
            esc(&r.path)
        );
    }
    out.push_str("</table>\n");
    out
}
