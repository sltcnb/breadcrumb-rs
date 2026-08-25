//! Signatures defined by the analyst, and the JSON reader behind them.
//!
//! A format nobody has heard of is the ordinary case in a real examination:
//! an application's own container, a proprietary log. A magic and an end marker
//! are enough to carve it, and getting that wrong should be a clear error
//! rather than a scan that quietly finds nothing.

use breadcrumb_rs::carver::{Carver, Options};
use breadcrumb_rs::customsig;
use breadcrumb_rs::jsonin::{self, Value};
use breadcrumb_rs::reader::Source;

struct Tmp(std::path::PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("bcrumb-customsig-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn write(&self, name: &str, body: &[u8]) -> String {
        let p = self.0.join(name);
        std::fs::write(&p, body).unwrap();
        p.to_string_lossy().to_string()
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// -- the JSON reader -------------------------------------------------------

#[test]
fn json_reads_the_shapes_a_config_file_uses() {
    let v = jsonin::parse(
        r#"{"a": 1, "b": [true, false, null], "c": {"d": "x\tyé"},
            "e": -2.5e3, "f": ""}"#,
    )
    .unwrap();
    assert_eq!(v.get("a").and_then(Value::as_f64), Some(1.0));
    assert_eq!(v.get("b").and_then(Value::as_array).unwrap().len(), 3);
    assert_eq!(
        v.get("c").and_then(|c| c.get("d")).and_then(Value::as_str),
        Some("x\ty\u{e9}")
    );
    assert_eq!(v.get("e").and_then(Value::as_f64), Some(-2500.0));
    assert_eq!(v.get("f").and_then(Value::as_str), Some(""));
    // Non-ASCII straight from the file, not escaped.
    let v = jsonin::parse(r#"{"name": "café ☕"}"#).unwrap();
    assert_eq!(v.get("name").and_then(Value::as_str), Some("café ☕"));
}

#[test]
fn malformed_json_is_an_error_with_a_position() {
    for bad in [
        "{",
        "{\"a\": }",
        "[1, 2",
        "{\"a\": 1} trailing",
        "{\"a\" 1}",
        "\"unterminated",
    ] {
        assert!(jsonin::parse(bad).is_err(), "accepted {bad:?}");
    }
    // Deep nesting stops rather than recursing until the stack gives out.
    let deep = "[".repeat(200) + &"]".repeat(200);
    assert!(jsonin::parse(&deep).is_err());
}

// -- loading signatures ----------------------------------------------------

#[test]
fn a_signature_file_loads_names_magics_and_caps() {
    let dir = Tmp::new("load");
    let path = dir.write(
        "sigs.json",
        br#"[
            {"name": "widget", "ext": "wdg", "magic": "57 49 44 47",
             "footer": "454e4457", "max_size": "1M"},
            {"name": "blob", "magic": ["0xCAFEBABE", "DEADBEEF"], "max_size": 4096}
        ]"#,
    );
    let sigs = customsig::load(&path).expect("load failed");
    assert_eq!(sigs.len(), 2);
    assert_eq!(sigs[0].name, "widget");
    assert_eq!(sigs[0].magics, &[b"WIDG".as_slice()]);
    assert_eq!(sigs[0].max_size, 1 << 20);
    assert_eq!(sigs[1].magics.len(), 2, "two magics for one type");
    assert_eq!(sigs[1].magics[0], &[0xCA, 0xFE, 0xBA, 0xBE]);
    assert_eq!(sigs[1].max_size, 4096);

    // The wrapped form is accepted too.
    let wrapped = dir.write(
        "wrapped.json",
        br#"{"signatures": [{"name": "x", "magic": "AA55"}]}"#,
    );
    assert_eq!(customsig::load(&wrapped).unwrap().len(), 1);
}

#[test]
fn a_bad_signature_file_says_what_is_wrong() {
    let dir = Tmp::new("bad");
    let cases: [(&str, &str); 6] = [
        (r#"[{"ext": "x", "magic": "AA"}]"#, "name"),
        (r#"[{"name": "x"}]"#, "magic"),
        (r#"[{"name": "x", "magic": "ABC"}]"#, "hex"),
        (r#"[{"name": "x", "magic": ""}]"#, "hex"),
        (r#"[]"#, "no signatures"),
        (r#"{"signatures": 3}"#, "list"),
    ];
    for (i, (body, want)) in cases.iter().enumerate() {
        let path = dir.write(&format!("bad{i}.json"), body.as_bytes());
        let err = match customsig::load(&path) {
            Err(e) => e,
            Ok(sigs) => panic!("accepted {body}: {} signature(s)", sigs.len()),
        };
        assert!(
            err.to_lowercase().contains(want),
            "{body} -> {err} (expected mention of {want})"
        );
    }
    assert!(customsig::load("/nonexistent/sigs.json").is_err());
}

// -- carving with them -----------------------------------------------------

fn carve_custom(sig_json: &[u8], image: &[u8], tag: &str) -> Vec<breadcrumb_rs::carver::Record> {
    let dir = Tmp::new(tag);
    let sig_path = dir.write("sigs.json", sig_json);
    let img_path = dir.write("disk.dd", image);
    let sigs = customsig::load(&sig_path).expect("load failed");
    let src = Source::open(&img_path).unwrap();
    let opts = Options {
        out_dir: dir.0.join("out").to_string_lossy().to_string(),
        dry_run: true, // the records are what is being checked
        ..Default::default()
    };
    Carver::new(&src, sigs, &opts).run()
}

#[test]
fn a_custom_footer_signature_carves_exactly_to_its_end_marker() {
    let mut img = vec![0u8; 1000];
    img.extend_from_slice(b"WIDGpayload-oneENDW");
    img.extend_from_slice(&vec![0u8; 500]);
    let recs = carve_custom(
        br#"[{"name": "widget", "ext": "wdg", "magic": "57494447",
              "footer": "454e4457", "max_size": "1M"}]"#,
        &img,
        "footer",
    );
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].offset, 1000);
    assert_eq!(recs[0].size, 19, "should end after the footer");
    assert_eq!(recs[0].ext, "wdg");
    assert!(recs[0].validated, "a footer match is a known end");
}

#[test]
fn a_missing_footer_is_refused_unless_it_was_declared_optional() {
    let mut img = vec![0u8; 100];
    img.extend_from_slice(b"WIDGpayload with no end marker");
    img.extend_from_slice(&vec![0u8; 400]);

    let strict = carve_custom(
        br#"[{"name": "widget", "magic": "57494447", "footer": "454e4457"}]"#,
        &img,
        "strict",
    );
    assert!(
        strict.is_empty(),
        "carved a file whose end was never found: {strict:?}"
    );

    let lenient = carve_custom(
        br#"[{"name": "widget", "magic": "57494447", "footer": "454e4457",
              "footer_optional": true, "max_size": 256}]"#,
        &img,
        "lenient",
    );
    assert_eq!(lenient.len(), 1);
    assert_eq!(lenient[0].size, 256, "should run to the declared cap");
    assert!(
        !lenient[0].validated,
        "nothing in the data marked the end, so this is not a verified length"
    );
}

#[test]
fn a_signature_with_no_footer_carves_the_capped_window() {
    let mut img = vec![0u8; 64];
    img.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
    img.extend_from_slice(&vec![0x41u8; 4096]);
    let recs = carve_custom(
        br#"[{"name": "blob", "magic": "CAFEBABE", "max_size": 1024}]"#,
        &img,
        "nofooter",
    );
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].size, 1024);
    assert!(!recs[0].validated);
}
