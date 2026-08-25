//! Signatures defined by the analyst, loaded from a JSON file.
//!
//! Schema (a list, or `{"signatures": [...]}`):
//!
//! ```json
//! {
//!   "name": "myfmt",             // type key, used with -t
//!   "ext": "mft",                // output extension (default: name)
//!   "magic": "DEADBEEF",         // hex, or a list of hex strings
//!   "header_offset": 0,          // bytes from file start to the magic
//!   "footer": "0a2525454f46",    // optional hex end marker
//!   "max_size": "16M",           // cap (default 64M); K/M/G/T suffixes ok
//!   "footer_optional": false     // carve to the cap when the footer is absent
//! }
//! ```
//!
//! With a footer, the carve ends after the first occurrence of it and counts as
//! validated. Without one, it runs to the cap and is reported unvalidated,
//! because nothing in the data says where the file ends.

use crate::jsonin::{self, Value};
use crate::signatures::{Handler, Signature};

/// What a footer-terminated custom signature needs at carve time.
#[derive(Debug, Clone)]
pub struct Spec {
    pub ext: &'static str,
    pub header_offset: u64,
    pub footer: Vec<u8>,
    pub footer_optional: bool,
}

fn parse_size(v: &Value) -> Result<u64, String> {
    match v {
        Value::Number(n) if *n >= 0.0 => Ok(*n as u64),
        Value::String(s) => {
            let t = s.trim().to_uppercase();
            let (num, mult) = match t.chars().last() {
                Some('K') => (&t[..t.len() - 1], 1u64 << 10),
                Some('M') => (&t[..t.len() - 1], 1 << 20),
                Some('G') => (&t[..t.len() - 1], 1 << 30),
                Some('T') => (&t[..t.len() - 1], 1u64 << 40),
                Some('B') => (&t[..t.len() - 1], 1),
                _ => (t.as_str(), 1),
            };
            let n: f64 = num
                .trim()
                .parse()
                .map_err(|_| format!("not a size: {s:?}"))?;
            if !(0.0..=(u64::MAX as f64)).contains(&n) {
                return Err(format!("size out of range: {s:?}"));
            }
            Ok((n * mult as f64) as u64)
        }
        other => Err(format!(
            "size must be a number or a string, not {}",
            other.kind()
        )),
    }
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    let cleaned = cleaned.trim_start_matches("0x").trim_start_matches("0X");
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return Err(format!("not an even-length hex string: {s:?}"));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| format!("bad hex: {s:?}")))
        .collect()
}

/// Read `path` and return the signatures it defines.
///
/// The signatures are leaked on purpose: they live for the whole scan, and the
/// registry they join is `&'static`.
pub fn load(path: &str) -> Result<Vec<&'static Signature>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let doc = jsonin::parse(&text).map_err(|e| format!("{path}: {e}"))?;
    let entries: &[Value] = match &doc {
        Value::Array(v) => v,
        Value::Object(_) => match doc.get("signatures") {
            Some(Value::Array(v)) => v,
            Some(other) => {
                return Err(format!(
                    "{path}: \"signatures\" must be a list, not {}",
                    other.kind()
                ))
            }
            None => return Err(format!("{path}: expected a list, or a \"signatures\" list")),
        },
        other => return Err(format!("{path}: expected a list, not {}", other.kind())),
    };
    if entries.is_empty() {
        return Err(format!("{path}: no signatures defined"));
    }

    let mut out = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let at = format!("{path}: signature #{i}");
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{at}: \"name\" is required"))?;
        let magic_field = entry
            .get("magic")
            .ok_or_else(|| format!("{at} ({name}): \"magic\" is required"))?;
        let magic_strs: Vec<&str> = match magic_field {
            Value::String(s) => vec![s.as_str()],
            Value::Array(v) => v
                .iter()
                .map(|m| {
                    m.as_str()
                        .ok_or_else(|| format!("{at} ({name}): magic list must hold strings"))
                })
                .collect::<Result<_, _>>()?,
            other => {
                return Err(format!(
                    "{at} ({name}): \"magic\" must be a hex string or a list, not {}",
                    other.kind()
                ))
            }
        };
        let mut magics: Vec<&'static [u8]> = Vec::new();
        for m in magic_strs {
            let bytes = parse_hex(m).map_err(|e| format!("{at} ({name}): {e}"))?;
            magics.push(Box::leak(bytes.into_boxed_slice()));
        }
        let header_offset = match entry.get("header_offset") {
            None => 0u64,
            Some(v) => v
                .as_f64()
                .filter(|n| *n >= 0.0)
                .map(|n| n as u64)
                .ok_or_else(|| format!("{at} ({name}): \"header_offset\" must be a number"))?,
        };
        let footer = match entry.get("footer") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::String(s)) => parse_hex(s).map_err(|e| format!("{at} ({name}): {e}"))?,
            Some(other) => {
                return Err(format!(
                    "{at} ({name}): \"footer\" must be a hex string, not {}",
                    other.kind()
                ))
            }
        };
        let max_size = match entry.get("max_size") {
            None => 64 << 20,
            Some(v) => parse_size(v).map_err(|e| format!("{at} ({name}): {e}"))?,
        };
        if max_size == 0 {
            return Err(format!("{at} ({name}): \"max_size\" must not be zero"));
        }
        let footer_optional = entry
            .get("footer_optional")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ext: &'static str = match entry.get("ext").and_then(Value::as_str) {
            Some(e) => Box::leak(e.to_string().into_boxed_str()),
            None => Box::leak(name.to_string().into_boxed_str()),
        };
        let name: &'static str = Box::leak(name.to_string().into_boxed_str());

        let sig = Signature {
            name,
            magics: Box::leak(magics.into_boxed_slice()),
            header_offset,
            handler: Handler::Footer(Spec {
                ext,
                header_offset,
                footer,
                footer_optional,
            }),
            max_size,
            precheck: None,
            description: Box::leak(format!("custom signature ({path})").into_boxed_str()),
        };
        out.push(&*Box::leak(Box::new(sig)));
    }
    Ok(out)
}
