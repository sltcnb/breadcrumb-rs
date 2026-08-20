//! Minimal JSON writer. The manifest is the only JSON this tool emits, and
//! its shape is fixed, so a serialization dependency would not earn its keep.

pub fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn number(n: u64) -> String {
    n.to_string()
}

pub fn float(f: f64) -> String {
    format!("{f:.3}")
}

pub fn boolean(b: bool) -> String {
    if b {
        "true".into()
    } else {
        "false".into()
    }
}

pub fn object(fields: Vec<(&str, String)>) -> String {
    let body: Vec<String> = fields
        .into_iter()
        .map(|(k, v)| format!("{}: {}", string(k), v))
        .collect();
    format!("{{{}}}", body.join(", "))
}

pub fn array(items: Vec<String>) -> String {
    format!("[\n    {}\n  ]", items.join(",\n    "))
}
