//! The curlrc vantage hands to curl via `-K /proc/self/fd/<n>`.
//! Error messages never contain a header value.

pub fn header_from_file(name: &str, content: &str) -> Result<String, String> {
    let v = content.strip_suffix('\n').unwrap_or(content);
    let v = v.strip_suffix('\r').unwrap_or(v);
    if v.is_empty() {
        return Err(format!("--header-file {name}: the file is empty"));
    }
    if v.contains('\n') || v.contains('\r') {
        return Err(format!(
            "--header-file {name}: the file has more than one line"
        ));
    }
    Ok(format!("{name}: {v}"))
}

pub fn render(headers: &[String]) -> Result<String, String> {
    let mut out = String::new();
    for h in headers {
        if h.contains('\n') || h.contains('\r') {
            let name = h.split(':').next().unwrap_or("");
            return Err(format!("header {name}: line breaks are not allowed"));
        }
        let esc = h.replace('\\', "\\\\").replace('"', "\\\"");
        out.push_str(&format!("header = \"{esc}\"\n"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_content_trailing_newline_stripped() {
        assert_eq!(
            header_from_file("X-Api-Key", "abc\n").unwrap(),
            "X-Api-Key: abc"
        );
        assert_eq!(
            header_from_file("X-Api-Key", "abc\r\n").unwrap(),
            "X-Api-Key: abc"
        );
        assert_eq!(
            header_from_file("X-Api-Key", "abc").unwrap(),
            "X-Api-Key: abc"
        );
    }
    #[test]
    fn file_content_errors_never_show_the_value() {
        let e = header_from_file("X", "zeile1\nzeile2\n").unwrap_err();
        assert!(!e.contains("zeile"));
        assert!(header_from_file("X", "").is_err());
        assert!(header_from_file("X", "\n").is_err());
    }
    #[test]
    fn render_quotes_and_escapes() {
        let rc = render(&["A: b\"c\\d".to_string(), "Accept: x/y".to_string()]).unwrap();
        assert_eq!(
            rc,
            "header = \"A: b\\\"c\\\\d\"\nheader = \"Accept: x/y\"\n"
        );
    }
    #[test]
    fn render_refuses_line_breaks() {
        assert!(render(&["A: b\nc".to_string()]).is_err());
        assert!(render(&["A: b\rc".to_string()]).is_err());
    }
}
