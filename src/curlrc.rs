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

/// A value in double quotes, the way `curl -K` reads it: backslash and
/// quote escaped, line breaks and tabs as `\n`, `\r`, `\t`. Until vantage
/// 0.4.0 this function existed twice (gast-pruefung `curl_wert`, signoff
/// `quote`), byte for byte the same.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A curl invocation written as a config file for `curl -K -` (stdin) or
/// `-K /proc/self/fd/<n>` (memfd), so that nothing sensitive — a bearer
/// token, an API key, a password — ever stands in argv, which `systemd-run`
/// writes into the guest's journal for 90 days.
///
/// One line per option; the methods are the curl options they name. Tools
/// put their own idioms on top (gast-pruefung's `nur_code`, signoff's
/// `code_only`), this type only knows curl's syntax.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CurlRc {
    lines: Vec<String>,
}

impl CurlRc {
    /// Starts with `url = "<url>"`.
    pub fn new(url: &str) -> CurlRc {
        CurlRc::default().url(url)
    }

    /// `name = "<quoted value>"`.
    pub fn option(mut self, name: &str, value: &str) -> CurlRc {
        self.lines.push(format!("{name} = {}", quote(value)));
        self
    }

    /// `name = <raw>` — for numbers (`max-time = 15`). The caller vouches
    /// that `raw` needs no quoting.
    pub fn option_raw(mut self, name: &str, raw: &str) -> CurlRc {
        self.lines.push(format!("{name} = {raw}"));
        self
    }

    /// A bare option (`silent`, `get`, `location`).
    pub fn flag(mut self, name: &str) -> CurlRc {
        self.lines.push(name.to_string());
        self
    }

    pub fn has_flag(&self, name: &str) -> bool {
        self.lines.iter().any(|l| l == name)
    }

    /// Another `url =` in the same invocation; curl pairs `output` lines
    /// with URLs in order.
    pub fn url(self, url: &str) -> CurlRc {
        self.option("url", url)
    }

    /// `header = "Name: value"`.
    pub fn header(self, name: &str, value: &str) -> CurlRc {
        self.option("header", &format!("{name}: {value}"))
    }

    /// `header = "<line>"` for a line that already reads `Name: value`.
    pub fn header_line(self, line: &str) -> CurlRc {
        self.option("header", line)
    }

    /// `request = "<method>"` (`-X`).
    pub fn request(self, method: &str) -> CurlRc {
        self.option("request", method)
    }

    /// `data = "<body>"` (`-d`, implies POST).
    pub fn data(self, body: &str) -> CurlRc {
        self.option("data", body)
    }

    /// `data-binary = "<body>"`.
    pub fn data_binary(self, body: &str) -> CurlRc {
        self.option("data-binary", body)
    }

    /// `--get --data-urlencode name=value`: a query parameter, encoded by
    /// curl. `get` is written once, however many parameters follow.
    pub fn query(self, name: &str, value: &str) -> CurlRc {
        let rc = if self.has_flag("get") {
            self
        } else {
            self.flag("get")
        };
        rc.option("data-urlencode", &format!("{name}={value}"))
    }

    /// `user = "user:password"` (`-u`).
    pub fn user(self, user: &str, password: &str) -> CurlRc {
        self.option("user", &format!("{user}:{password}"))
    }

    /// `resolve = "host:port:ip"` — measure the listener, not whatever a
    /// resolver points at right now.
    pub fn resolve(self, host: &str, port: u16, ip: &str) -> CurlRc {
        self.option("resolve", &format!("{host}:{port}:{ip}"))
    }

    /// `max-time = <secs>`.
    pub fn max_time(self, secs: u32) -> CurlRc {
        self.option_raw("max-time", &secs.to_string())
    }

    /// `write-out = "<format>"` (`-w`).
    pub fn write_out(self, format: &str) -> CurlRc {
        self.option("write-out", format)
    }

    /// `output = "<path>"` (`-o`).
    pub fn output(self, path: &str) -> CurlRc {
        self.option("output", path)
    }

    /// `output = "/dev/null"`: drop the body of the current URL.
    pub fn discard_body(self) -> CurlRc {
        self.output("/dev/null")
    }

    /// `cacert = "<path>"`: trust ONLY this certificate.
    pub fn cacert(self, path: &str) -> CurlRc {
        self.option("cacert", path)
    }

    /// `interface = "<address>"`: the source address.
    pub fn interface(self, address: &str) -> CurlRc {
        self.option("interface", address)
    }

    /// `include` (`-i`): response headers before the body.
    pub fn include(self) -> CurlRc {
        self.flag("include")
    }

    /// `location` (`-L`).
    pub fn location(self) -> CurlRc {
        self.flag("location")
    }

    /// `cookie = ""` (`-b ""`): the in-memory cookie engine, so cookies
    /// travel across redirects and further URLs of the same invocation
    /// without a cookie file in the guest.
    pub fn cookie_engine(self) -> CurlRc {
        self.option("cookie", "")
    }

    /// `silent`, `show-error` (`-sS`).
    pub fn silent_show_error(self) -> CurlRc {
        self.flag("silent").flag("show-error")
    }

    /// `fail` (`-f`): a 4xx/5xx becomes curl exit 22.
    pub fn fail(self) -> CurlRc {
        self.flag("fail")
    }

    /// The file: one option per line, a trailing newline.
    pub fn render(&self) -> String {
        let mut t = self.lines.join("\n");
        t.push('\n');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quote_escapes_backslash_quote_and_whitespace() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quote("x\ny\r\tz"), "\"x\\ny\\r\\tz\"");
        assert_eq!(quote(""), "\"\"");
    }
    #[test]
    fn curlrc_renders_one_option_per_line() {
        let rc = CurlRc::new("https://ghostfolio.example:8443/")
            .resolve("ghostfolio.example", 8443, "10.0.20.11")
            .silent_show_error()
            .discard_body()
            .write_out("%{http_code}")
            .max_time(15);
        assert_eq!(
            rc.render(),
            "url = \"https://ghostfolio.example:8443/\"\nresolve = \"ghostfolio.example:8443:10.0.20.11\"\nsilent\nshow-error\noutput = \"/dev/null\"\nwrite-out = \"%{http_code}\"\nmax-time = 15\n"
        );
    }
    #[test]
    fn curlrc_quotes_every_value() {
        let rc = CurlRc::new("http://x/")
            .header("Authorization", "Bearer a\"b")
            .request("POST")
            .data("a=1&b=2")
            .data_binary("{\"k\":\"v\"}")
            .user("admin", "p\\w")
            .cacert("/c.crt")
            .interface("100.64.0.1")
            .include()
            .location()
            .cookie_engine()
            .fail()
            .url("http://y/");
        let t = rc.render();
        assert!(
            t.contains("header = \"Authorization: Bearer a\\\"b\"\n"),
            "{t}"
        );
        assert!(t.contains("request = \"POST\"\n"));
        assert!(t.contains("data = \"a=1&b=2\"\n"));
        assert!(
            t.contains("data-binary = \"{\\\"k\\\":\\\"v\\\"}\"\n"),
            "{t}"
        );
        assert!(t.contains("user = \"admin:p\\\\w\"\n"), "{t}");
        assert!(t.contains("cacert = \"/c.crt\"\n"));
        assert!(t.contains("interface = \"100.64.0.1\"\n"));
        assert!(
            t.contains("\ninclude\nlocation\ncookie = \"\"\nfail\nurl = \"http://y/\"\n"),
            "{t}"
        );
    }
    #[test]
    fn query_writes_get_once() {
        let rc = CurlRc::new("http://x/").query("a", "1 2").query("b", "&");
        assert_eq!(
            rc.render(),
            "url = \"http://x/\"\nget\ndata-urlencode = \"a=1 2\"\ndata-urlencode = \"b=&\"\n"
        );
        assert!(rc.has_flag("get"));
        assert!(!rc.has_flag("fail"));
    }
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
