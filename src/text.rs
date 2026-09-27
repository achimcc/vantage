//! Text that did not come from vantage itself, made safe for a terminal.
//!
//! Guest-controlled strings (curl's stderr from the source guest, the HTTP
//! code it wrote, error texts of guest services) reach the operator's
//! terminal — during a deploy over ssh. A raw `ESC ] 52 ;` writes the
//! clipboard in many terminals, `ESC [ 2 J` wipes the lines above (audit 3 of
//! the homeserver, B81). Every control character (C0, DEL, C1) is shown as
//! an escape instead; printable text, including non-ASCII, stays as it is.

/// `s` with every control character written as `\u{..}` (`\x1b` for ESC).
pub fn visible(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            if (c as u32) < 0x80 {
                out.push_str(&format!("\\x{:02x}", c as u32));
            } else {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::visible;

    #[test]
    fn no_control_byte_survives() {
        let hostile = "a\x1b]52;c;S0FOQVJJRQ==\x07b\x1b[2J\u{9b}31m\r\n\t\x7f";
        let v = visible(hostile);
        assert!(!v.bytes().any(|b| b < 0x20 || b == 0x7f), "{v:?}");
        assert!(!v.contains('\u{9b}'), "{v:?}");
        assert!(v.contains("\\x1b]52;c;"), "{v}");
        assert!(v.contains("\\u{9b}"), "{v}");
    }

    #[test]
    fn printable_text_is_unchanged() {
        assert_eq!(
            visible("Verbindung abgelehnt: ümlaut 200"),
            "Verbindung abgelehnt: ümlaut 200"
        );
    }
}
