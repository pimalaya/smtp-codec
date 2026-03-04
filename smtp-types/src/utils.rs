//! Functions that may come in handy.

use std::borrow::Cow;

/// Converts bytes into a ready-to-be-printed form.
pub fn escape_byte_string<B>(bytes: B) -> String
where
    B: AsRef<[u8]>,
{
    let bytes = bytes.as_ref();

    bytes
        .iter()
        .map(|byte| match byte {
            0x00..=0x08 => format!("\\x{byte:02x}"),
            0x09 => String::from("\\t"),
            0x0A => String::from("\\n"),
            0x0B => format!("\\x{byte:02x}"),
            0x0C => format!("\\x{byte:02x}"),
            0x0D => String::from("\\r"),
            0x0e..=0x1f => format!("\\x{byte:02x}"),
            0x20..=0x21 => format!("{}", *byte as char),
            0x22 => String::from("\\\""),
            0x23..=0x5B => format!("{}", *byte as char),
            0x5C => String::from("\\\\"),
            0x5D..=0x7E => format!("{}", *byte as char),
            0x7f => format!("\\x{byte:02x}"),
            0x80..=0xff => format!("\\x{byte:02x}"),
        })
        .collect::<Vec<String>>()
        .join("")
}

pub mod indicators {
    //! Character class indicators for SMTP (RFC 5321).

    /// Any 7-bit US-ASCII character, excluding NUL
    ///
    /// CHAR = %x01-7F
    #[inline]
    pub fn is_char(byte: u8) -> bool {
        matches!(byte, 0x01..=0x7f)
    }

    /// Controls
    ///
    /// CTL = %x00-1F / %x7F
    #[inline]
    pub fn is_ctl(byte: u8) -> bool {
        matches!(byte, 0x00..=0x1f | 0x7f)
    }

    /// SMTP atext characters (RFC 5321/5322)
    ///
    /// ```abnf
    /// atext = ALPHA / DIGIT /
    ///         "!" / "#" / "$" / "%" / "&" / "'" / "*" /
    ///         "+" / "-" / "/" / "=" / "?" / "^" / "_" /
    ///         "`" / "{" / "|" / "}" / "~"
    /// ```
    #[inline]
    pub fn is_atext(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'/'
                    | b'='
                    | b'?'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'{'
                    | b'|'
                    | b'}'
                    | b'~'
            )
    }

    /// SMTP qtext characters (RFC 5321)
    ///
    /// ```abnf
    /// qtext = %d32-33 / %d35-91 / %d93-126  ; printable except \ and "
    /// ```
    #[inline]
    pub fn is_qtext(byte: u8) -> bool {
        matches!(byte, 32..=33 | 35..=91 | 93..=126)
    }

    /// Text string characters for SMTP response text
    ///
    /// ```abnf
    /// textstring = 1*(%d09 / %d32-126)  ; HT, SP, Printable US-ASCII
    /// ```
    #[inline]
    pub fn is_text_char(byte: u8) -> bool {
        byte == 0x09 || matches!(byte, 0x20..=0x7e)
    }

    /// Let-dig: alphanumeric character (RFC 5321)
    ///
    /// ```abnf
    /// Let-dig = ALPHA / DIGIT
    /// ```
    #[inline]
    pub fn is_let_dig(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
    }

    /// Ldh-str character: alphanumeric or hyphen (RFC 5321)
    ///
    /// ```abnf
    /// Ldh-str = *( ALPHA / DIGIT / "-" ) Let-dig
    /// ```
    #[inline]
    pub fn is_ldh_str_char(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'-'
    }

    /// ESMTP keyword character (RFC 5321)
    ///
    /// ```abnf
    /// esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
    /// ```
    #[inline]
    pub fn is_esmtp_keyword_char(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'-'
    }

    /// ESMTP value character (RFC 5321)
    ///
    /// ```abnf
    /// esmtp-value = 1*(%d33-60 / %d62-126)  ; any CHAR excluding "=", SP, and CTL
    /// ```
    #[inline]
    pub fn is_esmtp_value_char(byte: u8) -> bool {
        matches!(byte, 33..=60 | 62..=126)
    }

    /// Reply code digit (RFC 5321)
    #[inline]
    pub fn is_digit(byte: u8) -> bool {
        byte.is_ascii_digit()
    }

    /// Dcontent character for address literals (RFC 5321)
    ///
    /// ```abnf
    /// dcontent = %d33-90 / %d94-126  ; printable except [ \ ]
    /// ```
    #[inline]
    pub fn is_dcontent(byte: u8) -> bool {
        matches!(byte, 33..=90 | 94..=126)
    }
}

pub fn escape_quoted(unescaped: &str) -> Cow<'_, str> {
    let mut escaped = Cow::Borrowed(unescaped);

    if escaped.contains('\\') {
        escaped = Cow::Owned(escaped.replace('\\', "\\\\"));
    }

    if escaped.contains('\"') {
        escaped = Cow::Owned(escaped.replace('"', "\\\""));
    }

    escaped
}

pub fn unescape_quoted(escaped: &str) -> Cow<'_, str> {
    let mut unescaped = Cow::Borrowed(escaped);

    if unescaped.contains("\\\\") {
        unescaped = Cow::Owned(unescaped.replace("\\\\", "\\"));
    }

    if unescaped.contains("\\\"") {
        unescaped = Cow::Owned(unescaped.replace("\\\"", "\""));
    }

    unescaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_quoted() {
        let tests = [
            ("", ""),
            ("\\", "\\\\"),
            ("\"", "\\\""),
            ("alice", "alice"),
            ("\\alice\\", "\\\\alice\\\\"),
            ("alice\"", "alice\\\""),
            (r#"\alice\ ""#, r#"\\alice\\ \""#),
        ];

        for (test, expected) in tests {
            let got = escape_quoted(test);
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn test_unescape_quoted() {
        let tests = [
            ("", ""),
            ("\\\\", "\\"),
            ("\\\"", "\""),
            ("alice", "alice"),
            ("\\\\alice\\\\", "\\alice\\"),
            ("alice\\\"", "alice\""),
            (r#"\\alice\\ \""#, r#"\alice\ ""#),
        ];

        for (test, expected) in tests {
            let got = unescape_quoted(test);
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn test_that_unescape_is_inverse_of_escape() {
        let input = "\\\"\\abc_*:;059^$%!\"";

        assert_eq!(input, unescape_quoted(escape_quoted(input).as_ref()));
    }

    #[test]
    fn test_escape_byte_string() {
        for byte in 0u8..=255 {
            let got = escape_byte_string([byte]);

            if byte.is_ascii_alphanumeric() {
                assert_eq!((byte as char).to_string(), got.to_string());
            } else if byte.is_ascii_whitespace() {
                if byte == b'\t' {
                    assert_eq!(String::from("\\t"), got);
                } else if byte == b'\n' {
                    assert_eq!(String::from("\\n"), got);
                }
            } else if byte.is_ascii_punctuation() {
                if byte == b'\\' {
                    assert_eq!(String::from("\\\\"), got);
                } else if byte == b'"' {
                    assert_eq!(String::from("\\\""), got);
                } else {
                    assert_eq!((byte as char).to_string(), got);
                }
            } else {
                assert_eq!(format!("\\x{byte:02x}"), got);
            }
        }

        let tests = [(b"Hallo \"\\\x00", String::from(r#"Hallo \"\\\x00"#))];

        for (test, expected) in tests {
            let got = escape_byte_string(test);
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn test_is_atext() {
        // Alphanumeric
        assert!(indicators::is_atext(b'a'));
        assert!(indicators::is_atext(b'Z'));
        assert!(indicators::is_atext(b'0'));
        assert!(indicators::is_atext(b'9'));

        // Special chars
        assert!(indicators::is_atext(b'!'));
        assert!(indicators::is_atext(b'#'));
        assert!(indicators::is_atext(b'+'));
        assert!(indicators::is_atext(b'-'));

        // Invalid
        assert!(!indicators::is_atext(b' '));
        assert!(!indicators::is_atext(b'@'));
        assert!(!indicators::is_atext(b'<'));
        assert!(!indicators::is_atext(b'>'));
    }

    #[test]
    fn test_is_text_char() {
        assert!(indicators::is_text_char(b' '));
        assert!(indicators::is_text_char(b'A'));
        assert!(indicators::is_text_char(b'~'));
        assert!(indicators::is_text_char(0x09)); // HT

        // Invalid
        assert!(!indicators::is_text_char(0x00));
        assert!(!indicators::is_text_char(0x0d)); // CR
        assert!(!indicators::is_text_char(0x0a)); // LF
        assert!(!indicators::is_text_char(0x7f)); // DEL
    }
}
