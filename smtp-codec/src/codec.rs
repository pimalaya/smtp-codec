pub mod decode;
pub mod encode;

/// Codec for server greetings (220).
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct GreetingCodec;

/// Codec for client commands.
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct CommandCodec;

/// Codec for server responses.
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct ResponseCodec;

/// Codec for EHLO responses with capabilities.
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct EhloResponseCodec;

/// Codec for AUTH data lines (base64-encoded).
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
#[cfg(feature = "ext_auth")]
pub struct AuthenticateDataCodec;

/// Codec for DATA content (handles dot-stuffing).
#[derive(Clone, Debug, Default, PartialEq)]
#[non_exhaustive]
pub struct DataCodec;

macro_rules! impl_codec_new {
    ($codec:ty) => {
        impl $codec {
            /// Create codec with default configuration.
            pub fn new() -> Self {
                Self::default()
            }
        }
    };
}

impl_codec_new!(GreetingCodec);
impl_codec_new!(CommandCodec);
impl_codec_new!(ResponseCodec);
impl_codec_new!(EhloResponseCodec);
#[cfg(feature = "ext_auth")]
impl_codec_new!(AuthenticateDataCodec);
impl_codec_new!(DataCodec);

#[cfg(test)]
mod tests {
    use smtp_types::response::ReplyCode;

    use super::*;
    use crate::decode::{Decoder, GreetingDecodeError};

    #[test]
    fn test_greeting_decode() {
        let input = b"220 mail.example.com ESMTP ready\r\n";
        let result = GreetingCodec::default().decode(input);
        assert!(result.is_ok());
        let (remaining, greeting) = result.unwrap();
        assert!(remaining.is_empty());
        assert_eq!(greeting.domain.inner(), "mail.example.com");
    }

    #[test]
    fn test_greeting_incomplete() {
        let tests = [
            b"2".as_ref(),
            b"22".as_ref(),
            b"220".as_ref(),
            b"220 ".as_ref(),
            b"220 mail".as_ref(),
            b"220 mail.example.com".as_ref(),
            b"220 mail.example.com\r".as_ref(),
        ];

        for test in tests {
            let got = GreetingCodec::default().decode(test);
            assert_eq!(
                got,
                Err(GreetingDecodeError::Incomplete),
                "Expected Incomplete for {:?}",
                std::str::from_utf8(test).unwrap_or("<invalid>")
            );
        }
    }

    #[test]
    fn test_command_decode() {
        let input = b"EHLO client.example.com\r\n";
        let result = CommandCodec::default().decode(input);
        assert!(result.is_ok());
        let (remaining, cmd) = result.unwrap();
        assert!(remaining.is_empty());
        assert_eq!(cmd.name(), "EHLO");
    }

    #[test]
    fn test_simple_commands() {
        let tests = [
            (b"QUIT\r\n".as_ref(), "QUIT"),
            (b"DATA\r\n".as_ref(), "DATA"),
            (b"RSET\r\n".as_ref(), "RSET"),
            (b"NOOP\r\n".as_ref(), "NOOP"),
        ];

        for (input, expected_name) in tests {
            let result = CommandCodec::default().decode(input);
            assert!(result.is_ok(), "Failed to parse: {:?}", std::str::from_utf8(input));
            let (_, cmd) = result.unwrap();
            assert_eq!(cmd.name(), expected_name);
        }
    }

    #[test]
    fn test_response_decode() {
        let input = b"250 OK\r\n";
        let result = ResponseCodec::default().decode(input);
        assert!(result.is_ok());
        let (remaining, response) = result.unwrap();
        assert!(remaining.is_empty());
        assert_eq!(response.code, ReplyCode::OK);
    }

    #[test]
    fn test_multiline_response() {
        let input = b"250-First line\r\n250-Second line\r\n250 Last line\r\n";
        let result = ResponseCodec::default().decode(input);
        assert!(result.is_ok());
        let (remaining, response) = result.unwrap();
        assert!(remaining.is_empty());
        assert_eq!(response.code, ReplyCode::OK);
        assert_eq!(response.lines.as_ref().len(), 3);
    }
}
