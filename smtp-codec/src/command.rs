//! SMTP command parsers.
//!
//! This module provides parsers for all SMTP commands as defined in RFC 5321.

use std::borrow::Cow;

#[cfg(not(feature = "quirk_crlf_relaxed"))]
use abnf_core::streaming::crlf;
#[cfg(feature = "quirk_crlf_relaxed")]
use abnf_core::streaming::crlf_relaxed as crlf;
use abnf_core::streaming::sp;
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while},
    combinator::{map, opt, value},
    multi::many0,
    sequence::{preceded, terminated, tuple},
};
use smtp_types::{
    command::Command,
    core::Parameter,
    utils::indicators::is_text_char,
};

#[cfg(feature = "ext_auth")]
use crate::auth::auth_type;
#[cfg(feature = "ext_auth")]
use crate::core::base64_data;
use crate::{
    core::{domain, ehlo_domain, esmtp_param, forward_path, reverse_path},
    decode::SMTPResult,
};

/// Parse any SMTP command.
pub(crate) fn command(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    terminated(
        alt((
            ehlo,
            helo,
            mail,
            rcpt,
            data_cmd,
            rset,
            quit,
            noop,
            vrfy,
            expn,
            help,
            #[cfg(feature = "starttls")]
            starttls,
            #[cfg(feature = "ext_auth")]
            auth,
        )),
        crlf,
    )(input)
}

/// ```abnf
/// ehlo = "EHLO" SP ( Domain / address-literal ) CRLF
/// ```
fn ehlo(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    map(
        preceded(tuple((tag_no_case(b"EHLO"), sp)), ehlo_domain),
        |domain| Command::Ehlo { domain },
    )(input)
}

/// ```abnf
/// helo = "HELO" SP Domain CRLF
/// ```
fn helo(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    map(preceded(tuple((tag_no_case(b"HELO"), sp)), domain), |domain| {
        Command::Helo { domain }
    })(input)
}

/// ```abnf
/// mail = "MAIL FROM:" Reverse-path [SP Mail-parameters] CRLF
/// ```
fn mail(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    map(
        preceded(
            tag_no_case(b"MAIL FROM:"),
            tuple((reverse_path, mail_parameters)),
        ),
        |(reverse_path, parameters)| Command::Mail {
            reverse_path,
            parameters,
        },
    )(input)
}

/// Parse optional mail parameters.
fn mail_parameters(input: &[u8]) -> SMTPResult<'_, &[u8], Vec<Parameter<'_>>> {
    many0(preceded(sp, esmtp_param))(input)
}

/// ```abnf
/// rcpt = "RCPT TO:" ( "<Postmaster@" Domain ">" / "<Postmaster>" / Forward-path ) [SP Rcpt-parameters] CRLF
/// ```
fn rcpt(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    map(
        preceded(
            tag_no_case(b"RCPT TO:"),
            tuple((forward_path, rcpt_parameters)),
        ),
        |(forward_path, parameters)| Command::Rcpt {
            forward_path,
            parameters,
        },
    )(input)
}

/// Parse optional rcpt parameters.
fn rcpt_parameters(input: &[u8]) -> SMTPResult<'_, &[u8], Vec<Parameter<'_>>> {
    many0(preceded(sp, esmtp_param))(input)
}

/// ```abnf
/// data = "DATA" CRLF
/// ```
fn data_cmd(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    value(Command::Data, tag_no_case(b"DATA"))(input)
}

/// ```abnf
/// rset = "RSET" CRLF
/// ```
fn rset(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    value(Command::Rset, tag_no_case(b"RSET"))(input)
}

/// ```abnf
/// quit = "QUIT" CRLF
/// ```
fn quit(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    value(Command::Quit, tag_no_case(b"QUIT"))(input)
}

/// ```abnf
/// noop = "NOOP" [ SP String ] CRLF
/// ```
fn noop(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    map(
        preceded(tag_no_case(b"NOOP"), opt(preceded(sp, string_arg))),
        |string| Command::Noop { string },
    )(input)
}

/// ```abnf
/// vrfy = "VRFY" SP String CRLF
/// ```
fn vrfy(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    map(
        preceded(tuple((tag_no_case(b"VRFY"), sp)), string_arg),
        |string| Command::Vrfy { string },
    )(input)
}

/// ```abnf
/// expn = "EXPN" SP String CRLF
/// ```
fn expn(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    map(
        preceded(tuple((tag_no_case(b"EXPN"), sp)), string_arg),
        |string| Command::Expn { string },
    )(input)
}

/// ```abnf
/// help = "HELP" [ SP String ] CRLF
/// ```
fn help(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    map(
        preceded(tag_no_case(b"HELP"), opt(preceded(sp, string_arg))),
        |topic| Command::Help { topic },
    )(input)
}

/// Parse a string argument (free-form text until CRLF).
fn string_arg(input: &[u8]) -> SMTPResult<'_, &[u8], Cow<'_, str>> {
    map(
        take_while(is_text_char),
        |bytes: &[u8]| Cow::Borrowed(std::str::from_utf8(bytes).unwrap()),
    )(input)
}

/// ```abnf
/// starttls = "STARTTLS" CRLF
/// ```
#[cfg(feature = "starttls")]
fn starttls(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    value(Command::StartTls, tag_no_case(b"STARTTLS"))(input)
}

/// ```abnf
/// auth = "AUTH" SP sasl-mech [SP initial-response] CRLF
/// ```
#[cfg(feature = "ext_auth")]
fn auth(input: &[u8]) -> SMTPResult<'_, &[u8], Command<'_>> {
    use smtp_types::secret::Secret;

    map(
        preceded(
            tuple((tag_no_case(b"AUTH"), sp)),
            tuple((
                auth_type,
                opt(preceded(
                    sp,
                    alt((
                        // "=" means empty initial response
                        map(tag(b"="), |_| Vec::new()),
                        // Base64-encoded initial response
                        base64_data,
                    )),
                )),
            )),
        ),
        |(mechanism, initial_response)| Command::Auth {
            mechanism,
            initial_response: initial_response.map(|data| Secret::new(Cow::Owned(data))),
        },
    )(input)
}

#[cfg(test)]
mod tests {
    use smtp_types::core::ReversePath;

    use super::*;

    #[test]
    fn test_ehlo() {
        let (rem, cmd) = command(b"EHLO client.example.com\r\n").unwrap();
        assert!(rem.is_empty());
        match cmd {
            Command::Ehlo { domain } => {
                assert_eq!(domain.to_string(), "client.example.com");
            }
            _ => panic!("Expected EHLO"),
        }
    }

    #[test]
    fn test_ehlo_case_insensitive() {
        let (rem, cmd) = command(b"ehlo client.example.com\r\n").unwrap();
        assert!(rem.is_empty());
        assert!(matches!(cmd, Command::Ehlo { .. }));

        let (rem, cmd) = command(b"EhLo client.example.com\r\n").unwrap();
        assert!(rem.is_empty());
        assert!(matches!(cmd, Command::Ehlo { .. }));
    }

    #[test]
    fn test_helo() {
        let (rem, cmd) = command(b"HELO client.example.com\r\n").unwrap();
        assert!(rem.is_empty());
        match cmd {
            Command::Helo { domain } => {
                assert_eq!(domain.inner(), "client.example.com");
            }
            _ => panic!("Expected HELO"),
        }
    }

    #[test]
    fn test_mail_from_null() {
        let (rem, cmd) = command(b"MAIL FROM:<>\r\n").unwrap();
        assert!(rem.is_empty());
        match cmd {
            Command::Mail {
                reverse_path,
                parameters,
            } => {
                assert!(matches!(reverse_path, ReversePath::Null));
                assert!(parameters.is_empty());
            }
            _ => panic!("Expected MAIL"),
        }
    }

    #[test]
    fn test_mail_from_address() {
        let (rem, cmd) = command(b"MAIL FROM:<user@example.com>\r\n").unwrap();
        assert!(rem.is_empty());
        match cmd {
            Command::Mail {
                reverse_path,
                parameters,
            } => {
                assert!(matches!(reverse_path, ReversePath::Mailbox(_)));
                assert!(parameters.is_empty());
            }
            _ => panic!("Expected MAIL"),
        }
    }

    #[test]
    fn test_mail_from_with_size() {
        let (rem, cmd) = command(b"MAIL FROM:<user@example.com> SIZE=1024\r\n").unwrap();
        assert!(rem.is_empty());
        match cmd {
            Command::Mail {
                reverse_path: _,
                parameters,
            } => {
                assert_eq!(parameters.len(), 1);
                assert_eq!(parameters[0].keyword.inner(), "SIZE");
            }
            _ => panic!("Expected MAIL"),
        }
    }

    #[test]
    fn test_rcpt_to() {
        let (rem, cmd) = command(b"RCPT TO:<user@example.com>\r\n").unwrap();
        assert!(rem.is_empty());
        assert!(matches!(cmd, Command::Rcpt { .. }));
    }

    #[test]
    fn test_simple_commands() {
        let tests = [
            (b"DATA\r\n".as_ref(), "DATA"),
            (b"RSET\r\n".as_ref(), "RSET"),
            (b"QUIT\r\n".as_ref(), "QUIT"),
            (b"NOOP\r\n".as_ref(), "NOOP"),
            (b"HELP\r\n".as_ref(), "HELP"),
        ];

        for (input, expected) in tests {
            let (rem, cmd) = command(input).unwrap();
            assert!(rem.is_empty(), "Remaining: {:?}", rem);
            assert_eq!(cmd.name(), expected);
        }
    }

    #[test]
    fn test_noop_with_arg() {
        let (rem, cmd) = command(b"NOOP keep-alive\r\n").unwrap();
        assert!(rem.is_empty());
        match cmd {
            Command::Noop { string } => {
                assert_eq!(string, Some(Cow::Borrowed("keep-alive")));
            }
            _ => panic!("Expected NOOP"),
        }
    }

    #[test]
    fn test_vrfy() {
        let (rem, cmd) = command(b"VRFY postmaster\r\n").unwrap();
        assert!(rem.is_empty());
        match cmd {
            Command::Vrfy { string } => {
                assert_eq!(string, "postmaster");
            }
            _ => panic!("Expected VRFY"),
        }
    }

    #[test]
    fn test_help_with_topic() {
        let (rem, cmd) = command(b"HELP COMMANDS\r\n").unwrap();
        assert!(rem.is_empty());
        match cmd {
            Command::Help { topic } => {
                assert_eq!(topic, Some(Cow::Borrowed("COMMANDS")));
            }
            _ => panic!("Expected HELP"),
        }
    }

    #[cfg(feature = "starttls")]
    #[test]
    fn test_starttls() {
        let (rem, cmd) = command(b"STARTTLS\r\n").unwrap();
        assert!(rem.is_empty());
        assert!(matches!(cmd, Command::StartTls));
    }

    #[cfg(feature = "ext_auth")]
    #[test]
    fn test_auth_plain() {
        let (rem, cmd) = command(b"AUTH PLAIN\r\n").unwrap();
        assert!(rem.is_empty());
        match cmd {
            Command::Auth {
                mechanism,
                initial_response,
            } => {
                assert_eq!(mechanism, smtp_types::auth::AuthMechanism::Plain);
                assert!(initial_response.is_none());
            }
            _ => panic!("Expected AUTH"),
        }
    }

    #[cfg(feature = "ext_auth")]
    #[test]
    fn test_auth_with_initial_response() {
        let (rem, cmd) = command(b"AUTH PLAIN AGFsaWNlAHBhc3N3b3Jk\r\n").unwrap();
        assert!(rem.is_empty());
        match cmd {
            Command::Auth {
                mechanism,
                initial_response,
            } => {
                assert_eq!(mechanism, smtp_types::auth::AuthMechanism::Plain);
                assert!(initial_response.is_some());
                let data = initial_response.unwrap();
                assert_eq!(data.declassify().as_ref(), b"\0alice\0password");
            }
            _ => panic!("Expected AUTH"),
        }
    }

    #[test]
    fn test_incomplete() {
        assert!(matches!(command(b"EHLO"), Err(nom::Err::Incomplete(_))));
        assert!(matches!(command(b"EHLO "), Err(nom::Err::Incomplete(_))));
        assert!(matches!(
            command(b"EHLO example.com"),
            Err(nom::Err::Incomplete(_))
        ));
        assert!(matches!(
            command(b"EHLO example.com\r"),
            Err(nom::Err::Incomplete(_))
        ));
    }
}
