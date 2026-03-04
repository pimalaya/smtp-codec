//! SMTP response parsers.
//!
//! This module provides parsers for SMTP server responses as defined in RFC 5321.

use std::borrow::Cow;

#[cfg(not(feature = "quirk_crlf_relaxed"))]
use abnf_core::streaming::crlf;
#[cfg(feature = "quirk_crlf_relaxed")]
use abnf_core::streaming::crlf_relaxed as crlf;
use abnf_core::streaming::sp;
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while1},
    character::streaming::char,
    combinator::{map, opt},
    multi::many0,
    sequence::{preceded, terminated, tuple},
};
use smtp_types::{
    core::{Atom, Text, Vec1},
    response::{Capability, EhloResponse, Greeting, ReplyCode, Response},
    utils::indicators::is_text_char,
};

#[cfg(feature = "ext_auth")]
use crate::auth::auth_type;
use crate::{
    core::{domain, number, reply_code, text},
    decode::SMTPResult,
};

/// Parse server greeting (220).
///
/// ```abnf
/// greeting = "220" SP Domain [ SP textstring ] CRLF
/// ```
pub(crate) fn greeting(input: &[u8]) -> SMTPResult<'_, &[u8], Greeting<'_>> {
    map(
        terminated(
            tuple((
                tag(b"220"),
                sp,
                domain,
                opt(preceded(sp, text)),
            )),
            crlf,
        ),
        |(_, _, domain, text)| Greeting::new(domain, text),
    )(input)
}

/// Parse a general SMTP response (single or multi-line).
///
/// ```abnf
/// Reply-line = *( Reply-code "-" [ textstring ] CRLF )
///              Reply-code [ SP textstring ] CRLF
/// ```
pub(crate) fn response(input: &[u8]) -> SMTPResult<'_, &[u8], Response<'_>> {
    // First, try to parse continuation lines (code + "-")
    let (input, cont_lines) = many0(terminated(
        tuple((reply_code, char('-'), opt(text))),
        crlf,
    ))(input)?;

    // Then parse the final line (code + " " or just code)
    let (input, (code, _, final_text)) = terminated(
        tuple((
            reply_code,
            alt((map(sp, |_| ' '), map(tag(b""), |_| ' '))),
            opt(text),
        )),
        crlf,
    )(input)?;

    // Build the response
    let reply_code = ReplyCode::new(code).unwrap_or(ReplyCode::OK);

    // Collect all lines
    let mut lines: Vec<Text> = cont_lines
        .into_iter()
        .map(|(_, _, text_opt)| text_opt.unwrap_or_else(|| Text::unvalidated("")))
        .collect();
    lines.push(final_text.unwrap_or_else(|| Text::unvalidated("")));

    // Ensure we have at least one line
    let lines = Vec1::try_from(lines).unwrap_or_else(|_| Vec1::from(Text::unvalidated("")));

    Ok((input, Response::new_multiline(reply_code, lines)))
}

/// Parse EHLO response with capabilities.
///
/// ```abnf
/// ehlo-ok-rsp = ( "250" SP Domain [ SP ehlo-greet ] CRLF )
///               / ( "250-" Domain [ SP ehlo-greet ] CRLF
///                   *( "250-" ehlo-line CRLF )
///                   "250" SP ehlo-line CRLF )
/// ```
pub(crate) fn ehlo_response(input: &[u8]) -> SMTPResult<'_, &[u8], EhloResponse<'_>> {
    // Parse first line: 250 or 250-
    let (input, (_, separator, ehlo_domain, greet)) = terminated(
        tuple((
            tag(b"250"),
            alt((char('-'), char(' '))),
            domain,
            opt(preceded(sp, text)),
        )),
        crlf,
    )(input)?;

    let mut ehlo = match greet {
        Some(g) => EhloResponse::with_greet(ehlo_domain, g),
        None => EhloResponse::new(ehlo_domain),
    };

    // If separator was ' ', this was a single-line response
    if separator == ' ' {
        return Ok((input, ehlo));
    }

    // Parse continuation lines
    let (input, cont_lines) = many0(terminated(
        preceded(tag(b"250-"), capability_line),
        crlf,
    ))(input)?;

    for cap in cont_lines {
        ehlo.add_capability(cap);
    }

    // Parse final line
    let (input, final_cap) = terminated(
        preceded(tuple((tag(b"250"), sp)), capability_line),
        crlf,
    )(input)?;

    ehlo.add_capability(final_cap);

    Ok((input, ehlo))
}

/// Parse a single capability line.
fn capability_line(input: &[u8]) -> SMTPResult<'_, &[u8], Capability<'_>> {
    alt((
        #[cfg(feature = "ext_size")]
        size_capability,
        #[cfg(feature = "ext_8bitmime")]
        eightbitmime_capability,
        #[cfg(feature = "ext_pipelining")]
        pipelining_capability,
        #[cfg(feature = "starttls")]
        starttls_capability,
        #[cfg(feature = "ext_smtputf8")]
        smtputf8_capability,
        #[cfg(feature = "ext_enhancedstatuscodes")]
        enhancedstatuscodes_capability,
        #[cfg(feature = "ext_auth")]
        auth_capability,
        other_capability,
    ))(input)
}

#[cfg(feature = "ext_size")]
fn size_capability(input: &[u8]) -> SMTPResult<'_, &[u8], Capability<'_>> {
    map(
        preceded(
            tag_no_case(b"SIZE"),
            opt(preceded(sp, number)),
        ),
        Capability::Size,
    )(input)
}

#[cfg(feature = "ext_8bitmime")]
fn eightbitmime_capability(input: &[u8]) -> SMTPResult<'_, &[u8], Capability<'_>> {
    map(tag_no_case(b"8BITMIME"), |_| Capability::EightBitMime)(input)
}

#[cfg(feature = "ext_pipelining")]
fn pipelining_capability(input: &[u8]) -> SMTPResult<'_, &[u8], Capability<'_>> {
    map(tag_no_case(b"PIPELINING"), |_| Capability::Pipelining)(input)
}

#[cfg(feature = "starttls")]
fn starttls_capability(input: &[u8]) -> SMTPResult<'_, &[u8], Capability<'_>> {
    map(tag_no_case(b"STARTTLS"), |_| Capability::StartTls)(input)
}

#[cfg(feature = "ext_smtputf8")]
fn smtputf8_capability(input: &[u8]) -> SMTPResult<'_, &[u8], Capability<'_>> {
    map(tag_no_case(b"SMTPUTF8"), |_| Capability::SmtpUtf8)(input)
}

#[cfg(feature = "ext_enhancedstatuscodes")]
fn enhancedstatuscodes_capability(input: &[u8]) -> SMTPResult<'_, &[u8], Capability<'_>> {
    map(tag_no_case(b"ENHANCEDSTATUSCODES"), |_| {
        Capability::EnhancedStatusCodes
    })(input)
}

#[cfg(feature = "ext_auth")]
fn auth_capability(input: &[u8]) -> SMTPResult<'_, &[u8], Capability<'_>> {
    use nom::multi::separated_list1;

    map(
        preceded(
            tuple((tag_no_case(b"AUTH"), sp)),
            separated_list1(sp, auth_type),
        ),
        Capability::Auth,
    )(input)
}

fn other_capability(input: &[u8]) -> SMTPResult<'_, &[u8], Capability<'_>> {
    map(
        tuple((
            map(take_while1(|b| b != b' ' && b != b'\r' && b != b'\n'), |bytes: &[u8]| {
                Atom::unvalidated(std::str::from_utf8(bytes).unwrap())
            }),
            opt(preceded(sp, map(take_while(is_text_char), |bytes: &[u8]| {
                Cow::Borrowed(std::str::from_utf8(bytes).unwrap())
            }))),
        )),
        |(keyword, params)| Capability::Other { keyword, params },
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greeting() {
        let (rem, greet) = greeting(b"220 mail.example.com ESMTP ready\r\n").unwrap();
        assert!(rem.is_empty());
        assert_eq!(greet.domain.inner(), "mail.example.com");
        assert!(greet.text.is_some());
    }

    #[test]
    fn test_greeting_minimal() {
        let (rem, greet) = greeting(b"220 mail.example.com\r\n").unwrap();
        assert!(rem.is_empty());
        assert_eq!(greet.domain.inner(), "mail.example.com");
        assert!(greet.text.is_none());
    }

    #[test]
    fn test_response_single_line() {
        let (rem, resp) = response(b"250 OK\r\n").unwrap();
        assert!(rem.is_empty());
        assert_eq!(resp.code, ReplyCode::OK);
        assert_eq!(resp.lines.as_ref().len(), 1);
    }

    #[test]
    fn test_response_multiline() {
        let input = b"250-mail.example.com\r\n250-SIZE 10240000\r\n250 OK\r\n";
        let (rem, resp) = response(input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(resp.code, ReplyCode::OK);
        assert_eq!(resp.lines.as_ref().len(), 3);
    }

    #[test]
    fn test_response_error() {
        let (rem, resp) = response(b"550 User not found\r\n").unwrap();
        assert!(rem.is_empty());
        assert_eq!(resp.code, ReplyCode::MAILBOX_UNAVAILABLE);
        assert!(resp.is_error());
    }

    #[test]
    fn test_ehlo_response_single_line() {
        let (rem, ehlo) = ehlo_response(b"250 mail.example.com\r\n").unwrap();
        assert!(rem.is_empty());
        assert_eq!(ehlo.domain.inner(), "mail.example.com");
        assert!(ehlo.capabilities.is_empty());
    }

    #[test]
    fn test_ehlo_response_multiline() {
        let input = b"250-mail.example.com Hello\r\n250-PIPELINING\r\n250 8BITMIME\r\n";
        let (rem, ehlo) = ehlo_response(input).unwrap();
        assert!(rem.is_empty());
        assert_eq!(ehlo.domain.inner(), "mail.example.com");
        assert_eq!(ehlo.capabilities.len(), 2);
    }

    #[cfg(feature = "ext_size")]
    #[test]
    fn test_size_capability() {
        let (rem, ehlo) = ehlo_response(b"250-mail.example.com\r\n250-SIZE 10240000\r\n250 OK\r\n").unwrap();
        assert!(rem.is_empty());
        assert!(ehlo.has_capability("SIZE"));
    }

    #[cfg(feature = "ext_auth")]
    #[test]
    fn test_auth_capability() {
        let (rem, ehlo) = ehlo_response(b"250-mail.example.com\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n").unwrap();
        assert!(rem.is_empty());
        assert!(ehlo.has_capability("AUTH"));
        let mechs = ehlo.auth_mechanisms().unwrap();
        assert_eq!(mechs.len(), 2);
    }

    #[test]
    fn test_incomplete() {
        assert!(matches!(greeting(b"220"), Err(nom::Err::Incomplete(_))));
        assert!(matches!(greeting(b"220 "), Err(nom::Err::Incomplete(_))));
        assert!(matches!(
            greeting(b"220 mail.example.com"),
            Err(nom::Err::Incomplete(_))
        ));
        assert!(matches!(
            greeting(b"220 mail.example.com\r"),
            Err(nom::Err::Incomplete(_))
        ));
    }

    #[test]
    fn test_response_354() {
        let (rem, resp) = response(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n").unwrap();
        assert!(rem.is_empty());
        assert_eq!(resp.code, ReplyCode::START_MAIL_INPUT);
        assert!(resp.is_success());
    }
}
