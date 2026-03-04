//! Core SMTP parsers.
//!
//! This module provides parsers for fundamental SMTP types like domains,
//! addresses, atoms, and reply codes.

use std::{borrow::Cow, net::Ipv4Addr, str::from_utf8};

use abnf_core::{is_alpha, is_digit};
#[cfg(feature = "ext_auth")]
use base64::{Engine, engine::general_purpose::STANDARD as _base64};
#[cfg(feature = "ext_size")]
use nom::character::streaming::digit1;
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while, take_while_m_n, take_while1},
    combinator::{map, map_res, opt, recognize, verify},
    sequence::{delimited, preceded, tuple},
};
use smtp_types::{
    core::{
        AddressLiteral, Atom, Domain, EhloDomain, ForwardPath, LocalPart, Mailbox, Parameter,
        ReversePath, Text,
    },
    utils::indicators::{
        is_atext, is_dcontent, is_esmtp_keyword_char, is_esmtp_value_char, is_ldh_str_char,
        is_let_dig, is_text_char,
    },
};

use crate::decode::SMTPResult;

// ----- Number ------------------------------------------------------------------------------------

/// Parse a decimal number.
#[cfg(feature = "ext_size")]
pub(crate) fn number(input: &[u8]) -> SMTPResult<'_, &[u8], u64> {
    map_res(
        map(digit1, |val| from_utf8(val).unwrap()),
        str::parse::<u64>,
    )(input)
}

/// Parse a 3-digit reply code.
pub(crate) fn reply_code(input: &[u8]) -> SMTPResult<'_, &[u8], u16> {
    map_res(
        map(take_while_m_n(3, 3, is_digit), |val: &[u8]| {
            from_utf8(val).unwrap()
        }),
        str::parse::<u16>,
    )(input)
}

// ----- Domain ------------------------------------------------------------------------------------

/// ```abnf
/// Domain = sub-domain *("." sub-domain)
/// ```
pub(crate) fn domain(input: &[u8]) -> SMTPResult<'_, &[u8], Domain<'_>> {
    map(
        recognize(tuple((
            sub_domain,
            take_while(|b| is_ldh_str_char(b) || b == b'.'),
        ))),
        |bytes: &[u8]| {
            // Validate the domain structure
            let s = from_utf8(bytes).unwrap();
            Domain::unvalidated(s)
        },
    )(input)
}

/// ```abnf
/// sub-domain = Let-dig [Ldh-str]
/// ```
pub(crate) fn sub_domain(input: &[u8]) -> SMTPResult<'_, &[u8], &[u8]> {
    recognize(tuple((
        verify(take_while_m_n(1, 1, |_| true), |b: &[u8]| {
            !b.is_empty() && is_let_dig(b[0])
        }),
        take_while(is_ldh_str_char),
    )))(input)
}

// ----- Address Literal ---------------------------------------------------------------------------

/// ```abnf
/// address-literal = "[" ( IPv4-address-literal / IPv6-address-literal / General-address-literal ) "]"
/// ```
pub(crate) fn address_literal(input: &[u8]) -> SMTPResult<'_, &[u8], AddressLiteral<'_>> {
    delimited(
        tag(b"["),
        alt((
            map(ipv6_address_literal, AddressLiteral::IPv6),
            map(ipv4_address_literal, AddressLiteral::IPv4),
            general_address_literal,
        )),
        tag(b"]"),
    )(input)
}

/// ```abnf
/// IPv4-address-literal = Snum 3("." Snum)
/// ```
pub(crate) fn ipv4_address_literal(input: &[u8]) -> SMTPResult<'_, &[u8], Ipv4Addr> {
    map_res(
        recognize(tuple((
            snum,
            tag(b"."),
            snum,
            tag(b"."),
            snum,
            tag(b"."),
            snum,
        ))),
        |bytes: &[u8]| from_utf8(bytes).unwrap().parse::<Ipv4Addr>(),
    )(input)
}

/// ```abnf
/// Snum = 1*3DIGIT
/// ```
fn snum(input: &[u8]) -> SMTPResult<'_, &[u8], &[u8]> {
    verify(take_while_m_n(1, 3, is_digit), |bytes: &[u8]| {
        if let Ok(s) = from_utf8(bytes) {
            if let Ok(n) = s.parse::<u16>() {
                return n <= 255;
            }
        }
        false
    })(input)
}

/// ```abnf
/// IPv6-address-literal = "IPv6:" IPv6-addr
/// ```
pub(crate) fn ipv6_address_literal(input: &[u8]) -> SMTPResult<'_, &[u8], std::net::Ipv6Addr> {
    preceded(
        tag_no_case(b"IPv6:"),
        map_res(
            recognize(take_while1(|b| is_let_dig(b) || b == b':')),
            |bytes: &[u8]| from_utf8(bytes).unwrap().parse::<std::net::Ipv6Addr>(),
        ),
    )(input)
}

/// ```abnf
/// General-address-literal = Standardized-tag ":" 1*dcontent
/// ```
pub(crate) fn general_address_literal(input: &[u8]) -> SMTPResult<'_, &[u8], AddressLiteral<'_>> {
    map(
        tuple((
            map(take_while1(is_ldh_str_char), |bytes: &[u8]| {
                Atom::unvalidated(from_utf8(bytes).unwrap())
            }),
            tag(b":"),
            map(take_while1(is_dcontent), |bytes: &[u8]| {
                Cow::Borrowed(from_utf8(bytes).unwrap())
            }),
        )),
        |(tag_atom, _, content)| AddressLiteral::General {
            tag: tag_atom,
            content,
        },
    )(input)
}

// ----- EHLO Domain -------------------------------------------------------------------------------

/// ```abnf
/// ehlo-domain = Domain / address-literal
/// ```
pub(crate) fn ehlo_domain(input: &[u8]) -> SMTPResult<'_, &[u8], EhloDomain<'_>> {
    alt((
        map(address_literal, EhloDomain::AddressLiteral),
        map(domain, EhloDomain::Domain),
    ))(input)
}

// ----- Local Part --------------------------------------------------------------------------------

/// ```abnf
/// Local-part = Dot-string / Quoted-string
/// ```
pub(crate) fn local_part(input: &[u8]) -> SMTPResult<'_, &[u8], LocalPart<'_>> {
    map(
        recognize(alt((
            // Dot-string = Atom *("." Atom)
            recognize(tuple((atom_raw, take_while(|b| is_atext(b) || b == b'.')))),
            // Quoted-string (simplified)
            recognize(tuple((tag(b"\""), take_while(|b| b != b'"'), tag(b"\"")))),
        ))),
        |bytes: &[u8]| LocalPart::unvalidated(from_utf8(bytes).unwrap()),
    )(input)
}

// ----- Mailbox -----------------------------------------------------------------------------------

/// ```abnf
/// Mailbox = Local-part "@" ( Domain / address-literal )
/// ```
pub(crate) fn mailbox(input: &[u8]) -> SMTPResult<'_, &[u8], Mailbox<'_>> {
    map(
        tuple((local_part, tag(b"@"), ehlo_domain)),
        |(local, _, domain)| Mailbox::new(local, domain),
    )(input)
}

// ----- Path --------------------------------------------------------------------------------------

/// ```abnf
/// Path = "<" [ A-d-l ":" ] Mailbox ">"
/// ```
pub(crate) fn path(input: &[u8]) -> SMTPResult<'_, &[u8], Mailbox<'_>> {
    delimited(
        tag(b"<"),
        // Skip optional source route (A-d-l ":")
        preceded(
            opt(tuple((
                take_while(|b| is_let_dig(b) || b == b',' || b == b'@' || b == b'.'),
                tag(b":"),
            ))),
            mailbox,
        ),
        tag(b">"),
    )(input)
}

/// ```abnf
/// Reverse-path = Path / "<>"
/// ```
pub(crate) fn reverse_path(input: &[u8]) -> SMTPResult<'_, &[u8], ReversePath<'_>> {
    alt((
        map(tag(b"<>"), |_| ReversePath::Null),
        map(path, ReversePath::Mailbox),
    ))(input)
}

/// ```abnf
/// Forward-path = Path
/// ```
pub(crate) fn forward_path(input: &[u8]) -> SMTPResult<'_, &[u8], ForwardPath<'_>> {
    map(path, ForwardPath::from)(input)
}

// ----- Atom --------------------------------------------------------------------------------------

/// Raw atom bytes (for internal use).
fn atom_raw(input: &[u8]) -> SMTPResult<'_, &[u8], &[u8]> {
    take_while1(is_atext)(input)
}

/// ```abnf
/// Atom = 1*atext
/// ```
#[cfg(feature = "ext_auth")]
pub(crate) fn atom(input: &[u8]) -> SMTPResult<'_, &[u8], Atom<'_>> {
    map(atom_raw, |bytes: &[u8]| {
        Atom::unvalidated(from_utf8(bytes).unwrap())
    })(input)
}

// ----- Text --------------------------------------------------------------------------------------

/// ```abnf
/// textstring = 1*(%d09 / %d32-126)
/// ```
pub(crate) fn text(input: &[u8]) -> SMTPResult<'_, &[u8], Text<'_>> {
    map(take_while(is_text_char), |bytes: &[u8]| {
        Text::unvalidated(from_utf8(bytes).unwrap())
    })(input)
}

// ----- ESMTP Parameter ---------------------------------------------------------------------------

/// ```abnf
/// esmtp-param = esmtp-keyword ["=" esmtp-value]
/// ```
pub(crate) fn esmtp_param(input: &[u8]) -> SMTPResult<'_, &[u8], Parameter<'_>> {
    map(
        tuple((esmtp_keyword, opt(preceded(tag(b"="), esmtp_value)))),
        |(keyword, value)| match value {
            Some(v) => Parameter::with_value(keyword, v),
            None => Parameter::new(keyword),
        },
    )(input)
}

/// ```abnf
/// esmtp-keyword = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
/// ```
fn esmtp_keyword(input: &[u8]) -> SMTPResult<'_, &[u8], Atom<'_>> {
    map(
        recognize(tuple((
            verify(take_while_m_n(1, 1, |_| true), |b: &[u8]| {
                !b.is_empty() && (is_alpha(b[0]) || is_digit(b[0]))
            }),
            take_while(is_esmtp_keyword_char),
        ))),
        |bytes: &[u8]| Atom::unvalidated(from_utf8(bytes).unwrap()),
    )(input)
}

/// ```abnf
/// esmtp-value = 1*(%d33-60 / %d62-126)
/// ```
fn esmtp_value(input: &[u8]) -> SMTPResult<'_, &[u8], Cow<'_, str>> {
    map(take_while1(is_esmtp_value_char), |bytes: &[u8]| {
        Cow::Borrowed(from_utf8(bytes).unwrap())
    })(input)
}

// ----- Base64 ------------------------------------------------------------------------------------

/// Parse base64-encoded data.
#[cfg(feature = "ext_auth")]
pub(crate) fn base64_data(input: &[u8]) -> SMTPResult<'_, &[u8], Vec<u8>> {
    map_res(
        recognize(tuple((
            take_while(is_base64_char),
            opt(alt((tag(b"=="), tag(b"=")))),
        ))),
        |input| _base64.decode(input),
    )(input)
}

/// Base64 character.
#[cfg(feature = "ext_auth")]
fn is_base64_char(b: u8) -> bool {
    is_alpha(b) || is_digit(b) || b == b'+' || b == b'/'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain() {
        let (rem, dom) = domain(b"example.com ").unwrap();
        assert_eq!(rem, b" ");
        assert_eq!(dom.inner(), "example.com");

        let (rem, dom) = domain(b"mail.example.com\r\n").unwrap();
        assert_eq!(rem, b"\r\n");
        assert_eq!(dom.inner(), "mail.example.com");
    }

    #[test]
    fn test_reply_code() {
        let (rem, code) = reply_code(b"250 OK").unwrap();
        assert_eq!(rem, b" OK");
        assert_eq!(code, 250);

        let (rem, code) = reply_code(b"354 Start").unwrap();
        assert_eq!(rem, b" Start");
        assert_eq!(code, 354);
    }

    #[test]
    fn test_ipv4_address_literal() {
        let (rem, addr) = address_literal(b"[192.168.1.1]").unwrap();
        assert!(rem.is_empty());
        assert!(matches!(addr, AddressLiteral::IPv4(_)));
    }

    #[test]
    fn test_mailbox() {
        let (rem, mbox) = mailbox(b"user@example.com>").unwrap();
        assert_eq!(rem, b">");
        assert_eq!(mbox.local_part.inner(), "user");
    }

    #[test]
    fn test_reverse_path() {
        let (rem, path) = reverse_path(b"<>").unwrap();
        assert!(rem.is_empty());
        assert!(matches!(path, ReversePath::Null));

        let (rem, path) = reverse_path(b"<user@example.com>").unwrap();
        assert!(rem.is_empty());
        assert!(matches!(path, ReversePath::Mailbox(_)));
    }

    #[test]
    fn test_esmtp_param() {
        // Streaming parsers need trailing data to know when to stop
        let (rem, param) = esmtp_param(b"SIZE=1024\r\n").unwrap();
        assert_eq!(rem, b"\r\n");
        assert_eq!(param.keyword.inner(), "SIZE");
        assert_eq!(param.value, Some(Cow::Borrowed("1024")));

        let (rem, param) = esmtp_param(b"8BITMIME\r\n").unwrap();
        assert_eq!(rem, b"\r\n");
        assert_eq!(param.keyword.inner(), "8BITMIME");
        assert!(param.value.is_none());
    }

    #[test]
    fn test_text() {
        let (rem, txt) = text(b"Hello World!\r\n").unwrap();
        assert_eq!(rem, b"\r\n");
        assert_eq!(txt.inner(), "Hello World!");
    }
}
