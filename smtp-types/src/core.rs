//! Core SMTP data types.
//!
//! This module provides the fundamental types used in SMTP protocol messages,
//! including domain names, email addresses, and text types.

use std::{
    borrow::Cow,
    fmt::{Debug, Display, Formatter},
    net::{Ipv4Addr, Ipv6Addr},
    str::from_utf8,
    vec::IntoIter,
};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    error::{ValidationError, ValidationErrorKind},
    utils::indicators::{is_atext, is_qtext, is_text_char},
};

#[cfg(feature = "arbitrary")]
fn arbitrary_alphanum(u: &mut Unstructured) -> arbitrary::Result<char> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let idx = u.choose_index(CHARS.len())?;
    Ok(CHARS[idx] as char)
}

#[cfg(feature = "arbitrary")]
fn arbitrary_atext(u: &mut Unstructured) -> arbitrary::Result<char> {
    const CHARS: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~";
    let idx = u.choose_index(CHARS.len())?;
    Ok(CHARS[idx] as char)
}

#[cfg(feature = "arbitrary")]
fn arbitrary_text_char(u: &mut Unstructured) -> arbitrary::Result<char> {
    // Printable ASCII (32-126) plus tab (9)
    let c: u8 = u.int_in_range(32..=126)?;
    Ok(c as char)
}

#[cfg(feature = "ext_auth")]
macro_rules! impl_try_from {
    ($via:ty, $lifetime:lifetime, $from:ty, $target:ty) => {
        impl<$lifetime> TryFrom<$from> for $target {
            type Error = <$via as TryFrom<$from>>::Error;

            fn try_from(value: $from) -> Result<Self, Self::Error> {
                let value = <$via>::try_from(value)?;

                Ok(Self::from(value))
            }
        }
    };
}

#[cfg(feature = "ext_auth")]
pub(crate) use impl_try_from;

// =================================================================================================
// Domain
// =================================================================================================

/// A domain name (hostname).
///
/// # ABNF Definition (RFC 5321)
///
/// ```abnf
/// Domain         = sub-domain *("." sub-domain)
/// sub-domain     = Let-dig [Ldh-str]
/// Let-dig        = ALPHA / DIGIT
/// Ldh-str        = *( ALPHA / DIGIT / "-" ) Let-dig
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct Domain<'a>(pub(crate) Cow<'a, str>);

impl Debug for Domain<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Domain({:?})", self.0)
    }
}

impl Display for Domain<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> Domain<'a> {
    /// Validates if value conforms to domain's ABNF definition.
    pub fn validate(value: impl AsRef<[u8]>) -> Result<(), ValidationError> {
        let value = value.as_ref();

        if value.is_empty() {
            return Err(ValidationError::new(ValidationErrorKind::Empty));
        }

        // Check it's valid UTF-8 and contains only valid domain characters
        let s = from_utf8(value).map_err(|_| ValidationError::new(ValidationErrorKind::Invalid))?;

        // Check each subdomain
        for subdomain in s.split('.') {
            if subdomain.is_empty() {
                return Err(ValidationError::new(ValidationErrorKind::Invalid));
            }

            let bytes = subdomain.as_bytes();

            // First char must be alphanumeric
            if !bytes[0].is_ascii_alphanumeric() {
                return Err(ValidationError::new(ValidationErrorKind::InvalidByteAt {
                    byte: bytes[0],
                    at: 0,
                }));
            }

            // Last char must be alphanumeric
            if bytes.len() > 1 && !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
                return Err(ValidationError::new(ValidationErrorKind::InvalidByteAt {
                    byte: bytes[bytes.len() - 1],
                    at: bytes.len() - 1,
                }));
            }

            // Middle chars can be alphanumeric or hyphen
            for (i, &b) in bytes.iter().enumerate() {
                if !b.is_ascii_alphanumeric() && b != b'-' {
                    return Err(ValidationError::new(ValidationErrorKind::InvalidByteAt {
                        byte: b,
                        at: i,
                    }));
                }
            }
        }

        Ok(())
    }

    /// Returns a reference to the inner value.
    pub fn inner(&self) -> &str {
        self.0.as_ref()
    }

    /// Consumes the domain, returning the inner value.
    pub fn into_inner(self) -> Cow<'a, str> {
        self.0
    }

    /// Constructs a domain without validation.
    ///
    /// # Warning: SMTP conformance
    ///
    /// The caller must ensure that `inner` is valid according to [`Self::validate`].
    /// Failing to do so may create invalid/unparsable SMTP messages.
    /// Do not call this constructor with untrusted data.
    ///
    /// Note: This method will `panic!` on wrong input in debug builds.
    pub fn unvalidated<C>(inner: C) -> Self
    where
        C: Into<Cow<'a, str>>,
    {
        let inner = inner.into();

        #[cfg(debug_assertions)]
        Self::validate(inner.as_bytes()).unwrap();

        Self(inner)
    }
}

impl<'a> TryFrom<&'a [u8]> for Domain<'a> {
    type Error = ValidationError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::validate(value)?;
        Ok(Self(Cow::Borrowed(from_utf8(value).unwrap())))
    }
}

impl TryFrom<Vec<u8>> for Domain<'_> {
    type Error = ValidationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(Cow::Owned(String::from_utf8(value).unwrap())))
    }
}

impl<'a> TryFrom<&'a str> for Domain<'a> {
    type Error = ValidationError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::validate(value)?;
        Ok(Self(Cow::Borrowed(value)))
    }
}

impl TryFrom<String> for Domain<'_> {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Domain(Cow::Owned(value)))
    }
}

impl AsRef<str> for Domain<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Domain<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate a valid domain name
        let labels: u8 = u.int_in_range(1..=3)?;
        let mut parts = Vec::new();
        for _ in 0..labels {
            let len: usize = u.int_in_range(1..=10)?;
            let mut label = String::with_capacity(len);
            // First char must be alphanumeric
            label.push(arbitrary_alphanum(u)?);
            // Middle chars can be alphanumeric or hyphen
            for _ in 1..len.saturating_sub(1) {
                let c = if u.ratio(1, 4)? {
                    '-'
                } else {
                    arbitrary_alphanum(u)?
                };
                label.push(c);
            }
            // Last char must be alphanumeric (if len > 1)
            if len > 1 {
                label.push(arbitrary_alphanum(u)?);
            }
            parts.push(label);
        }
        Ok(Domain(Cow::Owned(parts.join("."))))
    }
}

// =================================================================================================
// AddressLiteral
// =================================================================================================

/// An address literal, either IPv4, IPv6, or a general address.
///
/// # ABNF Definition (RFC 5321)
///
/// ```abnf
/// address-literal  = "[" ( IPv4-address-literal /
///                          IPv6-address-literal /
///                          General-address-literal ) "]"
/// IPv4-address-literal  = Snum 3("." Snum)
/// IPv6-address-literal  = "IPv6:" IPv6-addr
/// General-address-literal  = Standardized-tag ":" 1*dcontent
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AddressLiteral<'a> {
    /// IPv4 address, e.g., `[192.168.1.1]`
    IPv4(Ipv4Addr),
    /// IPv6 address, e.g., `[IPv6:2001:db8::1]`
    IPv6(Ipv6Addr),
    /// General address literal, e.g., `[tag:content]`
    General {
        tag: Atom<'a>,
        content: Cow<'a, str>,
    },
}

impl bounded_static::ToBoundedStatic for AddressLiteral<'_> {
    type Static = AddressLiteral<'static>;

    fn to_static(&self) -> Self::Static {
        match self {
            AddressLiteral::IPv4(addr) => AddressLiteral::IPv4(*addr),
            AddressLiteral::IPv6(addr) => AddressLiteral::IPv6(*addr),
            AddressLiteral::General { tag, content } => AddressLiteral::General {
                tag: tag.to_static(),
                content: Cow::Owned(content.clone().into_owned()),
            },
        }
    }
}

impl bounded_static::IntoBoundedStatic for AddressLiteral<'_> {
    type Static = AddressLiteral<'static>;

    fn into_static(self) -> Self::Static {
        match self {
            AddressLiteral::IPv4(addr) => AddressLiteral::IPv4(addr),
            AddressLiteral::IPv6(addr) => AddressLiteral::IPv6(addr),
            AddressLiteral::General { tag, content } => AddressLiteral::General {
                tag: tag.into_static(),
                content: Cow::Owned(content.into_owned()),
            },
        }
    }
}

impl Display for AddressLiteral<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            AddressLiteral::IPv4(addr) => write!(f, "[{addr}]"),
            AddressLiteral::IPv6(addr) => write!(f, "[IPv6:{addr}]"),
            AddressLiteral::General { tag, content } => write!(f, "[{tag}:{content}]"),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AddressLiteral<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let variant: u8 = u.int_in_range(0..=1)?;
        match variant {
            0 => Ok(AddressLiteral::IPv4(Ipv4Addr::arbitrary(u)?)),
            _ => Ok(AddressLiteral::IPv6(Ipv6Addr::arbitrary(u)?)),
        }
    }
}

// =================================================================================================
// EhloDomain
// =================================================================================================

/// The domain identifier used in EHLO/HELO commands.
///
/// Can be either a domain name or an address literal.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum EhloDomain<'a> {
    /// A domain name
    Domain(Domain<'a>),
    /// An address literal (IPv4, IPv6, or general)
    AddressLiteral(AddressLiteral<'a>),
}

impl Display for EhloDomain<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            EhloDomain::Domain(domain) => write!(f, "{domain}"),
            EhloDomain::AddressLiteral(addr) => write!(f, "{addr}"),
        }
    }
}

impl<'a> From<Domain<'a>> for EhloDomain<'a> {
    fn from(domain: Domain<'a>) -> Self {
        EhloDomain::Domain(domain)
    }
}

impl<'a> From<AddressLiteral<'a>> for EhloDomain<'a> {
    fn from(addr: AddressLiteral<'a>) -> Self {
        EhloDomain::AddressLiteral(addr)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for EhloDomain<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(3, 4)? {
            Ok(EhloDomain::Domain(Domain::arbitrary(u)?))
        } else {
            Ok(EhloDomain::AddressLiteral(AddressLiteral::arbitrary(u)?))
        }
    }
}

// =================================================================================================
// LocalPart
// =================================================================================================

/// The local part of an email address (before the @).
///
/// # ABNF Definition (RFC 5321)
///
/// ```abnf
/// Local-part     = Dot-string / Quoted-string
/// Dot-string     = Atom *("." Atom)
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct LocalPart<'a>(pub(crate) Cow<'a, str>);

impl Debug for LocalPart<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "LocalPart({:?})", self.0)
    }
}

impl Display for LocalPart<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> LocalPart<'a> {
    /// Validates if value conforms to local-part's ABNF definition.
    pub fn validate(value: impl AsRef<[u8]>) -> Result<(), ValidationError> {
        let value = value.as_ref();

        if value.is_empty() {
            return Err(ValidationError::new(ValidationErrorKind::Empty));
        }

        // Check for valid UTF-8
        let _ = from_utf8(value).map_err(|_| ValidationError::new(ValidationErrorKind::Invalid))?;

        // Check each character is valid for local-part (simplified check)
        for (i, &b) in value.iter().enumerate() {
            if !is_atext(b) && b != b'.' && !is_qtext(b) {
                return Err(ValidationError::new(ValidationErrorKind::InvalidByteAt {
                    byte: b,
                    at: i,
                }));
            }
        }

        Ok(())
    }

    /// Returns a reference to the inner value.
    pub fn inner(&self) -> &str {
        self.0.as_ref()
    }

    /// Consumes the local part, returning the inner value.
    pub fn into_inner(self) -> Cow<'a, str> {
        self.0
    }

    /// Constructs a local part without validation.
    pub fn unvalidated<C>(inner: C) -> Self
    where
        C: Into<Cow<'a, str>>,
    {
        let inner = inner.into();

        #[cfg(debug_assertions)]
        Self::validate(inner.as_bytes()).unwrap();

        Self(inner)
    }
}

impl<'a> TryFrom<&'a [u8]> for LocalPart<'a> {
    type Error = ValidationError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::validate(value)?;
        Ok(Self(Cow::Borrowed(from_utf8(value).unwrap())))
    }
}

impl TryFrom<Vec<u8>> for LocalPart<'_> {
    type Error = ValidationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(Cow::Owned(String::from_utf8(value).unwrap())))
    }
}

impl<'a> TryFrom<&'a str> for LocalPart<'a> {
    type Error = ValidationError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::validate(value)?;
        Ok(Self(Cow::Borrowed(value)))
    }
}

impl TryFrom<String> for LocalPart<'_> {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(Cow::Owned(value)))
    }
}

impl AsRef<str> for LocalPart<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for LocalPart<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len: usize = u.int_in_range(1..=10)?;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            s.push(arbitrary_atext(u)?);
        }
        Ok(LocalPart(Cow::Owned(s)))
    }
}

// =================================================================================================
// Mailbox
// =================================================================================================

/// A full email address: local-part@domain.
///
/// # ABNF Definition (RFC 5321)
///
/// ```abnf
/// Mailbox        = Local-part "@" ( Domain / address-literal )
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Mailbox<'a> {
    /// The local part (before @)
    pub local_part: LocalPart<'a>,
    /// The domain (after @)
    pub domain: EhloDomain<'a>,
}

impl Display for Mailbox<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}@{}", self.local_part, self.domain)
    }
}

impl<'a> Mailbox<'a> {
    /// Creates a new mailbox.
    pub fn new(local_part: LocalPart<'a>, domain: EhloDomain<'a>) -> Self {
        Self { local_part, domain }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Mailbox<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Mailbox {
            local_part: LocalPart::arbitrary(u)?,
            domain: EhloDomain::arbitrary(u)?,
        })
    }
}

// =================================================================================================
// ReversePath
// =================================================================================================

/// The reverse path for MAIL FROM (can be null <>).
///
/// # ABNF Definition (RFC 5321)
///
/// ```abnf
/// Reverse-path   = Path / "<>"
/// Path           = "<" [ A-d-l ":" ] Mailbox ">"
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic, Default)]
pub enum ReversePath<'a> {
    /// Null reverse path (<>)
    #[default]
    Null,
    /// A mailbox address
    Mailbox(Mailbox<'a>),
}

impl Display for ReversePath<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ReversePath::Null => write!(f, "<>"),
            ReversePath::Mailbox(mailbox) => write!(f, "<{mailbox}>"),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ReversePath<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.ratio(1, 4)? {
            Ok(ReversePath::Null)
        } else {
            Ok(ReversePath::Mailbox(Mailbox::arbitrary(u)?))
        }
    }
}

// =================================================================================================
// ForwardPath
// =================================================================================================

/// The forward path for RCPT TO.
///
/// # ABNF Definition (RFC 5321)
///
/// ```abnf
/// Forward-path   = Path
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct ForwardPath<'a>(pub Mailbox<'a>);

impl Display for ForwardPath<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "<{}>", self.0)
    }
}

impl<'a> From<Mailbox<'a>> for ForwardPath<'a> {
    fn from(mailbox: Mailbox<'a>) -> Self {
        ForwardPath(mailbox)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ForwardPath<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(ForwardPath(Mailbox::arbitrary(u)?))
    }
}

// =================================================================================================
// Atom
// =================================================================================================

/// An SMTP atom (similar to IMAP but different character rules).
///
/// # ABNF Definition (RFC 5321)
///
/// ```abnf
/// Atom           = 1*atext
/// atext          = ALPHA / DIGIT /
///                  "!" / "#" / "$" / "%" / "&" / "'" / "*" /
///                  "+" / "-" / "/" / "=" / "?" / "^" / "_" /
///                  "`" / "{" / "|" / "}" / "~"
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct Atom<'a>(pub(crate) Cow<'a, str>);

impl Debug for Atom<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Atom({:?})", self.0)
    }
}

impl Display for Atom<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> Atom<'a> {
    /// Validates if value conforms to atom's ABNF definition.
    pub fn validate(value: impl AsRef<[u8]>) -> Result<(), ValidationError> {
        let value = value.as_ref();

        if value.is_empty() {
            return Err(ValidationError::new(ValidationErrorKind::Empty));
        }

        if let Some(at) = value.iter().position(|b| !is_atext(*b)) {
            return Err(ValidationError::new(ValidationErrorKind::InvalidByteAt {
                byte: value[at],
                at,
            }));
        };

        Ok(())
    }

    /// Returns a reference to the inner value.
    pub fn inner(&self) -> &str {
        self.0.as_ref()
    }

    /// Consumes the atom, returning the inner value.
    pub fn into_inner(self) -> Cow<'a, str> {
        self.0
    }

    /// Constructs an atom without validation.
    pub fn unvalidated<C>(inner: C) -> Self
    where
        C: Into<Cow<'a, str>>,
    {
        let inner = inner.into();

        #[cfg(debug_assertions)]
        Self::validate(inner.as_bytes()).unwrap();

        Self(inner)
    }
}

impl<'a> TryFrom<&'a [u8]> for Atom<'a> {
    type Error = ValidationError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::validate(value)?;
        Ok(Self(Cow::Borrowed(from_utf8(value).unwrap())))
    }
}

impl TryFrom<Vec<u8>> for Atom<'_> {
    type Error = ValidationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(Cow::Owned(String::from_utf8(value).unwrap())))
    }
}

impl<'a> TryFrom<&'a str> for Atom<'a> {
    type Error = ValidationError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::validate(value)?;
        Ok(Self(Cow::Borrowed(value)))
    }
}

impl TryFrom<String> for Atom<'_> {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Atom(Cow::Owned(value)))
    }
}

impl<'a> TryFrom<Cow<'a, str>> for Atom<'a> {
    type Error = ValidationError;

    fn try_from(value: Cow<'a, str>) -> Result<Self, Self::Error> {
        Self::validate(value.as_bytes())?;
        Ok(Self(value))
    }
}

impl AsRef<str> for Atom<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Atom<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len: usize = u.int_in_range(1..=10)?;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            s.push(arbitrary_atext(u)?);
        }
        Ok(Atom(Cow::Owned(s)))
    }
}

// =================================================================================================
// Text
// =================================================================================================

/// A human-readable text string used in SMTP responses.
///
/// # ABNF Definition (RFC 5321)
///
/// ```abnf
/// textstring     = 1*(%d09 / %d32-126)  ; HT, SP, Printable US-ASCII
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
#[derive(PartialEq, Eq, Hash, Clone, ToStatic)]
pub struct Text<'a>(pub(crate) Cow<'a, str>);

impl Debug for Text<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Text({:?})", self.0)
    }
}

impl Display for Text<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0.as_ref())
    }
}

impl<'a> Text<'a> {
    pub fn validate(value: impl AsRef<[u8]>) -> Result<(), ValidationError> {
        let value = value.as_ref();

        // Empty text is allowed in SMTP (unlike IMAP)
        if let Some(at) = value.iter().position(|b| !is_text_char(*b)) {
            return Err(ValidationError::new(ValidationErrorKind::InvalidByteAt {
                byte: value[at],
                at,
            }));
        };

        Ok(())
    }

    pub fn inner(&self) -> &str {
        self.0.as_ref()
    }

    pub fn into_inner(self) -> Cow<'a, str> {
        self.0
    }

    /// Constructs text without validation.
    pub fn unvalidated<C>(inner: C) -> Self
    where
        C: Into<Cow<'a, str>>,
    {
        let inner = inner.into();

        #[cfg(debug_assertions)]
        Self::validate(inner.as_bytes()).unwrap();

        Self(inner)
    }
}

impl<'a> TryFrom<&'a [u8]> for Text<'a> {
    type Error = ValidationError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::validate(value)?;
        Ok(Self(Cow::Borrowed(from_utf8(value).unwrap())))
    }
}

impl TryFrom<Vec<u8>> for Text<'_> {
    type Error = ValidationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(Cow::Owned(String::from_utf8(value).unwrap())))
    }
}

impl<'a> TryFrom<&'a str> for Text<'a> {
    type Error = ValidationError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::validate(value)?;
        Ok(Self(Cow::Borrowed(value)))
    }
}

impl TryFrom<String> for Text<'_> {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(Cow::Owned(value)))
    }
}

impl AsRef<str> for Text<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Text<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len: usize = u.int_in_range(0..=50)?;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            s.push(arbitrary_text_char(u)?);
        }
        Ok(Text(Cow::Owned(s)))
    }
}

// =================================================================================================
// Parameter
// =================================================================================================

/// An ESMTP parameter (keyword[=value]).
///
/// # ABNF Definition (RFC 5321)
///
/// ```abnf
/// esmtp-param    = esmtp-keyword ["=" esmtp-value]
/// esmtp-keyword  = (ALPHA / DIGIT) *(ALPHA / DIGIT / "-")
/// esmtp-value    = 1*(%d33-60 / %d62-126)  ; any CHAR excluding "=", SP, and CTL
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Parameter<'a> {
    /// The parameter keyword
    pub keyword: Atom<'a>,
    /// The optional parameter value
    pub value: Option<Cow<'a, str>>,
}

impl Display for Parameter<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match &self.value {
            Some(value) => write!(f, "{}={}", self.keyword, value),
            None => write!(f, "{}", self.keyword),
        }
    }
}

impl<'a> Parameter<'a> {
    /// Creates a new parameter with just a keyword.
    pub fn new(keyword: Atom<'a>) -> Self {
        Self {
            keyword,
            value: None,
        }
    }

    /// Creates a new parameter with a keyword and value.
    pub fn with_value(keyword: Atom<'a>, value: impl Into<Cow<'a, str>>) -> Self {
        Self {
            keyword,
            value: Some(value.into()),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Parameter<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let keyword = Atom::arbitrary(u)?;
        let has_value: bool = u.arbitrary()?;
        let value = if has_value {
            // Generate a valid esmtp-value (printable ASCII excluding '=' and space)
            let len: usize = u.int_in_range(1..=10)?;
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                let c: u8 = u.int_in_range(33..=126)?;
                // Skip '=' (61)
                if c != 61 {
                    s.push(c as char);
                } else {
                    s.push('a');
                }
            }
            Some(Cow::Owned(s))
        } else {
            None
        };
        Ok(Parameter { keyword, value })
    }
}

// =================================================================================================
// Vec1
// =================================================================================================

/// A [`Vec`] containing >= 1 elements, i.e., a non-empty vector.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "Vec<T>"))]
#[derive(Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Vec1<T>(pub(crate) Vec<T>);

impl<T> Debug for Vec1<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        self.0.fmt(f)?;
        write!(f, "+")
    }
}

impl<T> Vec1<T> {
    pub fn validate(value: &[T]) -> Result<(), ValidationError> {
        if value.is_empty() {
            return Err(ValidationError::new(ValidationErrorKind::NotEnough {
                min: 1,
            }));
        }
        Ok(())
    }

    /// Constructs a non-empty vector without validation.
    pub fn unvalidated(inner: Vec<T>) -> Self {
        #[cfg(debug_assertions)]
        Self::validate(&inner).unwrap();

        Self(inner)
    }

    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T> From<T> for Vec1<T> {
    fn from(value: T) -> Self {
        Vec1(vec![value])
    }
}

impl<T> TryFrom<Vec<T>> for Vec1<T> {
    type Error = ValidationError;

    fn try_from(inner: Vec<T>) -> Result<Self, Self::Error> {
        Self::validate(&inner)?;
        Ok(Self(inner))
    }
}

impl<T> IntoIterator for Vec1<T> {
    type Item = T;
    type IntoIter = IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> AsRef<[T]> for Vec1<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, T> Arbitrary<'a> for Vec1<T>
where
    T: Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len: usize = u.int_in_range(1..=5)?;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::arbitrary(u)?);
        }
        Ok(Vec1(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_validation() {
        assert!(Domain::try_from("example.com").is_ok());
        assert!(Domain::try_from("mail.example.com").is_ok());
        assert!(Domain::try_from("a").is_ok());
        assert!(Domain::try_from("a-b").is_ok());
        assert!(Domain::try_from("a1").is_ok());

        // Invalid: empty
        assert!(Domain::try_from("").is_err());
        // Invalid: starts with hyphen
        assert!(Domain::try_from("-example").is_err());
        // Invalid: ends with hyphen
        assert!(Domain::try_from("example-").is_err());
    }

    #[test]
    fn test_atom_validation() {
        assert!(Atom::try_from("HELLO").is_ok());
        assert!(Atom::try_from("test123").is_ok());
        assert!(Atom::try_from("a").is_ok());

        // Invalid: empty
        assert!(Atom::try_from("").is_err());
        // Invalid: space
        assert!(Atom::try_from("hello world").is_err());
    }

    #[test]
    fn test_text_validation() {
        assert!(Text::try_from("Hello World!").is_ok());
        assert!(Text::try_from("").is_ok()); // Empty is allowed in SMTP
        assert!(Text::try_from("\t tab").is_ok());

        // Invalid: CR
        assert!(Text::try_from("hello\rworld").is_err());
        // Invalid: LF
        assert!(Text::try_from("hello\nworld").is_err());
    }

    #[test]
    fn test_vec1() {
        assert!(Vec1::<u8>::try_from(vec![]).is_err());
        assert!(Vec1::<u8>::try_from(vec![1]).is_ok());
        assert!(Vec1::<u8>::try_from(vec![1, 2]).is_ok());
    }
}
