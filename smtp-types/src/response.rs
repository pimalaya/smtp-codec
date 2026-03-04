//! SMTP response types.
//!
//! This module defines the responses that an SMTP server sends to a client
//! as specified in RFC 5321.

use std::{
    borrow::Cow,
    fmt::{Debug, Display, Formatter},
    str::FromStr,
};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "ext_auth")]
use crate::auth::AuthMechanism;
use crate::{
    core::{Atom, Domain, Text, Vec1},
    error::{ValidationError, ValidationErrorKind},
};

// =================================================================================================
// ReplyCode
// =================================================================================================

/// A 3-digit SMTP reply code.
///
/// # ABNF Definition (RFC 5321)
///
/// ```abnf
/// Reply-code     = %x32-35 %x30-35 %x30-39
/// ```
///
/// # Reference
///
/// RFC 5321 Section 4.2: SMTP Replies
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, ToStatic)]
pub struct ReplyCode(u16);

impl ReplyCode {
    // Positive Completion (2xx)
    /// 211 System status
    pub const SYSTEM_STATUS: Self = Self(211);
    /// 214 Help message
    pub const HELP_MESSAGE: Self = Self(214);
    /// 220 Service ready
    pub const SERVICE_READY: Self = Self(220);
    /// 221 Service closing transmission channel
    pub const SERVICE_CLOSING: Self = Self(221);
    /// 235 Authentication successful (RFC 4954)
    pub const AUTH_SUCCESSFUL: Self = Self(235);
    /// 250 Requested mail action okay, completed
    pub const OK: Self = Self(250);
    /// 251 User not local; will forward
    pub const USER_NOT_LOCAL_WILL_FORWARD: Self = Self(251);
    /// 252 Cannot VRFY user, but will accept message
    pub const CANNOT_VRFY_USER: Self = Self(252);

    // Positive Intermediate (3xx)
    /// 334 Server challenge (AUTH continuation)
    pub const AUTH_CONTINUE: Self = Self(334);
    /// 354 Start mail input
    pub const START_MAIL_INPUT: Self = Self(354);

    // Transient Negative (4xx)
    /// 421 Service not available, closing transmission channel
    pub const SERVICE_NOT_AVAILABLE: Self = Self(421);
    /// 450 Requested mail action not taken: mailbox unavailable
    pub const MAILBOX_UNAVAILABLE_TEMP: Self = Self(450);
    /// 451 Requested action aborted: local error in processing
    pub const LOCAL_ERROR: Self = Self(451);
    /// 452 Requested action not taken: insufficient system storage
    pub const INSUFFICIENT_STORAGE: Self = Self(452);
    /// 455 Server unable to accommodate parameters
    pub const UNABLE_TO_ACCOMMODATE: Self = Self(455);

    // Permanent Negative (5xx)
    /// 500 Syntax error, command unrecognized
    pub const SYNTAX_ERROR: Self = Self(500);
    /// 501 Syntax error in parameters or arguments
    pub const SYNTAX_ERROR_PARAMS: Self = Self(501);
    /// 502 Command not implemented
    pub const COMMAND_NOT_IMPLEMENTED: Self = Self(502);
    /// 503 Bad sequence of commands
    pub const BAD_SEQUENCE: Self = Self(503);
    /// 504 Command parameter not implemented
    pub const PARAM_NOT_IMPLEMENTED: Self = Self(504);
    /// 530 Authentication required (RFC 4954)
    pub const AUTH_REQUIRED: Self = Self(530);
    /// 534 Authentication mechanism is too weak (RFC 4954)
    pub const AUTH_TOO_WEAK: Self = Self(534);
    /// 535 Authentication credentials invalid (RFC 4954)
    pub const AUTH_INVALID: Self = Self(535);
    /// 550 Requested action not taken: mailbox unavailable
    pub const MAILBOX_UNAVAILABLE: Self = Self(550);
    /// 551 User not local; please try forwarding
    pub const USER_NOT_LOCAL: Self = Self(551);
    /// 552 Requested mail action aborted: exceeded storage allocation
    pub const EXCEEDED_STORAGE: Self = Self(552);
    /// 553 Requested action not taken: mailbox name not allowed
    pub const MAILBOX_NAME_NOT_ALLOWED: Self = Self(553);
    /// 554 Transaction failed
    pub const TRANSACTION_FAILED: Self = Self(554);
    /// 555 MAIL FROM/RCPT TO parameters not recognized or not implemented
    pub const PARAMS_NOT_RECOGNIZED: Self = Self(555);

    /// Creates a new reply code from a u16.
    ///
    /// Returns `None` if the value is not a valid 3-digit code (200-599).
    pub fn new(code: u16) -> Option<Self> {
        if (200..600).contains(&code) {
            Some(Self(code))
        } else {
            None
        }
    }

    /// Returns the numeric value of the reply code.
    pub fn code(&self) -> u16 {
        self.0
    }

    /// Returns the first digit (class) of the reply code.
    pub fn class(&self) -> u8 {
        (self.0 / 100) as u8
    }

    /// Returns true if this is a positive completion reply (2xx).
    pub fn is_positive_completion(&self) -> bool {
        self.class() == 2
    }

    /// Returns true if this is a positive intermediate reply (3xx).
    pub fn is_positive_intermediate(&self) -> bool {
        self.class() == 3
    }

    /// Returns true if this is a transient negative reply (4xx).
    pub fn is_transient_negative(&self) -> bool {
        self.class() == 4
    }

    /// Returns true if this is a permanent negative reply (5xx).
    pub fn is_permanent_negative(&self) -> bool {
        self.class() == 5
    }

    /// Returns true if this is a success reply (2xx or 3xx).
    pub fn is_success(&self) -> bool {
        self.is_positive_completion() || self.is_positive_intermediate()
    }

    /// Returns true if this is an error reply (4xx or 5xx).
    pub fn is_error(&self) -> bool {
        self.is_transient_negative() || self.is_permanent_negative()
    }
}

impl Debug for ReplyCode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "ReplyCode({})", self.0)
    }
}

impl Display for ReplyCode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ReplyCode> for u16 {
    fn from(code: ReplyCode) -> Self {
        code.0
    }
}

impl TryFrom<u16> for ReplyCode {
    type Error = ValidationError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        ReplyCode::new(value).ok_or_else(|| ValidationError::new(ValidationErrorKind::Invalid))
    }
}

impl FromStr for ReplyCode {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code: u16 = s
            .parse()
            .map_err(|_| ValidationError::new(ValidationErrorKind::Invalid))?;
        ReplyCode::try_from(code)
    }
}

// =================================================================================================
// EnhancedStatusCode
// =================================================================================================

/// Enhanced status code (RFC 3463).
///
/// Format: class.subject.detail (e.g., 2.1.0, 5.7.1)
///
/// # Reference
///
/// RFC 3463: Enhanced Mail System Status Codes
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToStatic)]
#[cfg(feature = "ext_enhancedstatuscodes")]
pub struct EnhancedStatusCode {
    /// Class: 2 (success), 4 (temporary failure), or 5 (permanent failure)
    pub class: u8,
    /// Subject: 0-999
    pub subject: u16,
    /// Detail: 0-999
    pub detail: u16,
}

#[cfg(feature = "ext_enhancedstatuscodes")]
impl EnhancedStatusCode {
    /// Creates a new enhanced status code.
    ///
    /// Returns `None` if class is not 2, 4, or 5.
    pub fn new(class: u8, subject: u16, detail: u16) -> Option<Self> {
        if matches!(class, 2 | 4 | 5) && subject < 1000 && detail < 1000 {
            Some(Self {
                class,
                subject,
                detail,
            })
        } else {
            None
        }
    }

    /// Returns true if this indicates success.
    pub fn is_success(&self) -> bool {
        self.class == 2
    }

    /// Returns true if this indicates a temporary failure.
    pub fn is_temporary_failure(&self) -> bool {
        self.class == 4
    }

    /// Returns true if this indicates a permanent failure.
    pub fn is_permanent_failure(&self) -> bool {
        self.class == 5
    }
}

#[cfg(feature = "ext_enhancedstatuscodes")]
impl Display for EnhancedStatusCode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.class, self.subject, self.detail)
    }
}

// =================================================================================================
// Greeting
// =================================================================================================

/// Server greeting sent upon connection.
///
/// The greeting is the first response from an SMTP server,
/// typically a 220 response indicating the server is ready.
///
/// # ABNF
///
/// ```abnf
/// greeting = "220" SP Domain [ SP textstring ] CRLF
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Greeting<'a> {
    /// The server's domain name
    pub domain: Domain<'a>,
    /// Optional greeting text
    pub text: Option<Text<'a>>,
}

impl<'a> Greeting<'a> {
    /// Creates a new greeting.
    pub fn new(domain: Domain<'a>, text: Option<Text<'a>>) -> Self {
        Self { domain, text }
    }
}

impl Display for Greeting<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "220 {}", self.domain)?;
        if let Some(ref text) = self.text {
            write!(f, " {text}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Greeting<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Greeting {
            domain: Domain::arbitrary(u)?,
            text: if u.arbitrary()? {
                Some(Text::arbitrary(u)?)
            } else {
                None
            },
        })
    }
}

// =================================================================================================
// Response
// =================================================================================================

/// A complete SMTP response (possibly multi-line).
///
/// # ABNF
///
/// ```abnf
/// Reply-line     = *( Reply-code "-" [ textstring ] CRLF )
///                  Reply-code [ SP textstring ] CRLF
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct Response<'a> {
    /// The 3-digit reply code
    pub code: ReplyCode,
    /// Enhanced status code (if ENHANCEDSTATUSCODES extension is supported)
    #[cfg(feature = "ext_enhancedstatuscodes")]
    pub enhanced_code: Option<EnhancedStatusCode>,
    /// One or more response lines
    pub lines: Vec1<Text<'a>>,
}

impl<'a> Response<'a> {
    /// Creates a new single-line response.
    pub fn new(code: ReplyCode, text: Text<'a>) -> Self {
        Self {
            code,
            #[cfg(feature = "ext_enhancedstatuscodes")]
            enhanced_code: None,
            lines: Vec1::from(text),
        }
    }

    /// Creates a new multi-line response.
    pub fn new_multiline(code: ReplyCode, lines: Vec1<Text<'a>>) -> Self {
        Self {
            code,
            #[cfg(feature = "ext_enhancedstatuscodes")]
            enhanced_code: None,
            lines,
        }
    }

    /// Creates a new response with an enhanced status code.
    #[cfg(feature = "ext_enhancedstatuscodes")]
    pub fn with_enhanced_code(
        code: ReplyCode,
        enhanced_code: EnhancedStatusCode,
        text: Text<'a>,
    ) -> Self {
        Self {
            code,
            enhanced_code: Some(enhanced_code),
            lines: Vec1::from(text),
        }
    }

    /// Returns true if this is a success response.
    pub fn is_success(&self) -> bool {
        self.code.is_success()
    }

    /// Returns true if this is an error response.
    pub fn is_error(&self) -> bool {
        self.code.is_error()
    }

    /// Returns the first (or only) line of text.
    pub fn text(&self) -> &Text<'a> {
        &self.lines.as_ref()[0]
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Response<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Response {
            code: ReplyCode::arbitrary(u)?,
            #[cfg(feature = "ext_enhancedstatuscodes")]
            enhanced_code: if u.arbitrary()? {
                Some(EnhancedStatusCode::arbitrary(u)?)
            } else {
                None
            },
            lines: Vec1::arbitrary(u)?,
        })
    }
}

// =================================================================================================
// Capability
// =================================================================================================

/// An SMTP server capability announced in EHLO response.
///
/// # Reference
///
/// RFC 5321 Section 4.1.1.1
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
#[non_exhaustive]
pub enum Capability<'a> {
    /// SIZE extension with optional maximum size.
    ///
    /// # Reference
    ///
    /// RFC 1870: SMTP Service Extension for Message Size Declaration
    #[cfg(feature = "ext_size")]
    Size(Option<u64>),

    /// 8BITMIME extension.
    ///
    /// # Reference
    ///
    /// RFC 6152: SMTP Service Extension for 8-bit MIME Transport
    #[cfg(feature = "ext_8bitmime")]
    EightBitMime,

    /// PIPELINING extension.
    ///
    /// # Reference
    ///
    /// RFC 2920: SMTP Service Extension for Command Pipelining
    #[cfg(feature = "ext_pipelining")]
    Pipelining,

    /// STARTTLS extension.
    ///
    /// # Reference
    ///
    /// RFC 3207: SMTP Service Extension for Secure SMTP over TLS
    #[cfg(feature = "starttls")]
    StartTls,

    /// SMTPUTF8 extension.
    ///
    /// # Reference
    ///
    /// RFC 6531: SMTP Extension for Internationalized Email
    #[cfg(feature = "ext_smtputf8")]
    SmtpUtf8,

    /// ENHANCEDSTATUSCODES extension.
    ///
    /// # Reference
    ///
    /// RFC 2034: SMTP Service Extension for Returning Enhanced Error Codes
    #[cfg(feature = "ext_enhancedstatuscodes")]
    EnhancedStatusCodes,

    /// AUTH extension with supported mechanisms.
    ///
    /// # Reference
    ///
    /// RFC 4954: SMTP Service Extension for Authentication
    #[cfg(feature = "ext_auth")]
    Auth(Vec<AuthMechanism<'a>>),

    /// Other/unknown capability.
    Other {
        /// The capability keyword
        keyword: Atom<'a>,
        /// Optional parameters
        params: Option<Cow<'a, str>>,
    },
}

impl Display for Capability<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            #[cfg(feature = "ext_size")]
            Capability::Size(Some(size)) => write!(f, "SIZE {size}"),
            #[cfg(feature = "ext_size")]
            Capability::Size(None) => write!(f, "SIZE"),
            #[cfg(feature = "ext_8bitmime")]
            Capability::EightBitMime => write!(f, "8BITMIME"),
            #[cfg(feature = "ext_pipelining")]
            Capability::Pipelining => write!(f, "PIPELINING"),
            #[cfg(feature = "starttls")]
            Capability::StartTls => write!(f, "STARTTLS"),
            #[cfg(feature = "ext_smtputf8")]
            Capability::SmtpUtf8 => write!(f, "SMTPUTF8"),
            #[cfg(feature = "ext_enhancedstatuscodes")]
            Capability::EnhancedStatusCodes => write!(f, "ENHANCEDSTATUSCODES"),
            #[cfg(feature = "ext_auth")]
            Capability::Auth(mechanisms) => {
                write!(f, "AUTH")?;
                for mech in mechanisms {
                    write!(f, " {}", mech.as_ref())?;
                }
                Ok(())
            }
            Capability::Other { keyword, params } => {
                write!(f, "{keyword}")?;
                if let Some(params) = params {
                    write!(f, " {params}")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Capability<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Count available variants based on features
        #[allow(unused_mut)]
        let mut variant_count = 1; // Other is always available
        #[cfg(feature = "ext_size")]
        {
            variant_count += 1;
        }
        #[cfg(feature = "ext_8bitmime")]
        {
            variant_count += 1;
        }
        #[cfg(feature = "ext_pipelining")]
        {
            variant_count += 1;
        }
        #[cfg(feature = "starttls")]
        {
            variant_count += 1;
        }
        #[cfg(feature = "ext_smtputf8")]
        {
            variant_count += 1;
        }
        #[cfg(feature = "ext_enhancedstatuscodes")]
        {
            variant_count += 1;
        }
        #[cfg(feature = "ext_auth")]
        {
            variant_count += 1;
        }

        #[allow(unused_variables)]
        let variant: u8 = u.int_in_range(0..=(variant_count - 1))?;
        #[allow(unused_mut, unused_variables)]
        let mut idx = 0u8;

        #[cfg(feature = "ext_size")]
        {
            if variant == idx {
                return Ok(Capability::Size(if u.arbitrary()? {
                    Some(u.arbitrary()?)
                } else {
                    None
                }));
            }
            idx += 1;
        }
        #[cfg(feature = "ext_8bitmime")]
        {
            if variant == idx {
                return Ok(Capability::EightBitMime);
            }
            idx += 1;
        }
        #[cfg(feature = "ext_pipelining")]
        {
            if variant == idx {
                return Ok(Capability::Pipelining);
            }
            idx += 1;
        }
        #[cfg(feature = "starttls")]
        {
            if variant == idx {
                return Ok(Capability::StartTls);
            }
            idx += 1;
        }
        #[cfg(feature = "ext_smtputf8")]
        {
            if variant == idx {
                return Ok(Capability::SmtpUtf8);
            }
            idx += 1;
        }
        #[cfg(feature = "ext_enhancedstatuscodes")]
        {
            if variant == idx {
                return Ok(Capability::EnhancedStatusCodes);
            }
            idx += 1;
        }
        #[cfg(feature = "ext_auth")]
        {
            if variant == idx {
                let len: usize = u.int_in_range(1..=3)?;
                let mut mechs = Vec::with_capacity(len);
                for _ in 0..len {
                    mechs.push(AuthMechanism::arbitrary(u)?);
                }
                return Ok(Capability::Auth(mechs));
            }
            #[allow(unused_assignments)]
            {
                idx += 1;
            }
        }

        // Default: Other capability
        Ok(Capability::Other {
            keyword: Atom::arbitrary(u)?,
            params: if u.arbitrary()? {
                Some(Cow::Owned(String::arbitrary(u)?))
            } else {
                None
            },
        })
    }
}

// =================================================================================================
// EhloResponse
// =================================================================================================

/// EHLO response containing server capabilities.
///
/// The first line contains the server's domain, subsequent lines
/// contain one capability per line.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct EhloResponse<'a> {
    /// The server's domain name
    pub domain: Domain<'a>,
    /// Optional greeting text on the first line
    pub greet: Option<Text<'a>>,
    /// Server capabilities
    pub capabilities: Vec<Capability<'a>>,
}

impl<'a> EhloResponse<'a> {
    /// Creates a new EHLO response.
    pub fn new(domain: Domain<'a>) -> Self {
        Self {
            domain,
            greet: None,
            capabilities: Vec::new(),
        }
    }

    /// Creates a new EHLO response with greeting text.
    pub fn with_greet(domain: Domain<'a>, greet: Text<'a>) -> Self {
        Self {
            domain,
            greet: Some(greet),
            capabilities: Vec::new(),
        }
    }

    /// Adds a capability to the response.
    pub fn add_capability(&mut self, capability: Capability<'a>) {
        self.capabilities.push(capability);
    }

    /// Returns true if the server supports the given capability.
    pub fn has_capability(&self, name: &str) -> bool {
        let name_upper = name.to_ascii_uppercase();
        self.capabilities.iter().any(|cap| match cap {
            #[cfg(feature = "ext_size")]
            Capability::Size(_) => name_upper == "SIZE",
            #[cfg(feature = "ext_8bitmime")]
            Capability::EightBitMime => name_upper == "8BITMIME",
            #[cfg(feature = "ext_pipelining")]
            Capability::Pipelining => name_upper == "PIPELINING",
            #[cfg(feature = "starttls")]
            Capability::StartTls => name_upper == "STARTTLS",
            #[cfg(feature = "ext_smtputf8")]
            Capability::SmtpUtf8 => name_upper == "SMTPUTF8",
            #[cfg(feature = "ext_enhancedstatuscodes")]
            Capability::EnhancedStatusCodes => name_upper == "ENHANCEDSTATUSCODES",
            #[cfg(feature = "ext_auth")]
            Capability::Auth(_) => name_upper == "AUTH",
            Capability::Other { keyword, .. } => {
                keyword.as_ref().to_ascii_uppercase() == name_upper
            }
        })
    }

    /// Returns the AUTH mechanisms if AUTH capability is present.
    #[cfg(feature = "ext_auth")]
    pub fn auth_mechanisms(&self) -> Option<&[AuthMechanism<'a>]> {
        self.capabilities.iter().find_map(|cap| match cap {
            Capability::Auth(mechanisms) => Some(mechanisms.as_slice()),
            _ => None,
        })
    }

    /// Returns the maximum message size if SIZE capability is present.
    #[cfg(feature = "ext_size")]
    pub fn max_size(&self) -> Option<u64> {
        self.capabilities.iter().find_map(|cap| match cap {
            Capability::Size(size) => *size,
            _ => None,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for EhloResponse<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len: usize = u.int_in_range(0..=5)?;
        let mut capabilities = Vec::with_capacity(len);
        for _ in 0..len {
            capabilities.push(Capability::arbitrary(u)?);
        }
        Ok(EhloResponse {
            domain: Domain::arbitrary(u)?,
            greet: if u.arbitrary()? {
                Some(Text::arbitrary(u)?)
            } else {
                None
            },
            capabilities,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reply_code() {
        assert_eq!(ReplyCode::OK.code(), 250);
        assert!(ReplyCode::OK.is_positive_completion());
        assert!(ReplyCode::OK.is_success());
        assert!(!ReplyCode::OK.is_error());

        assert_eq!(ReplyCode::START_MAIL_INPUT.code(), 354);
        assert!(ReplyCode::START_MAIL_INPUT.is_positive_intermediate());
        assert!(ReplyCode::START_MAIL_INPUT.is_success());

        assert_eq!(ReplyCode::MAILBOX_UNAVAILABLE_TEMP.code(), 450);
        assert!(ReplyCode::MAILBOX_UNAVAILABLE_TEMP.is_transient_negative());
        assert!(ReplyCode::MAILBOX_UNAVAILABLE_TEMP.is_error());

        assert_eq!(ReplyCode::SYNTAX_ERROR.code(), 500);
        assert!(ReplyCode::SYNTAX_ERROR.is_permanent_negative());
        assert!(ReplyCode::SYNTAX_ERROR.is_error());
    }

    #[test]
    fn test_reply_code_parse() {
        assert_eq!(ReplyCode::from_str("250").unwrap(), ReplyCode::OK);
        assert!(ReplyCode::from_str("999").is_err());
        assert!(ReplyCode::from_str("abc").is_err());
    }

    #[test]
    fn test_reply_code_class() {
        assert_eq!(ReplyCode::OK.class(), 2);
        assert_eq!(ReplyCode::START_MAIL_INPUT.class(), 3);
        assert_eq!(ReplyCode::LOCAL_ERROR.class(), 4);
        assert_eq!(ReplyCode::SYNTAX_ERROR.class(), 5);
    }

    #[cfg(feature = "ext_enhancedstatuscodes")]
    #[test]
    fn test_enhanced_status_code() {
        let code = EnhancedStatusCode::new(2, 1, 0).unwrap();
        assert!(code.is_success());
        assert_eq!(code.to_string(), "2.1.0");

        let code = EnhancedStatusCode::new(5, 7, 1).unwrap();
        assert!(code.is_permanent_failure());
        assert_eq!(code.to_string(), "5.7.1");

        // Invalid class
        assert!(EnhancedStatusCode::new(3, 0, 0).is_none());
    }

    #[test]
    fn test_greeting() {
        let domain = Domain::try_from("mail.example.com").unwrap();
        let greeting = Greeting::new(domain.clone(), None);
        assert_eq!(greeting.to_string(), "220 mail.example.com");

        let text = Text::try_from("ESMTP ready").unwrap();
        let greeting = Greeting::new(domain, Some(text));
        assert_eq!(greeting.to_string(), "220 mail.example.com ESMTP ready");
    }

    #[test]
    fn test_response() {
        let text = Text::try_from("OK").unwrap();
        let response = Response::new(ReplyCode::OK, text);
        assert!(response.is_success());
        assert!(!response.is_error());
        assert_eq!(response.text().inner(), "OK");
    }
}
