//! Authentication-related types for SMTP AUTH command.

use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
    str::FromStr,
};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    core::{Atom, impl_try_from},
    error::ValidationError,
    secret::Secret,
};

/// Authentication mechanism for SMTP AUTH.
///
/// # Reference
///
/// RFC 4954: SMTP Service Extension for Authentication
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
#[non_exhaustive]
pub enum AuthMechanism<'a> {
    /// The PLAIN SASL mechanism.
    ///
    /// ```text
    /// base64(b"<authorization identity>\x00<authentication identity>\x00<password>")
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 4616: The PLAIN Simple Authentication and Security Layer (SASL) Mechanism
    Plain,

    /// The (non-standardized) LOGIN SASL mechanism.
    ///
    /// ```text
    /// base64(b"<username>")
    /// base64(b"<password>")
    /// ```
    ///
    /// # Reference
    ///
    /// draft-murchison-sasl-login-00: The LOGIN SASL Mechanism
    Login,

    /// OAuth 2.0 bearer token mechanism.
    ///
    /// # Reference
    ///
    /// RFC 7628: A Set of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth
    OAuthBearer,

    /// Google's OAuth 2.0 mechanism.
    ///
    /// ```text
    /// base64(b"user=<user>\x01auth=Bearer <token>\x01\x01")
    /// ```
    XOAuth2,

    /// SCRAM-SHA-1
    ///
    /// # Reference
    ///
    /// RFC 5802: Salted Challenge Response Authentication Mechanism (SCRAM)
    ScramSha1,

    /// SCRAM-SHA-1-PLUS
    ///
    /// # Reference
    ///
    /// RFC 5802: Salted Challenge Response Authentication Mechanism (SCRAM)
    ScramSha1Plus,

    /// SCRAM-SHA-256
    ///
    /// # Reference
    ///
    /// RFC 7677: SCRAM-SHA-256 and SCRAM-SHA-256-PLUS SASL Mechanisms
    ScramSha256,

    /// SCRAM-SHA-256-PLUS
    ///
    /// # Reference
    ///
    /// RFC 7677: SCRAM-SHA-256 and SCRAM-SHA-256-PLUS SASL Mechanisms
    ScramSha256Plus,

    /// SCRAM-SHA3-512
    ScramSha3_512,

    /// SCRAM-SHA3-512-PLUS
    ScramSha3_512Plus,

    /// CRAM-MD5 (legacy mechanism)
    ///
    /// # Reference
    ///
    /// RFC 2195: IMAP/POP AUTHorize Extension for Simple Challenge/Response
    CramMd5,

    /// Some other (unknown) mechanism.
    Other(AuthMechanismOther<'a>),
}

impl_try_from!(Atom<'a>, 'a, &'a [u8], AuthMechanism<'a>);
impl_try_from!(Atom<'a>, 'a, Vec<u8>, AuthMechanism<'a>);
impl_try_from!(Atom<'a>, 'a, &'a str, AuthMechanism<'a>);
impl_try_from!(Atom<'a>, 'a, String, AuthMechanism<'a>);
impl_try_from!(Atom<'a>, 'a, Cow<'a, str>, AuthMechanism<'a>);

impl<'a> From<Atom<'a>> for AuthMechanism<'a> {
    fn from(atom: Atom<'a>) -> Self {
        match atom.as_ref().to_ascii_uppercase().as_str() {
            "PLAIN" => Self::Plain,
            "LOGIN" => Self::Login,
            "OAUTHBEARER" => Self::OAuthBearer,
            "XOAUTH2" => Self::XOAuth2,
            "SCRAM-SHA-1" => Self::ScramSha1,
            "SCRAM-SHA-1-PLUS" => Self::ScramSha1Plus,
            "SCRAM-SHA-256" => Self::ScramSha256,
            "SCRAM-SHA-256-PLUS" => Self::ScramSha256Plus,
            "SCRAM-SHA3-512" => Self::ScramSha3_512,
            "SCRAM-SHA3-512-PLUS" => Self::ScramSha3_512Plus,
            "CRAM-MD5" => Self::CramMd5,
            _ => Self::Other(AuthMechanismOther(atom)),
        }
    }
}

impl Display for AuthMechanism<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl AsRef<str> for AuthMechanism<'_> {
    fn as_ref(&self) -> &str {
        match self {
            Self::Plain => "PLAIN",
            Self::Login => "LOGIN",
            Self::OAuthBearer => "OAUTHBEARER",
            Self::XOAuth2 => "XOAUTH2",
            Self::ScramSha1 => "SCRAM-SHA-1",
            Self::ScramSha1Plus => "SCRAM-SHA-1-PLUS",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha256Plus => "SCRAM-SHA-256-PLUS",
            Self::ScramSha3_512 => "SCRAM-SHA3-512",
            Self::ScramSha3_512Plus => "SCRAM-SHA3-512-PLUS",
            Self::CramMd5 => "CRAM-MD5",
            Self::Other(other) => other.0.as_ref(),
        }
    }
}

impl FromStr for AuthMechanism<'static> {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AuthMechanism::try_from(s.to_string())
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for AuthMechanism<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let variant: u8 = u.int_in_range(0..=10)?;
        Ok(match variant {
            0 => AuthMechanism::Plain,
            1 => AuthMechanism::Login,
            2 => AuthMechanism::OAuthBearer,
            3 => AuthMechanism::XOAuth2,
            4 => AuthMechanism::ScramSha1,
            5 => AuthMechanism::ScramSha1Plus,
            6 => AuthMechanism::ScramSha256,
            7 => AuthMechanism::ScramSha256Plus,
            8 => AuthMechanism::ScramSha3_512,
            9 => AuthMechanism::ScramSha3_512Plus,
            _ => AuthMechanism::CramMd5,
        })
    }
}

/// An (unknown) authentication mechanism.
///
/// It's guaranteed that this type can't represent any known mechanism from [`AuthMechanism`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct AuthMechanismOther<'a>(pub(crate) Atom<'a>);

/// Data line used during SMTP AUTH exchange.
///
/// Holds the raw binary data, i.e., a `Vec<u8>`, *not* the BASE64 string.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum AuthenticateData<'a> {
    /// Continue SASL authentication with response data.
    Continue(Secret<Cow<'a, [u8]>>),
    /// Cancel SASL authentication.
    ///
    /// The client sends a single "*" to cancel the authentication exchange.
    Cancel,
}

impl<'a> AuthenticateData<'a> {
    /// Create a continuation response with the given data.
    pub fn r#continue<D>(data: D) -> Self
    where
        D: Into<Cow<'a, [u8]>>,
    {
        Self::Continue(Secret::new(data.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion() {
        assert!(AuthMechanism::try_from("plain").is_ok());
        assert!(AuthMechanism::try_from("login").is_ok());
        assert!(AuthMechanism::try_from("oauthbearer").is_ok());
        assert!(AuthMechanism::try_from("xoauth2").is_ok());
        assert!(AuthMechanism::try_from("cram-md5").is_ok());
        assert!(AuthMechanism::try_from("xxxplain").is_ok());
        assert!(AuthMechanism::try_from("xxxlogin").is_ok());
    }

    #[test]
    fn test_display() {
        assert_eq!(AuthMechanism::Plain.to_string(), "PLAIN");
        assert_eq!(AuthMechanism::Login.to_string(), "LOGIN");
        assert_eq!(AuthMechanism::CramMd5.to_string(), "CRAM-MD5");
    }
}
