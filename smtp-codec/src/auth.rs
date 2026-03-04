//! Authentication parsers for SMTP AUTH extension.

#[cfg(not(feature = "quirk_crlf_relaxed"))]
use abnf_core::streaming::crlf;
#[cfg(feature = "quirk_crlf_relaxed")]
use abnf_core::streaming::crlf_relaxed as crlf;
use nom::{
    branch::alt,
    bytes::streaming::tag,
    combinator::{map, value},
    sequence::terminated,
};
use smtp_types::auth::{AuthMechanism, AuthenticateData};

use crate::{
    core::{atom, base64_data},
    decode::SMTPResult,
};

/// ```abnf
/// auth-type = atom
/// ```
pub(crate) fn auth_type(input: &[u8]) -> SMTPResult<'_, &[u8], AuthMechanism<'_>> {
    let (rem, atom) = atom(input)?;
    Ok((rem, AuthMechanism::from(atom)))
}

/// Parse AUTH data line (client response during SASL exchange).
///
/// Either base64-encoded data followed by CRLF, or "*" to cancel.
pub(crate) fn authenticate_data(input: &[u8]) -> SMTPResult<'_, &[u8], AuthenticateData<'_>> {
    alt((
        map(terminated(base64_data, crlf), AuthenticateData::r#continue),
        value(AuthenticateData::Cancel, terminated(tag(b"*"), crlf)),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_type() {
        let (rem, mech) = auth_type(b"PLAIN ").unwrap();
        assert_eq!(rem, b" ");
        assert_eq!(mech, AuthMechanism::Plain);

        let (rem, mech) = auth_type(b"LOGIN ").unwrap();
        assert_eq!(rem, b" ");
        assert_eq!(mech, AuthMechanism::Login);

        let (rem, mech) = auth_type(b"XOAUTH2 ").unwrap();
        assert_eq!(rem, b" ");
        assert_eq!(mech, AuthMechanism::XOAuth2);
    }

    #[test]
    fn test_authenticate_data() {
        // Cancel
        let (rem, data) = authenticate_data(b"*\r\n").unwrap();
        assert!(rem.is_empty());
        assert!(matches!(data, AuthenticateData::Cancel));

        // Base64 data
        let (rem, data) = authenticate_data(b"VGVzdA==\r\n").unwrap();
        assert!(rem.is_empty());
        match data {
            AuthenticateData::Continue(secret) => {
                assert_eq!(secret.declassify().as_ref(), b"Test");
            }
            _ => panic!("Expected Continue"),
        }
    }
}
