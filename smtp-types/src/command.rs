//! SMTP command types.
//!
//! This module defines the commands that an SMTP client sends to a server
//! as specified in RFC 5321.

use std::borrow::Cow;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::core::{Domain, EhloDomain, ForwardPath, Parameter, ReversePath};
#[cfg(feature = "ext_auth")]
use crate::{auth::AuthMechanism, secret::Secret};

/// An SMTP command.
///
/// # Reference
///
/// RFC 5321 Section 4.1: SMTP Commands
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
#[non_exhaustive]
pub enum Command<'a> {
    /// Extended HELLO - identifies the client and requests extended features.
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// ehlo = "EHLO" SP ( Domain / address-literal ) CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.1
    Ehlo {
        /// The client's domain or address literal
        domain: EhloDomain<'a>,
    },

    /// HELLO - identifies the client to the server (legacy).
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// helo = "HELO" SP Domain CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.1
    Helo {
        /// The client's domain
        domain: Domain<'a>,
    },

    /// MAIL FROM - initiates a mail transaction with the sender's address.
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// mail = "MAIL FROM:" Reverse-path [SP Mail-parameters] CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.2
    Mail {
        /// The sender's reverse path (can be null <>)
        reverse_path: ReversePath<'a>,
        /// Optional ESMTP parameters (e.g., SIZE, BODY)
        parameters: Vec<Parameter<'a>>,
    },

    /// RCPT TO - specifies a recipient for the mail.
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// rcpt = "RCPT TO:" ( "<Postmaster@" Domain ">" / "<Postmaster>" /
    ///        Forward-path ) [SP Rcpt-parameters] CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.3
    Rcpt {
        /// The recipient's forward path
        forward_path: ForwardPath<'a>,
        /// Optional ESMTP parameters
        parameters: Vec<Parameter<'a>>,
    },

    /// DATA - begins the mail data transfer.
    ///
    /// After this command, the client sends the message content,
    /// terminated by `<CRLF>.<CRLF>`.
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// data = "DATA" CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.4
    Data,

    /// RSET - aborts the current mail transaction.
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// rset = "RSET" CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.5
    Rset,

    /// QUIT - requests connection termination.
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// quit = "QUIT" CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.10
    Quit,

    /// NOOP - no operation (used to keep connection alive).
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// noop = "NOOP" [ SP String ] CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.9
    Noop {
        /// Optional string argument (ignored by server)
        string: Option<Cow<'a, str>>,
    },

    /// VRFY - verifies a user or mailbox name.
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// vrfy = "VRFY" SP String CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.6
    Vrfy {
        /// The string to verify (usually a user name or address)
        string: Cow<'a, str>,
    },

    /// EXPN - expands a mailing list.
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// expn = "EXPN" SP String CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.7
    Expn {
        /// The mailing list name to expand
        string: Cow<'a, str>,
    },

    /// HELP - requests help information.
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// help = "HELP" [ SP String ] CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 5321 Section 4.1.1.8
    Help {
        /// Optional topic for specific help
        topic: Option<Cow<'a, str>>,
    },

    /// STARTTLS - initiates TLS encryption.
    ///
    /// # Reference
    ///
    /// RFC 3207: SMTP Service Extension for Secure SMTP over Transport Layer Security
    #[cfg(feature = "starttls")]
    StartTls,

    /// AUTH - initiates SASL authentication.
    ///
    /// # ABNF
    ///
    /// ```abnf
    /// auth = "AUTH" SP sasl-mech [SP initial-response] CRLF
    /// ```
    ///
    /// # Reference
    ///
    /// RFC 4954: SMTP Service Extension for Authentication
    #[cfg(feature = "ext_auth")]
    Auth {
        /// The SASL mechanism to use
        mechanism: AuthMechanism<'a>,
        /// Optional initial response (base64-encoded by encoder)
        initial_response: Option<Secret<Cow<'a, [u8]>>>,
    },
}

impl<'a> Command<'a> {
    /// Creates an EHLO command.
    pub fn ehlo(domain: impl Into<EhloDomain<'a>>) -> Self {
        Command::Ehlo {
            domain: domain.into(),
        }
    }

    /// Creates a HELO command.
    pub fn helo(domain: Domain<'a>) -> Self {
        Command::Helo { domain }
    }

    /// Creates a MAIL FROM command with no parameters.
    pub fn mail(reverse_path: ReversePath<'a>) -> Self {
        Command::Mail {
            reverse_path,
            parameters: Vec::new(),
        }
    }

    /// Creates a MAIL FROM command with parameters.
    pub fn mail_with_params(reverse_path: ReversePath<'a>, parameters: Vec<Parameter<'a>>) -> Self {
        Command::Mail {
            reverse_path,
            parameters,
        }
    }

    /// Creates a RCPT TO command with no parameters.
    pub fn rcpt(forward_path: ForwardPath<'a>) -> Self {
        Command::Rcpt {
            forward_path,
            parameters: Vec::new(),
        }
    }

    /// Creates a RCPT TO command with parameters.
    pub fn rcpt_with_params(forward_path: ForwardPath<'a>, parameters: Vec<Parameter<'a>>) -> Self {
        Command::Rcpt {
            forward_path,
            parameters,
        }
    }

    /// Creates a DATA command.
    pub fn data() -> Self {
        Command::Data
    }

    /// Creates a RSET command.
    pub fn rset() -> Self {
        Command::Rset
    }

    /// Creates a QUIT command.
    pub fn quit() -> Self {
        Command::Quit
    }

    /// Creates a NOOP command with no argument.
    pub fn noop() -> Self {
        Command::Noop { string: None }
    }

    /// Creates a NOOP command with an argument.
    pub fn noop_with_string(string: impl Into<Cow<'a, str>>) -> Self {
        Command::Noop {
            string: Some(string.into()),
        }
    }

    /// Creates a VRFY command.
    pub fn vrfy(string: impl Into<Cow<'a, str>>) -> Self {
        Command::Vrfy {
            string: string.into(),
        }
    }

    /// Creates an EXPN command.
    pub fn expn(string: impl Into<Cow<'a, str>>) -> Self {
        Command::Expn {
            string: string.into(),
        }
    }

    /// Creates a HELP command with no topic.
    pub fn help() -> Self {
        Command::Help { topic: None }
    }

    /// Creates a HELP command with a specific topic.
    pub fn help_with_topic(topic: impl Into<Cow<'a, str>>) -> Self {
        Command::Help {
            topic: Some(topic.into()),
        }
    }

    /// Creates a STARTTLS command.
    #[cfg(feature = "starttls")]
    pub fn starttls() -> Self {
        Command::StartTls
    }

    /// Creates an AUTH command with no initial response.
    #[cfg(feature = "ext_auth")]
    pub fn auth(mechanism: AuthMechanism<'a>) -> Self {
        Command::Auth {
            mechanism,
            initial_response: None,
        }
    }

    /// Creates an AUTH command with an initial response.
    #[cfg(feature = "ext_auth")]
    pub fn auth_with_initial_response(
        mechanism: AuthMechanism<'a>,
        initial_response: impl Into<Cow<'a, [u8]>>,
    ) -> Self {
        Command::Auth {
            mechanism,
            initial_response: Some(Secret::new(initial_response.into())),
        }
    }

    /// Returns the command name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Ehlo { .. } => "EHLO",
            Command::Helo { .. } => "HELO",
            Command::Mail { .. } => "MAIL",
            Command::Rcpt { .. } => "RCPT",
            Command::Data => "DATA",
            Command::Rset => "RSET",
            Command::Quit => "QUIT",
            Command::Noop { .. } => "NOOP",
            Command::Vrfy { .. } => "VRFY",
            Command::Expn { .. } => "EXPN",
            Command::Help { .. } => "HELP",
            #[cfg(feature = "starttls")]
            Command::StartTls => "STARTTLS",
            #[cfg(feature = "ext_auth")]
            Command::Auth { .. } => "AUTH",
        }
    }
}

#[cfg(feature = "arbitrary")]
fn arbitrary_string(u: &mut Unstructured) -> arbitrary::Result<Cow<'static, str>> {
    let len: usize = u.int_in_range(1..=20)?;
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let c: u8 = u.int_in_range(32..=126)?;
        s.push(c as char);
    }
    Ok(Cow::Owned(s))
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Command<'static> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        #[cfg(all(feature = "starttls", feature = "ext_auth"))]
        let max_variant = 12;
        #[cfg(all(feature = "starttls", not(feature = "ext_auth")))]
        let max_variant = 11;
        #[cfg(all(not(feature = "starttls"), feature = "ext_auth"))]
        let max_variant = 11;
        #[cfg(all(not(feature = "starttls"), not(feature = "ext_auth")))]
        let max_variant = 10;

        let variant: u8 = u.int_in_range(0..=max_variant)?;
        Ok(match variant {
            0 => Command::Ehlo {
                domain: EhloDomain::arbitrary(u)?,
            },
            1 => Command::Helo {
                domain: Domain::arbitrary(u)?,
            },
            2 => Command::Mail {
                reverse_path: ReversePath::arbitrary(u)?,
                parameters: Vec::new(), // Keep simple for fuzzing
            },
            3 => Command::Rcpt {
                forward_path: ForwardPath::arbitrary(u)?,
                parameters: Vec::new(),
            },
            4 => Command::Data,
            5 => Command::Rset,
            6 => Command::Quit,
            7 => Command::Noop {
                string: if u.arbitrary()? {
                    Some(arbitrary_string(u)?)
                } else {
                    None
                },
            },
            8 => Command::Vrfy {
                string: arbitrary_string(u)?,
            },
            9 => Command::Expn {
                string: arbitrary_string(u)?,
            },
            10 => Command::Help {
                topic: if u.arbitrary()? {
                    Some(arbitrary_string(u)?)
                } else {
                    None
                },
            },
            #[cfg(feature = "starttls")]
            11 => Command::StartTls,
            #[cfg(feature = "ext_auth")]
            #[cfg(feature = "starttls")]
            12 => Command::Auth {
                mechanism: AuthMechanism::arbitrary(u)?,
                initial_response: None,
            },
            #[cfg(feature = "ext_auth")]
            #[cfg(not(feature = "starttls"))]
            11 => Command::Auth {
                mechanism: AuthMechanism::arbitrary(u)?,
                initial_response: None,
            },
            _ => Command::Quit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{LocalPart, Mailbox};

    #[test]
    fn test_command_creation() {
        // EHLO
        let domain = Domain::try_from("example.com").unwrap();
        let cmd = Command::ehlo(domain);
        assert!(matches!(cmd, Command::Ehlo { .. }));
        assert_eq!(cmd.name(), "EHLO");

        // MAIL FROM with null path
        let cmd = Command::mail(ReversePath::Null);
        assert!(matches!(
            cmd,
            Command::Mail {
                reverse_path: ReversePath::Null,
                ..
            }
        ));
        assert_eq!(cmd.name(), "MAIL");

        // RCPT TO
        let local = LocalPart::try_from("user").unwrap();
        let domain = Domain::try_from("example.com").unwrap();
        let mailbox = Mailbox::new(local, domain.into());
        let cmd = Command::rcpt(ForwardPath::from(mailbox));
        assert!(matches!(cmd, Command::Rcpt { .. }));
        assert_eq!(cmd.name(), "RCPT");

        // Simple commands
        assert!(matches!(Command::data(), Command::Data));
        assert_eq!(Command::data().name(), "DATA");
        assert!(matches!(Command::rset(), Command::Rset));
        assert_eq!(Command::rset().name(), "RSET");
        assert!(matches!(Command::quit(), Command::Quit));
        assert_eq!(Command::quit().name(), "QUIT");
        assert!(matches!(Command::noop(), Command::Noop { string: None }));
        assert_eq!(Command::noop().name(), "NOOP");
        assert!(matches!(Command::help(), Command::Help { topic: None }));
        assert_eq!(Command::help().name(), "HELP");
    }

    #[test]
    fn test_noop_with_string() {
        let cmd = Command::noop_with_string("test");
        match cmd {
            Command::Noop { string } => {
                assert_eq!(string, Some(Cow::Borrowed("test")));
            }
            _ => panic!("Expected Noop command"),
        }
    }

    #[test]
    fn test_vrfy_expn() {
        let cmd = Command::vrfy("postmaster");
        assert!(matches!(cmd, Command::Vrfy { .. }));
        assert_eq!(cmd.name(), "VRFY");

        let cmd = Command::expn("users");
        assert!(matches!(cmd, Command::Expn { .. }));
        assert_eq!(cmd.name(), "EXPN");
    }
}
