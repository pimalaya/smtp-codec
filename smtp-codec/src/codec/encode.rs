//! # Encoding of SMTP messages.
//!
//! SMTP encoding is simpler than IMAP - no literals, just line-oriented messages.

use std::{borrow::Borrow, io::Write};

use base64::{engine::general_purpose::STANDARD as base64, Engine};
use smtp_types::{
    command::Command,
    core::{Atom, Domain, EhloDomain, ForwardPath, Parameter, ReversePath, Text},
    response::{Greeting, ReplyCode, Response},
};

#[cfg(feature = "ext_auth")]
use smtp_types::auth::{AuthMechanism, AuthenticateData};

use crate::{CommandCodec, GreetingCodec, ResponseCodec};
#[cfg(feature = "ext_auth")]
use crate::AuthenticateDataCodec;

/// Encoder trait for SMTP messages.
///
/// Implemented for types that know how to encode a specific SMTP message.
pub trait Encoder {
    type Message<'a>;

    /// Encode this message.
    fn encode(&self, message: &Self::Message<'_>) -> Vec<u8>;
}

// -------------------------------------------------------------------------------------------------

pub(crate) trait EncodeIntoContext {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()>;
}

macro_rules! impl_encoder_for_codec {
    ($codec:ty, $message:ty) => {
        impl Encoder for $codec {
            type Message<'a> = $message;

            fn encode(&self, message: &Self::Message<'_>) -> Vec<u8> {
                let mut buf = Vec::new();
                EncodeIntoContext::encode_ctx(message.borrow(), &mut buf).unwrap();
                buf
            }
        }
    };
}

impl_encoder_for_codec!(GreetingCodec, Greeting<'a>);
impl_encoder_for_codec!(CommandCodec, Command<'a>);
impl_encoder_for_codec!(ResponseCodec, Response<'a>);
#[cfg(feature = "ext_auth")]
impl_encoder_for_codec!(AuthenticateDataCodec, AuthenticateData<'a>);

// ----- Primitive ---------------------------------------------------------------------------------

impl EncodeIntoContext for u16 {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        ctx.write_all(self.to_string().as_bytes())
    }
}

impl EncodeIntoContext for u64 {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        ctx.write_all(self.to_string().as_bytes())
    }
}

// ----- Core types --------------------------------------------------------------------------------

impl EncodeIntoContext for Domain<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        ctx.write_all(self.inner().as_bytes())
    }
}

impl EncodeIntoContext for EhloDomain<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        match self {
            EhloDomain::Domain(domain) => domain.encode_ctx(ctx),
            EhloDomain::AddressLiteral(addr) => {
                write!(ctx, "{addr}")
            }
        }
    }
}

impl EncodeIntoContext for Atom<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        ctx.write_all(self.inner().as_bytes())
    }
}

impl EncodeIntoContext for Text<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        ctx.write_all(self.inner().as_bytes())
    }
}

impl EncodeIntoContext for ReversePath<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        write!(ctx, "{self}")
    }
}

impl EncodeIntoContext for ForwardPath<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        write!(ctx, "{self}")
    }
}

impl EncodeIntoContext for Parameter<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        write!(ctx, "{self}")
    }
}

// ----- Command -----------------------------------------------------------------------------------

impl EncodeIntoContext for Command<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        match self {
            Command::Ehlo { domain } => {
                ctx.write_all(b"EHLO ")?;
                domain.encode_ctx(ctx)?;
            }
            Command::Helo { domain } => {
                ctx.write_all(b"HELO ")?;
                domain.encode_ctx(ctx)?;
            }
            Command::Mail {
                reverse_path,
                parameters,
            } => {
                ctx.write_all(b"MAIL FROM:")?;
                reverse_path.encode_ctx(ctx)?;
                for param in parameters {
                    ctx.write_all(b" ")?;
                    param.encode_ctx(ctx)?;
                }
            }
            Command::Rcpt {
                forward_path,
                parameters,
            } => {
                ctx.write_all(b"RCPT TO:")?;
                forward_path.encode_ctx(ctx)?;
                for param in parameters {
                    ctx.write_all(b" ")?;
                    param.encode_ctx(ctx)?;
                }
            }
            Command::Data => ctx.write_all(b"DATA")?,
            Command::Rset => ctx.write_all(b"RSET")?,
            Command::Quit => ctx.write_all(b"QUIT")?,
            Command::Noop { string } => {
                ctx.write_all(b"NOOP")?;
                if let Some(s) = string {
                    ctx.write_all(b" ")?;
                    ctx.write_all(s.as_bytes())?;
                }
            }
            Command::Vrfy { string } => {
                ctx.write_all(b"VRFY ")?;
                ctx.write_all(string.as_bytes())?;
            }
            Command::Expn { string } => {
                ctx.write_all(b"EXPN ")?;
                ctx.write_all(string.as_bytes())?;
            }
            Command::Help { topic } => {
                ctx.write_all(b"HELP")?;
                if let Some(t) = topic {
                    ctx.write_all(b" ")?;
                    ctx.write_all(t.as_bytes())?;
                }
            }
            #[cfg(feature = "starttls")]
            Command::StartTls => ctx.write_all(b"STARTTLS")?,
            #[cfg(feature = "ext_auth")]
            Command::Auth {
                mechanism,
                initial_response,
            } => {
                ctx.write_all(b"AUTH ")?;
                ctx.write_all(mechanism.as_ref().as_bytes())?;
                if let Some(ir) = initial_response {
                    ctx.write_all(b" ")?;
                    let data = ir.declassify();
                    if data.is_empty() {
                        ctx.write_all(b"=")?;
                    } else {
                        ctx.write_all(base64.encode(data).as_bytes())?;
                    }
                }
            }
            // Handle any future variants added to the non-exhaustive Command enum
            #[allow(unreachable_patterns)]
            _ => unreachable!("Unknown command variant"),
        }
        ctx.write_all(b"\r\n")
    }
}

// ----- Response ----------------------------------------------------------------------------------

impl EncodeIntoContext for ReplyCode {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        write!(ctx, "{:03}", self.code())
    }
}

impl EncodeIntoContext for Greeting<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        ctx.write_all(b"220 ")?;
        self.domain.encode_ctx(ctx)?;
        if let Some(ref text) = self.text {
            ctx.write_all(b" ")?;
            text.encode_ctx(ctx)?;
        }
        ctx.write_all(b"\r\n")
    }
}

impl EncodeIntoContext for Response<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        let lines = self.lines.as_ref();
        let last_idx = lines.len() - 1;

        for (i, line) in lines.iter().enumerate() {
            self.code.encode_ctx(ctx)?;

            #[cfg(feature = "ext_enhancedstatuscodes")]
            if let Some(ref enhanced) = self.enhanced_code {
                if i == 0 {
                    // Enhanced status code only on first line
                    ctx.write_all(b" ")?;
                    write!(ctx, "{enhanced}")?;
                }
            }

            if i == last_idx {
                ctx.write_all(b" ")?;
            } else {
                ctx.write_all(b"-")?;
            }
            line.encode_ctx(ctx)?;
            ctx.write_all(b"\r\n")?;
        }

        Ok(())
    }
}

// ----- Auth --------------------------------------------------------------------------------------

#[cfg(feature = "ext_auth")]
impl EncodeIntoContext for AuthMechanism<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        ctx.write_all(self.as_ref().as_bytes())
    }
}

#[cfg(feature = "ext_auth")]
impl EncodeIntoContext for AuthenticateData<'_> {
    fn encode_ctx(&self, ctx: &mut Vec<u8>) -> std::io::Result<()> {
        match self {
            AuthenticateData::Continue(data) => {
                let encoded = base64.encode(data.declassify());
                ctx.write_all(encoded.as_bytes())?;
                ctx.write_all(b"\r\n")
            }
            AuthenticateData::Cancel => ctx.write_all(b"*\r\n"),
        }
    }
}

#[cfg(test)]
mod tests {
    use smtp_types::core::{LocalPart, Mailbox};

    use super::*;

    #[test]
    fn test_encode_ehlo() {
        let domain = Domain::try_from("client.example.com").unwrap();
        let cmd = Command::ehlo(domain);
        let encoded = CommandCodec::default().encode(&cmd);
        assert_eq!(encoded, b"EHLO client.example.com\r\n");
    }

    #[test]
    fn test_encode_mail_from() {
        let cmd = Command::mail(ReversePath::Null);
        let encoded = CommandCodec::default().encode(&cmd);
        assert_eq!(encoded, b"MAIL FROM:<>\r\n");
    }

    #[test]
    fn test_encode_rcpt_to() {
        let local = LocalPart::try_from("user").unwrap();
        let domain = Domain::try_from("example.com").unwrap();
        let mailbox = Mailbox::new(local, domain.into());
        let cmd = Command::rcpt(ForwardPath::from(mailbox));
        let encoded = CommandCodec::default().encode(&cmd);
        assert_eq!(encoded, b"RCPT TO:<user@example.com>\r\n");
    }

    #[test]
    fn test_encode_simple_commands() {
        assert_eq!(CommandCodec::default().encode(&Command::data()), b"DATA\r\n");
        assert_eq!(CommandCodec::default().encode(&Command::quit()), b"QUIT\r\n");
        assert_eq!(CommandCodec::default().encode(&Command::rset()), b"RSET\r\n");
        assert_eq!(CommandCodec::default().encode(&Command::noop()), b"NOOP\r\n");
    }

    #[test]
    fn test_encode_greeting() {
        let domain = Domain::try_from("mail.example.com").unwrap();
        let text = Text::try_from("ESMTP ready").unwrap();
        let greeting = Greeting::new(domain, Some(text));
        let encoded = GreetingCodec::default().encode(&greeting);
        assert_eq!(encoded, b"220 mail.example.com ESMTP ready\r\n");
    }

    #[test]
    fn test_encode_response() {
        let text = Text::try_from("OK").unwrap();
        let response = Response::new(ReplyCode::OK, text);
        let encoded = ResponseCodec::default().encode(&response);
        assert_eq!(encoded, b"250 OK\r\n");
    }
}
