//! # SMTP protocol codec
//!
//! smtp-codec provides complete and detailed parsing and construction of SMTP commands and responses
//! as defined in [RFC 5321]. It is based on [smtp-types] and extends it with parsing support using [nom].
//!
//! The main codecs are:
//! - [`GreetingCodec`] - to parse the initial server greeting (220)
//! - [`CommandCodec`] - to parse commands from a client
//! - [`ResponseCodec`] - to parse responses from a server
//! - [`EhloResponseCodec`] - to parse EHLO responses with capabilities
//!
//! ## Decoding
//!
//! Decoding is provided through the [`Decoder`](`crate::decode::Decoder`) trait.
//! Every parser takes an input (`&[u8]`) and produces a remainder and a parsed value.
//!
//! ### Example
//!
//! ```rust
//! use smtp_codec::{
//!     GreetingCodec,
//!     decode::Decoder,
//! };
//!
//! let input = b"220 mail.example.com ESMTP ready\r\n<remaining>";
//! let (remaining, greeting) = GreetingCodec::default().decode(input).unwrap();
//!
//! assert_eq!(greeting.domain.inner(), "mail.example.com");
//! assert_eq!(remaining, b"<remaining>");
//! ```
//!
//! ## Encoding
//!
//! Encoding is provided through the [`Encoder`](`crate::encode::Encoder`) trait.
//!
//! ### Example
//!
//! ```rust
//! use smtp_codec::{
//!     CommandCodec,
//!     encode::Encoder,
//!     smtp_types::command::Command,
//! };
//!
//! let cmd = Command::quit();
//! let bytes = CommandCodec::default().encode(&cmd);
//!
//! assert_eq!(bytes, b"QUIT\r\n");
//! ```
//!
//! ## Features
//!
//! smtp-codec supports the following SMTP extensions:
//!
//! | Feature                 | Description                              | RFC      |
//! |-------------------------|------------------------------------------|----------|
//! | starttls                | SMTP over TLS                            | RFC 3207 |
//! | ext_auth                | SMTP Authentication                      | RFC 4954 |
//! | ext_size                | Message Size Declaration                 | RFC 1870 |
//! | ext_8bitmime            | 8-bit MIME Transport                     | RFC 6152 |
//! | ext_pipelining          | Command Pipelining                       | RFC 2920 |
//! | ext_smtputf8            | Internationalized Email                  | RFC 6531 |
//! | ext_enhancedstatuscodes | Enhanced Error Codes                     | RFC 2034 |
//!
//! Additional features:
//!
//! | Feature            | Description                    | Default |
//! |--------------------|--------------------------------|---------|
//! | quirk_crlf_relaxed | Make `\r` in `\r\n` optional   | No      |
//! | fuzz               | Expose parsers for fuzzing     | No      |
//!
//! [RFC 5321]: https://tools.ietf.org/html/rfc5321
//! [smtp-types]: https://docs.rs/smtp-types

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "ext_auth")]
mod auth;
mod codec;
mod command;
mod core;
mod response;

pub use codec::*;

// Re-export smtp-types for convenience.
pub use smtp_types;

/// Decoding functionality.
pub mod decode {
    pub use crate::codec::decode::*;
}

/// Encoding functionality.
pub mod encode {
    pub use crate::codec::encode::*;
}
