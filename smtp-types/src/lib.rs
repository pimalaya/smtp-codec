//! # Misuse-resistant SMTP types
//!
//! The most prominent types in smtp-types are [`Greeting`](response::Greeting),
//! [`Command`](command::Command), and [`Response`](response::Response).
//! These types ensure correctness by validating their contents at construction time.
//!
//! ## Understanding and using the core types
//!
//! The [`core`] module contains fundamental types like [`Domain`](core::Domain),
//! [`Mailbox`](core::Mailbox), [`Atom`](core::Atom), and [`Text`](core::Text).
//! These types validate their contents according to RFC 5321 rules.
//!
//! ## Construction of messages
//!
//! smtp-types relies on the standard conversion traits, i.e., [`From`], [`TryFrom`],
//! [`Into`], and [`TryInto`]. More convenient constructors are available for types
//! that are more cumbersome to create.
//!
//! Note: When you are *sure* that the thing you want to create is valid, you can use
//! the `unvalidated(...)` functions. These bypass validation in release builds but
//! will panic in debug builds if the value is invalid.
//!
//! ### Example
//!
//! ```
//! use smtp_types::{
//!     command::Command,
//!     core::{Domain, ForwardPath, LocalPart, Mailbox, ReversePath},
//! };
//!
//! // Create an EHLO command
//! let domain = Domain::try_from("client.example.com").unwrap();
//! let cmd = Command::ehlo(domain);
//!
//! // Create a MAIL FROM command with null path (bounce message)
//! let cmd = Command::mail(ReversePath::Null);
//!
//! // Create a RCPT TO command
//! let local = LocalPart::try_from("user").unwrap();
//! let domain = Domain::try_from("example.com").unwrap();
//! let mailbox = Mailbox::new(local, domain.into());
//! let cmd = Command::rcpt(ForwardPath::from(mailbox));
//!
//! // Simple commands
//! let cmd = Command::data();
//! let cmd = Command::quit();
//! ```
//!
//! # Supported SMTP extensions
//!
//! | Feature                 | Description                                                | RFC      |
//! |-------------------------|-----------------------------------------------------------|----------|
//! | starttls                | SMTP over TLS                                             | RFC 3207 |
//! | ext_auth                | SMTP Authentication                                       | RFC 4954 |
//! | ext_size                | Message Size Declaration                                  | RFC 1870 |
//! | ext_8bitmime            | 8-bit MIME Transport                                      | RFC 6152 |
//! | ext_pipelining          | Command Pipelining                                        | RFC 2920 |
//! | ext_smtputf8            | Internationalized Email                                   | RFC 6531 |
//! | ext_enhancedstatuscodes | Enhanced Error Codes                                      | RFC 2034 |
//!
//! # Features
//!
//! | Feature   | Description                                                   | Default |
//! |-----------|---------------------------------------------------------------|---------|
//! | arbitrary | Derive `Arbitrary` implementations for fuzzing                | No      |
//! | serde     | Derive `Serialize` and `Deserialize` implementations          | No      |
//!
//! [RFC 1870]: https://datatracker.ietf.org/doc/html/rfc1870
//! [RFC 2034]: https://datatracker.ietf.org/doc/html/rfc2034
//! [RFC 2920]: https://datatracker.ietf.org/doc/html/rfc2920
//! [RFC 3207]: https://datatracker.ietf.org/doc/html/rfc3207
//! [RFC 4954]: https://datatracker.ietf.org/doc/html/rfc4954
//! [RFC 5321]: https://datatracker.ietf.org/doc/html/rfc5321
//! [RFC 6152]: https://datatracker.ietf.org/doc/html/rfc6152
//! [RFC 6531]: https://datatracker.ietf.org/doc/html/rfc6531

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use bounded_static::{IntoBoundedStatic, ToBoundedStatic};

#[cfg(feature = "ext_auth")]
pub mod auth;
pub mod command;
pub mod core;
pub mod error;
pub mod response;
pub mod secret;
pub mod state;
pub mod utils;

/// Create owned variant of object.
///
/// Useful, e.g., if you want to pass the object to another thread or executor.
pub trait ToStatic {
    type Static: 'static;

    fn to_static(&self) -> Self::Static;
}

impl<T> ToStatic for T
where
    T: ToBoundedStatic,
{
    type Static = <T as ToBoundedStatic>::Static;

    fn to_static(&self) -> Self::Static {
        ToBoundedStatic::to_static(self)
    }
}

/// Create owned variant of object (consuming it).
///
/// Useful, e.g., if you want to pass the object to another thread or executor.
pub trait IntoStatic {
    type Static: 'static;

    fn into_static(self) -> Self::Static;
}

impl<T> IntoStatic for T
where
    T: IntoBoundedStatic,
{
    type Static = <T as IntoBoundedStatic>::Static;

    fn into_static(self) -> Self::Static {
        IntoBoundedStatic::into_static(self)
    }
}
