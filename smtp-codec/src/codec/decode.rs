//! # Decoding of SMTP messages.
//!
//! SMTP is a line-oriented protocol, which makes parsing simpler than IMAP.
//! Each command or response line ends with CRLF.

use std::{
    net::AddrParseError,
    num::{ParseIntError, TryFromIntError},
    str::Utf8Error,
};

use nom::error::{ErrorKind, FromExternalError, ParseError};
#[cfg(feature = "ext_auth")]
use smtp_types::auth::AuthenticateData;
use smtp_types::{
    IntoStatic,
    command::Command,
    response::{EhloResponse, Greeting, Response},
};

#[cfg(feature = "ext_auth")]
use crate::AuthenticateDataCodec;
#[cfg(feature = "ext_auth")]
use crate::auth::authenticate_data;
use crate::{
    CommandCodec, EhloResponseCodec, GreetingCodec, ResponseCodec,
    command::command,
    response::{ehlo_response, greeting, response},
};

/// An extended version of [`nom::IResult`].
pub(crate) type SMTPResult<'a, I, O> = Result<(I, O), nom::Err<SMTPParseError<'a, I>>>;

/// An extended version of [`nom::error::Error`].
#[derive(Debug)]
pub(crate) struct SMTPParseError<'a, I> {
    #[allow(unused)]
    pub input: I,
    #[allow(dead_code)]
    pub kind: SMTPErrorKind<'a>,
}

/// An extended version of [`nom::error::ErrorKind`].
#[derive(Debug)]
pub(crate) enum SMTPErrorKind<'a> {
    BadNumber,
    BadBase64,
    BadUtf8,
    Nom(#[allow(dead_code)] ErrorKind),
    #[allow(dead_code)]
    Custom(&'a str),
}

impl<I> ParseError<I> for SMTPParseError<'_, I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        Self {
            input,
            kind: SMTPErrorKind::Nom(kind),
        }
    }

    fn append(input: I, kind: ErrorKind, _: Self) -> Self {
        Self {
            input,
            kind: SMTPErrorKind::Nom(kind),
        }
    }
}

impl<I> FromExternalError<I, ParseIntError> for SMTPParseError<'_, I> {
    fn from_external_error(input: I, _: ErrorKind, _: ParseIntError) -> Self {
        Self {
            input,
            kind: SMTPErrorKind::BadNumber,
        }
    }
}

impl<I> FromExternalError<I, TryFromIntError> for SMTPParseError<'_, I> {
    fn from_external_error(input: I, _: ErrorKind, _: TryFromIntError) -> Self {
        Self {
            input,
            kind: SMTPErrorKind::BadNumber,
        }
    }
}

impl<I> FromExternalError<I, base64::DecodeError> for SMTPParseError<'_, I> {
    fn from_external_error(input: I, _: ErrorKind, _: base64::DecodeError) -> Self {
        Self {
            input,
            kind: SMTPErrorKind::BadBase64,
        }
    }
}

impl<I> FromExternalError<I, Utf8Error> for SMTPParseError<'_, I> {
    fn from_external_error(input: I, _: ErrorKind, _: Utf8Error) -> Self {
        Self {
            input,
            kind: SMTPErrorKind::BadUtf8,
        }
    }
}

impl<I> FromExternalError<I, AddrParseError> for SMTPParseError<'_, I> {
    fn from_external_error(input: I, _: ErrorKind, _: AddrParseError) -> Self {
        Self {
            input,
            kind: SMTPErrorKind::BadNumber, // Reuse BadNumber for address parsing
        }
    }
}

/// Decoder trait for SMTP messages.
///
/// Implemented for types that know how to decode a specific SMTP message.
pub trait Decoder {
    type Message<'a>: Sized;
    type Error<'a>;

    fn decode<'a>(&self, input: &'a [u8])
    -> Result<(&'a [u8], Self::Message<'a>), Self::Error<'a>>;

    fn decode_static<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Self::Message<'static>), Self::Error<'static>>
    where
        Self::Message<'a>: IntoStatic<Static = Self::Message<'static>>,
        Self::Error<'a>: IntoStatic<Static = Self::Error<'static>>,
    {
        let (remaining, value) = self.decode(input).map_err(IntoStatic::into_static)?;
        Ok((remaining, value.into_static()))
    }
}

/// Error during greeting decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GreetingDecodeError {
    /// More data is needed.
    Incomplete,
    /// Decoding failed.
    Failed,
}

impl IntoStatic for GreetingDecodeError {
    type Static = Self;

    fn into_static(self) -> Self::Static {
        self
    }
}

/// Error during command decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandDecodeError {
    /// More data is needed.
    Incomplete,
    /// Decoding failed.
    Failed,
}

impl IntoStatic for CommandDecodeError {
    type Static = Self;

    fn into_static(self) -> Self::Static {
        self
    }
}

/// Error during response decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseDecodeError {
    /// More data is needed.
    Incomplete,
    /// Decoding failed.
    Failed,
}

impl IntoStatic for ResponseDecodeError {
    type Static = Self;

    fn into_static(self) -> Self::Static {
        self
    }
}

/// Error during EHLO response decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EhloResponseDecodeError {
    /// More data is needed.
    Incomplete,
    /// Decoding failed.
    Failed,
}

impl IntoStatic for EhloResponseDecodeError {
    type Static = Self;

    fn into_static(self) -> Self::Static {
        self
    }
}

/// Error during authenticate data decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "ext_auth")]
pub enum AuthenticateDataDecodeError {
    /// More data is needed.
    Incomplete,
    /// Decoding failed.
    Failed,
}

#[cfg(feature = "ext_auth")]
impl IntoStatic for AuthenticateDataDecodeError {
    type Static = Self;

    fn into_static(self) -> Self::Static {
        self
    }
}

// -------------------------------------------------------------------------------------------------

impl Decoder for GreetingCodec {
    type Message<'a> = Greeting<'a>;
    type Error<'a> = GreetingDecodeError;

    fn decode<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Self::Message<'a>), Self::Error<'static>> {
        match greeting(input) {
            Ok((rem, grt)) => Ok((rem, grt)),
            Err(nom::Err::Incomplete(_)) => Err(GreetingDecodeError::Incomplete),
            Err(nom::Err::Failure(_)) | Err(nom::Err::Error(_)) => Err(GreetingDecodeError::Failed),
        }
    }
}

impl Decoder for CommandCodec {
    type Message<'a> = Command<'a>;
    type Error<'a> = CommandDecodeError;

    fn decode<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Self::Message<'a>), Self::Error<'static>> {
        match command(input) {
            Ok((rem, cmd)) => Ok((rem, cmd)),
            Err(nom::Err::Incomplete(_)) => Err(CommandDecodeError::Incomplete),
            Err(nom::Err::Failure(_)) | Err(nom::Err::Error(_)) => Err(CommandDecodeError::Failed),
        }
    }
}

impl Decoder for ResponseCodec {
    type Message<'a> = Response<'a>;
    type Error<'a> = ResponseDecodeError;

    fn decode<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Self::Message<'a>), Self::Error<'static>> {
        match response(input) {
            Ok((rem, rsp)) => Ok((rem, rsp)),
            Err(nom::Err::Incomplete(_)) => Err(ResponseDecodeError::Incomplete),
            Err(nom::Err::Failure(_)) | Err(nom::Err::Error(_)) => Err(ResponseDecodeError::Failed),
        }
    }
}

impl Decoder for EhloResponseCodec {
    type Message<'a> = EhloResponse<'a>;
    type Error<'a> = EhloResponseDecodeError;

    fn decode<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Self::Message<'a>), Self::Error<'static>> {
        match ehlo_response(input) {
            Ok((rem, rsp)) => Ok((rem, rsp)),
            Err(nom::Err::Incomplete(_)) => Err(EhloResponseDecodeError::Incomplete),
            Err(nom::Err::Failure(_)) | Err(nom::Err::Error(_)) => {
                Err(EhloResponseDecodeError::Failed)
            }
        }
    }
}

#[cfg(feature = "ext_auth")]
impl Decoder for AuthenticateDataCodec {
    type Message<'a> = AuthenticateData<'a>;
    type Error<'a> = AuthenticateDataDecodeError;

    fn decode<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(&'a [u8], Self::Message<'a>), Self::Error<'static>> {
        match authenticate_data(input) {
            Ok((rem, data)) => Ok((rem, data)),
            Err(nom::Err::Incomplete(_)) => Err(AuthenticateDataDecodeError::Incomplete),
            Err(nom::Err::Failure(_)) | Err(nom::Err::Error(_)) => {
                Err(AuthenticateDataDecodeError::Failed)
            }
        }
    }
}
