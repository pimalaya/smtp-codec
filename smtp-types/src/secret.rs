//! Handling of secret values.
//!
//! This module provides a `Secret<T>` ensuring that sensitive values are not
//! `Debug`-printed by accident.

use std::fmt::{Debug, Formatter};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A wrapper to ensure that secrets are redacted during `Debug`-printing.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Eq, Hash, PartialEq, ToStatic)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Create a new secret.
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Expose the inner secret.
    pub fn declassify(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T> Debug for Secret<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(debug_assertions))]
        return write!(f, "/* REDACTED */");
        #[cfg(debug_assertions)]
        return self.0.fmt(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_that_secret_is_redacted() {
        let secret = Secret("xyz123");
        let got = format!("{:?}", secret);
        assert!(!got.contains("xyz123"));
        assert!(got.contains("REDACTED"));
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_that_secret_is_visible_in_debug() {
        let secret = Secret("xyz123");
        let got = format!("{:?}", secret);
        assert!(got.contains("xyz123"));
    }
}
