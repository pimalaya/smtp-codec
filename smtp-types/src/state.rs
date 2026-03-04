//! SMTP session state.
//!
//! SMTP is a stateful protocol where certain commands are only valid in certain states.
//! The session progresses through states as commands are executed successfully.
//!
//! ```text
//!       +----------------------+
//!       |connection established|
//!       +----------------------+
//!                  ||
//!                  \/
//!       +----------------------+
//!       |    Greeting (220)    |
//!       +----------------------+
//!                  ||
//!                  \/
//!       +----------------------+
//!       |     EHLO/HELO        |<----+
//!       +----------------------+     |
//!                  ||                |
//!                  \/                |
//!       +----------------------+     |
//!       |       Ready          |-----+ (RSET)
//!       +----------------------+
//!                  ||
//!                  \/ (MAIL FROM)
//!       +----------------------+
//!       |        Mail          |
//!       +----------------------+
//!                  ||
//!                  \/ (RCPT TO)
//!       +----------------------+
//!       |        Rcpt          |<----+ (more RCPT TO)
//!       +----------------------+-----+
//!                  ||
//!                  \/ (DATA)
//!       +----------------------+
//!       |        Data          |
//!       +----------------------+
//!                  ||
//!                  \/ (message + CRLF.CRLF)
//!       +----------------------+
//!       |       Ready          |
//!       +----------------------+
//!                  ||
//!                  \/ (QUIT)
//!       +----------------------+
//!       |        Quit          |
//!       +----------------------+
//! ```

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// State of an SMTP session.
///
/// # Reference
///
/// RFC 5321 Section 3: The SMTP Procedures
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToStatic)]
pub enum State {
    /// Initial state after connection, waiting for server greeting.
    ///
    /// The client should wait for a 220 response from the server.
    Connect,

    /// After receiving the 220 greeting, before EHLO/HELO.
    ///
    /// The client should send EHLO or HELO to identify itself.
    Greeted,

    /// After successful EHLO/HELO, ready for mail transaction.
    ///
    /// In this state, the client can:
    /// - Send MAIL FROM to start a transaction
    /// - Send QUIT to end the session
    /// - Send RSET, NOOP, HELP, VRFY, EXPN
    /// - Send STARTTLS (if supported)
    /// - Send AUTH (if supported and not authenticated)
    Ready,

    /// After successful MAIL FROM, waiting for RCPT TO.
    ///
    /// In this state, the client must send at least one RCPT TO.
    Mail,

    /// After at least one successful RCPT TO, ready for DATA or more RCPT TO.
    ///
    /// In this state, the client can:
    /// - Send more RCPT TO commands
    /// - Send DATA to begin message transfer
    /// - Send RSET to abort the transaction
    Rcpt,

    /// After DATA command, transferring message content.
    ///
    /// In this state, the client sends the message content,
    /// terminated by <CRLF>.<CRLF>.
    Data,

    /// Session ended (after QUIT or server disconnect).
    ///
    /// No more commands should be sent.
    Quit,
}

impl State {
    /// Returns true if MAIL FROM is valid in this state.
    pub fn can_mail(&self) -> bool {
        matches!(self, State::Ready)
    }

    /// Returns true if RCPT TO is valid in this state.
    pub fn can_rcpt(&self) -> bool {
        matches!(self, State::Mail | State::Rcpt)
    }

    /// Returns true if DATA is valid in this state.
    pub fn can_data(&self) -> bool {
        matches!(self, State::Rcpt)
    }

    /// Returns true if RSET is valid in this state.
    pub fn can_rset(&self) -> bool {
        !matches!(self, State::Connect | State::Quit | State::Data)
    }

    /// Returns true if the session is active (not quit).
    pub fn is_active(&self) -> bool {
        !matches!(self, State::Quit)
    }

    /// Returns true if we're in the middle of a mail transaction.
    pub fn in_transaction(&self) -> bool {
        matches!(self, State::Mail | State::Rcpt | State::Data)
    }
}

impl Default for State {
    fn default() -> Self {
        State::Connect
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IntoStatic, ToStatic};

    #[test]
    fn test_state_transitions() {
        // Initial state
        let state = State::default();
        assert_eq!(state, State::Connect);
        assert!(!state.can_mail());
        assert!(state.is_active());

        // After greeting
        let state = State::Greeted;
        assert!(!state.can_mail());

        // Ready state
        let state = State::Ready;
        assert!(state.can_mail());
        assert!(!state.can_rcpt());
        assert!(!state.can_data());
        assert!(state.can_rset());

        // Mail state
        let state = State::Mail;
        assert!(!state.can_mail());
        assert!(state.can_rcpt());
        assert!(!state.can_data());
        assert!(state.in_transaction());

        // Rcpt state
        let state = State::Rcpt;
        assert!(state.can_rcpt());
        assert!(state.can_data());
        assert!(state.in_transaction());

        // Data state
        let state = State::Data;
        assert!(!state.can_rset());
        assert!(state.in_transaction());

        // Quit state
        let state = State::Quit;
        assert!(!state.is_active());
        assert!(!state.can_rset());
    }

    #[test]
    fn test_conversion() {
        let tests = [
            State::Connect,
            State::Greeted,
            State::Ready,
            State::Mail,
            State::Rcpt,
            State::Data,
            State::Quit,
        ];

        for test in tests {
            let test_to_static = test.to_static();
            assert_eq!(test, test_to_static);

            let test_into_static = test.into_static();
            assert_eq!(test_to_static, test_into_static);
        }
    }
}
