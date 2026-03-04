# smtp-types

Misuse-resistant data structures for SMTP (RFC 5321).

## Overview

This crate provides types for SMTP protocol messages including:

- **Core types**: `Domain`, `Mailbox`, `Atom`, `Text`, `Parameter`
- **Commands**: `Command` enum with all RFC 5321 commands (EHLO, HELO, MAIL, RCPT, DATA, etc.)
- **Responses**: `Response`, `Greeting`, `EhloResponse`, `ReplyCode`
- **Authentication**: `AuthMechanism`, `AuthenticateData` (with `ext_auth` feature)

## Features

| Feature                 | Description                              |
|-------------------------|------------------------------------------|
| `starttls`              | STARTTLS command support                 |
| `ext_auth`              | SMTP Authentication (RFC 4954)           |
| `ext_size`              | Message Size Declaration (RFC 1870)      |
| `ext_8bitmime`          | 8-bit MIME Transport (RFC 6152)          |
| `ext_pipelining`        | Command Pipelining (RFC 2920)            |
| `ext_smtputf8`          | Internationalized Email (RFC 6531)       |
| `ext_enhancedstatuscodes` | Enhanced Error Codes (RFC 2034)        |
| `arbitrary`             | Derive `Arbitrary` for fuzzing           |
| `serde`                 | Derive `Serialize`/`Deserialize`         |

## Usage

```rust
use smtp_types::{
    command::Command,
    core::{Domain, ForwardPath, LocalPart, Mailbox, ReversePath},
};

// Create an EHLO command
let domain = Domain::try_from("client.example.com").unwrap();
let cmd = Command::ehlo(domain);

// Create a MAIL FROM command
let cmd = Command::mail(ReversePath::Null);

// Create a RCPT TO command
let local = LocalPart::try_from("user").unwrap();
let domain = Domain::try_from("example.com").unwrap();
let mailbox = Mailbox::new(local, domain.into());
let cmd = Command::rcpt(ForwardPath::from(mailbox));
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
