# smtp-codec

Rock-solid and complete codec for SMTP (RFC 5321).

## Overview

This crate provides parsing and serialization for SMTP protocol messages:

- **Codecs**: `GreetingCodec`, `CommandCodec`, `ResponseCodec`, `EhloResponseCodec`
- **Decoding**: Parse raw bytes into typed SMTP messages
- **Encoding**: Serialize typed messages into wire format

## Usage

### Decoding

```rust
use smtp_codec::{GreetingCodec, decode::Decoder};

let input = b"220 mail.example.com ESMTP ready\r\n<remaining>";
let (remaining, greeting) = GreetingCodec::default().decode(input).unwrap();

assert_eq!(greeting.domain.inner(), "mail.example.com");
assert_eq!(remaining, b"<remaining>");
```

### Encoding

```rust
use smtp_codec::{CommandCodec, encode::Encoder, smtp_types::command::Command};

let cmd = Command::quit();
let bytes = CommandCodec::default().encode(&cmd);

assert_eq!(bytes.dump(), b"QUIT\r\n");
```

## Features

| Feature                 | Description                              |
|-------------------------|------------------------------------------|
| `starttls`              | STARTTLS command support                 |
| `ext_auth`              | SMTP Authentication (RFC 4954)           |
| `ext_size`              | SIZE parameter parsing                   |
| `ext_8bitmime`          | 8BITMIME capability                      |
| `ext_pipelining`        | PIPELINING capability                    |
| `ext_smtputf8`          | SMTPUTF8 capability                      |
| `ext_enhancedstatuscodes` | Enhanced status codes                  |
| `quirk_crlf_relaxed`    | Accept LF without CR                     |
| `fuzz`                  | Expose parsers for fuzzing               |

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
