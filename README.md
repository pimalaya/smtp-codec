# smtp-{codec,types}

This workspace contains `smtp-codec` and `smtp-types`, two crates for building SMTP clients and servers following [RFC 5321].

`smtp-codec` provides parsing and serialization, and is based on `smtp-types`.
`smtp-types` provides misuse-resistant types, constructors, and general support for SMTP implementations.

## Features

* Complete formal syntax of SMTP is implemented following RFC 5321
* Several SMTP extensions are supported (AUTH, SIZE, 8BITMIME, PIPELINING, STARTTLS, SMTPUTF8, ENHANCEDSTATUSCODES)
* Correctness and misuse-resistance are enforced on the type level
* Comprehensive test coverage

## Usage

```rust
use smtp_codec::{decode::Decoder, encode::Encoder, CommandCodec, GreetingCodec};

// Parse a greeting
let input = b"220 mail.example.com ESMTP ready\r\n";
let (remaining, greeting) = GreetingCodec::default().decode(input).unwrap();
println!("Domain: {}", greeting.domain);

// Encode a command
use smtp_codec::smtp_types::command::Command;
let cmd = Command::quit();
let bytes = CommandCodec::default().encode(&cmd);
assert_eq!(bytes.dump(), b"QUIT\r\n");
```

## Supported Extensions

| Feature                 | Description                              | RFC      |
|-------------------------|------------------------------------------|----------|
| starttls                | SMTP over TLS                            | RFC 3207 |
| ext_auth                | SMTP Authentication                      | RFC 4954 |
| ext_size                | Message Size Declaration                 | RFC 1870 |
| ext_8bitmime            | 8-bit MIME Transport                     | RFC 6152 |
| ext_pipelining          | Command Pipelining                       | RFC 2920 |
| ext_smtputf8            | Internationalized Email                  | RFC 6531 |
| ext_enhancedstatuscodes | Enhanced Error Codes                     | RFC 2034 |

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

[RFC 5321]: https://tools.ietf.org/html/rfc5321
