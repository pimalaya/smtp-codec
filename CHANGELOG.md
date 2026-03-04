# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - YYYY-MM-DD

### Added

* Initial implementation of smtp-codec and smtp-types
* Support for RFC 5321 SMTP protocol
* Commands: EHLO, HELO, MAIL, RCPT, DATA, RSET, QUIT, NOOP, VRFY, EXPN, HELP
* Responses: Single-line and multi-line responses with reply codes
* Greeting parsing (220 response)
* EHLO response parsing with capability extraction

### SMTP Extensions

* `starttls` - STARTTLS command (RFC 3207)
* `ext_auth` - SMTP Authentication (RFC 4954)
* `ext_size` - Message Size Declaration (RFC 1870)
* `ext_8bitmime` - 8-bit MIME Transport (RFC 6152)
* `ext_pipelining` - Command Pipelining (RFC 2920)
* `ext_smtputf8` - Internationalized Email (RFC 6531)
* `ext_enhancedstatuscodes` - Enhanced Error Codes (RFC 2034)

### Additional Features

* `quirk_crlf_relaxed` - Accept LF without preceding CR
* `arbitrary` - Derive Arbitrary for fuzzing
* `serde` - Serialize/Deserialize support
