#![no_main]

use smtp_codec::{smtp_types::response::Response, ResponseCodec};
use smtp_codec_fuzz::impl_to_bytes_and_back;

impl_to_bytes_and_back!(ResponseCodec, Response);
