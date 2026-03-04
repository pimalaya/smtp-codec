#![no_main]

use smtp_codec::ResponseCodec;
use smtp_codec_fuzz::impl_decode_target;

impl_decode_target!(ResponseCodec);
