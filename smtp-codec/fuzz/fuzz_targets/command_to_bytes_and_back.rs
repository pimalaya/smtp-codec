#![no_main]

use smtp_codec::{smtp_types::command::Command, CommandCodec};
use smtp_codec_fuzz::impl_to_bytes_and_back;

impl_to_bytes_and_back!(CommandCodec, Command);
