#[macro_export]
macro_rules! impl_decode_target {
    ($codec:ident) => {
        use libfuzzer_sys::fuzz_target;

        fuzz_target!(|input: &[u8]| {
            #[cfg(feature = "debug")]
            use smtp_codec::smtp_types::utils::escape_byte_string;
            use smtp_codec::{decode::Decoder, encode::Encoder};

            #[cfg(feature = "debug")]
            println!("[!] Input:      {}", escape_byte_string(input));

            if let Ok((_rem, parsed1)) = $codec::default().decode(input) {
                #[cfg(feature = "debug")]
                {
                    let input = &input[..input.len() - _rem.len()];
                    println!("[!] Consumed:   {}", escape_byte_string(input));
                    println!("[!] Parsed1: {parsed1:?}");
                }

                let output = $codec::default().encode(&parsed1);
                #[cfg(feature = "debug")]
                println!("[!] Serialized: {}", escape_byte_string(&output));

                let (rem, parsed2) = $codec::default().decode(&output).unwrap();
                #[cfg(feature = "debug")]
                println!("[!] Parsed2: {parsed2:?}");
                assert!(rem.is_empty());

                assert_eq!(parsed1, parsed2);
            } else {
                #[cfg(feature = "debug")]
                println!("[!] <invalid>");
            }

            #[cfg(feature = "debug")]
            println!("{}", str::repeat("-", 120));
        });
    };
}

#[macro_export]
macro_rules! impl_to_bytes_and_back {
    ($codec:tt, $object:tt) => {
        use libfuzzer_sys::fuzz_target;

        fuzz_target!(|input: $object| {
            #[cfg(feature = "debug")]
            use smtp_codec::smtp_types::utils::escape_byte_string;
            use smtp_codec::{decode::Decoder, encode::Encoder};

            #[cfg(feature = "debug")]
            println!("[!] Input:  {:?}", input);

            let buffer = <$codec>::default().encode(&input);

            #[cfg(feature = "debug")]
            println!("[!] Serialized: {}", escape_byte_string(&buffer));

            let (rem, parsed) = <$codec>::default().decode(&buffer).unwrap();
            assert!(rem.is_empty());

            #[cfg(feature = "debug")]
            println!("[!] Parsed: {parsed:?}");

            assert_eq!(input, parsed);

            #[cfg(feature = "debug")]
            println!("{}", str::repeat("-", 120));
        });
    };
}
