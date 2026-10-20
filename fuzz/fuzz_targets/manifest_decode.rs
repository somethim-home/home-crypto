#![no_main]

use home_crypto::manifest::ManifestState;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((kind, state)) = ManifestState::decode(data) {
        let encoded = state.encode(kind);
        assert!(matches!(encoded.as_deref(), Ok(bytes) if bytes == data));
        let _ = state.view();
        let mut compacted = state.clone();
        compacted.compact();
        let _ = compacted.merge(&state);
    }
});
