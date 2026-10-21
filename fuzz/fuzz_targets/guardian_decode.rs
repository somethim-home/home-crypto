#![no_main]

//! Every guardian record parser (format §9): anything accepted must re-encode to the same bytes.

use home_crypto::guardian::{GuardianEnd, GuardianWrap, KidIdentity, PassphraseKey};
use libfuzzer_sys::fuzz_target;

/// The bytes a signature covers: everything before the last line.
fn signed_part(data: &[u8]) -> Option<&[u8]> {
    let body = data.strip_suffix(b"\n")?;
    let split = body.iter().rposition(|&b| b == b'\n')? + 1;
    data.get(..split)
}

fuzz_target!(|data: &[u8]| {
    if let Ok(signed) = GuardianWrap::decode(data) {
        let wrap = signed.unverified();
        let again = wrap.signed_bytes(signed.signer());
        assert!(matches!(again.as_deref(), Ok(bytes) if Some(bytes) == signed_part(data)));
        assert!(wrap.guardians().len() <= home_crypto::guardian::MAX_GUARDIANS);
        let _ = wrap.guardians().iter().map(|g| g.key.fingerprint()).count();
    }
    if let Ok(signed) = GuardianEnd::decode(data) {
        let again = signed.unverified().signed_bytes(signed.signer());
        assert!(matches!(again.as_deref(), Ok(bytes) if Some(bytes) == signed_part(data)));
    }
    if let Ok(identity) = KidIdentity::decode(data) {
        assert!(matches!(identity.encode().as_deref(), Ok(bytes) if bytes.as_slice() == data));
    }
    if let Ok(key) = PassphraseKey::decode(data) {
        assert!(matches!(key.encode().as_deref(), Ok(bytes) if bytes.as_slice() == data));
    }
});
