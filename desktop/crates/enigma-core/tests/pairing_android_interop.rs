use std::{
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use enigma_core::{PairingBootstrap, DEFAULT_PAIRING_TTL_MS};

#[test]
#[ignore = "run only from the Android/Rust pairing interoperability CI gate"]
fn rust_emits_android_pairing_uri() {
    let path = PathBuf::from(
        env::var_os("ENIGMA_ANDROID_PAIRING_URI")
            .expect("ENIGMA_ANDROID_PAIRING_URI must point to the cross-runtime fixture"),
    );
    let now_unix_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_millis(),
    )
    .expect("current Unix time must fit u64");
    let bootstrap =
        PairingBootstrap::generate(now_unix_ms, DEFAULT_PAIRING_TTL_MS).expect("pairing bootstrap");

    fs::write(path, bootstrap.uri()).expect("write Android pairing URI fixture");
}
