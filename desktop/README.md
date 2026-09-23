# ENIGMA Desktop 1.0 foundation

This workspace is the shared Rust foundation for the Windows and Linux clients.

The desktop frontends are deliberately thin. Signal session handling, multi-device fanout, replay/deduplication rules, transport selection, relay semantics, storage cryptography and synchronization belong in this Rust workspace and must not be reimplemented independently in C# or C++.

The libsodium storage boundary is pinned through `libsodium-sys-stable = 1.24.0` and uses guarded allocations plus XChaCha20-Poly1305. The production libsignal backend is integrated from the immutable `v0.86.5` source revision (`b39e93f1a5e6531044dfcdf5876585cbcf08f884`). The mandatory Android↔Rust bidirectional interoperability gate exercises a real PREKEY/WHISPER exchange, while Windows and Linux consume the same Rust backend through the common ABI. These gates must remain green; no substitute cryptography is permitted.
