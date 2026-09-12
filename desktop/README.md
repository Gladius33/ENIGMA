# ENIGMA Desktop 1.0 foundation

This workspace is the shared Rust foundation for the Windows and Linux clients.

The desktop frontends are deliberately thin. Signal session handling, multi-device fanout, replay/deduplication rules, transport selection, relay semantics, storage cryptography and synchronization belong in this Rust workspace and must not be reimplemented independently in C# or C++.

The libsodium storage boundary is pinned through `libsodium-sys-stable = 1.24.0` and uses guarded allocations plus XChaCha20-Poly1305. The libsignal production backend remains release-gated until the pinned `v0.86.5` source revision is actually integrated and Android/Windows/Linux golden interoperability vectors pass. No substitute cryptography is permitted.
