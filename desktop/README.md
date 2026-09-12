# ENIGMA Desktop 1.0 foundation

This workspace is the shared Rust foundation for the Windows and Linux clients.

The desktop frontends are deliberately thin. Signal session handling, multi-device fanout, replay/deduplication rules, transport selection, relay semantics, storage cryptography and synchronization belong in this Rust workspace and must not be reimplemented independently in C# or C++.

The libsignal and libsodium production backends remain release-gated until their exact upstream pins, license obligations and cross-platform build strategy are validated. No substitute cryptography is permitted.
