# Enigma

Enigma is an open-source, end-to-end encrypted messaging project built around a **P2P-first** transport model and a shared security core across Android, Windows and Linux.

> **Status:** actively developed and testable. Automated CI/release gates are extensive, but **Enigma is not yet production-ready and is not a security certification**. Independent review and real-device qualification remain required before a 1.0 release.

## What Enigma is trying to achieve

Enigma prefers direct device-to-device communication whenever possible. When direct reachability fails, TURN and temporary application relays provide availability without turning the central infrastructure into the normal place where conversation content lives.

The design goal is therefore not merely “E2EE over a central server”, but a multi-device messaging system in which:

- message and attachment content remains opaque to the server wherever the protocol permits;
- direct P2P paths are preferred;
- TURN is used when NAT traversal requires it;
- application relay/storage is a temporary fallback;
- relay ciphertext is subject to bounded lifetime and deletion semantics;
- Android, Windows and Linux share the same protocol and security boundaries rather than reimplementing cryptography independently.

## Current platforms

### Android

- Kotlin / Jetpack Compose.
- Room and DataStore.
- Android Keystore integration.
- libsignal-based end-to-end encrypted direct messaging.
- WebRTC signaling and NAT traversal support.
- P2P-first messaging and attachment transfer.
- Delivery/read receipts and recoverable local outboxes.

### Windows

- WinUI 3 / C# frontend.
- Shared Rust backend exposed through a versioned C ABI.
- Self-contained Windows distributable validated in CI.
- The C# layer is intentionally thin: cryptographic/session logic remains in the common Rust core.

### Linux

- Qt 6 / C++ frontend.
- Same shared Rust backend and ABI as Windows.
- Debian package produced and validated in CI.
- The C++ frontend does not independently reimplement the security protocol.

## Shared desktop Rust core

The desktop workspace centralizes the security-sensitive logic used by Windows and Linux:

- protocol version/capability negotiation with fail-closed behavior;
- certified device authorization with libsignal identity binding;
- multi-device fanout;
- device revocation checks;
- bounded replay/deduplication handling;
- P2P → TURN → temporary relay transport selection;
- mandatory relay TTL and ACK-delete semantics;
- ciphertext purge after acknowledgement or expiry;
- guarded, single-use history transfer rules;
- secure local storage primitives backed by libsodium;
- XChaCha20-Poly1305 for the appropriate local-storage boundary;
- controlled/limited unsafe surface;
- common C ABI consumed by both desktop frontends.

The production desktop libsignal backend is pinned to an immutable source revision. CI includes an **Android ↔ Rust bidirectional libsignal interoperability gate** using real PREKEY/WHISPER exchanges.

## Server architecture

The server is implemented in Rust with Axum and uses PostgreSQL, Redis and S3-compatible object storage.

The server:

- authenticates users/devices;
- routes opaque envelopes;
- coordinates signaling;
- issues/controls relay and storage access;
- supports STUN/TURN-assisted connectivity;
- provides temporary relay/storage fallback when direct P2P cannot be established.

WebRTC media is negotiated through signaling; the application server is not intended to receive media in cleartext. TURN is a relay at the network layer and must not be confused with a direct peer path.

## Multi-device

The 1.0 workstream includes the foundation for Android/Windows/Linux multi-device operation:

- device linking/authorization;
- identity binding;
- per-device delivery/fanout;
- revocation;
- replay/deduplication protection;
- shared wire contracts;
- guarded history-transfer mechanisms.

These mechanisms have automated coverage, but they still require qualification on real hardware and real networks.

## P2P-first routing

For supported messaging, attachment and call flows, Enigma prefers this order:

1. direct peer-to-peer path;
2. TURN-assisted path when direct NAT traversal is not possible;
3. temporary application relay/storage fallback when necessary for availability.

Transfers can resume from offsets and verify ciphertext hashes. Relay data is designed to be bounded by TTL/acknowledgement rules rather than acting as permanent plaintext-accessible message storage.

## Release status

The main automated 1.0 workstream has passed CI gates covering Android, server, desktop, security, supply chain and interoperability.

**REAL-LAB-001 remains a release blocker.**

Before a 1.0 RC/release is considered qualified, physical Android/Windows/Linux devices must be exercised across scenarios including:

- pairing and multi-device synchronization;
- real Internet paths;
- normal NAT and difficult NAT;
- CGNAT;
- direct P2P success/failure;
- TURN fallback;
- application-relay fallback;
- Wi-Fi ↔ mobile network changes;
- process restart;
- sleep/wake cycles;
- offline/reconnect behavior;
- interrupted/resumed transfers;
- device revocation;
- WebRTC calls under real network conditions.

Passing automated CI does **not** replace this real-device qualification.

## Security and supply-chain gates

The repository includes automated checks such as:

- Rust builds/tests on Linux and Windows;
- Android builds, lint, unit and instrumented tests;
- Windows WinUI 3 consumer validation;
- Linux Qt 6 consumer validation;
- Android ↔ Rust libsignal interoperability;
- unsafe-policy checks for the desktop core;
- CodeQL for Java/Kotlin, Rust, C# and C/C++;
- dependency review;
- Rust advisory scanning;
- Gitleaks;
- Trivy source/IaC/secret scanning;
- workflow/shell policy checks;
- SBOM generation;
- deterministic source/release artifacts and attestations where configured.

These controls reduce risk but are not a substitute for independent cryptographic/security review.

## Building and testing

### Server

```bash
cd server
cargo fmt --check
cargo build
cargo test
```

### Android

```bash
cd android
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest
```

### Desktop shared Rust core

```bash
cd desktop
cargo fmt --check
cargo build --workspace
cargo test --workspace
```

Integration services can be started with the versioned server compose file:

```bash
docker compose -f server/docker-compose.yml up -d postgres redis minio coturn
```

Some checks require Docker, an Android SDK/emulator or physical device, Windows tooling, Qt 6, or external network services.

## Repository structure

- `android/` — Android client and tests.
- `desktop/` — shared Rust desktop core, ABI, Windows WinUI 3 client and Linux Qt 6 client.
- `server/` — Rust API/server, migrations and integration tests.
- `infra/` — infrastructure/deployment support assets.
- `docs/` — protocol, architecture, security, threat-model and feature documentation.
- `scripts/` — local validation helpers.
- `.github/` — CI, security and supply-chain automation.

## Security reporting

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability. Do not publish credentials, private keys, production configuration, device dumps or exploitable security details in public issues.

## Branching model

`main` is the single long-lived development branch.

Feature/fix branches are temporary integration vehicles and should be removed after merge. Dependabot may create short-lived automated branches for dependency pull requests; they are not development branches.

## License

Enigma is released under the **GNU Affero General Public License v3.0 only (AGPL-3.0-only)**. See [LICENSE](LICENSE) and [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

Commercial use is permitted subject to the AGPL-3.0-only terms and the licenses of third-party components.

---

## Présentation française

Enigma est une messagerie libre chiffrée de bout en bout, conçue autour d’un modèle **P2P-first** et d’un cœur de sécurité partagé entre Android, Windows et Linux.

Les connexions directes sont privilégiées. Lorsque le réseau les empêche, TURN puis un relais applicatif temporaire peuvent assurer la disponibilité. L’infrastructure centrale est conçue pour rester aveugle au contenu E2EE et pour ne pas devenir le lieu normal de conservation permanente des conversations.

Le projet dispose désormais de clients Android, Windows et Linux ainsi que d’une architecture multi-appareils. La qualification **REAL-LAB-001 sur matériel et réseaux réels reste obligatoire avant une Release Candidate 1.0**.
