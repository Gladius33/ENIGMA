# Enigma 2

Enigma 2 is an open-source messaging project focused on privacy and end-to-end encryption. It combines an Android client with a Rust server and prefers direct peer-to-peer communication while retaining relays and fallbacks for reachability.

> **Status:** actively developed and testable, but not production-ready or a security guarantee. Independent review and real-device validation remain necessary.

## Why Enigma 2?

The project aims to keep message and attachment content opaque to the server wherever the protocol permits, while remaining usable across restrictive networks. Direct paths are preferred; signaling, STUN/TURN and application relays remain available when a direct path cannot be established.

## Current status

The repository contains implementations and tests for the main server and Android paths, alongside experimental or incomplete product surfaces. Group/channel cryptography, production push configuration, signed release validation and real-device WebRTC/P2P qualification still require further audit and validation.

## Features

- Kotlin Android client with Jetpack Compose, Room, DataStore and Android Keystore.
- Rust/Axum server with PostgreSQL, Redis and S3-compatible storage.
- libsignal integration for end-to-end encrypted direct messaging.
- Direct messages, groups and channels with opaque server-side envelopes.
- WebRTC calls with signaling, ICE and STUN/TURN credentials.
- P2P-first messaging and attachments, receipts (`DELIVERED`/`READ`), resumable offsets and SHA-256 ciphertext verification.
- Application relay and storage fallback when direct P2P is unavailable.
- Private relays and an official relay, with configured plans/quotas where enabled.

## Architecture

Android owns identity material, session state and encryption. The server authenticates devices, routes opaque envelopes, coordinates signaling and controls relay/storage access. WebRTC media is negotiated through signaling but is not carried as clear media by the application server. TURN is a network traversal path, not fully direct transfer.

## End-to-end encryption

Text is encrypted on Android through libsignal. The server is intended to remain blind to E2EE content, but metadata, availability and relay/storage operations still exist. This project is not a security certification.

## P2P-first messaging, attachments and calls

The client attempts direct peer communication for supported messaging and attachment flows. Transfers can resume from offsets and verify ciphertext hashes; receipts and attachment commits use recoverable local outboxes. Calls use WebRTC offer/answer and ICE signaling. If direct connectivity is unavailable, TURN or application relay/storage fallbacks preserve availability according to the active relay configuration. Real-device and difficult-network qualification remains ongoing.

## Building and testing

The repository includes development and example deployment assets. Production secrets and machine-specific configuration must remain outside Git.

```bash
cd server
cargo fmt --check
cargo build
cargo test

cd ../android
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest
```

Integration dependencies can use the versioned server compose file:

```bash
docker compose -f server/docker-compose.yml up -d postgres redis minio coturn
```

From the root, `./scripts/check-server.sh`, `./scripts/check-android.sh` and `./scripts/check-all.sh` provide project checks. Some checks require Docker, an Android SDK, an emulator/device or external services.

Firebase is optional and is not configured automatically. Keep `google-services.json` and release credentials outside the repository.

## Repository structure

- `android/` — Android application and tests.
- `server/` — Rust API, migrations and integration tests.
- `docs/` — architecture, API, security and feature notes.
- `scripts/` — local validation helpers.
- `.github/` — public automation when present.

## Security

Do not publish credentials, private keys, device dumps or production configuration. Until a security policy and private reporting channel are published, contact the maintainers through the project’s current trusted channel rather than posting exploitable details publicly.

## Contributing

Preserve the documented security boundaries, avoid logging sensitive material and include focused tests for behavior changes. Describe required services or device capabilities when a check cannot run locally.

## Présentation française

Enigma 2 est une messagerie open source orientée confidentialité et chiffrement de bout en bout. Le client Android privilégie les communications directes P2P, tout en conservant des relais et des mécanismes de secours lorsque le réseau ne permet pas une connexion directe.

## License

Enigma 2 is released under the [MIT License](LICENSE).
