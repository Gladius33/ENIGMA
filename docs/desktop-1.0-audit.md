# ENIGMA Desktop / Multi-device / P2P-first — audit de départ

## Baseline

Branche de travail : `feat/desktop-multidevice-p2p-1.0`.

Point de départ : `ef3d6322cf389026a57937f762717b01818adacf` (`main`, 2026-09-11).

Le dernier HEAD de PR ayant exécuté les quatre gates historiques est `0438f439eb334ee6a0ea2add5f981e6891f4a767` : `android-ci`, `server-ci`, `security-ci` et `codeql` étaient verts. Cette baseline ne doit pas régresser.

## Cartographie existante

Android possède déjà libsignal (pin Gradle 0.86.5), `SignalCryptoEngine`, un `SignalProtocolStore` persistant, prekeys/signed prekeys/Kyber prekeys, safety number, P2P WebRTC DataChannel, DIRECT/TURN, pièces jointes P2P avec reprise, receipts/outboxes et fallback relay.

Le serveur Rust/Axum possède déjà comptes/devices/sessions device-bound, révocation, publication/discovery/claim de prekeys, message queue opaque avec TTL et ACK, WebSocket de signalisation P2P, TURN temporaire, blobs S3-compatible chiffrés côté client, lifecycle/GC, PostgreSQL, Redis et tests d'intégration.

La règle est donc de réutiliser ces contrats lorsqu'ils sont stables. Il est interdit de réimplémenter Signal Protocol ou de remplacer des primitives existantes seulement par préférence architecturale.

## Écarts avant RC 1.0

- cérémonie d'appairage desktop avec preuve cryptographique d'autorisation ;
- registre de devices vérifiable côté clients, et pas seulement accepté parce que le serveur le retourne ;
- wire protocol versionné fail-closed ;
- fanout vers tous les devices du destinataire + sender-sync vers les autres devices de l'émetteur ;
- transfert initial d'historique device-to-device, single-use et temporaire ;
- clients Windows/Linux distribuables ;
- golden vectors Android/Rust/Windows/Linux ;
- tests E2E, anti-plaintext, SBOM, attestations et real lab.

## Blockers de release

### LIC-001 — libsignal / licence

Le dépôt racine est actuellement sous MIT alors que la documentation interne identifie la dépendance libsignal Android comme AGPL-3.0-only.

**BLOCK RELEASE** jusqu'à analyse et décision de conformité/licence de la distribution 1.0.

Ce point ne doit jamais être contourné par une implémentation cryptographique maison.

### SIG-001 — pin exact libsignal desktop

`enigma-signal` doit isoler un backend libsignal épinglé à une version/révision exacte auditée. `main`, `master` et `latest` sont interdits.

**BLOCK RELEASE** tant que ce pin et ses golden vectors ne sont pas validés.

### REAL-LAB-001

La CI ne prouve pas le NAT traversal Internet réel, le CGNAT, les changements Wi-Fi/mobile ni les cycles sommeil/réveil.

**BLOCK RELEASE** jusqu'à qualification physique Android/Windows/Linux.

## Frontière 1.0

macOS, iOS, Web, appels audio/vidéo desktop, Tor/mixnet, fédération, sauvegarde cloud permanente, plugins/bots, stickers avancés, multi-compte desktop et toute nouvelle crypto restent post-1.0.
