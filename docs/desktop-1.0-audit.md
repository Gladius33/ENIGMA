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

### LIC-001 — libsignal / licence — RESOLVED

ENIGMA 1.0 est licencié intégralement sous **AGPL-3.0-only**. Les manifests Rust et la documentation racine doivent rester cohérents avec cette licence.

La dépendance libsignal conserve sa propre attribution/licence et ne doit jamais être remplacée par une implémentation cryptographique maison pour contourner une obligation de licence.

**RELEASE GATE:** le contrôle CI de politique de licence doit rester vert et les notices tierces doivent être conservées.

### SIG-001 — libsignal desktop / interop — PARTIALLY RESOLVED

La version Android reste `0.86.5`. Le tag correspondant `v0.86.5` est désormais relié à la révision source immuable :

`b39e93f1a5e6531044dfcdf5876585cbcf08f884`

`enigma-signal` conserve ce SHA complet comme pin de référence. `main`, `master`, `latest` et un tag seul sont interdits comme source de build RC.

**BLOCK RELEASE** reste actif jusqu'à ce que le backend libsignal desktop réel utilise cette révision et que les golden vectors Android ↔ Windows ↔ Linux soient validés. Un pin source seul ne rend pas le backend release-ready.

### REAL-LAB-001

La CI ne prouve pas le NAT traversal Internet réel, le CGNAT, les changements Wi-Fi/mobile ni les cycles sommeil/réveil.

**BLOCK RELEASE** jusqu'à qualification physique Android/Windows/Linux.

## Frontière 1.0

macOS, iOS, Web, appels audio/vidéo desktop, Tor/mixnet, fédération, sauvegarde cloud permanente, plugins/bots, stickers avancés, multi-compte desktop et toute nouvelle crypto restent post-1.0.
