# Appels V1

La V1 implemente le signaling WebRTC cote serveur et un moteur media WebRTC Android.

## Serveur

- creation d'appel audio/video 1-to-1;
- accept/reject/hangup;
- offre SDP opaque;
- reponse SDP opaque;
- ICE candidates opaques;
- lecture des evenements distants via `GET /v1/calls/{call_id}/signaling`;
- notifications WebSocket `incoming_call` et `call_signaling`;
- credentials TURN temporaires compatibles coturn.

Le serveur Rust ne transporte pas les flux media et ne voit aucun media clair. Les flux audio/video passent par WebRTC entre clients, avec DTLS-SRTP gere par la pile WebRTC.

## Android

Android utilise `io.github.webrtc-sdk:android:125.6422.07`, version fixe centralisee dans `android/gradle/libs.versions.toml`.

`WebRtcCallEngine` cree une `PeerConnection`, configure les ICE servers depuis `/v1/turn/credentials`, cree une track audio, cree une track video avec camera avant par defaut pour les appels video, genere offer/answer, applique answer distante, ajoute ICE distant et emet ICE local vers le repository.

`CallsRepository` cree l'appel serveur dans la bulle active, genere automatiquement l'offer WebRTC, envoie l'offer via le relais actif, accepte une offer distante en generant automatiquement l'answer, synchronise answer/ICE via `/signaling`, et envoie l'ICE local via `/v1/calls/{call_id}/ice-candidates`.

`CallsScreen` ne contient plus de saisie manuelle SDP/ICE en parcours normal. L'ecran demande les permissions micro/camera, expose appeler audio, appeler video, accepter, refuser, raccrocher, mute/unmute, camera on/off, haut-parleur on/off, synchronisation signaling et test TURN. Les tracks video locale et distante sont rendues via `SurfaceViewRenderer`.

## Limites restantes

- validation reelle audio/video sur deux telephones non executee dans cette passe;
- qualite reseau, timeouts, Bluetooth/audio route avancee et monitoring TURN a auditer;
- release signee deux appareils non validee;
- appels de groupe et SFU E2EE hors V1 immediate.

Verdict maximal tant que les tests deux appareils ne sont pas passes : `PRÊT POUR AUDIT HUMAIN FINAL`.
