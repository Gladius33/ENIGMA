# Statut libsignal et WebRTC Android

## libsignal

Etat actuel :

- `CryptoEngine` est l'interface active.
- `SignalCryptoEngine` est le moteur applicatif Android pour les messages texte 1-to-1.
- L'ancien moteur crypto provisoire a ete retire du code Android principal.
- `ReleaseCryptoGuard` bloque une release qui utiliserait un moteur non libsignal.
- `org.signal:libsignal-android:0.76.1` est centralise dans `android/gradle/libs.versions.toml` et reference par le build Android.
- Le test `LibsignalProtocolSmokeTest` etablit une session libsignal avec prekey, signed prekey et Kyber prekey, puis chiffre/dechiffre un premier message et une reponse.
- Le test `SignalCryptoEngineTest` chiffre Alice vers Bob, dechiffre, rouvre les stores persistants, puis chiffre Bob vers Alice sans regenerer de cles.
- Le serveur et les DTO Android acceptent maintenant `registration_id`, `protocol_device_id` et `kyber_prekey` dans `/v1/keys/upload` et les restituent dans `/v1/keys/{user_id}`.
- La migration `0009_libsignal_key_metadata.sql` ajoute ces champs sans casser les appareils existants.
- `SignalKeyCodec` convertit de vraies cles libsignal en bundle Enigma et reconstruit un `PreKeyBundle` libsignal depuis le bundle distant. `SignalKeyCodecTest` prouve qu'une session peut etre etablie avec ce format.
- `SafetyNumber` expose une empreinte locale et un code de conversation stable depuis les cles d'identite. Android affiche l'empreinte locale dans `Parametres` et le code de conversation quand la cle distante est disponible ou recuperable. Le marquage manuel `verifie` est persiste localement et reinitialise si la cle distante change.
- `SignalPreKeyBundleFactory` genere identity metadata, signed prekey, Kyber prekey et one-time prekeys dans un `SignalProtocolStore`, puis produit le payload Enigma uploadable.
- `PersistentSignalProtocolStore` implemente `SignalProtocolStore` avec stockage key-value chiffre; `SharedPreferencesSignalRecordStorage` fournit le backend Android via `LocalCipher`.

Dependance actuelle :

```kotlin
implementation(libs.libsignal.android)
coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
```

Cette dependance est sous licence AGPL-3.0-only. Une distribution publique doit respecter les obligations de licence applicables.

Fichiers a modifier :

- `android/gradle/libs.versions.toml` et `android/app/build.gradle.kts` : dependance AAR Android libsignal centralisee; desugaring active; packaging exclut les binaires desktop `.dylib`/`.dll` et `libsignal_jni_testing.so`.
- `android/app/src/main/java/com/enigma/securechat/crypto/SignalCryptoEngine.kt` : moteur texte 1-to-1 libsignal actif.
- `android/app/src/main/java/com/enigma/securechat/crypto/SignalKeyCodec.kt` : codec bundle libsignal deja present.
- `android/app/src/main/java/com/enigma/securechat/crypto/SignalPreKeyBundleFactory.kt` : generation/upload bundle deja present.
- `android/app/src/main/java/com/enigma/securechat/crypto/PersistentSignalProtocolStore.kt` : store libsignal persistant deja present.
- `android/app/src/main/java/com/enigma/securechat/storage/SharedPreferencesSignalRecordStorage.kt` : stockage Android chiffre deja present.
- `android/app/src/main/java/com/enigma/securechat/di/AppContainer.kt` : `SignalCryptoEngine` est instancie avec le store persistant chiffre.
- `android/app/src/main/java/com/enigma/securechat/data/repository/MessagesRepository.kt` : passe par `CryptoEngine`, donc utilise libsignal pour le texte 1-to-1.
- `android/app/src/main/java/com/enigma/securechat/data/repository/GroupsRepository.kt` et `ChannelsRepository.kt` : V1 chiffre par destinataire/device dans une enveloppe opaque; definir le sender-key/group protocol avant optimisation production large echelle.

Classes/fonctions restantes avant production :

- ceremonie de confiance complete : QR code finalise, alertes produit de changement de cle et validation instrumentee de la politique d'envoi.
- validation release signee deux appareils reels du flux message complet.
- rotation/renouvellement complet des prekeys.
- UX de verification d'identite.

Blocage actuel :

- les smoke tests instrumentes demarrent l'app reelle sur un telephone S35; le test debug deux appareils du flux message complet a ete effectue, mais le test release signee deux appareils reste a faire;
- groupes/canaux n'ont pas de sender-key Signal.

Conclusion : le texte 1-to-1 utilise maintenant libsignal et expose des empreintes minimales avec verification manuelle persistante, mais la release production reste bloquee tant que la validation release signee deux appareils, l'audit de confiance/fingerprint et FCM production ne sont pas termines.

## WebRTC

Etat actuel :

- serveur : signaling, TURN credentials, WebSocket `incoming_call`/`call_signaling` et endpoint `GET /v1/calls/{call_id}/signaling` disponibles;
- Android : `WebRtcCallEngine` implemente `PeerConnectionFactory`, PeerConnection, offer, answer, setLocalDescription, setRemoteDescription, ICE local/distant, track audio, track video camera avant, mute/unmute, camera on/off, speaker on/off et release;
- Android : `CallsRepository` cree l'appel serveur, genere automatiquement l'offer, genere l'answer a partir d'une offer distante, envoie ICE local et applique answer/ICE distants;
- Android : `CallsScreen` demande micro/camera en runtime, retire la saisie manuelle SDP/ICE du parcours normal et rend les tracks video locale/distante via `SurfaceViewRenderer`.

Dependance WebRTC Android :

```kotlin
webrtcAndroid = "125.6422.07"
implementation(libs.webrtc.android)
```

Artefact : `io.github.webrtc-sdk:android:125.6422.07`, AAR BSD-3-Clause publie sur Maven Central.

Fichiers principaux :

- `android/gradle/libs.versions.toml` et `android/app/build.gradle.kts` : dependance WebRTC centralisee.
- `android/app/src/main/java/com/enigma/securechat/calls/WebRtcCallEngine.kt` : moteur media reel.
- `android/app/src/main/java/com/enigma/securechat/calls/CallSignalingCodec.kt` : encodage ICE opaque.
- `android/app/src/main/java/com/enigma/securechat/data/repository/CallsRepository.kt` : orchestration signaling/media.
- `android/app/src/main/java/com/enigma/securechat/ui/screens/CallsScreen.kt` : UI appel utilisable.
- `server/src/calls/mod.rs` : lecture signaling distant.
- `docs/calls.md` : flux final documente.

Limites restantes :

- validation audio/video sur deux appareils Android non executee dans cette passe;
- release signee deux appareils non validee;
- routage audio avance/Bluetooth et monitoring TURN a auditer.

Conclusion : WebRTC media est integre dans Android et compile, mais le verdict maximal reste `PRÊT POUR AUDIT HUMAIN FINAL` tant que les appels audio/video reels ne sont pas valides sur deux appareils.
