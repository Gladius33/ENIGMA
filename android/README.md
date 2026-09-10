# Enigma Android V1

Client Android Kotlin pour une messagerie 1-to-1 chiffrée de bout en bout consommant le backend Rust V1.

## Stack

- Kotlin, Jetpack Compose, MVVM manuel.
- Room pour le stockage local.
- DataStore + Android Keystore pour secrets locaux, session et clés privées encodées.
- Retrofit/OkHttp pour HTTP.
- OkHttp WebSocket pour `/v1/ws`.
- FCM côté réception.
- Crypto isolée derrière `CryptoEngine`.

## Crypto V1

`SignalCryptoEngine` est branche au flux applicatif texte 1-to-1 via l'AAR Android `org.signal:libsignal-android:0.76.1`, centralise dans `gradle/libs.versions.toml`. Les cles privees restent locales et sont chiffrees via Android Keystore/DataStore/SharedPreferences chiffre par `LocalCipher`.

L'ancien moteur crypto provisoire a ete retire. Le chemin applicatif V1 reste `SignalCryptoEngine` et une release ne doit jamais accepter un moteur non libsignal.

`signal/SignalReadiness.kt`, `crypto/SafetyNumber.kt` et `security/ReleaseCryptoGuard.kt` rendent le statut crypto explicite. L'app affiche une empreinte locale et un code de securite de conversation. Les smoke tests instrumentes passent sur un telephone reel, mais une release publique reste bloquee tant que la validation deux appareils reels et une ceremonie de confiance complete ne sont pas terminees.

## Configuration backend

Par défaut, `BuildConfig.DEFAULT_BASE_URL` vaut en debug :

```text
http://10.0.2.2:8080/
```

En release sans `ENIGMA_BASE_URL`, la valeur par defaut est un placeholder HTTPS :

```text
https://relay.example.invalid/
```

TLS est obligatoire en release. Le source set debug autorise le HTTP clair pour `localhost`, `10.0.2.2`, `10.0.3.2` et les IP LAN de test. Les parametres refusent une URL HTTP en release avant de reconstruire le client reseau.

Le certificate pinning release est optionnel et actif seulement si les deux variables sont presentes :

```kotlin
ENIGMA_PINNED_HOST
ENIGMA_PINNED_SHA256
```

Voir `android.env.example` pour les valeurs attendues.

## FCM

Ajoute ton `google-services.json` dans `app/` si tu actives Firebase. Le client reçoit les messages FCM et affiche une notification générique sans contenu sensible.

À chaque rotation de token, `EnigmaFirebaseMessagingService` appelle `POST /v1/devices/fcm-token`. Le serveur associe le token FCM à l'appareil lié au JWT courant.

En production, le serveur doit être lancé avec `PUSH_PROVIDER=fcm` et des credentials Firebase HTTP v1 valides. En dev/test, le backend reste sur `NoopPushSender`.

## Commandes

```bash
./gradlew :app:assembleDebug
./gradlew :app:testDebugUnitTest
./gradlew :app:connectedDebugAndroidTest
```

Sans wrapper local :

```bash
gradle :app:assembleDebug
gradle :app:testDebugUnitTest
```

## Fonctionnalités V1

- Onboarding, création de compte, connexion.
- Choix langue FR/EN minimal au premier lancement et dans les paramètres.
- Reseau et relais dans `Parametres` et `Bulles` : relais officiel affiche par libelle produit, relais personnalises synchronises/crees, QR relais importables, et attachement explicite a une bulle.
- Test manuel du relais depuis `Parametres` via `/health` et `/version`, avec affichage version serveur.
- Affichage version APK locale dans `Parametres`.
- Creation d'identite avec check handle, secret de recuperation affiche une seule fois, et confirmation.
- Recuperation d'identite par handle + secret avec creation d'un nouveau device.
- Génération identité locale et prekeys.
- Publication prekeys.
- Contacts par identifiant public.
- Conversation 1-to-1.
- Messages texte E2EE.
- Pièces jointes chiffrées avant upload via URL pré-signée.
- Téléchargement de pièce jointe protégé par `download_secret` transmis dans le message E2EE.
- DTO/API, Room, repositories, ViewModels et UI expérimentales pour groupes, canaux, calls signaling et TURN.
- Stockage local chiffré, pas de message clair en base.
- Verrouillage local par code.
- WebSocket + polling pending.
- Retry réseau via OkHttp et file locale `QUEUED/FAILED`.
- Mapping des erreurs API structurees : `error_code` et `request_id` sont conserves cote client et affiches sur le parcours principal avec une reference support.
- Logs minimaux sans contenu, clé, token ou blob déchiffré.
- Suppression compte depuis les paramètres avec confirmation textuelle, tombstone serveur, purge Room/fichiers/session/device/PIN/cles Signal, et conservation de l'URL relais/langue.

## Limites actuelles

- WebRTC Android média réel non finalisé; l'app expose seulement une UI mock/signalisation expérimentale.
- libsignal est disponible et actif pour les messages texte 1-to-1. Le contrat de clés, le codec, la génération de prekeys, le store persistant et `SignalCryptoEngine` sont couverts par tests unitaires.
- Le push Firebase HTTP v1 côté serveur existe, mais il n'est production-ready qu'après validation avec un vrai projet Firebase et un appareil réel.
