# Plan V1 Production-Ready Enigma

## Resume executif

Enigma est actuellement une V1 testable/beta, pas une V1 production-ready.

Le serveur Rust couvre deja les surfaces principales : identites, appareils, contacts, messages directs, pieces jointes, WebSocket, TURN, groupes, canaux et calls signaling. Android permet un test debug du flux principal, avec URL relais configurable, recuperation/suppression visibles, parcours stable FR/EN, update checker manuel, migrations Room explicites, empreintes de securite minimales et libsignal actif pour le texte 1-to-1. Les smoke tests instrumentes FR/EN passent sur un telephone reel S35 et un test debug deux telephones LAN a valide creation d'identites, contacts, A vers B, B vers A et fermeture/reouverture. La production reste bloquee par la validation release signee sur appareils reels, la validation FCM production et l'audit securite manuel final; un audit automatise logs/secrets existe maintenant pour bloquer les regressions evidentes.

La V1 production doit rester centree sur la messagerie 1-to-1 fiable :

- identite Enigma, recuperation et suppression;
- contacts;
- messages texte 1-to-1;
- fichiers/attachments seulement si UX et tests sont complets;
- WebSocket avec fallback polling;
- notifications opaques;
- FR/EN;
- APK debug et release;
- Docker/HTTPS self-host.

Groupes, canaux et appels WebRTC restent hors perimetre production V1. Ils peuvent rester dans le code comme surfaces avancees, sans promesse produit.

## Etat reel du depot

- `server/` : Axum/Tokio/SQLx avec PostgreSQL, Redis, S3/MinIO, JWT device-bound, migrations versionnees, WebSocket par appareil, TURN et endpoints produit larges.
- `android/` : Kotlin/Compose, Room, DataStore, Keystore, Retrofit/OkHttp, FCM client, relais officiel resolu par build, relais personnalises par bulle, ecrans debug pour flux principal et surfaces avancees.
- `docs/` : contrat API, deploiement, test Android, securite, libsignal/WebRTC, groupes/canaux/calls et vision future.
- `infra/` : exemples Docker prod/dev, nginx, caddy, coturn, systemd.
- `.github/` : workflows serveur et Android minimaux.

## Verdict initial

Production-ready est bloque tant que ces gates ne sont pas verts :

- libsignal reel reste le seul moteur du flux app release;
- APK release/lint/tests Android passent;
- Room a des migrations non destructives;
- WebSocket Android est relie au cycle de vie global avec fallback polling;
- recuperation/suppression identite sont accessibles et testees dans Android; la suppression revoque cote serveur puis purge Room, fichiers locaux, session, device id, PIN local et cles Signal en conservant URL relais/langue;
- FCM serveur reel valide ou push explicitement declare comme gate bloquant release;
- erreurs API stables avec `error_code`;
- documentation et CI executent les memes gates que le release process.

## Hard gates

- `./scripts/check-server.sh` vert avec integration non skippee.
- `./scripts/check-android.sh` vert.
- `cd android && ./gradlew :app:lintDebug :app:assembleRelease` vert.
- APK release signee si `ENIGMA_RELEASE_STORE_FILE`, `ENIGMA_RELEASE_STORE_PASSWORD`, `ENIGMA_RELEASE_KEY_ALIAS` et `ENIGMA_RELEASE_KEY_PASSWORD` sont fournis; APK unsigned seulement pour gate interne.
- `docker compose up -d --build`, `/health` et `/version` verts.
- Tests identite : creation, check handle, recuperation, suppression, tombstone.
- Tests messages : A vers B, B vers A, retry, fermeture/reouverture, unknown sender; le parcours A/B debug reel est valide, les gates release restent a executer.
- Aucun JWT, token FCM, URL S3 presignee complete, cle ou ciphertext complet dans les logs; `./scripts/audit-secret-logs.sh` bloque les logs bruts et les patterns de fuite evidents dans le gate global.
- Moteur crypto non libsignal impossible en release.

## Passes ordonnees

### 0. Plan fichier

Objectif : garder le plan de livraison dans le depot.

- Fichiers : `docs/PLAN_V1_PROD_READY.md`.
- Acceptation : plan present, honnete, sans promesse libsignal/WebRTC/FCM si absent.

### 1. Stabilisation serveur critique

- Modules : `server/src/http`, `config`, `error`, `calls`, `messages`, `ws`.
- Etat actuel : routes verifiees, logs sans secrets, CORS strict en production, WebSocket avec header `Authorization`, calls sans dette de handler.
- Verification actuelle : tests unitaires `config::tests::*` prouvent que `APP_ENV=production` refuse `CORS_ALLOWED_ORIGINS=*`, refuse `PUSH_PROVIDER=noop` et accepte `PUSH_PROVIDER=fcm` avec service account fourni.
- Verification actuelle : `./scripts/audit-secret-logs.sh` refuse les macros de log serveur non revues, les `Log.*` Android hors `SafeLog`, `HttpLoggingInterceptor`, les tokens WebSocket en query string et les appels `SafeLog` avec mots sensibles non explicitement rediges.
- Tests : `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`.
- Acceptation : serveur compile sans warning.
- Isolement : si groupes/calls cassent, les garder experimentaux et hors gates V1.

### 2. Tests serveur non trompeurs

- Modules : `scripts/check-server.sh`, `server/tests`, CI serveur.
- Changements : integration non skippee sauf `SKIP_INTEGRATION=1`, MinIO inclus, health/version testes.
- Acceptation : echec clair si PostgreSQL/Redis/MinIO manquent.

### 3. Migrations SQL

- Modules : `server/migrations`.
- Changements : verifier contraintes `message_type`, identites, tombstones, sessions device-bound, index uniques.
- Acceptation : base neuve et upgrade incremental passent.

### 4. Erreurs API structurees

- Modules : `server/src/error.rs`, Android error mapper, docs API.
- Etat actuel : serveur retourne `{error_code,message,request_id}`; Android parse ces corps via `ApiErrorMapper`, conserve `errorCode`/`requestId` dans `UserVisibleError`, traduit les codes stables sur les repositories du parcours principal et affiche la reference support dans Auth, Contacts, Conversation et Settings.
- Changements restants : externaliser toutes les traductions d'erreurs dans `values`/`values-fr` et couvrir toutes les surfaces experimentales.
- Acceptation : client alternatif peut traduire sans parser le texte.

### 5. Identite Enigma complete

- Modules : `identities`, `users`, Android onboarding.
- Changements : check handle live, canonicalisation serveur, affichage `@handle`, generation de cles.
- Acceptation : identite independante du relais, token device-bound actif.

### 6. Recuperation, suppression et tombstones

- Modules : `identities`, Android auth/settings.
- Changements : flux recuperation avec nouvelles cles, avertissement de securite, suppression compte et tombstone.
- Acceptation : aucune promesse de restaurer anciennes cles ou anciens messages.

### 7. Android reseau debug/release

- Modules : `NetworkConfig`, `SecureOkHttpFactory`, settings.
- Etat actuel : HTTP debug/LAN est autorise via le source set debug, la release refuse HTTP dans `NetworkConfig` et dans `Parametres`, ignore au demarrage une ancienne URL HTTP stockee, le defaut release est un placeholder HTTPS, le pinning est configurable par `ENIGMA_PINNED_HOST` + `ENIGMA_PINNED_SHA256`, et la sauvegarde de l'URL relais reconstruit immediatement le conteneur reseau/app sans relance manuelle.
- Changements restants : validation certificat/pinning release sur un domaine HTTPS reel.
- Acceptation : debug simple, release stricte.

### 8. Onboarding Android

- Modules : `OnboardingScreen`, `AuthScreen`, `AuthViewModel`.
- Changements : langue, creer/recuperer, check handle, secret recuperation affiche et confirme.
- Acceptation : premier lancement complet sans ambiguite.

### 9. Persistance locale

- Modules : Room, DataStore, Keystore.
- Etat actuel : migrations Room explicites `1 -> 2`, `2 -> 3` et `3 -> 4`, schemas exportes, aucun `fallbackToDestructiveMigration` dans `AppContainer`.
- Etat actuel : un test instrumente existe et compile pour la migration `3 -> 4` qui ajoute l'etat local de verification du code de securite, ainsi qu'un chemin legacy `1 -> 4`.
- Changements restants : execution `connectedDebugAndroidTest` sur appareil/emulateur et validation upgrade depuis une APK ancienne reellement installee.
- Acceptation : pas de perte locale silencieuse.

### 10. WebSocket Android reel

- Modules : `ChatWebSocketClient`, cycle de vie app, sync.
- Etat actuel : `DirectSyncCoordinator` attend le device, connecte le WebSocket en foreground, synchronise sur evenement, reconnecte avec backoff et coupe la socket hors foreground.
- Changements restants : test instrumente de deconnexion/reconnexion et validation release signee sur deux appareils reels.
- Acceptation : reception sans ouvrir manuellement la conversation.

### 11. Sync globale

- Modules : repositories messages/contacts/devices.
- Etat actuel : sync au demarrage foreground, retour foreground, evenement WebSocket et polling fallback toutes les 60 secondes.
- Changements restants : validation release signee A vers B et B vers A sur deux appareils apres fermeture/reouverture.
- Acceptation : A vers B et B vers A fiables apres relance.

### 12. Messages inconnus

- Modules : `MessagesRepository`, contacts.
- Etat actuel : `MessagesRepository` cree un contact/conversation placeholder depuis `sender_user_id` et `sender_public_id` si l'expediteur n'est pas encore connu localement.
- Changements restants : validation UX deux appareils quand le message arrive avant ajout manuel du contact.
- Acceptation : message visible ou erreur recuperable.

### 13. Retry/statuts messages

- Modules : DAO messages, repository, UI.
- Etat actuel : statuts locaux `QUEUED`, `SENDING`, `SENT`, `DELIVERED`, `READ`, `FAILED`; retry outbound idempotent par `client_message_id`; bouton retry manuel quand un message sortant est en echec; statuts visibles dans la conversation avec libelles FR/EN; receipts serveur synchronisables via `/v1/messages/receipts`; WebSocket `receipt_updated`; l'ouverture d'une conversation envoie une receipt `read` monotone pour les messages entrants deja livres.
- Changements restants : validation release signee deux appareils apres fermeture/reouverture et UX avancee pour filtrer/parametrer explicitement les confirmations de lecture.
- Acceptation : pas de doublon utilisateur et messages sortants marques `DELIVERED` apres ACK.

### 14. Libsignal 1-to-1

- Modules : `SignalCryptoEngine`, key stores, messages.
- Etat actuel : dependance Android `org.signal:libsignal-android:0.76.1` ajoutee, `coreLibraryDesugaring` active, `.dylib`/`.dll` et `libsignal_jni_testing.so` exclus du packaging, smoke test unitaire libsignal vert.
- Etat actuel : migration `0009` et DTO/API transportent `registration_id`, `protocol_device_id` et `kyber_prekey` pour les bundles libsignal.
- Etat actuel : `SignalKeyCodec` convertit les bundles Enigma vers/de libsignal et le prouve par test de session.
- Etat actuel : `SignalPreKeyBundleFactory` genere/stocke les prekeys dans un `SignalProtocolStore` et produit un upload bundle Enigma.
- Etat actuel : `PersistentSignalProtocolStore` et `SharedPreferencesSignalRecordStorage` fournissent un store libsignal persistant chiffre.
- Etat actuel : `SignalCryptoEngine` est branche par `AppContainer`; `SignalCryptoEngineTest` couvre Alice vers Bob, reouverture des stores, puis Bob vers Alice.
- Etat actuel : `SafetyNumber` calcule une empreinte locale et un code de conversation depuis les cles d'identite; Android les affiche dans `Parametres` et les conversations quand les cles distantes sont connues. L'utilisateur peut marquer le code comme verifie; l'etat est persiste localement et reinitialise si la cle distante change.
- Changements restants : ceremonie de confiance complete (QR code, historique/alerte de changement de cle, politique d'envoi non-verifie), validation release signee sur deux appareils reels, renouvellement/rotation prekeys, tests instrumentes.
- Acceptation : aucun moteur crypto non libsignal dans le chemin release.
- Blocage : tant que la validation release signee deux appareils, la validation FCM production et l'audit de confiance utilisateur ne sont pas termines, V1 reste beta.

### 15. Medias/fichiers

- Modules : attachments, media UI.
- Etat actuel : backend attachments et repositories Android upload/download chiffres generiques existent; aucune UI stable SAF/previews/vocaux n'est exposee.
- Decision : hors production V1; garder masque/report V1.1 tant que UX selection, ouverture, nettoyage et tests ne sont pas complets.
- Changements restants : selection SAF, chiffrement local, upload/download via message descriptor, previews sures, ouverture intent securisee, nettoyage.
- Acceptation : fichier E2EE utilisable en 1-to-1.
- Isolement : masquer si incomplet.

### 16. Push FCM reel

- Modules : `server/src/push`, Android FCM service.
- Etat actuel : `FcmPushSender` HTTP v1 compile, endpoints mockables en test, tokens invalides desactivent le push, payload Firebase limite a `type=sync_hint`, Android lance sync pending/receipts/retry/contacts sur `sync_hint`/`wake`, affiche une notification generique et expose la demande runtime `POST_NOTIFICATIONS` dans les parametres.
- Tests actuels : payload opaque pour tous les evenements push, sender FCM HTTP v1 teste contre un endpoint mock local incluant le mapping `400/404 -> InvalidToken`, et configuration production testee pour refuser `noop`.
- Changements restants : validation avec vrai projet Firebase et appareil reel.
- Acceptation : Noop uniquement dev/test; production exige `PUSH_PROVIDER=fcm` valide.

### 17. i18n FR/EN

- Modules : resources Android, error mapper.
- Etat actuel : choix langue persistant; onboarding, auth, contacts, conversation, verrouillage et parametres affichent les libelles critiques via `values`/`values-fr`; les statuts serveur/crypto/update/suppression des parametres sont modelises puis localises cote UI; les erreurs API et erreurs locales stables sont traduites par `error_code`.
- Verification actuelle : `xmllint` sur les ressources, `./scripts/check-android.sh`, `lintDebug`, `assembleRelease` et `:app:compileDebugAndroidTestKotlin` passent apres cette externalisation du parcours stable.
- Tests actuels : smoke tests Compose instrumentes pour onboarding FR/EN et verrouillage FR/EN passent sur telephone reel S35 via `connectedDebugAndroidTest` : 4/4, 0 skipped, 0 failed.
- Changements restants : couvrir completement les surfaces experimentales groupes/canaux/appels et executer les smoke tests UI FR/EN sur appareil/emulateur apres ce refactor.
- Acceptation : parcours principal traduit.

### 18. Parametres Android

- Modules : settings.
- Etat actuel : identite, `@handle`, URL relais appliquee immediatement, test serveur `/health` + `/version`, version app, langue, notifications, update checker, suppression compte et crypto status sont visibles dans `Parametres`.
- Changements restants : mode export/sauvegarde futur et validation UI sur appareil reel.
- Acceptation : utilisable hors dev.

### 19. Update checker sideload

- Modules : serveur releases, Android settings/update.
- Etat actuel : endpoint manifeste stable; Android valide `https`, SHA-256 hex et signature si presente, affiche Play Store/sideload quand Android expose l'origine, telecharge explicitement l'APK en cache si l'origine n'est pas Play Store, verifie le SHA-256 des bytes telecharges, verifie la signature Ed25519 des bytes telecharges quand `ENIGMA_UPDATE_ED25519_PUBLIC_KEY` est configuree au build, refuse un manifeste signe si aucune cle publique n'est embarquee, supprime le fichier si le hash ou la signature divergent, ouvre les parametres sources inconnues si necessaire, puis l'installateur Android via `FileProvider`; aucune installation silencieuse.
- Changements restants : cle publique officielle de release, signature effective des APK publiees, UX finale de release et validation appareil reel du flux installateur.
- Acceptation : notification update sure; pas de contournement Play Store.

### 20. Groupes/canaux

- Decision : reporter production V1.
- Changements : masquer ou badger experimental.
- Acceptation : aucune promesse production.

### 21. Appels WebRTC

- Decision : reporter production V1.
- Changements : garder signaling/TURN experimental, masquer media appel stable.
- Acceptation : aucun appel presente comme pret.

### 22. Docker prod / HTTPS / self-host

- Modules : `infra`, `.env.example`, docs.
- Changements : compose prod clair, services externes, reverse proxy HTTPS, secrets requis, CORS strict.
- Acceptation : ThinkStation et self-host reproductibles.

### 23. API clients alternatifs

- Modules : `docs/API.md`, `docs/api-contract.md`.
- Changements : routes, payloads, erreurs, WS events, release manifest, exemples curl.
- Acceptation : client CLI possible sans lire Android.

### 24. CI / qualite

- Modules : `.github/workflows`, scripts.
- Changements : MinIO CI, Android lint, release assemble, cache Gradle, artifact APK debug.
- Acceptation : CI bloque les regressions critiques.

### 25. Documentation finale

- Modules : docs existantes.
- Changements : etat reel, limites, runbooks, test deux telephones, release checklist.
- Acceptation : aucune doc ne vend libsignal/WebRTC/FCM si absent.

### 26. Release checklist

- Livrables : version, changelog, APK signee, backend image taggee, env prod, backup/restore, rollback.
- Etat actuel : Gradle signe `release` via variables d'environnement `ENIGMA_RELEASE_STORE_FILE`, `ENIGMA_RELEASE_STORE_PASSWORD`, `ENIGMA_RELEASE_KEY_ALIAS` et `ENIGMA_RELEASE_KEY_PASSWORD`; sans ces variables, `assembleRelease` produit seulement une APK unsigned.
- Changements restants : cle officielle de production, coffre de secrets CI, rotation/backup de la cle et validation d'installation sur appareils reels.
- Acceptation : V1 production declarable seulement si tous hard gates sont verts.

## Commandes de verification

```bash
./scripts/audit-secret-logs.sh
./scripts/check-server.sh
./scripts/check-android.sh
cd android && ./gradlew :app:lintDebug :app:assembleRelease
docker compose up -d --build
curl http://localhost:8080/health
curl http://localhost:8080/version
```

## Criteres de reussite

- Deux telephones creent Alice/Bob, verifient les handles, s'ajoutent en contact et echangent A vers B puis B vers A.
- Fermeture/reouverture conserve session, device, identite et messages.
- Recuperation ajoute un nouvel appareil et avertit que les anciens messages peuvent etre perdus.
- Suppression revoque sessions/appareils/prekeys, reserve le handle et purge les donnees locales de compte sans effacer URL relais/langue.
- Release Android ne doit pas demarrer avec un moteur crypto non libsignal; elle ne devient production-ready qu'apres validation release signee deux appareils reels, confiance/fingerprint auditee, sync/retry et FCM production.

## Conditions de declaration V1 production-ready

Declarer V1 production-ready uniquement si :

- serveur prod et CI sont verts;
- Android debug/release/lint/tests sont verts;
- `SignalCryptoEngine` est actif dans le flux app release et valide sur appareils reels avec APK release signee;
- WebSocket, fallback polling et retry sont valides;
- FCM production ou statut push explicitement non production;
- docs et scripts reproduisent exactement le release process.

Sinon le statut reste : **V1 beta testable**.
