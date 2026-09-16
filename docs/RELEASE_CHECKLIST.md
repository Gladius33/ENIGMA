# Checklist release V1

## Gates serveur

```bash
./scripts/audit-secret-logs.sh
./scripts/check-server.sh
docker compose up -d --build
curl http://localhost:8080/health
curl http://localhost:8080/version
```

- `APP_ENV=production`.
- `JWT_SECRET`, `JWT_ISSUER`, `JWT_AUDIENCE`, credentials S3, secret TURN et credentials Firebase fournis par secrets externes.
- `TRUSTED_PROXIES` et `PUBLIC_CLIENT_IP_HEADER` configures uniquement si le reverse proxy reecrit strictement les headers client.
- `CORS_ALLOWED_ORIGINS` ne contient pas `*`.
- `PUSH_PROVIDER=fcm` si les notifications Android sont un gate release.
- Logs verifies sans JWT, token FCM complet, URL S3 presignee complete, cle ou ciphertext complet; `./scripts/audit-secret-logs.sh` doit passer, puis revue manuelle finale avant publication.

### Gate commercial obligatoire avant lancement du relais officiel

Ce gate est bloquant avant toute mise en production publique avec `OFFICIAL_RELAY_MODE=true`.

- Les valeurs commerciales definitives des plans `free`, `supporter`, `plus` et `pro` sont validees produit/business avant lancement.
- `max_devices` est explicitement verifie pour chaque plan et correspond a l'offre publique annoncee.
- `max_groups`, `max_group_members`, `max_channels`, `max_channel_subscribers` et `turn_monthly_seconds` ne doivent plus etre laisses a `NULL` si le service officiel doit effectivement limiter ou monetiser ces ressources. Dans le code, `NULL` signifie volontairement **illimite**.
- Les valeurs retenues sont renseignees dans la base/migration de production, versionnees et revues avant ouverture des inscriptions publiques; aucune modification manuelle non tracee directement en base de production.
- Les limites sont coherentes entre plans (pas de downgrade involontaire d'un plan superieur) et coherentes avec les pages tarifaires, CGV/conditions d'offre et l'interface Android.
- Les cas limites sont testes avant lancement : atteindre exactement la limite, tentative au-dela de la limite, changement de plan, renouvellement/expiration d'abonnement et retour au plan Free.
- Les limites commerciales ne s'appliquent qu'au relais officiel. Un relais communautaire/prive avec `OFFICIAL_RELAY_MODE=false` reste hors de ces restrictions SaaS.
- Le quota TURN n'est declare production-ready que lorsque l'usage reel coturn est mesure et remonte de facon fiable au serveur. Ne pas simuler la consommation en debitant simplement la duree de validite des credentials TURN.

## Gates Android

```bash
./scripts/check-android.sh
cd android
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
ANDROID_HOME=$HOME/Android/Sdk \
ANDROID_SDK_ROOT=$HOME/Android/Sdk \
GRADLE_USER_HOME=/tmp/gradle-home \
./gradlew :app:lintDebug :app:assembleRelease
./gradlew :app:compileDebugAndroidTestKotlin
```

- Release signee :
  ```bash
  cd android
  ENIGMA_BASE_URL=https://ton-domaine.example/ \
  ENIGMA_RELEASE_STORE_FILE=/chemin/absolu/enigma-release.jks \
  ENIGMA_RELEASE_STORE_PASSWORD='secret-keystore' \
  ENIGMA_RELEASE_KEY_ALIAS=enigma \
  ENIGMA_RELEASE_KEY_PASSWORD='secret-cle' \
  ./gradlew :app:assembleRelease
  ```
- Sans ces variables, le livrable est `android/app/build/outputs/apk/release/app-release-unsigned.apk`, non publiable publiquement.
- Avec ces variables, le livrable attendu est `android/app/build/outputs/apk/release/app-release.apk`.
- Secrets CI optionnels pour produire une APK signee dans `.github/workflows/android.yml` :
  - `ENIGMA_RELEASE_KEYSTORE_BASE64` : keystore JKS encode en base64.
  - `ENIGMA_RELEASE_STORE_PASSWORD`.
  - `ENIGMA_RELEASE_KEY_ALIAS`.
  - `ENIGMA_RELEASE_KEY_PASSWORD`.
  - variable repo `ENIGMA_RELEASE_BASE_URL` pour l'URL HTTPS de production.
- Aucun moteur crypto non libsignal dans le chemin release.
- `SignalCryptoEngine`/libsignal reel actif en release.
- Migrations Room reelles, pas de migration destructive en production.
- URL relais HTTPS configuree pour release.
- APK signee avec cle de release.
- Parcours stable verifie en FR et EN : onboarding, creation, recuperation, contacts, conversation, parametres, suppression.
- Tests instrumentes : `compileDebugAndroidTestKotlin` vert, puis `connectedDebugAndroidTest` vert sur appareil/emulateur avant publication.

## Gates desktop et multi-device

- `desktop-ci` est vert sur Ubuntu et Windows : format, check, Clippy `-D warnings`, tests debug/release et documentation.
- Le client Linux Qt6 compile contre l'ABI Rust et produit un paquet `.deb` dont le layout est valide.
- Le client Windows WinUI 3 compile contre la meme ABI Rust et produit le livrable self-contained attendu.
- Le gate Android <-> Rust libsignal valide pairing, PREKEY puis WHISPER dans les deux sens.
- La policy `unsafe` desktop reste verte et aucune exception de securite n'est ajoutee pour faire passer la CI.
- Le gate final manuel est `docs/V1_REAL_WORLD_TEST_PLAN.md` (`REAL-LAB-001`) sur Android, Windows et Linux : multi-device, P2P-first, NAT/CGNAT/TURN, relay fallback temporaire, ACK/TTL, changements reseau, sleep/wake et resilience processus.

## Gates produit

- Deux appareils creent deux identites, s'ajoutent en contact et echangent A vers B puis B vers A.
- Fermeture/reouverture conserve session, device, identite et messages.
- Les deux appareils affichent le meme code de securite pour la conversation; le marquage `verifie` persiste apres relance et se reinitialise si la cle distante change.
- Discovery des cles ne consomme pas de one-time prekey; seul `claim-prekey` consomme et Android ne claim pas quand `hasSession` est vrai.
- Les attachements ne sont telechargeables qu'apres `complete`/verification S3.
- Groupes/canaux restent experimentaux/post-1.0 tant qu'un protocole de groupe/sender-key et leur qualification production ne sont pas finalises; ils ne bloquent pas la RC 1.0 actuelle s'ils ne sont pas exposes comme production.
- Les appels audio/video WebRTC restent post-1.0 pour la surface production. Leur validation deux appareils reels devient bloquante uniquement avant activation production de cette fonction.
- Recuperation ajoute un nouvel appareil et avertit que les anciens messages peuvent etre perdus.
- Suppression revoque sessions, appareils et prekeys, puis reserve le handle.
- WebSocket livre les evenements en foreground; polling fallback recupere les messages apres relance.
- Unknown sender n'abandonne pas silencieusement un pending.

## Verdict release

Declarer la RC 1.0 qualifiee uniquement lorsque les gates automatises applicables sont verts et que `REAL-LAB-001` est passe. Les scenarios explicitement marques experimentaux/post-1.0 ne bloquent pas cette RC. Tant que `REAL-LAB-001` n'est pas passe, le statut maximal est `PRET POUR REAL LAB`, pas production-ready.
