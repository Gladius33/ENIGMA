# Test Android réel

## Générer l'APK

Depuis la racine :

```bash
./scripts/check-android.sh
```

Ou directement :

```bash
cd android
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
ANDROID_HOME=$HOME/Android/Sdk \
ANDROID_SDK_ROOT=$HOME/Android/Sdk \
./gradlew :app:assembleDebug
```

Compiler les tests instrumentes sans appareil :

```bash
cd android
JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
ANDROID_HOME=$HOME/Android/Sdk \
ANDROID_SDK_ROOT=$HOME/Android/Sdk \
GRADLE_USER_HOME=/tmp/gradle-home \
./gradlew :app:compileDebugAndroidTestKotlin
```

Executer les tests instrumentes quand un telephone ou emulateur est connecte :

```bash
adb devices
cd android
./gradlew :app:connectedDebugAndroidTest
```

APK :

```text
android/app/build/outputs/apk/debug/app-debug.apk
```

Pour compiler avec une URL LAN par défaut :

```bash
cd android
ENIGMA_BASE_URL=http://IP_THINKSTATION:8080/ ./gradlew :app:assembleDebug
```

## Installer

Via ADB :

```bash
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

`adb install -r` remplace l'APK en conservant les donnees de l'application quand la signature est compatible. Ne pas utiliser `adb uninstall`, `pm clear` ou une suppression de fichiers si l'objectif est de conserver l'etat du telephone.

Ou copie l'APK sur le téléphone, autorise l'installation depuis cette source, puis installe-le.

## Configurer le serveur LAN

Au premier écran, ouvre `Serveur`, saisis :

```text
http://IP_THINKSTATION:8080/
```

Sauvegarde. L'application reconstruit immédiatement son client réseau avec cette URL.

Appuie ensuite sur `Tester le serveur`. Le résultat attendu est un relais joignable avec :

```text
Serveur: enigma-e2ee-server 0.1.0
```

En build debug, HTTP clair est autorise pour le LAN et l'emulateur. En release, HTTP clair reste interdit et les parametres refusent une URL `http://`; utilise HTTPS devant le backend. Si une ancienne version avait deja stocke une URL HTTP, la release l'ignore au demarrage et revient au defaut HTTPS jusqu'a sauvegarde d'une URL valide.

Pour une release interne connectee a ton relais :

```bash
cd android
ENIGMA_BASE_URL=https://ton-domaine.example/ ./gradlew :app:assembleRelease
```

Sans variables de signature, Gradle produit :

```text
android/app/build/outputs/apk/release/app-release-unsigned.apk
```

Pour produire une APK release signee, fournis un keystore hors depot :

```bash
cd android
ENIGMA_BASE_URL=https://ton-domaine.example/ \
ENIGMA_RELEASE_STORE_FILE=/chemin/absolu/enigma-release.jks \
ENIGMA_RELEASE_STORE_PASSWORD='secret-keystore' \
ENIGMA_RELEASE_KEY_ALIAS=enigma \
ENIGMA_RELEASE_KEY_PASSWORD='secret-cle' \
./gradlew :app:assembleRelease
```

APK signee attendue :

```text
android/app/build/outputs/apk/release/app-release.apk
```

Ne stocke jamais le keystore ni les mots de passe dans le depot. `.gitignore` ignore deja `*.jks` et `*.keystore`, mais les secrets doivent rester dans un coffre ou l'environnement CI.

Le pinning certificat est optionnel. Il s'active seulement si `ENIGMA_PINNED_HOST` et `ENIGMA_PINNED_SHA256` sont fournis.

## Scénario minimum

Téléphone A :

1. choisir la langue si necessaire;
2. verifier la disponibilite du handle `alice_test`;
3. creer une identite `alice_test`;
4. noter le secret de recuperation affiche une seule fois;
5. recopier le secret pour confirmer;
6. attendre l'écran contacts.

Téléphone B :

1. verifier la disponibilite du handle `bob_test`;
2. creer une identite `bob_test`;
3. noter et confirmer le secret de recuperation;
4. attendre l'écran contacts.

Sur A :

1. ajouter `bob_test`;
2. ouvrir la conversation;
3. envoyer un message texte.

Sur B :

1. ajouter `alice_test` si nécessaire;
2. ouvrir/revenir dans l'app;
3. vérifier réception via WebSocket si l'app est au premier plan, ou via polling/synchro pending au retour dans l'app.
4. comparer le `Code de sécurité` affiche dans la conversation avec le code affiche sur A pour la meme conversation.
5. sur chaque telephone, appuyer sur `Marquer comme vérifié` seulement si les codes correspondent.
6. fermer puis rouvrir l'app et verifier que l'etat `Vérifié sur cet appareil` reste affiche.

## Persistance

Ferme l'app, rouvre-la :

- la session locale doit rester présente;
- l'identité et le device id doivent être conservés;
- les messages locaux doivent rester dans Room.
- le retour au premier plan doit relancer la sync globale.
- l'empreinte locale dans `Parametres` doit rester stable.
- l'etat de verification du code de securite doit rester stable tant que la cle distante ne change pas.

## Recuperation et suppression

Test recuperation :

1. sur un nouvel appareil ou apres reinstall, choisir `Recuperer une identite`;
2. saisir le handle et le secret de recuperation;
3. verifier que l'app cree un nouveau device et entre dans l'app;
4. ne pas attendre la restauration des anciens messages sans sauvegarde future.

Test suppression :

1. ouvrir `Parametres`;
2. saisir `SUPPRIMER` dans la confirmation;
3. supprimer le compte;
4. verifier le retour onboarding;
5. verifier que les conversations, messages, fichiers locaux, session, device id, PIN local et cles Signal sont purges;
6. verifier que l'URL serveur et la langue restent conservees;
7. verifier que le handle reste reserve cote serveur.

## Fonctionnalités expérimentales

Les écrans groupes, canaux et appels sont accessibles mais marqués expérimentaux. Ils ne remplacent pas le test stable : identité, contacts, messages texte 1-to-1.

WebRTC média réel et FCM réel serveur ne sont pas actifs en production. Libsignal est actif pour les messages texte 1-to-1, mais le chemin complet doit encore être validé sur deux téléphones réels avant publication.

## Notifications

Sur Android 13+, ouvre `Parametres` et autorise les notifications si tu veux tester le reveil FCM. Les notifications restent generiques; le contenu et l'expediteur ne sont jamais envoyes par FCM. Si la permission est refusee, WebSocket et polling doivent encore recuperer les messages au retour dans l'app.

## Mise a jour APK

L'ecran `Parametres` peut verifier `GET /v1/releases/android?channel=stable`. Si le relais ne configure pas de manifeste, l'app affiche que la mise a jour sideload n'est pas disponible. Si un manifeste existe, l'app valide `https`, le SHA-256 hex et la signature si presente, affiche l'origine d'installation Play Store/sideload quand Android l'expose, puis affiche les notes FR/EN. Pour une installation non Play Store, le bouton `Telecharger et verifier l'APK` telecharge le fichier en cache, verifie le SHA-256 des bytes telecharges et verifie la signature Ed25519 si l'APK a ete construit avec `ENIGMA_UPDATE_ED25519_PUBLIC_KEY=base64-x509-ed25519-public-key`. Le bouton `Ouvrir l'installateur Android` ouvre les parametres sources inconnues si necessaire, puis l'installateur Android. Aucune APK n'est installee silencieusement.
