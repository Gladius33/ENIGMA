# Android UI et branding

## Source logo

Logo detecte a la racine du depot :

```text
logo.jpg
```

Format source : JPEG 640 x 640.

Ressource principale Android :

```text
android/app/src/main/res/drawable-nodpi/enigma_logo.png
```

Le logo est utilise dans l'onboarding, la barre haute des ecrans principaux, le profil, l'icone launcher et le splash screen.

## Icones Android

Les ressources launcher sont generees dans :

```text
android/app/src/main/res/mipmap-mdpi/
android/app/src/main/res/mipmap-hdpi/
android/app/src/main/res/mipmap-xhdpi/
android/app/src/main/res/mipmap-xxhdpi/
android/app/src/main/res/mipmap-xxxhdpi/
android/app/src/main/res/mipmap-anydpi-v26/
```

Le manifeste pointe vers :

```xml
android:icon="@mipmap/ic_launcher"
android:roundIcon="@mipmap/ic_launcher_round"
```

Android 13+ utilise aussi `@drawable/ic_launcher_monochrome`.

## Splash screen

Le splash Android 12+ est configure dans :

```text
android/app/src/main/res/values-v31/styles.xml
android/app/src/main/res/values-night-v31/styles.xml
```

Il affiche le logo Enigma sur fond clair/sombre selon le theme systeme.

## Navigation stable

La navigation stable visible en V1 est :

- Messages
- Bulles
- Contacts
- Profil

Les conversations 1-to-1 restent le chemin principal. Les groupes, canaux et appels existent encore cote code et serveur, mais ne sont pas presentes comme production-ready.

Les onglets principaux affichent une barre de contexte reseau avec le nom de la bulle active, son mode, le relais actif par libelle produit et l'etat du fallback officiel. Cette barre ne doit pas afficher l'URL brute du relais officiel en release.

## Actions non finalisees

Les actions non finalisees ne doivent pas etre exposees comme boutons actifs. Une surface V1 doit soit brancher un comportement reel, soit masquer/desactiver clairement l'action tant que le flux n'est pas testable.

## Regles visuelles

- Ne pas utiliser d'asset Telegram, de logo Telegram, de nom Telegram ou de bleu Telegram exact.
- Ne pas presenter l'app comme SMS ou telephone classique.
- Garder le test stable centre sur identite, contacts et messages texte 1-to-1.
- Garder les surfaces groupes/canaux/appels sobres en production tant que la strategie enveloppe par device, les appels WebRTC deux appareils et les validations release ne sont pas audites, sans libelle utilisateur de promesse future.
- Afficher le relais officiel sous forme de libelle produit et etat de confiance; ne pas afficher son URL brute en release.
