# Plan de test réel V1

1. Préparer `.env` :
   ```bash
   cp .env.example .env
   ```
2. Lancer le serveur :
   ```bash
   docker compose up -d --build
   ```
3. Vérifier santé/version :
   ```bash
   curl http://localhost:8080/health
   curl http://localhost:8080/version
   curl http://IP_THINKSTATION:8080/health
   ```
4. Générer l'APK :
   ```bash
   ./scripts/check-android.sh
   ```
5. Installer l'APK sur téléphone A et téléphone B :
   ```bash
   adb install -r android/app/build/outputs/apk/debug/app-debug.apk
   ```
6. Dans chaque app, configurer `http://IP_THINKSTATION:8080/` dans l'écran Serveur puis sauvegarder; le client réseau est reconstruit immédiatement.
7. Appuyer sur `Tester le serveur` et vérifier `enigma-e2ee-server 0.1.0`.
8. Créer identité A avec un handle unique, par exemple `alice_test`.
9. Créer identité B avec un handle unique, par exemple `bob_test`.
10. Sur A, ajouter `bob_test`, ouvrir la conversation et envoyer `Bonjour Bob`.
11. Sur B, ouvrir l'app, ajouter `alice_test` si besoin, vérifier réception puis répondre.
12. Fermer et rouvrir les deux apps, vérifier que sessions et messages locaux persistent.
13. Tester la suppression sur une identite de test : retour onboarding, purge locale, URL/langue conservees et handle reserve cote serveur.
14. Consulter les logs backend si erreur :
    ```bash
    docker compose logs -f backend
    ```

Succès V1 réel : deux téléphones sur le même LAN créent deux identités, ajoutent un contact, échangent des messages texte et gardent l'état local après relance.

Hors succès V1 stable : groupes, canaux, appels, médias, FCM réel et récupération complète d'anciens messages.
