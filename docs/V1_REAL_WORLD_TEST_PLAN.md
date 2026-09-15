# Plan de qualification réelle V1 — Android / Windows / Linux

Ce plan ferme le gate **REAL-LAB-001**. Il complète la CI : une exécution automatisée ne peut pas prouver le comportement réel des NAT, du CGNAT, de TURN, des changements de réseau ni des cycles veille/réveil.

## Verdict

La RC 1.0 reste bloquée tant que les scénarios marqués **obligatoires** ci-dessous ne sont pas passés sur du matériel réel.

## 1. Préparation

- Déployer le backend ENIGMA avec PostgreSQL, Redis, stockage S3-compatible et coturn.
- Exposer le relais en HTTPS/WSS avec un certificat valide.
- Vérifier `/health` et `/version` depuis Internet, pas seulement depuis le LAN du serveur.
- Utiliser une APK Android de qualification correspondant au même commit que les clients desktop.
- Utiliser les artefacts CI du même commit :
  - `ENIGMA-1.0.0-win-x64.zip`;
  - paquet `.deb` Linux Qt 6.
- Conserver les logs serveur, coturn et clients en veillant à l'absence de plaintext, JWT, secrets TURN ou clés privées.

Topologie minimale recommandée :

- compte A : Android A + Windows A + Linux A liés au même compte ;
- compte B : Android B sur un réseau distinct ;
- au moins un poste desktop doit être placé derrière un autre NAT que le téléphone B.

## 2. Appairage multi-device — obligatoire

1. Créer ou restaurer le compte A sur Android A.
2. Démarrer Windows A et créer une nouvelle session d'appairage.
3. Scanner/autoriser cette session depuis Android A.
4. Vérifier que Windows A devient opérationnel sans transmettre de clé privée au serveur.
5. Répéter avec Linux A.
6. Fermer puis relancer les trois clients et vérifier la restauration des sessions.
7. Vérifier qu'un QR expiré, réutilisé ou modifié est refusé.
8. Révoquer un desktop depuis le compte, puis vérifier qu'il ne peut plus recevoir ni envoyer comme device autorisé.

Succès : le registre de devices est cohérent sur les trois plateformes et aucune ancienne session révoquée n'est acceptée.

## 3. Interop E2EE et sender-sync — obligatoire

Effectuer chaque échange avec du texte distinct permettant d'identifier l'émetteur sans ambiguïté :

1. Android A → Android B.
2. Windows A → Android B.
3. Linux A → Android B.
4. Android B → compte A.
5. Vérifier que le message entrant de B apparaît sur Android A, Windows A et Linux A.
6. Vérifier le sender-sync : un message émis depuis l'un des devices A apparaît comme sortant sur les deux autres devices A.
7. Fermer un device A, envoyer plusieurs messages, puis le relancer et vérifier la reprise sans doublon.
8. Répéter après redémarrage complet d'un desktop.

Contrôles :

- le serveur ne contient jamais le plaintext ;
- la session libsignal continue après plusieurs messages ratchetés ;
- `client_message_id` ne génère pas de doublon utilisateur ;
- les statuts de livraison restent monotones.

## 4. P2P direct sur réseaux distincts — obligatoire

1. Placer les pairs sur deux accès Internet distincts.
2. Envoyer plusieurs messages avec les deux directions.
3. Vérifier dans la télémétrie autorisée que la route P2P est établie lorsque possible.
4. Répéter Windows ↔ Android et Linux ↔ Android.
5. Vérifier qu'aucun contenu en clair n'est exposé par la signalisation.

Le test sur un même LAN est utile mais ne suffit pas à fermer REAL-LAB-001.

## 5. CGNAT / TURN — obligatoire

1. Placer au moins un pair derrière un accès mobile/CGNAT.
2. Tester l'échange Android ↔ Windows puis Android ↔ Linux.
3. Créer une condition où la route directe n'est pas utilisable afin de forcer TURN.
4. Vérifier que la session reste E2EE et que coturn ne voit que du trafic chiffré.
5. Vérifier la récupération après expiration/renouvellement des credentials TURN.

Succès : un échec de route directe bascule vers TURN sans perte de confidentialité ni blocage durable.

## 6. Fallback relais temporaire — obligatoire

1. Rendre temporairement P2P/TURN indisponible tout en laissant le relais applicatif accessible.
2. Envoyer un message.
3. Vérifier que seul le ciphertext est stocké par le relais.
4. Restaurer le destinataire, vérifier la livraison puis l'ACK.
5. Vérifier la suppression du ciphertext après ACK.
6. Vérifier séparément l'expiration TTL d'un message non récupéré.

Succès : aucune conservation permanente et aucun plaintext côté serveur.

## 7. Changement Wi-Fi / mobile — obligatoire

Sur Android B pendant une conversation active :

1. Wi-Fi → données mobiles.
2. Données mobiles → Wi-Fi.
3. Changement de Wi-Fi vers un autre NAT.
4. Envoyer avant, pendant et après chaque transition.
5. Vérifier reconnexion de la signalisation et reprise de livraison.

Répéter un changement de réseau sur un laptop lorsque possible (Ethernet ↔ Wi-Fi ou Wi-Fi ↔ hotspot mobile).

## 8. Veille, suspension et reprise — obligatoire

Pour Windows A puis Linux A :

1. Laisser une session opérationnelle.
2. Mettre la machine en veille/suspend pendant au moins quelques minutes.
3. Envoyer depuis B pendant la suspension.
4. Réveiller la machine.
5. Vérifier la reconnexion, la récupération des messages et l'absence de doublon.
6. Envoyer immédiatement un message après reprise.

Sur Android, répéter avec écran éteint / application en arrière-plan selon les capacités du build testé.

## 9. Résilience processus — obligatoire

Pour chaque plateforme :

- tuer l'application pendant une livraison ;
- relancer et vérifier l'outbox/inbox durable ;
- couper brièvement Internet puis le restaurer ;
- redémarrer complètement le système ;
- vérifier que les secrets persistants restent protégés et que les sessions valides sont restaurées.

## 10. Sécurité et observabilité — obligatoire

Pendant l'ensemble de la campagne :

- rechercher le plaintext de test dans les logs backend, coturn et traces applicatives ;
- vérifier l'absence de JWT, access tokens, secrets TURN, clés privées et ciphertexts complets dans les logs ;
- vérifier qu'un device révoqué échoue de manière fail-closed ;
- vérifier qu'une identité distante changée déclenche la politique de confiance prévue ;
- conserver les versions exactes, SHA du commit, OS, modèles de téléphones et topologies réseau utilisées.

## 11. Critère de fermeture REAL-LAB-001

Le gate peut être déclaré **PASS** uniquement si :

- Android, Windows et Linux ont tous participé à des échanges E2EE réels ;
- le fanout multi-device et le sender-sync ont été observés sur matériel réel ;
- un scénario Internet avec NAT distinct a réussi ;
- un scénario CGNAT/TURN a réussi ;
- le fallback relais temporaire et l'ACK-delete/TTL ont été vérifiés ;
- les changements de réseau et veille/réveil ont été testés ;
- aucune fuite de plaintext ou de secret n'a été observée.

Tout échec non expliqué ou tout scénario obligatoire non exécuté maintient **REAL-LAB-001 = BLOCK RELEASE**.
