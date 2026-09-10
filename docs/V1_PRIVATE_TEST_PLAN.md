# Plan de test prive V1

Ce plan sert a valider une installation serveur locale et des APK installees sur plusieurs telephones. Il ne remplace pas les checks automatises et ne doit pas etre utilise pour declarer la branche prod-ready si une section reste non testee ou non implementee.

## Pre-requis

- Serveur local demarre avec PostgreSQL, Redis, MinIO et TURN si les appels sont testes.
- APK debug ou release installee sur au moins deux telephones physiques.
- URL du relais serveur configuree depuis l'app, puis validee par le test de serveur visible.
- Comptes distincts A et B, chacun avec un appareil enregistre et des prekeys publiees.
- Logs filtres sans JWT, secrets, query string sensible, ciphertext complet ou URL presignee.

## Main Bubble

1. Creer les comptes A et B.
2. Ajouter B comme contact de A.
3. Verifier que la Main Bubble active utilise le relais officiel.
4. Verifier que la barre de contexte des onglets principaux affiche la bulle active, le mode et le relais actif sans URL brute officielle.
5. Envoyer un message 1-to-1 A -> B.
6. Synchroniser B pendant qu'une autre bulle est active, puis verifier que la conversation est creee dans le `bubble_id` renvoye par le serveur.
7. Repondre B -> A depuis cette conversation et verifier que le meme contexte de bulle est conserve.
8. Redemarrer les deux apps, synchroniser, puis verifier l'historique local.
9. Envoyer une piece jointe chiffree et verifier upload complete + download.
10. Verifier les receipts `delivered` puis `read`.
11. Verifier le safety number, puis simuler un changement d'identite et confirmer l'alerte.

## Private Connected

1. Ajouter un relais prive valide.
2. Creer ou selectionner une bulle `PRIVATE_CONNECTED`.
3. Attacher le relais prive comme primaire.
4. Activer le fallback officiel.
5. Verifier dans l'UI le relais actif et le fallback.
6. Verifier que la barre de contexte des onglets principaux affiche `PRIVATE_CONNECTED`, le relais prive et l'etat du fallback.
7. Depuis l'ecran Bulles, connecter la session du relais prive avec le compte local de ce relais.
8. Verifier que `/v1/devices/register` sur le relais prive reutilise le `device_id` local et que le token officiel n'est pas envoye a ce relais.
9. Cliquer `Tester le relais actif` et verifier que le test passe par la bulle active.
10. Envoyer un contact/message via le relais prive.
11. Rendre le relais prive indisponible et verifier le comportement de fallback.
12. Revenir explicitement au relais officiel.

## Private Isolated

1. Creer une bulle `PRIVATE_ISOLATED`.
2. Attacher un relais prive avant tout test reseau.
3. Verifier que l'UI refuse ou avertit si aucun relais prive n'est attache.
4. Verifier que la barre de contexte des onglets principaux affiche `PRIVATE_ISOLATED`, relais prive requis ou relais prive actif, et fallback officiel interdit.
5. Cliquer `Tester le relais actif` et verifier que le test echoue tant qu'aucun relais prive n'est attache.
6. Connecter la session dediee du relais prive depuis l'ecran Bulles.
7. Verifier que `/v1/devices/register` sur le relais prive reutilise le `device_id` local et que le token officiel n'est pas envoye a ce relais.
8. Verifier qu'aucun contact ou conversation Main n'apparait.
9. Envoyer/recevoir un message et confirmer que le `bubble_id` reste celui de la bulle isolated.
10. Envoyer une piece jointe et verifier qu'aucun appel au relais officiel n'est effectue.
11. Verifier que l'upload et le download de piece jointe portent le `bubble_id` isolated.
12. Tester groupes, canaux et appels dans cette bulle uniquement.
13. Couper le relais prive et verifier qu'il n'y a aucun fallback officiel.

## Groupes

1. Creer un groupe dans la bulle active.
2. Ajouter un membre.
3. Afficher la liste des membres.
4. Envoyer et recevoir des messages de groupe.
5. Redemarrer les apps et resynchroniser.
6. Verifier l'idempotence avec le meme `client_message_id`.
7. Verifier que le serveur ne stocke aucun plaintext.
8. Verifier que le groupe reste filtre par `bubble_id`.
9. Tester le mauvais relais ou relais indisponible.
10. Verifier qu'une bulle locale non synchronisee affiche une erreur de synchronisation au lieu d'envoyer un `bubble_id` local.

## Canaux

1. Creer un canal dans la bulle active.
2. S'abonner ou ajouter l'audience prevue, puis verifier owner + abonne dans l'ecran canal.
3. Publier un post chiffre depuis owner/admin.
4. Synchroniser la reception et verifier le texte local apres dechiffrement.
5. Verifier que le canal et les posts restent filtres par `bubble_id`.
6. Verifier `INDEX_FORBIDDEN` et `PRIVATE_ONLY` : rien d'indexable.
7. Verifier `INDEX_OPT_IN` : indexation seulement apres opt-in explicite.
8. Verifier qu'aucun contenu prive n'est expose hors bulle.
9. Verifier qu'un post cree depuis une autre bulle est refuse par le serveur.

## Appels

1. Verifier l'etat reel des appels : UI, signaling, WebRTC Android, STUN/TURN.
2. Depuis A, saisir le User ID de B et lancer `Audio`.
3. Sur B, selectionner l'appel entrant, accepter, verifier audio bidirectionnel, mute/unmute, haut-parleur on/off, raccrocher.
4. Depuis A, saisir le User ID de B et lancer `Video`.
5. Sur B, accepter, verifier video locale et distante, camera on/off, mute/unmute, raccrocher.
6. Verifier les etats ringing, connecting, connected, rejected, ended, failed.
7. Verifier que l'UI normale ne montre pas de saisie SDP/ICE.
8. Verifier que offer, answer et ICE sont envoyes automatiquement via le relais actif et `GET /v1/calls/{call_id}/signaling`.
9. Tester refuser, raccrocher et timeout.
10. Tester perte reseau et reconnexion.
11. Verifier que le serveur applicatif ne voit aucun media et ne journalise pas SDP/ICE complet.
12. Tester appel audio Main Bubble.
13. Tester appel video Main Bubble.
14. Tester appel audio Private Isolated sans fallback officiel.
15. Tester appel video Private Isolated sans fallback officiel.
16. Verifier que les evenements d'appel portent le `bubble_id` de la bulle active.
17. Recuperer les credentials TURN depuis le relais actif sans journaliser credential/SDP/ICE.
18. Verifier NAT difficile avec TURN si possible.

Si WebRTC audio/video complet n'est pas testable sur deux appareils, verdict V1 : `NON PRET V1 PROD-READY`.

## QR

1. Afficher QR identite/contact.
2. Scanner/importer le QR contact depuis un autre telephone.
3. Afficher QR relais prive.
4. Scanner/importer le QR relais depuis l'ecran Bulles et verifier qu'il est attache a la bulle active, pas ajoute seulement comme preference globale.
5. Afficher QR invitation bulle.
6. Scanner/importer l'invitation et verifier la bulle, le mode et le relais hint.
7. Rejeter tout payload contenant `token`, `password`, `private_key`, `identity_private`, `download_secret` ou schema non autorise.
8. Rejeter une URL relais invalide.
9. Rejeter une URL relais contenant userinfo ou un secret en query string.

## Update APK

1. Installer par sideload.
2. Verifier qu'aucun bloc "aucune mise a jour disponible" n'apparait.
3. Publier un manifest de mise a jour valide.
4. Verifier affichage banner uniquement si update disponible.
5. Telecharger l'APK.
6. Verifier hash et signature si cle configuree.
7. Verifier permission installation APK inconnue.
8. Verifier qu'une installation Play Store ne propose pas un APK externe.

## Securite

1. Verifier aucun JWT en query string WebSocket.
2. Verifier aucun secret dans logs Android/serveur.
3. Verifier FCM uniquement `sync_hint`.
4. Verifier aucun plaintext message/groupe/canal/appel cote serveur.
5. Verifier `SignalCryptoEngine` comme moteur applicatif.
6. Verifier absence du moteur provisoire dans le chemin release.
7. Verifier version libsignal fixe.
8. Verifier rate limit, CORS production et trusted proxy.
9. Verifier migrations non destructives.

## Verdict manuel

- Tous les scenarios automatises et manuels passes : candidat pour audit humain.
- Un scenario groupe/canal/attachment/QR/update incomplet : `NON PRET V1 PROD-READY`.
- Appels sans WebRTC 1-to-1 reel sur deux appareils : `NON PRET V1 PROD-READY`.
- Token officiel envoye aveuglement a un relais prive : `NON PRET V1 PROD-READY`.
