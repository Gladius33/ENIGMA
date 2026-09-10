# Medias et fichiers

Les medias et fichiers ne sont pas comptes comme production-ready dans la V1 actuelle. Le socle serveur et repository Android existe pour des blobs chiffres, mais l'UX stable fichier/image/video/vocal est reportee tant que selection, previews, ouverture, nettoyage et tests appareil ne sont pas complets.

## Modele

- Le client chiffre le blob original avant upload S3/MinIO.
- Le client peut generer une miniature locale, puis chiffre cette miniature comme un blob separe.
- Le serveur ne recoit jamais de fichier clair, miniature claire, cle ni nonce.
- Les URLs pre-signees expirent vite et ne doivent jamais etre loggees.

## Etat Android

L'implementation actuelle couvre l'upload/download chiffre generique via repositories. Apres upload S3, Android appelle `complete` et le serveur refuse le download tant que l'objet n'est pas verifie. Les modules `media` doivent encore isoler selection SAF, thumbnails, previews locales, ouverture securisee et nettoyage des fichiers temporaires clairs.

## Limites

Aucun transcodage serveur en V1. Toute preview claire doit rester memoire/temporaire et nettoyee apres usage. Tant que ce parcours n'est pas teste sur appareil reel, les medias restent hors V1 production.
