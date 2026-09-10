# Annonces officielles

Les annonces sont une surface serveur distincte des bulles et ne sont pas des messages E2EE utilisateur. Elles sont absentes (`404`) sur un relais privé. L'admin utilise un secret d'au moins 32 octets en production officielle; il n'est jamais journalisé. Audience: `all`, `free`, `premium`.

Flux: créer un brouillon, publier, puis broadcast. Broadcast matérialise les deliveries et FCM reçoit exclusivement `{type: sync_hint}`: jamais titre, corps ou CTA. Le client authentifié récupère le texte, puis marque lu ou masqué. Android affiche clairement « Enigma Officiel » avec badge et ouvre le CTA dans le navigateur externe.
