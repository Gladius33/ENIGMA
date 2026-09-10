# Bubbles

Slogan : "Creez votre bulle".

Une Bubble est un espace Enigma gouverne par des regles, relais et politiques d'indexation propres.

- Main Bubble : espace officiel principal.
- Private Bubble : espace prive auto-heberge ou infogere.
- Community Bubble : espace communautaire avec relais et moderation propres.

La V1 contient maintenant un socle fonctionnel experimental :

- sync Android des bulles, membres et relais via `/v1/bubbles`;
- creation de bulles privees cote serveur depuis Android;
- attachement d'un relais a une bulle avec option de fallback officiel;
- routage Retrofit/WebSocket par bulle active via `RelayScopedApiProvider`;
- `bubble_id` local sur les conversations pour filtrer Messages/Contacts.

Modes reseau :

- Main Bubble : relais officiel uniquement.
- Private Connected : relais prive primaire, fallback officiel optionnel.
- Private Isolated : relais prive obligatoire, aucun fallback officiel, contacts/conversations globaux masques.

Les invitations serveur, la federation, les signatures finales de descriptors et l'audit produit complet restent non finalises.
