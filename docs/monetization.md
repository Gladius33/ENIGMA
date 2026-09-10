# Monétisation du relais officiel

Cette couche est active uniquement avec `OFFICIAL_RELAY_MODE=true`; un relais privé reste souverain et peut désactiver support et annonces. Sans abonnement actif, le plan est `free`. Les offres sont Free (250 Mio, fichier 25 Mio, 7 jours, 1 appareil), Supporter (2,99 €/mois ou 29 €/an; 5 Gio, 100 Mio, 30 jours, 2 appareils), Plus (5,99 €/mois ou 59 €/an; 25 Gio, 512 Mio, 90 jours, 5 appareils) et Pro (11,99 €/mois ou 119 €/an; 100 Gio, 2 Gio, 180 jours, 10 appareils).

Le gratuit conserve la messagerie texte E2EE. Ses limites financent le stockage et réduisent l'abus. Aucun paiement n'est traité dans l'app: les boutons don/premium ouvrent les URL externes fournies par `/v1/support/config`. `subscriptions` prépare les futurs fournisseurs Stripe/Play sans stocker de donnée bancaire.
