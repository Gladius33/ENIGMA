# Vision Enigma

Enigma est concu comme une couche applicative universelle chiffree de bout en bout. La messagerie est la premiere application, pas la limite du systeme.

Concepts a preserver :

- enveloppe universelle `EnigmaEnvelope`;
- services applicatifs au-dessus du transport;
- streams generiques;
- relais officiels, communautaires et prives;
- identite independante;
- future encapsulation/remplacement de HTTP, FTP, API et mail;
- futur Enigma Proxy.

La V1 produit garde un serveur aveugle au contenu et des payloads opaques afin de ne pas bloquer ces evolutions.
