# Device linking protocol — ENIGMA 1.0

## Objectif

Un serveur ENIGMA ne doit pas pouvoir ajouter silencieusement un device malveillant à un compte. En 1.0, Android est l'autorité UX d'appairage d'un desktop déjà demandé par l'utilisateur.

Chaque device possède sa propre identité Signal, ses propres prekeys, ses propres secrets d'authentification et sa propre clé de coffre. Une clé privée Signal n'est jamais copiée entre devices.

## 1. Création locale desktop

Le nouveau desktop génère localement son identité Signal, signed prekey/prekeys, une clé éphémère d'appairage, un `PairingSessionId` aléatoire et un identifiant de device candidat.

Aucun secret privé n'est envoyé au serveur ni placé dans le QR.

## 2. QR court-vivant

Le QR contient uniquement des éléments publics et bornés : version du protocole, version minimale, `pairing_session_id`, expiration stricte, matériau public d'appairage et capabilities.

Il ne contient jamais token de compte, clé privée Signal, clé du coffre local, clé de pièce jointe, mot de passe ou secret de récupération.

Une session expirée échoue fermée.

## 3. Approbation Android

Android scanne le QR, récupère les éléments publics du desktop et exige une approbation utilisateur explicite.

L'appareil autorisé construit une représentation canonique versionnée de `DeviceAuthorizationPayload` comprenant au minimum : compte, nouveau device, device autorisant, identité Signal publique du nouveau device, session d'appairage, date d'émission et version/capabilities.

Le payload est signé au moyen d'une primitive d'identité établie via libsignal. ENIGMA n'invente aucun algorithme de signature.

`DeviceAuthorizationCertificate = payload canonique + signature de l'authorizer`.

### Transcript canonique v1

La signature porte exactement sur les octets UTF-8 suivants, avec des noms de champs fixes, des UUID canoniques minuscules, l'ordre ci-dessous et un `\n` final. Aucun champ supplémentaire n'est toléré :

```text
ENIGMA_DEVICE_LINK_V1
account_id=<uuid>
new_device_id=<uuid>
authorizing_device_id=<uuid>
pairing_session_id=<uuid>
platform=<windows|linux>
protocol_version=1
min_supported_version=1
capabilities=<u64 decimal>
issued_at_unix_ms=<u64 decimal>
target_identity_key=<base64 public Signal identity>
authorizer_identity_key=<base64 public Signal identity>
```

Le bit `MULTI_DEVICE` (`1 << 2`) est obligatoire dans `capabilities`. Toute différence de casse, ordre, séparateur, identifiant, identité publique ou signature fait échouer la vérification.

Android construit ce transcript avec son `account_id`, son propre `authorizing_device_id` et sa véritable identité publique Signal, puis appelle la primitive de signature d'identité de libsignal. Le serveur persiste le transcript et la signature sans les réécrire. Le desktop les revalide contre les paramètres de la session d'appairage et l'identité connue de l'authorizer.

### QR de bootstrap v1

Le QR `enigma.pair_device` contient uniquement :

- `version=1` ;
- `protocol_version=1` et `min_supported_version=1` ;
- `capabilities`, incluant `MULTI_DEVICE` ;
- `pairing_session_id` aléatoire ;
- `expires_at_unix_ms` court-vivant ;
- `pairing_public_key` publique et bornée.

Le QR ne contient ni token device/account, ni identité privée Signal, ni secret de coffre. L'identité Signal publique candidate du desktop et les autres paramètres d'admission sont transmis dans le canal d'appairage authentifié établi à partir de ce bootstrap.

## 4. Admission

Le serveur n'accepte l'admission que dans une session courte liée à un compte/device authentifié et non révoqué. Le certificat est conservé comme preuve publique du registre de devices.

La confiance cliente ne repose pas uniquement sur la réponse du serveur : les clients vérifient la chaîne d'autorisation et la cohérence avec les identités publiques déjà connues. Un device sans preuve valide n'entre pas dans le fanout E2EE.

Après admission, le desktop reçoit uniquement son propre token device-bound et publie ses propres prekeys.

## 5. Historique initial

L'historique vient d'un device autorisé existant, jamais d'une archive plaintext serveur.

Ordre de transport : P2P direct, TURN si les deux devices sont présents mais non directement joignables, puis blob temporaire chiffré si nécessaire.

Le transfert est lié à l'appairage, TTL obligatoire, authentifié, anti-replay et single-use. Import réussi => ACK => suppression.

## Révocation

La révocation retire le device du registre actif, invalide ses sessions serveur et l'exclut immédiatement de tout nouveau fanout. Un évènement/certificat de révocation versionné doit être vérifiable par les autres devices.

La révocation ne peut pas effacer ce qu'un device avait déjà déchiffré.

## Fail-closed

Refus si version incompatible, session expirée, signature absente/invalide, authorizer révoqué, identité incohérente, replay, payload non canonique ou paramètres hors bornes.
