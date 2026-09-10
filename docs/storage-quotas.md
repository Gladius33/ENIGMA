# Quotas et purge des pièces jointes

`presign-upload` réserve atomiquement les octets pending avant toute émission d'URL S3. Les limites plan, pending et journalières sont contrôlées; les codes stables sont `STORAGE_QUOTA_EXCEEDED`, `PENDING_STORAGE_QUOTA_EXCEEDED`, `ATTACHMENT_TOO_LARGE_FOR_PLAN` et `DAILY_UPLOAD_LIMIT_EXCEEDED`. `complete` transfère atomiquement pending vers verified; un mismatch libère la réservation. Le téléchargement existant n'est jamais bloqué après downgrade.

`maintenance::purge_attachments` traite des lots configurables: pending expirés, verified arrivés à TTL, et verified non référencés. La suppression objet est tentée avant la transition DB; un échec par objet est non fatal et retenté. Les compteurs sont décrémentés sous transaction. `recalculate_usage_for_identity` répare les compteurs depuis `attachments`. Les logs ne contiennent ni URL pré-signée, secret, contenu, JWT, ni token FCM.
