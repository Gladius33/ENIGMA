ALTER TABLE attachment_references
    ADD COLUMN group_id UUID,
    ADD COLUMN channel_id UUID;

UPDATE attachment_references r
SET group_id = gm.group_id
FROM group_message_queue gm
WHERE r.conversation_kind = 'group'
  AND r.group_message_id = gm.id
  AND r.group_id IS NULL;

UPDATE attachment_references r
SET channel_id = cp.channel_id
FROM channel_posts_queue cp
WHERE r.conversation_kind = 'channel'
  AND r.channel_post_id = cp.id
  AND r.channel_id IS NULL;

-- Enforce complete ACL scope metadata for every new reference. The constraint is
-- NOT VALID so a legacy reference whose parent queue row was already removed
-- cannot block deployment; such an incomplete legacy reference is denied by the
-- runtime ACL until it is recreated with complete scope metadata.
ALTER TABLE attachment_references
    ADD CONSTRAINT attachment_references_acl_scope_check
    CHECK (
        (conversation_kind = 'direct'
            AND recipient_device_id IS NOT NULL
            AND group_id IS NULL
            AND channel_id IS NULL)
        OR (conversation_kind = 'group'
            AND recipient_device_id IS NULL
            AND group_id IS NOT NULL
            AND channel_id IS NULL)
        OR (conversation_kind = 'channel'
            AND recipient_device_id IS NULL
            AND group_id IS NULL
            AND channel_id IS NOT NULL)
    ) NOT VALID;

CREATE INDEX attachment_references_direct_acl_idx
    ON attachment_references(blob_id, recipient_device_id)
    WHERE conversation_kind = 'direct';

CREATE INDEX attachment_references_group_acl_idx
    ON attachment_references(blob_id, group_id)
    WHERE conversation_kind = 'group';

CREATE INDEX attachment_references_channel_acl_idx
    ON attachment_references(blob_id, channel_id)
    WHERE conversation_kind = 'channel';
