ALTER TABLE attachment_references
    ADD CONSTRAINT attachment_references_kind_check
        CHECK (conversation_kind IN ('direct','group','channel')),
    ADD CONSTRAINT attachment_references_exact_parent_check
        CHECK (
            (conversation_kind='direct' AND direct_message_id IS NOT NULL AND group_message_id IS NULL AND channel_post_id IS NULL)
            OR (conversation_kind='group' AND direct_message_id IS NULL AND group_message_id IS NOT NULL AND channel_post_id IS NULL)
            OR (conversation_kind='channel' AND direct_message_id IS NULL AND group_message_id IS NULL AND channel_post_id IS NOT NULL)
        ),
    ADD CONSTRAINT attachment_references_blob_fk
        FOREIGN KEY (blob_id) REFERENCES attachments(blob_id) ON DELETE CASCADE;

CREATE UNIQUE INDEX attachment_references_direct_unique
    ON attachment_references(direct_message_id, blob_id)
    WHERE conversation_kind='direct';

CREATE UNIQUE INDEX attachment_references_group_unique
    ON attachment_references(group_message_id, blob_id)
    WHERE conversation_kind='group';

CREATE UNIQUE INDEX attachment_references_channel_unique
    ON attachment_references(channel_post_id, blob_id)
    WHERE conversation_kind='channel';

CREATE INDEX attachment_references_active_blob_idx
    ON attachment_references(blob_id, expires_at);
