ALTER TABLE attachment_references
    ADD COLUMN client_message_id UUID;

ALTER TABLE attachment_references
    DROP CONSTRAINT attachment_references_exact_parent_check;

ALTER TABLE attachment_references
    ADD CONSTRAINT attachment_references_exact_parent_check
        CHECK (
            (
                conversation_kind='direct'
                AND group_message_id IS NULL
                AND channel_post_id IS NULL
                AND (direct_message_id IS NOT NULL OR client_message_id IS NOT NULL)
            )
            OR (
                conversation_kind='group'
                AND direct_message_id IS NULL
                AND client_message_id IS NULL
                AND group_message_id IS NOT NULL
                AND channel_post_id IS NULL
            )
            OR (
                conversation_kind='channel'
                AND direct_message_id IS NULL
                AND client_message_id IS NULL
                AND group_message_id IS NULL
                AND channel_post_id IS NOT NULL
            )
        );

CREATE UNIQUE INDEX attachment_references_direct_client_unique
    ON attachment_references(owner_id, bubble_id, recipient_device_id, client_message_id, blob_id)
    WHERE conversation_kind='direct' AND client_message_id IS NOT NULL;
