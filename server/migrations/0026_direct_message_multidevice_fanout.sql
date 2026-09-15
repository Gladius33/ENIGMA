DROP INDEX IF EXISTS message_queue_sender_client_message_unique_idx;

CREATE UNIQUE INDEX message_queue_sender_recipient_client_message_unique_idx
    ON message_queue(sender_device_id, recipient_device_id, client_message_id);
