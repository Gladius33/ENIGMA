CREATE UNIQUE INDEX message_receipts_message_device_unique_idx
    ON message_receipts(message_id, recipient_device_id);

