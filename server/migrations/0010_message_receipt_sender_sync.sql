ALTER TABLE message_receipts
    ADD COLUMN IF NOT EXISTS sender_device_id UUID REFERENCES devices(id) ON DELETE SET NULL;

ALTER TABLE message_receipts
    ADD COLUMN IF NOT EXISTS client_message_id UUID;

ALTER TABLE message_receipts
    ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ;

UPDATE message_receipts
SET delivered_at = COALESCE(delivered_at, received_at)
WHERE delivered_at IS NULL;

CREATE INDEX IF NOT EXISTS message_receipts_sender_device_delivered_idx
    ON message_receipts(sender_device_id, delivered_at DESC)
    WHERE sender_device_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS message_receipts_sender_client_message_idx
    ON message_receipts(sender_device_id, client_message_id)
    WHERE sender_device_id IS NOT NULL AND client_message_id IS NOT NULL;
