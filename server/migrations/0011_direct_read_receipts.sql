ALTER TABLE message_receipts
    DROP CONSTRAINT IF EXISTS message_receipts_status_check;

ALTER TABLE message_receipts
    ADD CONSTRAINT message_receipts_status_check
    CHECK (status IN ('delivered', 'read'));
