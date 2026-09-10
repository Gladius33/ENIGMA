ALTER TABLE sessions
    ADD COLUMN device_id UUID NULL REFERENCES devices(id) ON DELETE SET NULL;

CREATE INDEX sessions_device_id_idx ON sessions(device_id);

ALTER TABLE message_queue
    ADD COLUMN client_message_id UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN message_type TEXT NOT NULL DEFAULT 'text' CHECK (message_type IN ('text'));

CREATE UNIQUE INDEX message_queue_sender_client_message_unique_idx
    ON message_queue(sender_device_id, client_message_id);
