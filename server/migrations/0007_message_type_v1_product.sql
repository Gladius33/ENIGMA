ALTER TABLE message_queue
    DROP CONSTRAINT IF EXISTS message_queue_message_type_check;

ALTER TABLE message_queue
    DROP CONSTRAINT IF EXISTS message_queue_message_type_v1_product_check;

ALTER TABLE message_queue
    ADD CONSTRAINT message_queue_message_type_v1_product_check
    CHECK (message_type IN (
        'text',
        'opaque',
        'image',
        'video',
        'audio_message',
        'video_message',
        'file'
    ));
