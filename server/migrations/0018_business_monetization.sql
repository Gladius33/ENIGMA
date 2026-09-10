CREATE TABLE IF NOT EXISTS plans (
 code TEXT PRIMARY KEY, name_fr TEXT NOT NULL, name_en TEXT NOT NULL,
 monthly_price_cents INTEGER NOT NULL CHECK(monthly_price_cents >= 0), yearly_price_cents INTEGER NOT NULL CHECK(yearly_price_cents >= 0),
 storage_quota_bytes BIGINT NOT NULL CHECK(storage_quota_bytes > 0), pending_storage_quota_bytes BIGINT NOT NULL CHECK(pending_storage_quota_bytes > 0),
 max_attachment_bytes BIGINT NOT NULL CHECK(max_attachment_bytes > 0), attachment_retention_seconds BIGINT NOT NULL,
 message_retention_seconds BIGINT NOT NULL, max_devices INTEGER NOT NULL, max_groups INTEGER, max_group_members INTEGER,
 max_channels INTEGER, max_channel_subscribers INTEGER, turn_monthly_seconds INTEGER, is_public BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO plans(code,name_fr,name_en,monthly_price_cents,yearly_price_cents,storage_quota_bytes,pending_storage_quota_bytes,max_attachment_bytes,attachment_retention_seconds,message_retention_seconds,max_devices)
VALUES
 ('free','Gratuit','Free',0,0,262144000,104857600,26214400,604800,604800,1),
 ('supporter','Supporter','Supporter',299,2900,5368709120,1073741824,104857600,2592000,604800,2),
 ('plus','Plus','Plus',599,5900,26843545600,5368709120,536870912,7776000,604800,5),
 ('pro','Pro','Pro',1199,11900,107374182400,10737418240,2147483648,15552000,604800,10)
ON CONFLICT(code) DO UPDATE SET name_fr=EXCLUDED.name_fr,name_en=EXCLUDED.name_en,monthly_price_cents=EXCLUDED.monthly_price_cents,yearly_price_cents=EXCLUDED.yearly_price_cents,storage_quota_bytes=EXCLUDED.storage_quota_bytes,pending_storage_quota_bytes=EXCLUDED.pending_storage_quota_bytes,max_attachment_bytes=EXCLUDED.max_attachment_bytes,attachment_retention_seconds=EXCLUDED.attachment_retention_seconds,max_devices=EXCLUDED.max_devices,updated_at=now();
CREATE TABLE IF NOT EXISTS subscriptions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), identity_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 plan_code TEXT NOT NULL REFERENCES plans(code), provider TEXT NOT NULL DEFAULT 'internal', provider_customer_id TEXT,
 provider_subscription_id TEXT, status TEXT NOT NULL DEFAULT 'active', current_period_end TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS subscriptions_one_active_identity ON subscriptions(identity_id) WHERE status='active';
CREATE INDEX IF NOT EXISTS subscriptions_identity_status ON subscriptions(identity_id,status,current_period_end);
CREATE TABLE IF NOT EXISTS identity_usage_counters (
 identity_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, storage_verified_bytes BIGINT NOT NULL DEFAULT 0 CHECK(storage_verified_bytes>=0),
 storage_pending_bytes BIGINT NOT NULL DEFAULT 0 CHECK(storage_pending_bytes>=0), uploads_today_bytes BIGINT NOT NULL DEFAULT 0 CHECK(uploads_today_bytes>=0),
 uploads_today_count INTEGER NOT NULL DEFAULT 0 CHECK(uploads_today_count>=0), uploads_window_date DATE NOT NULL DEFAULT CURRENT_DATE,
 turn_seconds_month INTEGER NOT NULL DEFAULT 0, turn_window_month TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS attachment_references (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), blob_id UUID NOT NULL, owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 bubble_id UUID NOT NULL, conversation_kind TEXT NOT NULL, direct_message_id UUID, group_message_id UUID, channel_post_id UUID,
 recipient_device_id UUID, delivered_at TIMESTAMPTZ, downloaded_at TIMESTAMPTZ, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS attachment_references_blob ON attachment_references(blob_id);
CREATE TABLE IF NOT EXISTS official_announcements (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), kind TEXT NOT NULL, title_fr TEXT NOT NULL, body_fr TEXT NOT NULL, title_en TEXT, body_en TEXT,
 cta_label_fr TEXT, cta_label_en TEXT, cta_url_fr TEXT, cta_url_en TEXT, audience TEXT NOT NULL DEFAULT 'all' CHECK(audience IN('all','free','premium')),
 priority TEXT NOT NULL DEFAULT 'normal', starts_at TIMESTAMPTZ, expires_at TIMESTAMPTZ, status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN('draft','published')),
 created_by TEXT NOT NULL DEFAULT 'system', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS official_announcement_deliveries (
 announcement_id UUID NOT NULL REFERENCES official_announcements(id) ON DELETE CASCADE, identity_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 delivered_at TIMESTAMPTZ, opened_at TIMESTAMPTZ, dismissed_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY(announcement_id,identity_id)
);
