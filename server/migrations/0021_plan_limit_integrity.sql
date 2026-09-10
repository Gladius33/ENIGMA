ALTER TABLE plans
    ADD CONSTRAINT plans_max_devices_positive
        CHECK (max_devices > 0),
    ADD CONSTRAINT plans_max_groups_nonnegative
        CHECK (max_groups IS NULL OR max_groups >= 0),
    ADD CONSTRAINT plans_max_group_members_nonnegative
        CHECK (max_group_members IS NULL OR max_group_members >= 0),
    ADD CONSTRAINT plans_max_channels_nonnegative
        CHECK (max_channels IS NULL OR max_channels >= 0),
    ADD CONSTRAINT plans_max_channel_subscribers_nonnegative
        CHECK (max_channel_subscribers IS NULL OR max_channel_subscribers >= 0),
    ADD CONSTRAINT plans_turn_monthly_seconds_nonnegative
        CHECK (turn_monthly_seconds IS NULL OR turn_monthly_seconds >= 0);
