use uuid::Uuid;

/// Stable public identifier of the official Enigma relay.
///
/// This UUID is part of the server, Android seed data, QR payloads and tests.
/// Do not replace it with an app-local string alias.
pub const OFFICIAL_RELAY_ID: Uuid = Uuid::from_u128(1);
pub const OFFICIAL_RELAY_ID_STR: &str = "00000000-0000-0000-0000-000000000001";
pub const OFFICIAL_RELAY_NAME: &str = "Relais officiel Enigma";
pub const OFFICIAL_RELAY_URL: &str = "https://relay.example.invalid/";
