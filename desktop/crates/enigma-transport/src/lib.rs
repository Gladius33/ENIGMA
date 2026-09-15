#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    DirectP2p,
    TurnTransit,
    TemporaryRelay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryState {
    Attempt(Route),
    Delivered(Route),
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryPlanner {
    state: DeliveryState,
}

impl DeliveryPlanner {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: DeliveryState::Attempt(Route::DirectP2p),
        }
    }

    #[must_use]
    pub const fn state(self) -> DeliveryState {
        self.state
    }

    /// Advances after a failed attempt.
    ///
    /// If the peer is known to be offline, TURN is skipped because there is no
    /// live peer to transit to and the encrypted store-and-forward relay is the
    /// only availability path.
    pub fn failed_attempt(&mut self, peer_online: bool) {
        self.state = match self.state {
            DeliveryState::Attempt(Route::DirectP2p) if peer_online => {
                DeliveryState::Attempt(Route::TurnTransit)
            }
            DeliveryState::Attempt(Route::DirectP2p | Route::TurnTransit) => {
                DeliveryState::Attempt(Route::TemporaryRelay)
            }
            DeliveryState::Attempt(Route::TemporaryRelay) => DeliveryState::Failed,
            DeliveryState::Delivered(_) | DeliveryState::Failed => self.state,
        };
    }

    pub fn delivered(&mut self) {
        if let DeliveryState::Attempt(route) = self.state {
            self.state = DeliveryState::Delivered(route);
        }
    }
}

impl Default for DeliveryPlanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_peer_falls_back_direct_then_turn_then_relay() {
        let mut planner = DeliveryPlanner::new();
        assert_eq!(planner.state(), DeliveryState::Attempt(Route::DirectP2p));
        planner.failed_attempt(true);
        assert_eq!(planner.state(), DeliveryState::Attempt(Route::TurnTransit));
        planner.failed_attempt(true);
        assert_eq!(
            planner.state(),
            DeliveryState::Attempt(Route::TemporaryRelay)
        );
    }

    #[test]
    fn offline_peer_goes_direct_then_store_and_forward() {
        let mut planner = DeliveryPlanner::new();
        planner.failed_attempt(false);
        assert_eq!(
            planner.state(),
            DeliveryState::Attempt(Route::TemporaryRelay)
        );
    }
}

#[derive(Debug)]
pub enum PairingRendezvousError {
    InvalidEndpoint,
    InsecureEndpoint,
    ClientBuild,
    Transport,
    Rejected(u16),
    InvalidResponse,
}

impl std::fmt::Display for PairingRendezvousError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEndpoint => formatter.write_str("invalid pairing rendezvous endpoint"),
            Self::InsecureEndpoint => formatter.write_str("insecure pairing rendezvous endpoint"),
            Self::ClientBuild => formatter.write_str("unable to build pairing HTTP client"),
            Self::Transport => formatter.write_str("pairing rendezvous transport failure"),
            Self::Rejected(status) => {
                write!(formatter, "pairing rendezvous rejected with HTTP {status}")
            }
            Self::InvalidResponse => formatter.write_str("invalid pairing rendezvous response"),
        }
    }
}

impl std::error::Error for PairingRendezvousError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingClaimState {
    PendingAuthorization,
    Claimed,
    AlreadyClaimed,
    Expired,
    Missing,
}

#[derive(Debug, serde::Serialize)]
pub struct PairingCandidatePublish<'a> {
    pub pairing_session_id: &'a str,
    pub device_id: &'a str,
    pub display_name: &'a str,
    pub platform: &'a str,
    pub protocol_version: u16,
    pub min_supported_version: u16,
    pub capabilities: u64,
    pub expires_at_unix_ms: u64,
    pub pairing_public_key: &'a str,
    pub target_identity_key: &'a str,
    pub claim_secret_hash: &'a str,
    pub candidate_commitment: &'a str,
}

#[derive(Debug, serde::Serialize)]
struct PairingClaimRequest<'a> {
    pairing_session_id: &'a str,
    claim_secret: &'a str,
}

#[derive(Debug, serde::Deserialize)]
struct PairingClaimResponse {
    access_token: String,
}

#[derive(Debug, serde::Deserialize)]
struct ErrorResponse {
    error_code: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct PublicSignedPreKey<'a> {
    pub key_id: u32,
    pub public_key: &'a str,
    pub signature: &'a str,
}

#[derive(Debug, serde::Serialize)]
pub struct PublicOneTimePreKey<'a> {
    pub key_id: u32,
    pub public_key: &'a str,
}

#[derive(Debug, serde::Serialize)]
pub struct PublicKeyUpload<'a> {
    pub device_id: &'a str,
    pub identity_key: &'a str,
    pub registration_id: u32,
    pub protocol_device_id: u32,
    pub signed_prekey: PublicSignedPreKey<'a>,
    pub kyber_prekey: PublicSignedPreKey<'a>,
    pub one_time_prekeys: Vec<PublicOneTimePreKey<'a>>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
pub struct PendingRelayMessage {
    pub id: String,
    pub bubble_id: String,
    pub sender_device_id: String,
    pub sender_user_id: String,
    pub sender_public_id: String,
    pub recipient_device_id: String,
    pub client_message_id: String,
    pub message_type: String,
    pub ciphertext: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, serde::Deserialize)]
struct PendingRelayMessagesResponse {
    messages: Vec<PendingRelayMessage>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
pub struct SentRelayReceipt {
    pub message_id: String,
    pub bubble_id: String,
    pub client_message_id: String,
    pub recipient_device_id: String,
    pub status: String,
    pub delivered_at: String,
}

#[derive(Debug, serde::Deserialize)]
struct SentRelayReceiptsResponse {
    receipts: Vec<SentRelayReceipt>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
pub struct DeviceAuthorizationProof {
    pub authorizing_device_id: String,
    pub canonical_payload: String,
    pub authorizer_signature: String,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
pub struct RemoteSignedPreKey {
    pub key_id: i64,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
pub struct RemoteOneTimePreKey {
    pub key_id: i64,
    pub public_key: String,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
pub struct RemoteDeviceKeyBundle {
    pub device_id: String,
    pub identity_key: String,
    pub registration_id: Option<i32>,
    pub protocol_device_id: Option<i32>,
    pub signed_prekey: RemoteSignedPreKey,
    pub kyber_prekey: Option<RemoteSignedPreKey>,
    pub one_time_prekey_count: i64,
    pub prekey_low: bool,
    pub authorization: Option<DeviceAuthorizationProof>,
}

#[derive(Debug, serde::Deserialize)]
struct KeyDiscoveryResponse {
    user_id: String,
    devices: Vec<RemoteDeviceKeyBundle>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
pub struct ClaimedRemoteDeviceKeyBundle {
    pub device_id: String,
    pub identity_key: String,
    pub registration_id: Option<i32>,
    pub protocol_device_id: Option<i32>,
    pub signed_prekey: RemoteSignedPreKey,
    pub kyber_prekey: Option<RemoteSignedPreKey>,
    pub one_time_prekey: Option<RemoteOneTimePreKey>,
    pub one_time_prekey_count_after_claim: i64,
    pub prekey_low: bool,
    pub authorization: Option<DeviceAuthorizationProof>,
}

#[derive(Debug, serde::Deserialize)]
struct ClaimPreKeyResponse {
    user_id: String,
    device: ClaimedRemoteDeviceKeyBundle,
}

#[derive(Debug, serde::Deserialize)]
struct AccountDevicesResponse {
    user_id: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
pub struct ContactSummary {
    pub user_id: String,
    pub public_id: String,
    pub created_at: String,
}

#[derive(Debug, serde::Deserialize)]
struct ContactsResponse {
    contacts: Vec<ContactSummary>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
pub struct BubbleSummary {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub mode: String,
    pub visibility: String,
}

#[derive(Debug, serde::Deserialize)]
struct BubblesResponse {
    bubbles: Vec<BubbleSummary>,
}

#[derive(Debug, serde::Serialize)]
pub struct RelayMessageSend<'a> {
    pub bubble_id: &'a str,
    pub sender_device_id: &'a str,
    pub recipient_device_id: &'a str,
    pub client_message_id: &'a str,
    pub message_type: &'a str,
    pub ciphertext: &'a str,
    pub attachment_blob_ids: Vec<&'a str>,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
pub struct RelayMessageSendResponse {
    pub id: String,
    pub bubble_id: String,
    pub client_message_id: String,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq)]
pub struct TurnCredentials {
    pub username: String,
    pub credential: String,
    pub ttl_seconds: u64,
    pub expires_at: String,
    pub uris: Vec<String>,
    pub realm: String,
}

#[derive(Debug, serde::Serialize)]
struct ReceiptRequest<'a> {
    device_id: &'a str,
    status: &'a str,
}

pub struct PairingRendezvousClient {
    client: reqwest::blocking::Client,
    base_url: reqwest::Url,
}

impl PairingRendezvousClient {
    pub fn new(base_url: &str, allow_insecure_http: bool) -> Result<Self, PairingRendezvousError> {
        let mut parsed =
            reqwest::Url::parse(base_url).map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        match parsed.scheme() {
            "https" => {}
            "http" if allow_insecure_http => {}
            "http" => return Err(PairingRendezvousError::InsecureEndpoint),
            _ => return Err(PairingRendezvousError::InvalidEndpoint),
        }
        if parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(PairingRendezvousError::InvalidEndpoint);
        }
        if !parsed.path().ends_with('/') {
            let normalized = format!("{}/", parsed.path());
            parsed.set_path(&normalized);
        }

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| PairingRendezvousError::ClientBuild)?;

        Ok(Self {
            client,
            base_url: parsed,
        })
    }

    pub fn publish_candidate(
        &self,
        candidate: &PairingCandidatePublish<'_>,
    ) -> Result<(), PairingRendezvousError> {
        let endpoint = self
            .base_url
            .join("v1/devices/link/candidate")
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        let response = self
            .client
            .post(endpoint)
            .json(candidate)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(PairingRendezvousError::Rejected(response.status().as_u16()))
        }
    }

    pub fn upload_keys(
        &self,
        access_token: &[u8],
        bundle: &PublicKeyUpload<'_>,
    ) -> Result<(), PairingRendezvousError> {
        let endpoint = self
            .base_url
            .join("v1/keys/upload")
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;

        let header = bearer_header(access_token)?;

        let response = self
            .client
            .post(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .json(bundle)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(PairingRendezvousError::Rejected(response.status().as_u16()))
        }
    }

    pub fn account_user_id(
        &self,
        access_token: &[u8],
    ) -> Result<String, PairingRendezvousError> {
        let endpoint = self
            .base_url
            .join("v1/devices")
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        let header = bearer_header(access_token)?;
        let response = self
            .client
            .get(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if !response.status().is_success() {
            return Err(PairingRendezvousError::Rejected(response.status().as_u16()));
        }
        let body = response
            .json::<AccountDevicesResponse>()
            .map_err(|_| PairingRendezvousError::InvalidResponse)?;
        if !is_canonical_uuid(&body.user_id) {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        Ok(body.user_id)
    }

    pub fn contacts(
        &self,
        access_token: &[u8],
    ) -> Result<Vec<ContactSummary>, PairingRendezvousError> {
        let endpoint = self
            .base_url
            .join("v1/contacts")
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        let header = bearer_header(access_token)?;
        let response = self
            .client
            .get(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if !response.status().is_success() {
            return Err(PairingRendezvousError::Rejected(response.status().as_u16()));
        }
        let body = response
            .json::<ContactsResponse>()
            .map_err(|_| PairingRendezvousError::InvalidResponse)?;
        if body.contacts.len() > 4096
            || body.contacts.iter().any(|contact| {
                !is_canonical_uuid(&contact.user_id)
                    || contact.public_id.is_empty()
                    || contact.public_id.len() > 128
                    || contact.created_at.is_empty()
                    || contact.created_at.len() > 128
            })
        {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        Ok(body.contacts)
    }

    pub fn bubbles(
        &self,
        access_token: &[u8],
    ) -> Result<Vec<BubbleSummary>, PairingRendezvousError> {
        let endpoint = self
            .base_url
            .join("v1/bubbles")
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        let header = bearer_header(access_token)?;
        let response = self
            .client
            .get(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if !response.status().is_success() {
            return Err(PairingRendezvousError::Rejected(response.status().as_u16()));
        }
        let body = response
            .json::<BubblesResponse>()
            .map_err(|_| PairingRendezvousError::InvalidResponse)?;
        if body.bubbles.len() > 4096
            || body.bubbles.iter().any(|bubble| {
                !is_canonical_uuid(&bubble.id)
                    || bubble.slug.is_empty()
                    || bubble.slug.len() > 256
                    || bubble.name.is_empty()
                    || bubble.name.len() > 256
                    || bubble.mode.is_empty()
                    || bubble.mode.len() > 64
                    || bubble.visibility.is_empty()
                    || bubble.visibility.len() > 64
            })
        {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        Ok(body.bubbles)
    }

    pub fn discover_devices(
        &self,
        access_token: &[u8],
        user_id: &str,
    ) -> Result<Vec<RemoteDeviceKeyBundle>, PairingRendezvousError> {
        if !is_canonical_uuid(user_id) {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        let endpoint = self
            .base_url
            .join(&format!("v1/keys/{user_id}/devices"))
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        let header = bearer_header(access_token)?;
        let response = self
            .client
            .get(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if !response.status().is_success() {
            return Err(PairingRendezvousError::Rejected(response.status().as_u16()));
        }
        let body = response
            .json::<KeyDiscoveryResponse>()
            .map_err(|_| PairingRendezvousError::InvalidResponse)?;
        if body.user_id != user_id
            || body.devices.len() > 128
            || body.devices.iter().any(|device| {
                !valid_remote_device_metadata(
                    &device.device_id,
                    &device.identity_key,
                    device.registration_id,
                    device.protocol_device_id,
                    &device.signed_prekey,
                    device.kyber_prekey.as_ref(),
                )
            })
        {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        Ok(body.devices)
    }

    pub fn claim_prekey(
        &self,
        access_token: &[u8],
        user_id: &str,
        device_id: &str,
    ) -> Result<ClaimedRemoteDeviceKeyBundle, PairingRendezvousError> {
        if !is_canonical_uuid(user_id) || !is_canonical_uuid(device_id) {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        let endpoint = self
            .base_url
            .join(&format!(
                "v1/keys/{user_id}/devices/{device_id}/claim-prekey"
            ))
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        let header = bearer_header(access_token)?;
        let response = self
            .client
            .post(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if !response.status().is_success() {
            return Err(PairingRendezvousError::Rejected(response.status().as_u16()));
        }
        let body = response
            .json::<ClaimPreKeyResponse>()
            .map_err(|_| PairingRendezvousError::InvalidResponse)?;
        let device = body.device;
        if body.user_id != user_id
            || device.device_id != device_id
            || !valid_remote_device_metadata(
                &device.device_id,
                &device.identity_key,
                device.registration_id,
                device.protocol_device_id,
                &device.signed_prekey,
                device.kyber_prekey.as_ref(),
            )
            || device.one_time_prekey.as_ref().is_some_and(|prekey| {
                !valid_key_id(prekey.key_id) || !valid_key_material(&prekey.public_key)
            })
        {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        Ok(device)
    }

    pub fn send_message(
        &self,
        access_token: &[u8],
        message: &RelayMessageSend<'_>,
    ) -> Result<RelayMessageSendResponse, PairingRendezvousError> {
        if !is_canonical_uuid(message.bubble_id)
            || !is_canonical_uuid(message.sender_device_id)
            || !is_canonical_uuid(message.recipient_device_id)
            || !is_canonical_uuid(message.client_message_id)
            || message.sender_device_id == message.recipient_device_id
            || message.message_type.is_empty()
            || message.message_type.len() > 64
            || message.ciphertext.is_empty()
            || message.ciphertext.len() > 4 * 1024 * 1024
            || message.attachment_blob_ids.len() > 128
            || message
                .attachment_blob_ids
                .iter()
                .any(|blob_id| !is_canonical_uuid(blob_id))
        {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        let endpoint = self
            .base_url
            .join("v1/messages")
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        let header = bearer_header(access_token)?;
        let response = self
            .client
            .post(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .json(message)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if !response.status().is_success() {
            return Err(PairingRendezvousError::Rejected(response.status().as_u16()));
        }
        let body = response
            .json::<RelayMessageSendResponse>()
            .map_err(|_| PairingRendezvousError::InvalidResponse)?;
        if !is_canonical_uuid(&body.id)
            || body.bubble_id != message.bubble_id
            || body.client_message_id != message.client_message_id
            || body.created_at.is_empty()
            || body.created_at.len() > 128
            || body.expires_at.is_empty()
            || body.expires_at.len() > 128
        {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        Ok(body)
    }

    pub fn turn_credentials(
        &self,
        access_token: &[u8],
    ) -> Result<TurnCredentials, PairingRendezvousError> {
        let endpoint = self
            .base_url
            .join("v1/turn/credentials")
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        let header = bearer_header(access_token)?;
        let response = self
            .client
            .post(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if !response.status().is_success() {
            return Err(PairingRendezvousError::Rejected(response.status().as_u16()));
        }
        let body = response
            .json::<TurnCredentials>()
            .map_err(|_| PairingRendezvousError::InvalidResponse)?;
        if body.username.is_empty()
            || body.username.len() > 2048
            || body.credential.is_empty()
            || body.credential.len() > 4096
            || body.ttl_seconds == 0
            || body.ttl_seconds > 86_400
            || body.expires_at.is_empty()
            || body.expires_at.len() > 128
            || body.realm.is_empty()
            || body.realm.len() > 512
            || body.uris.is_empty()
            || body.uris.len() > 16
            || body.uris.iter().any(|uri| {
                uri.is_empty()
                    || uri.len() > 2048
                    || !(uri.starts_with("turn:") || uri.starts_with("turns:"))
            })
        {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        Ok(body)
    }

    pub fn pending_messages(
        &self,
        access_token: &[u8],
        device_id: &str,
    ) -> Result<Vec<PendingRelayMessage>, PairingRendezvousError> {
        if !is_canonical_uuid(device_id) {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        let mut endpoint = self
            .base_url
            .join("v1/messages/pending")
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        endpoint
            .query_pairs_mut()
            .append_pair("device_id", device_id);

        let header = bearer_header(access_token)?;
        let response = self
            .client
            .get(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if !response.status().is_success() {
            return Err(PairingRendezvousError::Rejected(response.status().as_u16()));
        }

        let body = response
            .json::<PendingRelayMessagesResponse>()
            .map_err(|_| PairingRendezvousError::InvalidResponse)?;
        if body.messages.len() > 4096
            || body.messages.iter().any(|message| {
                !is_canonical_uuid(&message.id)
                    || !is_canonical_uuid(&message.bubble_id)
                    || !is_canonical_uuid(&message.sender_device_id)
                    || !is_canonical_uuid(&message.sender_user_id)
                    || !is_canonical_uuid(&message.recipient_device_id)
                    || !is_canonical_uuid(&message.client_message_id)
                    || message.recipient_device_id != device_id
                    || message.ciphertext.is_empty()
                    || message.ciphertext.len() > 2 * 1024 * 1024
                    || message.message_type.is_empty()
                    || message.message_type.len() > 64
            })
        {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        Ok(body.messages)
    }

    pub fn sent_receipts(
        &self,
        access_token: &[u8],
        device_id: &str,
    ) -> Result<Vec<SentRelayReceipt>, PairingRendezvousError> {
        if !is_canonical_uuid(device_id) {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        let mut endpoint = self
            .base_url
            .join("v1/messages/receipts")
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        endpoint
            .query_pairs_mut()
            .append_pair("device_id", device_id);

        let header = bearer_header(access_token)?;
        let response = self
            .client
            .get(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if !response.status().is_success() {
            return Err(PairingRendezvousError::Rejected(response.status().as_u16()));
        }

        let body = response
            .json::<SentRelayReceiptsResponse>()
            .map_err(|_| PairingRendezvousError::InvalidResponse)?;
        if body.receipts.len() > 500
            || body.receipts.iter().any(|receipt| {
                !is_canonical_uuid(&receipt.message_id)
                    || !is_canonical_uuid(&receipt.bubble_id)
                    || !is_canonical_uuid(&receipt.client_message_id)
                    || !is_canonical_uuid(&receipt.recipient_device_id)
                    || !matches!(receipt.status.as_str(), "delivered" | "read")
                    || receipt.delivered_at.is_empty()
                    || receipt.delivered_at.len() > 128
            })
        {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        Ok(body.receipts)
    }

    pub fn acknowledge_message(
        &self,
        access_token: &[u8],
        message_id: &str,
        device_id: &str,
    ) -> Result<(), PairingRendezvousError> {
        if !is_canonical_uuid(message_id) || !is_canonical_uuid(device_id) {
            return Err(PairingRendezvousError::InvalidResponse);
        }
        let endpoint = self
            .base_url
            .join(&format!("v1/messages/{message_id}/receipt"))
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        let header = bearer_header(access_token)?;
        let response = self
            .client
            .post(endpoint)
            .header(reqwest::header::AUTHORIZATION, header)
            .json(&ReceiptRequest {
                device_id,
                status: "delivered",
            })
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(PairingRendezvousError::Rejected(response.status().as_u16()))
        }
    }

    pub fn claim(
        &self,
        pairing_session_id: &str,
        claim_secret: &str,
    ) -> Result<(PairingClaimState, Option<String>), PairingRendezvousError> {
        let endpoint = self
            .base_url
            .join("v1/devices/link/claim")
            .map_err(|_| PairingRendezvousError::InvalidEndpoint)?;
        let response = self
            .client
            .post(endpoint)
            .json(&PairingClaimRequest {
                pairing_session_id,
                claim_secret,
            })
            .send()
            .map_err(|_| PairingRendezvousError::Transport)?;

        if response.status().is_success() {
            let body = response
                .json::<PairingClaimResponse>()
                .map_err(|_| PairingRendezvousError::InvalidResponse)?;
            if body.access_token.is_empty() {
                return Err(PairingRendezvousError::InvalidResponse);
            }
            return Ok((PairingClaimState::Claimed, Some(body.access_token)));
        }

        let status = response.status();
        let error_code = response
            .json::<ErrorResponse>()
            .ok()
            .and_then(|body| body.error_code)
            .unwrap_or_default();

        let state = match (status.as_u16(), error_code.as_str()) {
            (400, "PAIRING_NOT_AUTHORIZED") => PairingClaimState::PendingAuthorization,
            (400, "PAIRING_RENDEZVOUS_EXPIRED") => PairingClaimState::Expired,
            (404, _) => PairingClaimState::Missing,
            (409, "PAIRING_CLAIM_ALREADY_USED") => PairingClaimState::AlreadyClaimed,
            _ => return Err(PairingRendezvousError::Rejected(status.as_u16())),
        };
        Ok((state, None))
    }
}

fn valid_key_id(value: i64) -> bool {
    (0..=i32::MAX as i64).contains(&value)
}

fn valid_key_material(value: &str) -> bool {
    !value.is_empty() && value.len() <= 16 * 1024
}

fn valid_remote_device_metadata(
    device_id: &str,
    identity_key: &str,
    registration_id: Option<i32>,
    protocol_device_id: Option<i32>,
    signed_prekey: &RemoteSignedPreKey,
    kyber_prekey: Option<&RemoteSignedPreKey>,
) -> bool {
    let Some(registration_id) = registration_id else {
        return false;
    };
    let Some(protocol_device_id) = protocol_device_id else {
        return false;
    };
    let Some(kyber_prekey) = kyber_prekey else {
        return false;
    };
    is_canonical_uuid(device_id)
        && valid_key_material(identity_key)
        && (1..=16_380).contains(&registration_id)
        && (1..=127).contains(&protocol_device_id)
        && valid_key_id(signed_prekey.key_id)
        && valid_key_material(&signed_prekey.public_key)
        && valid_key_material(&signed_prekey.signature)
        && valid_key_id(kyber_prekey.key_id)
        && valid_key_material(&kyber_prekey.public_key)
        && valid_key_material(&kyber_prekey.signature)
}

fn bearer_header(
    access_token: &[u8],
) -> Result<reqwest::header::HeaderValue, PairingRendezvousError> {
    if access_token.is_empty() || access_token.len() > 16 * 1024 {
        return Err(PairingRendezvousError::InvalidResponse);
    }
    let mut authorization = Vec::with_capacity(7 + access_token.len());
    authorization.extend_from_slice(b"Bearer ");
    authorization.extend_from_slice(access_token);
    let header = reqwest::header::HeaderValue::from_bytes(&authorization)
        .map_err(|_| PairingRendezvousError::InvalidResponse)?;
    authorization.fill(0);
    Ok(header)
}

fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

#[cfg(test)]
mod rendezvous_tests {
    use super::*;

    #[test]
    fn rendezvous_rejects_plain_http_by_default() {
        assert!(matches!(
            PairingRendezvousClient::new("http://127.0.0.1:8080", false),
            Err(PairingRendezvousError::InsecureEndpoint)
        ));
    }

    #[test]
    fn rendezvous_accepts_https_and_explicit_lab_http() {
        assert!(PairingRendezvousClient::new("https://relay.example", false).is_ok());
        assert!(PairingRendezvousClient::new("http://127.0.0.1:8080", true).is_ok());
    }

    #[test]
    fn rendezvous_rejects_credential_bearing_endpoint() {
        assert!(matches!(
            PairingRendezvousClient::new("https://user:password@relay.example", false),
            Err(PairingRendezvousError::InvalidEndpoint)
        ));
    }
}
