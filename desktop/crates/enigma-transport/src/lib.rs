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
            Self::Rejected(status) => write!(formatter, "pairing rendezvous rejected with HTTP {status}"),
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

pub struct PairingRendezvousClient {
    client: reqwest::blocking::Client,
    base_url: reqwest::Url,
}

impl PairingRendezvousClient {
    pub fn new(
        base_url: &str,
        allow_insecure_http: bool,
    ) -> Result<Self, PairingRendezvousError> {
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
