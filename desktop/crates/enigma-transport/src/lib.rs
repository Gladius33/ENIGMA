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
