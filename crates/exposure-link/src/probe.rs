use std::collections::VecDeque;
use std::time::{Duration, Instant};

use exposure_core::config::ProbeConfig;
use exposure_core::routing::LinkHealthState;

const PROBE_LOSS_MAX_AGE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct EndpointProbeTracker {
    pub state: LinkHealthState,
    pub last_rtt_ms: Option<u64>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    window: VecDeque<(Instant, bool)>,
}

impl Default for EndpointProbeTracker {
    fn default() -> Self {
        Self {
            state: LinkHealthState::Up,
            last_rtt_ms: None,
            consecutive_failures: 0,
            consecutive_successes: 0,
            window: VecDeque::with_capacity(20),
        }
    }
}

impl EndpointProbeTracker {
    pub fn record_success(&mut self, rtt_ms: u64, cfg: &ProbeConfig) {
        self.last_rtt_ms = Some(rtt_ms);
        self.consecutive_failures = 0;
        self.consecutive_successes += 1;
        self.push_window(true);

        let loss = self.loss_rate();
        if self.state == LinkHealthState::Down {
            if self.consecutive_successes >= cfg.recover_successes {
                self.state = if rtt_ms > cfg.degraded_rtt_ms || loss > cfg.degraded_loss_rate {
                    LinkHealthState::Degraded
                } else {
                    LinkHealthState::Up
                };
            }
        } else if rtt_ms > cfg.degraded_rtt_ms || loss > cfg.degraded_loss_rate {
            self.state = LinkHealthState::Degraded;
        } else {
            self.state = LinkHealthState::Up;
        }
    }

    pub fn record_failure(&mut self, cfg: &ProbeConfig) {
        self.consecutive_successes = 0;
        self.consecutive_failures += 1;
        self.push_window(false);

        if self.consecutive_failures >= cfg.down_failures {
            self.state = LinkHealthState::Down;
        } else if self.state == LinkHealthState::Up {
            self.state = LinkHealthState::Degraded;
        }
    }

    pub fn loss_rate(&self) -> f64 {
        let now = Instant::now();
        let mut total = 0usize;
        let mut fails = 0usize;
        for &(ts, ok) in &self.window {
            if now.duration_since(ts) <= PROBE_LOSS_MAX_AGE {
                total += 1;
                if !ok {
                    fails += 1;
                }
            }
        }
        if total == 0 {
            return 0.0;
        }
        fails as f64 / total as f64
    }

    fn push_window(&mut self, ok: bool) {
        let now = Instant::now();
        while let Some(&(ts, _)) = self.window.front() {
            if self.window.len() >= 60 || now.duration_since(ts) > PROBE_LOSS_MAX_AGE {
                self.window.pop_front();
            } else {
                break;
            }
        }
        self.window.push_back((now, ok));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_state_transitions() {
        let cfg = ProbeConfig {
            degraded_rtt_ms: 100,
            down_failures: 2,
            recover_successes: 2,
            ..Default::default()
        };
        let mut t = EndpointProbeTracker::default();
        t.record_success(20, &cfg);
        assert_eq!(t.state, LinkHealthState::Up);

        t.record_success(200, &cfg);
        assert_eq!(t.state, LinkHealthState::Degraded);

        t.record_failure(&cfg);
        t.record_failure(&cfg);
        assert_eq!(t.state, LinkHealthState::Down);

        t.record_success(15, &cfg);
        assert_eq!(t.state, LinkHealthState::Down); // needs 2 successes
        t.record_success(15, &cfg);
        assert_ne!(t.state, LinkHealthState::Down);
    }
}
