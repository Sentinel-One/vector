use metrics::{counter, gauge, Counter, Gauge};

#[derive(Clone)]
pub(super) struct Metrics {
    pub sessions_active_captured: Gauge,
    pub sessions_active_uncaptured: Gauge,
    pub sessions_closed: Counter,
    pub sessions_reset: Counter,
    pub sessions_upstream_connect_failed: Counter,
    pub sessions_refused: Counter,
    pub capture_bytes: Counter,
    pub capture_bytes_dropped_buffer_full: Counter,
    pub capture_bytes_dropped_rate_limited: Counter,
    pub capture_gaps: Counter,
    pub capture_stopped: Gauge,
    pub capture_budget_exhausted: Gauge,
    pub control_stream_connected: Gauge,
    pub datagrams_truncated: Counter,
    pub ignored_responses: Counter,
}

impl Metrics {
    pub(super) fn new() -> Self {
        Self {
            sessions_active_captured: gauge!("bsp_sessions_active", "captured" => "true"),
            sessions_active_uncaptured: gauge!("bsp_sessions_active", "captured" => "false"),
            sessions_closed: counter!("bsp_sessions_total", "outcome" => "closed"),
            sessions_reset: counter!("bsp_sessions_total", "outcome" => "reset"),
            sessions_upstream_connect_failed: counter!(
                "bsp_sessions_total",
                "outcome" => "upstream_connect_failed"
            ),
            sessions_refused: counter!("bsp_sessions_total", "outcome" => "refused"),
            capture_bytes: counter!("bsp_capture_bytes_total"),
            capture_bytes_dropped_buffer_full: counter!(
                "bsp_capture_bytes_dropped_total",
                "reason" => "buffer_full"
            ),
            capture_bytes_dropped_rate_limited: counter!(
                "bsp_capture_bytes_dropped_total",
                "reason" => "rate_limited"
            ),
            capture_gaps: counter!("bsp_capture_gaps_total"),
            capture_stopped: gauge!("bsp_capture_stopped"),
            capture_budget_exhausted: gauge!("bsp_capture_budget_exhausted"),
            control_stream_connected: gauge!("bsp_control_stream_connected"),
            datagrams_truncated: counter!("bsp_datagrams_truncated_total"),
            ignored_responses: counter!("bsp_ignored_responses_total"),
        }
    }

    pub(super) fn active(&self, captured: bool) -> ActiveSession {
        let gauge = if captured {
            self.sessions_active_captured.clone()
        } else {
            self.sessions_active_uncaptured.clone()
        };
        gauge.increment(1.0);
        ActiveSession(gauge)
    }
}

/// Decrements `bsp_sessions_active` when the session ends, whichever way it ends.
pub(super) struct ActiveSession(Gauge);

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.0.decrement(1.0);
    }
}
