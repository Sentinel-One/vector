use super::{EstimatedJsonEncodedSizeOf, LogEvent};

/// Encapsulates the inductive events merging algorithm.
///
/// Tracks the size of everything merged so far so callers can apply circuit-breaker logic:
/// a merge that is never terminated returns nothing to the pipeline, so bounded-channel
/// backpressure cannot engage and the accumulator is otherwise unbounded.
#[derive(Debug)]
pub struct LogEventMergeState {
    /// Intermediate event we merge into.
    intermediate_merged_event: LogEvent,
    /// Running total of the sizes of every event folded in so far.
    merged_bytes: usize,
}

impl LogEventMergeState {
    /// Initialize the algorithm with a first (partial) event.
    pub fn new(first_partial_event: LogEvent) -> Self {
        let merged_bytes = first_partial_event.estimated_json_encoded_size_of().get();
        Self {
            intermediate_merged_event: first_partial_event,
            merged_bytes,
        }
    }

    /// Merge the incoming (partial) event in.
    pub fn merge_in_next_event(&mut self, incoming: LogEvent, fields: &[impl AsRef<str>]) {
        // Measured on the incoming event rather than the accumulator, so this stays O(incoming)
        // and adds no term to the merge's existing cost.
        self.merged_bytes = self
            .merged_bytes
            .saturating_add(incoming.estimated_json_encoded_size_of().get());
        self.intermediate_merged_event.merge(incoming, fields);
    }

    /// The total size of every event folded in so far.
    pub const fn merged_bytes(&self) -> usize {
        self.merged_bytes
    }

    /// Take the event accumulated so far, abandoning the merge.
    ///
    /// Used to flush an over-budget merge downstream instead of growing it further.
    pub fn into_merged_event(self) -> LogEvent {
        self.intermediate_merged_event
    }

    /// Merge the final (non-partial) event in and return the resulting (merged)
    /// event.
    pub fn merge_in_final_event(
        mut self,
        incoming: LogEvent,
        fields: &[impl AsRef<str>],
    ) -> LogEvent {
        self.merge_in_next_event(incoming, fields);
        self.intermediate_merged_event
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn log_event_with_message(message: &str) -> LogEvent {
        LogEvent::from(message)
    }

    #[test]
    fn log_event_merge_state_example() {
        let fields = vec!["message".to_string()];

        let mut state = LogEventMergeState::new(log_event_with_message("hel"));
        state.merge_in_next_event(log_event_with_message("lo "), &fields);
        let merged_event = state.merge_in_final_event(log_event_with_message("world"), &fields);

        assert_eq!(
            merged_event
                .get("message")
                .unwrap()
                .coerce_to_bytes()
                .as_ref(),
            b"hello world"
        );
    }

    #[test]
    fn merged_bytes_grows_with_every_event_folded_in() {
        let fields = vec!["message".to_string()];

        let mut state = LogEventMergeState::new(log_event_with_message("hel"));
        let after_first = state.merged_bytes();
        assert!(after_first > 0, "the initial event must be accounted for");

        state.merge_in_next_event(log_event_with_message("lo "), &fields);
        let after_second = state.merged_bytes();
        assert!(
            after_second > after_first,
            "folding an event in must grow the running total"
        );

        // Growth tracks payload size, which is what a caller budgets against.
        state.merge_in_next_event(log_event_with_message(&"x".repeat(1024)), &fields);
        assert!(state.merged_bytes() >= after_second + 1024);
    }

    #[test]
    fn into_merged_event_returns_what_was_accumulated() {
        let fields = vec!["message".to_string()];

        let mut state = LogEventMergeState::new(log_event_with_message("hel"));
        state.merge_in_next_event(log_event_with_message("lo"), &fields);

        let event = state.into_merged_event();

        assert_eq!(
            event.get("message").unwrap().coerce_to_bytes().as_ref(),
            b"hello"
        );
    }
}
