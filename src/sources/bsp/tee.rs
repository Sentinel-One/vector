use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

use bytes::Bytes;
use futures::FutureExt;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::Instant,
};
use tracing::Instrument;

use super::capture::{now, Admission, Capture, SessionStream, SessionTx};
use crate::proto::beam::{session_response, SessionResponse};

/// How a session's offsets advance.
#[derive(Clone, Copy, Debug)]
pub(super) enum Unit {
    /// Byte offsets; payloads are split at `max_chunk` bytes.
    Bytes { max_chunk: usize },
    /// Datagram indexes; one payload is one datagram.
    Datagrams,
}

impl Unit {
    const fn advance(self, len: usize) -> u64 {
        match self {
            Self::Bytes { .. } => len as u64,
            Self::Datagrams => 1,
        }
    }

    /// `(offset, payload)` pieces of one read, each at most `max_chunk` bytes.
    pub(super) fn chunks(self, offset: u64, payload: Bytes) -> Vec<(u64, Bytes)> {
        match self {
            Self::Bytes { max_chunk } if payload.len() > max_chunk => (0..payload.len())
                .step_by(max_chunk)
                .map(|start| {
                    let end = (start + max_chunk).min(payload.len());
                    (offset + start as u64, payload.slice(start..end))
                })
                .collect(),
            Self::Bytes { .. } | Self::Datagrams => vec![(offset, payload)],
        }
    }
}

enum Item {
    Data {
        offset: u64,
        received_at: prost_types::Timestamp,
        payload: Bytes,
    },
    Gap {
        offset: u64,
        length: u64,
    },
    HalfClose,
}

/// A `[offset, offset + length)` hole that hasn't been reported yet.
#[derive(Default)]
struct PendingGap(Option<(u64, u64)>);

impl PendingGap {
    /// Returns the pending gap it replaces when the new one isn't adjacent; the caller must
    /// report it.
    fn extend(&mut self, offset: u64, length: u64) -> Option<(u64, u64)> {
        match self.0 {
            Some((start, len)) if start + len == offset => {
                self.0 = Some((start, len + length));
                None
            }
            previous => {
                self.0 = Some((offset, length));
                previous
            }
        }
    }
}

/// Update-mode copy of one session's client bytes towards control-agent.
///
/// Pushing never waits: when the bounded queue is full the bytes are dropped and reported as a
/// `Gap`, so capture can never slow the upstream down.
pub(super) struct Tee {
    queue: mpsc::UnboundedSender<Item>,
    queued: Arc<AtomicUsize>,
    capturing: Arc<AtomicBool>,
    limit: usize,
    unit: Unit,
    offset: u64,
    gap: PendingGap,
    capture: Arc<Capture>,
    drain: JoinHandle<()>,
    /// Never sent: dropping it with the Tee tells the drain the connection has ended.
    _connected: oneshot::Sender<()>,
}

impl Tee {
    /// Opens the `Session` RPC for an admitted session and starts draining towards it.
    pub(super) fn open(
        capture: &Arc<Capture>,
        admission: Admission,
        client_addr: String,
        local_addr: String,
        limit: usize,
        unit: Unit,
        offset: u64,
    ) -> Self {
        let session = capture.open(admission, client_addr, local_addr);
        Self::spawn(Arc::clone(capture), session, limit, unit, offset)
    }

    pub(super) fn spawn(
        capture: Arc<Capture>,
        session: SessionStream,
        limit: usize,
        unit: Unit,
        offset: u64,
    ) -> Self {
        let (queue, rx) = mpsc::unbounded_channel();
        let (connected, disconnected) = oneshot::channel();
        let queued = Arc::new(AtomicUsize::new(0));
        let capturing = Arc::new(AtomicBool::new(true));
        let drain = Drain {
            capture: Arc::clone(&capture),
            queued: Arc::clone(&queued),
            unit,
            gap: PendingGap::default(),
            sent: 0,
        };
        let drain = tokio::spawn(
            drain
                .run(session, rx, disconnected, Arc::clone(&capturing))
                .in_current_span(),
        );
        Self {
            queue,
            queued,
            capturing,
            limit,
            unit,
            offset,
            gap: PendingGap::default(),
            capture,
            drain,
            _connected: connected,
        }
    }

    /// Queues a copy of `payload`. Do not queue a slice of the caller's read buffer: it would keep
    /// the whole buffer alive while queued, and `limit` only counts the payload.
    pub(super) fn push(&mut self, payload: &[u8]) {
        let len = payload.len();
        let advance = self.unit.advance(len);
        let full = self.queued.load(Ordering::Relaxed) + len > self.limit;
        match (self.capturing.load(Ordering::Relaxed), full) {
            (false, _) => {}
            (true, true) => {
                self.capture
                    .metrics
                    .capture_bytes_dropped_buffer_full
                    .increment(len as u64);
                if let Some((offset, length)) = self.gap.extend(self.offset, advance) {
                    _ = self.queue.send(Item::Gap { offset, length });
                }
            }
            (true, false) => {
                self.flush_gap();
                self.queued.fetch_add(len, Ordering::Relaxed);
                _ = self.queue.send(Item::Data {
                    offset: self.offset,
                    received_at: now(),
                    payload: Bytes::copy_from_slice(payload),
                });
            }
        }
        self.offset += advance;
    }

    /// Advances past one datagram that sampling left out.
    pub(super) fn skip(&mut self) {
        self.offset += self.unit.advance(0);
    }

    pub(super) fn half_close(&mut self) {
        self.flush_gap();
        _ = self.queue.send(Item::HalfClose);
    }

    fn flush_gap(&mut self) {
        if let Some((offset, length)) = self.gap.0.take() {
            _ = self.queue.send(Item::Gap { offset, length });
        }
    }

    /// Ends the capture normally once the queue has drained.
    pub(super) fn finish(mut self) {
        self.flush_gap();
    }

    /// Cancels the `Session` RPC: the session was reset or cut short.
    pub(super) fn abort(self) {
        self.drain.abort();
    }
}

enum DrainEnd {
    /// Capture of this session is over; the RPC ends normally.
    Finish,
    /// The RPC failed or was stopped; nothing more can be sent.
    Gone,
}

struct Drain {
    capture: Arc<Capture>,
    queued: Arc<AtomicUsize>,
    unit: Unit,
    gap: PendingGap,
    sent: u64,
}

impl Drain {
    async fn run(
        mut self,
        mut session: SessionStream,
        mut queue: mpsc::UnboundedReceiver<Item>,
        disconnected: oneshot::Receiver<()>,
        capturing: Arc<AtomicBool>,
    ) {
        let capture = Arc::clone(&self.capture);
        let stopped = capture.stopped();
        tokio::pin!(stopped);
        // Once the connection ends, delivering what is queued and ending the RPC must fit in
        // `finish_timeout`, so a stalled control-agent can't keep the session alive.
        let finish_timeout = session.finish_timeout();
        let deadline = async move {
            _ = disconnected.await;
            Instant::now() + finish_timeout
        }
        .shared();
        let expired = {
            let deadline = deadline.clone();
            async move { tokio::time::sleep_until(deadline.await).await }
        };
        let pump = async {
            loop {
                tokio::select! {
                    biased;
                    () = &mut stopped => break DrainEnd::Finish,
                    response = session.rx.recv() => match response {
                        Some(Ok(SessionResponse { msg: Some(session_response::Msg::Stop(_)) })) => {
                            break DrainEnd::Finish;
                        }
                        Some(Ok(_)) => self.capture.metrics.ignored_responses.increment(1),
                        Some(Err(status)) => {
                            debug!(message = "Capture session failed; proxying continues.", %status);
                            break DrainEnd::Gone;
                        }
                        None => break DrainEnd::Gone,
                    },
                    item = queue.recv() => match item {
                        None => {
                            break match self.flush_gap(&session.tx).await {
                                Ok(()) => DrainEnd::Finish,
                                Err(()) => DrainEnd::Gone,
                            };
                        }
                        Some(item) => match self.handle(&session.tx, item).await {
                            Ok(true) => {}
                            Ok(false) => break DrainEnd::Finish,
                            Err(()) => break DrainEnd::Gone,
                        },
                    },
                }
            }
        };
        let end = tokio::select! {
            end = pump => end,
            () = expired => {
                debug!(message = "Capture session did not finish in time; cancelling it.");
                DrainEnd::Gone
            }
        };
        capturing.store(false, Ordering::Relaxed);
        match end {
            DrainEnd::Finish => match deadline.now_or_never() {
                Some(deadline) => session.finish_by(deadline),
                None => session.finish(),
            },
            DrainEnd::Gone => drop(session),
        }
    }

    /// `Ok(false)` once `max_session_bytes` is reached.
    async fn handle(&mut self, tx: &SessionTx, item: Item) -> Result<bool, ()> {
        match item {
            Item::Gap { offset, length } => match self.gap.extend(offset, length) {
                Some(previous) => self.send_gap(tx, previous).await,
                None => Ok(()),
            }
            .map(|()| true),
            Item::HalfClose => {
                self.flush_gap(tx).await?;
                tx.half_close().await.map(|()| true)
            }
            Item::Data {
                offset,
                received_at,
                payload,
            } => {
                let len = payload.len();
                self.queued.fetch_sub(len, Ordering::Relaxed);
                if self.sent + len as u64 > self.capture.max_session_bytes() {
                    Ok(false)
                } else if !self.capture.try_rate(len) {
                    self.capture
                        .metrics
                        .capture_bytes_dropped_rate_limited
                        .increment(len as u64);
                    match self.gap.extend(offset, self.unit.advance(len)) {
                        Some(previous) => self.send_gap(tx, previous).await,
                        None => Ok(()),
                    }
                    .map(|()| true)
                } else {
                    self.flush_gap(tx).await?;
                    self.capture.charge(len);
                    self.sent += len as u64;
                    for (offset, chunk) in self.unit.chunks(offset, payload) {
                        tx.data(offset, received_at.clone(), chunk).await?;
                    }
                    Ok(true)
                }
            }
        }
    }

    async fn flush_gap(&mut self, tx: &SessionTx) -> Result<(), ()> {
        match self.gap.0.take() {
            Some(gap) => self.send_gap(tx, gap).await,
            None => Ok(()),
        }
    }

    async fn send_gap(&self, tx: &SessionTx, (offset, length): (u64, u64)) -> Result<(), ()> {
        self.capture.metrics.capture_gaps.increment(1);
        tx.gap(offset, length).await
    }
}

#[cfg(test)]
mod tests {
    use super::PendingGap;

    #[test]
    fn test_pending_gap_extend_merges_adjacent_gaps_and_returns_the_one_it_replaces() {
        let mut gap = PendingGap::default();

        assert_eq!(gap.extend(5, 1), None);
        assert_eq!(gap.extend(6, 2), None);
        assert_eq!(gap.0, Some((5, 3)));
        assert_eq!(gap.extend(10, 1), Some((5, 3)));
        assert_eq!(gap.0, Some((10, 1)));
    }
}
