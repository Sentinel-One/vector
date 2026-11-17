use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

use bytes::Bytes;
use tokio::{sync::mpsc, task::JoinHandle};

use super::capture::{now, Capture, SessionStream, SessionTx};
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
    fn extend(&mut self, offset: u64, length: u64) {
        self.0 = match self.0 {
            Some((start, len)) if start + len == offset => Some((start, len + length)),
            Some(_) | None => Some((offset, length)),
        };
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
}

impl Tee {
    pub(super) fn spawn(
        capture: Arc<Capture>,
        session: SessionStream,
        limit: usize,
        unit: Unit,
        offset: u64,
    ) -> Self {
        let (queue, rx) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        let capturing = Arc::new(AtomicBool::new(true));
        let drain = Drain {
            capture: Arc::clone(&capture),
            queued: Arc::clone(&queued),
            unit,
            gap: PendingGap::default(),
            sent: 0,
        };
        let drain = tokio::spawn(drain.run(session, rx, Arc::clone(&capturing)));
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
        }
    }

    pub(super) fn push(&mut self, payload: Bytes) {
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
                self.gap.extend(self.offset, advance);
            }
            (true, false) => {
                self.flush_gap();
                self.queued.fetch_add(len, Ordering::Relaxed);
                _ = self.queue.send(Item::Data {
                    offset: self.offset,
                    received_at: now(),
                    payload,
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

    /// Cancels the `Session` RPC: the session was reset.
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
        capturing: Arc<AtomicBool>,
    ) {
        let end = loop {
            tokio::select! {
                biased;
                _ = self.capture.stopped() => break DrainEnd::Finish,
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
        };
        capturing.store(false, Ordering::Relaxed);
        match end {
            DrainEnd::Finish => session.finish(),
            DrainEnd::Gone => drop(session),
        }
    }

    /// `Ok(false)` once `max_session_bytes` is reached.
    async fn handle(&mut self, tx: &SessionTx, item: Item) -> Result<bool, ()> {
        match item {
            Item::Gap { offset, length } => {
                self.gap.extend(offset, length);
                Ok(true)
            }
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
                    self.gap.extend(offset, self.unit.advance(len));
                    Ok(true)
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
            Some((offset, length)) => {
                self.capture.metrics.capture_gaps.increment(1);
                tx.gap(offset, length).await
            }
            None => Ok(()),
        }
    }
}
