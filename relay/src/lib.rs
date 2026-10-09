//! VeilDB blind rendezvous relay.
//!
//! A **zero-knowledge** TCP rendezvous: two clients connect, each
//! sends one fixed 33-byte header `[room_id: 32][role: 1]`, and once
//! two sockets share a `room_id` the relay pipes bytes verbatim in
//! both directions and forgets everything on disconnect.
//!
//! The relay NEVER parses, stores, or interprets the payload. The
//! VeilDB `SyncMessage` stream crossing it is already end-to-end
//! encrypted and authenticated by the peers, so even a fully hostile
//! relay operator only observes opaque ciphertext sizes and timing.
//! (Operators SHOULD terminate TLS in front of this relay for
//! transport confidentiality; VeilDB's correctness does not depend on
//! it.)
//!
//! `room_id` is `BLAKE3(db_id)` as computed by the clients — both
//! peers can derive it, the relay learns nothing about `db_id`.
//!
//! Limits: hard cap on concurrently waiting sockets, a pairing
//! timeout for lonely clients, and an idle timeout for paired pipes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc};
use tokio::sync::Mutex;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// `[room_id: 32 bytes][role: 1 byte]`.
pub const HEADER_LEN: usize = 33;
/// Role byte: the dialing (probe-sending) side.
pub const ROLE_INITIATOR: u8 = 0;
/// Role byte: the listening (probe-receiving) side.
pub const ROLE_RESPONDER: u8 = 1;
/// Status byte written to each client once its partner arrives.
pub const STATUS_PAIRED: u8 = 0;
/// Status byte written when no partner showed up in time.
pub const STATUS_NO_PARTNER: u8 = 1;
/// Status byte written when the relay is at capacity.
pub const STATUS_AT_CAPACITY: u8 = 2;

/// Relay tuning knobs.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// How long a client may wait in a room for a partner.
    pub pair_timeout: std::time::Duration,
    /// How long a paired pipe may sit idle before being torn down.
    pub idle_timeout: std::time::Duration,
    /// Hard cap on concurrently *waiting* sockets (the DoS bound —
    /// paired pipes are anonymous and stateless beyond the pipe task).
    pub max_waiting: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            pair_timeout: std::time::Duration::from_secs(60),
            idle_timeout: std::time::Duration::from_secs(300),
            max_waiting: 1024,
        }
    }
}

/// One socket waiting in a room for its partner. The waiting task
/// keeps only the receiver half of the oneshot — ownership of the
/// stream moves into the room map until a partner (or a timeout)
/// takes it back.
struct Waiting {
    id: u64,
    role: u8,
    stream: TcpStream,
    /// Fired by the arriving partner when it takes this entry.
    paired_tx: tokio::sync::oneshot::Sender<()>,
    #[allow(dead_code)]
    created: Instant,
}

struct State {
    /// room_id → sockets currently waiting in it.
    rooms: HashMap<[u8; 32], Vec<Waiting>>,
    next_id: AtomicU64,
}

/// Serve the relay until the listener is dropped.
///
/// Each connection is handled on its own task; nothing outlives the
/// pairing except the anonymous pipe task, which forgets everything
/// when either side disconnects.
pub async fn serve(listener: TcpListener, config: RelayConfig) {
    let state = Arc::new(Mutex::new(State {
        rooms: HashMap::new(),
        next_id: AtomicU64::new(1),
    }));

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = Arc::clone(&state);
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, state, config).await;
                });
            }
            Err(_) => continue,
        }
    }
}

async fn send_status(stream: &mut TcpStream, status: u8) -> std::io::Result<()> {
    stream.write_all(&[status]).await?;
    stream.flush().await
}

async fn pipe(mut a: TcpStream, mut b: TcpStream, idle: std::time::Duration) {
    let _ = tokio::time::timeout(idle, tokio::io::copy_bidirectional(&mut a, &mut b)).await;
}

async fn handle_connection(
    stream: TcpStream,
    state: Arc<Mutex<State>>,
    config: RelayConfig,
) -> std::io::Result<()> {
    let mut stream = stream;
    let mut header = [0u8; HEADER_LEN];

    // 1. Read the fixed rendezvous header — bounded, never more.
    let read = tokio::time::timeout(config.pair_timeout, stream.read_exact(&mut header)).await;
    match read {
        Ok(Ok(_bytes)) => {} // header read succeeded (or timeout already handled)
        Ok(Err(_)) => return Ok(()), // client hung up — forget it
        Err(_) => return send_status(&mut stream, STATUS_NO_PARTNER).await,
    }

    let mut room_id = [0u8; 32];
    room_id.copy_from_slice(&header[..32]);
    let role = header[32];
    if role != ROLE_INITIATOR && role != ROLE_RESPONDER {
        return Ok(()); // protocol violation — drop silently
    }

    // 2. Try to pair with an opposite-role waiter in the same room.
    let partner = {
        let mut guard = state.lock().await;
        let mut found = None;
        if let Some(entries) = guard.rooms.get_mut(&room_id) {
            if let Some(pos) = entries.iter().position(|w| w.role != role) {
                found = Some(entries.remove(pos));
                if entries.is_empty() {
                    guard.rooms.remove(&room_id);
                }
            }
        } else if guard.rooms.values().map(|v| v.len()).sum::<usize>() >= config.max_waiting {
            drop(guard);
            return send_status(&mut stream, STATUS_AT_CAPACITY).await;
        }
        found
    };

    if let Some(waiter) = partner {
        // `entries.remove(pos)` moved the whole entry out, so we own
        // the waiting socket now. Announce the pairing to both sides,
        // release the waiter task, then pipe bytes verbatim.
        let mut partner_stream = waiter.stream;
        let _ = waiter.paired_tx.send(());
        send_status(&mut stream, STATUS_PAIRED).await?;
        send_status(&mut partner_stream, STATUS_PAIRED).await?;
        tokio::spawn(pipe(stream, partner_stream, config.idle_timeout));
        return Ok(());
    }

    // 3. No partner yet: park the socket in the room and wait.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let id = {
        let mut guard = state.lock().await;
        let id = guard.next_id.fetch_add(1, Ordering::Relaxed);
        guard.rooms.entry(room_id).or_default().push(Waiting {
            id,
            role,
            stream,
            paired_tx: tx,
            created: Instant::now(),
        });
        id
    };

    match tokio::time::timeout(config.pair_timeout, rx).await {
        // A partner took our socket (it owns the pipe now) — done.
        Ok(Ok(())) => Ok(()),
        // Timed out alone: reclaim the socket, tell the client, drop.
        _ => {
            let reclaimed = {
                let mut guard = state.lock().await;
                let mut reclaimed = None;
                if let Some(entries) = guard.rooms.get_mut(&room_id) {
                    if let Some(pos) = entries.iter().position(|w| w.id == id) {
                        reclaimed = Some(entries.remove(pos).stream);
                    }
                    if entries.is_empty() {
                        guard.rooms.remove(&room_id);
                    }
                }
                reclaimed
            };
            match reclaimed {
                // A partner grabbed it between our timeout and the
                // lock — honor the pairing instead of erroring.
                None => Ok(()),
                Some(mut own) => {
                    send_status(&mut own, STATUS_NO_PARTNER).await?;
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn start_relay(max_waiting: usize) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cfg = RelayConfig {
            pair_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(5),
            max_waiting,
        };
        tokio::spawn(serve(listener, cfg));
        addr
    }

    fn header(room: &[u8; 32], role: u8) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[..32].copy_from_slice(room);
        h[32] = role;
        h
    }

    /// Two clients with the same room pair up and the relay pipes
    /// bytes verbatim — including bytes that are NOT valid UTF-8 or
    /// structured messages (the relay must not care what it sees).
    #[tokio::test]
    async fn pairs_and_forwards_verbatim() {
        let addr = start_relay(16).await;
        let room = [7u8; 32];

        let a = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&header(&room, ROLE_INITIATOR)).await.unwrap();
            let mut status = [0u8; 1];
            s.read_exact(&mut status).await.unwrap();
            assert_eq!(status[0], STATUS_PAIRED);
            // Send ciphertext-looking junk; the relay must forward as-is.
            let payload: Vec<u8> = (0u8..=255).collect();
            s.write_all(&payload).await.unwrap();
            s.flush().await.unwrap();
            let mut back = vec![0u8; payload.len()];
            s.read_exact(&mut back).await.unwrap();
            assert_eq!(back, payload);
        });

        let b = tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&header(&room, ROLE_RESPONDER)).await.unwrap();
            let mut status = [0u8; 1];
            s.read_exact(&mut status).await.unwrap();
            assert_eq!(status[0], STATUS_PAIRED);
            let mut buf = vec![0u8; 256];
            s.read_exact(&mut buf).await.unwrap();
            // Echo back — proves bidirectional verbatim piping.
            s.write_all(&buf).await.unwrap();
            s.flush().await.unwrap();
        });

        a.await.unwrap();
        b.await.unwrap();
    }

    /// Different rooms never pair: the lonely client gets
    /// STATUS_NO_PARTNER instead of receiving the other room's bytes.
    #[tokio::test]
    async fn different_rooms_do_not_pair() {
        let addr = start_relay(16).await;

        let mut s1 = TcpStream::connect(addr).await.unwrap();
        s1.write_all(&header(&[1u8; 32], ROLE_INITIATOR)).await.unwrap();

        let mut s2 = TcpStream::connect(addr).await.unwrap();
        s2.write_all(&header(&[2u8; 32], ROLE_RESPONDER)).await.unwrap();
        let mut status = [0u8; 1];
        s2.read_exact(&mut status).await.unwrap();
        assert_eq!(status[0], STATUS_NO_PARTNER);
        drop(s1);
    }

    /// The waiting-room cap is enforced: beyond `max_waiting`, new
    /// clients are rejected with STATUS_AT_CAPACITY.
    #[tokio::test]
    async fn capacity_cap_enforced() {
        let addr = start_relay(2).await;

        let mut waiters = Vec::new();
        for i in 0..2u8 {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(&header(&[i; 32], ROLE_INITIATOR)).await.unwrap();
            waiters.push(s);
        }

        let mut extra = TcpStream::connect(addr).await.unwrap();
        extra.write_all(&header(&[9u8; 32], ROLE_RESPONDER)).await.unwrap();
        let mut status = [0u8; 1];
        extra.read_exact(&mut status).await.unwrap();
        assert_eq!(status[0], STATUS_AT_CAPACITY);
    }

    /// Same-role clients in one room never pair with each other (the
    /// dialing side must meet the listening side).
    #[tokio::test]
    async fn same_role_does_not_pair() {
        let addr = start_relay(16).await;
        let room = [3u8; 32];

        let mut s1 = TcpStream::connect(addr).await.unwrap();
        s1.write_all(&header(&room, ROLE_INITIATOR)).await.unwrap();

        let mut s2 = TcpStream::connect(addr).await.unwrap();
        s2.write_all(&header(&room, ROLE_INITIATOR)).await.unwrap();
        let mut status = [0u8; 1];
        s2.read_exact(&mut status).await.unwrap();
        assert_eq!(status[0], STATUS_NO_PARTNER);
        drop(s1);
    }
}



