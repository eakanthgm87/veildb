//! UDP multicast peer discovery for LAN sync.
//!
//! Devices periodically broadcast a signed announcement to the
//! `239.255.0.7:45678` multicast group. Any VeilDB device listening on
//! the same network and group collects these announcements and can
//! then open a direct TCP sync session with the discovered peer.
//!
//! Each announcement contains:
//! - the announcing device's ID (hash of its Ed25519 public key),
//! - the Ed25519 public key itself,
//! - the database ID being shared,
//! - a fresh nonce, and
//! - an Ed25519 signature over `db_id || nonce`, so listeners can
//!   verify the announcement really came from the claimed device.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use veildb_crypto::{SigningKeyPair, verify_signature};

use crate::error::SyncError;

/// The IPv4 multicast group used for peer discovery.
pub const DISCOVERY_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 0, 7);

/// The UDP port announcements are sent to and received on.
pub const DISCOVERY_PORT: u16 = 45678;

/// A signed peer announcement broadcast over UDP multicast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    /// The announcing device's ID (hash of its public key).
    pub device_id: [u8; 32],
    /// The announcing device's Ed25519 public key.
    pub public_key: [u8; 32],
    /// The database ID being announced.
    pub db_id: [u8; 32],
    /// A fresh one-time nonce.
    pub nonce: [u8; 32],
    /// Ed25519 signature over `db_id || nonce`.
    pub signature: Vec<u8>,
    /// The TCP sync port the device listens on.
    pub sync_port: u16,
}

/// A verified discovery result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// The peer's device ID.
    pub device_id: [u8; 32],
    /// The peer's public key.
    pub public_key: [u8; 32],
    /// The peer's address for TCP sync.
    pub sync_addr: SocketAddr,
}

/// Build a signed announcement for this device.
pub fn make_announcement(
    signing: &SigningKeyPair,
    db_id: [u8; 32],
    sync_port: u16,
) -> PeerAnnouncement {
    let public_key = signing.public_key();
    let device_id = veildb_crypto::hash(&public_key);
    let nonce = veildb_crypto::random_bytes_32();

    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(&db_id);
    msg.extend_from_slice(&nonce);
    let signature = signing.sign(&msg);

    PeerAnnouncement {
        device_id,
        public_key,
        db_id,
        nonce,
        signature,
        sync_port,
    }
}

/// Verify a received announcement's signature and device ID binding.
pub fn validate_announcement(announcement: &PeerAnnouncement) -> Result<(), SyncError> {
    // The device ID must bind to the public key.
    let derived = veildb_crypto::hash(&announcement.public_key);
    if derived != announcement.device_id {
        return Err(SyncError::PeerAuthenticationFailed);
    }

    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(&announcement.db_id);
    msg.extend_from_slice(&announcement.nonce);
    verify_signature(&announcement.public_key, &msg, &announcement.signature)
        .map_err(|_| SyncError::PeerAuthenticationFailed)
}

/// Encode an announcement for the wire.
pub fn encode_announcement(announcement: &PeerAnnouncement) -> Result<Vec<u8>, SyncError> {
    postcard::to_allocvec(announcement).map_err(|e| SyncError::Serialization(e.to_string()))
}

/// Decode an announcement from the wire.
pub fn decode_announcement(bytes: &[u8]) -> Result<PeerAnnouncement, SyncError> {
    postcard::from_bytes(bytes).map_err(|e| SyncError::Serialization(e.to_string()))
}

/// Listen for peer announcements on the multicast group for `timeout`
/// and return every verified peer discovered in that window.
///
/// Duplicates (same device ID) are deduplicated; the first verified
/// announcement for a device wins.
pub async fn discover(
    timeout: Duration,
    db_id: [u8; 32],
) -> Result<Vec<DiscoveredPeer>, SyncError> {
    let socket = tokio::net::UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)).await?;
    socket.join_multicast_v4(DISCOVERY_GROUP, Ipv4Addr::UNSPECIFIED)?;

    let mut peers: Vec<DiscoveredPeer> = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    let mut buf = vec![0u8; 1024];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let recv = tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await;
        let (len, origin) = match recv {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => return Err(SyncError::Io(e)),
            Err(_) => break, // timeout elapsed
        };

        let announcement = match decode_announcement(&buf[..len]) {
            Ok(a) => a,
            Err(_) => continue, // malformed: ignore
        };

        // Ignore announcements for other databases.
        if announcement.db_id != db_id {
            continue;
        }

        if validate_announcement(&announcement).is_err() {
            continue;
        }

        let sync_addr = SocketAddr::new(origin.ip(), announcement.sync_port);
        if !peers.iter().any(|p| p.device_id == announcement.device_id) {
            peers.push(DiscoveredPeer {
                device_id: announcement.device_id,
                public_key: announcement.public_key,
                sync_addr,
            });
        }
    }

    Ok(peers)
}

/// Spawn a background task that periodically broadcasts this device's
/// signed announcement to the multicast group.
///
/// The task runs until a message is sent on the returned sender.
pub async fn spawn_beacon(
    signing: Arc<SigningKeyPair>,
    db_id: [u8; 32],
    sync_port: u16,
    interval: Duration,
) -> Result<(mpsc::Sender<()>, tokio::task::JoinHandle<()>), SyncError> {
    let socket = tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await?;
    let target = SocketAddr::from((DISCOVERY_GROUP, DISCOVERY_PORT));

    let (tx, mut rx) = mpsc::channel::<()>(1);

    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let announcement = make_announcement(&signing, db_id, sync_port);
                    if let Ok(bytes) = encode_announcement(&announcement) {
                        let _ = socket.send_to(&bytes, target).await;
                    }
                }
                _ = rx.recv() => break,
            }
        }
    });

    Ok((tx, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_roundtrip_and_verification() {
        let signing = SigningKeyPair::generate();
        let db_id = [0x42u8; 32];

        let announcement = make_announcement(&signing, db_id, 9000);
        assert!(validate_announcement(&announcement).is_ok());

        let bytes = encode_announcement(&announcement).unwrap();
        let decoded = decode_announcement(&bytes).unwrap();
        assert_eq!(decoded, announcement);
        assert!(validate_announcement(&decoded).is_ok());
    }

    #[test]
    fn tampered_announcement_rejected() {
        let signing = SigningKeyPair::generate();
        let announcement = make_announcement(&signing, [1u8; 32], 9000);

        let mut bad = announcement.clone();
        bad.db_id = [2u8; 32];
        assert!(validate_announcement(&bad).is_err());

        let mut bad_key = announcement;
        bad_key.public_key = [9u8; 32];
        assert!(validate_announcement(&bad_key).is_err());
    }
}
