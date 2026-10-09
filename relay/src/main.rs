//! VeilDB blind rendezvous relay — standalone server.
//!
//! Usage:
//!   veildb-relay [--listen 0.0.0.0:8444] [--max-waiting 1024]
//!                [--pair-timeout-secs 60] [--idle-timeout-secs 300]
//!
//! Run this on any reachable host (a VPS, a cloud instance, a friend's
//! machine). Both VeilDB devices point at it in Sync → "Connect over
//! internet"; the relay pairs them by `BLAKE3(db_id)` room and pipes
//! their already-encrypted bytes verbatim. It never sees keys,
//! plaintext, index tokens, or operation content.

use std::time::Duration;

use veildb_relay::{serve, RelayConfig};

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let listen = arg_value(&args, "--listen").unwrap_or_else(|| "0.0.0.0:8444".to_string());
    let max_waiting = arg_value(&args, "--max-waiting")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);
    let pair_timeout = Duration::from_secs(
        arg_value(&args, "--pair-timeout-secs")
            .and_then(|v| v.parse().ok())
            .unwrap_or(60),
    );
    let idle_timeout = Duration::from_secs(
        arg_value(&args, "--idle-timeout-secs")
            .and_then(|v| v.parse().ok())
            .unwrap_or(300),
    );

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    eprintln!("veildb-relay listening on {listen}");
    eprintln!("  zero-knowledge: forwards opaque bytes only (room = BLAKE3(db_id))");

    serve(
        listener,
        RelayConfig {
            pair_timeout,
            idle_timeout,
            max_waiting,
        },
    )
    .await;
    Ok(())
}
