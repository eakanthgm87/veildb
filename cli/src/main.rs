//! VeilDB CLI entry point.
//!
//! Depends only on `core`. No direct storage/crypto/sync access.
//!
//! Exit codes:
//! - 0: success
//! - 1: general error
//! - 2: integrity/tamper failure

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use veildb_core::{IntegrityStatus, SecretString, SyncBackendKind, VeilDbCore};

/// VeilDB — a privacy-first, local-first, zero-trust embedded database.
#[derive(Parser)]
#[command(name = "veildb", version, about)]
struct Cli {
    /// Path to the database file.
    #[arg(short, long, default_value = "veildb.vdb")]
    db: PathBuf,

    /// Passphrase (non-interactive). Use only for scripts and tests.
    #[arg(long)]
    passphrase: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new database.
    Init,
    /// Put a key-value pair.
    Put {
        /// The key.
        key: String,
        /// The value.
        value: String,
    },
    /// Get a value by key.
    Get {
        /// The key.
        key: String,
    },
    /// Sync with a peer.
    Sync {
        /// The backend to use.
        #[arg(long, default_value = "lan")]
        backend: String,
        /// The peer address (for LAN backend), or bind address with --listen.
        #[arg(long)]
        addr: Option<String>,
        /// Accept one incoming connection instead of dialing.
        #[arg(long)]
        listen: bool,
    },
    /// Discover peers on the LAN via UDP multicast.
    Discover {
        /// How long to listen for announcements (ms).
        #[arg(long, default_value = "2000")]
        timeout_ms: u64,
    },
    /// Show the merge log (deterministic conflict resolutions).
    Merges,
    /// Verify database integrity.
    Verify,
    /// Show the operation log.
    Log {
        /// Logical clock to query at (comma-separated device:counter pairs).
        #[arg(long)]
        at: Option<String>,
    },
    /// Manage devices.
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Share a key with a device.
    Share {
        /// The key to share.
        key: String,
        /// The target device ID (hex).
        #[arg(long)]
        to: String,
    },
    /// Create an encrypted backup.
    Backup {
        /// Output file path.
        output: PathBuf,
    },
    /// Restore from an encrypted backup.
    Restore {
        /// Archive file path.
        archive: PathBuf,
    },
    /// Show database status.
    Status,
    /// Create a snapshot.
    Snapshot,
}

#[derive(Subcommand)]
enum DeviceAction {
    /// List all devices.
    List,
    /// Trust a new device by public key (hex).
    Trust {
        /// The public key (hex, 64 chars).
        pubkey: String,
    },
    /// Revoke a device by ID (hex).
    Revoke {
        /// The device ID (hex, 64 chars).
        device_id: String,
    },
    /// Export a pairing bundle for a new device.
    ExportPairing {
        /// Output file for the JSON bundle.
        output: PathBuf,
    },
    /// Import a pairing bundle and approve the inviting device.
    ImportPairing {
        /// JSON bundle file.
        file: PathBuf,
    },
    /// Rotate the master key.
    RotateKey,
}

fn main() {
    let cli = Cli::parse();
    let result = run(cli);
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            eprintln!("Error: {e:#}");
            // Check if it's an integrity error.
            if e.to_string().contains("integrity") || e.to_string().contains("tamper") {
                std::process::exit(2);
            }
            std::process::exit(1);
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    // Make the passphrase available to open_core/init_core helpers.
    PASSPHRASE.with(|p| *p.borrow_mut() = cli.passphrase.clone());
    match cli.command {
        Command::Init => cmd_init(&cli.db),
        Command::Put { key, value } => cmd_put(&cli.db, &key, value.as_bytes()),
        Command::Get { key } => cmd_get(&cli.db, &key),
        Command::Sync { backend, addr, listen } => cmd_sync(&cli.db, &backend, addr, listen),
        Command::Discover { timeout_ms } => cmd_discover(&cli.db, timeout_ms),
        Command::Merges => cmd_merges(&cli.db),
        Command::Verify => cmd_verify(&cli.db),
        Command::Log { at } => cmd_log(&cli.db, at),
        Command::Device { action } => cmd_device(&cli.db, action),
        Command::Share { key, to } => cmd_share(&cli.db, &key, &to),
        Command::Backup { output } => cmd_backup(&cli.db, &output),
        Command::Restore { archive } => cmd_restore(&cli.db, &archive),
        Command::Status => cmd_status(&cli.db),
        Command::Snapshot => cmd_snapshot(&cli.db),
    }
}

thread_local! {
    /// Optional passphrase supplied via --passphrase (scripts/tests).
    static PASSPHRASE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn prompt_passphrase() -> Result<SecretString> {
    if let Some(p) = PASSPHRASE.with(|p| p.borrow().clone()) {
        return Ok(SecretString::new(p));
    }
    let passphrase = rpassword::prompt_password("Enter passphrase: ")
        .context("Failed to read passphrase")?;
    Ok(SecretString::new(passphrase))
}

fn open_core(db: &PathBuf) -> Result<VeilDbCore> {
    if !db.exists() {
        return Err(anyhow!("Database not found: {}", db.display()));
    }
    let passphrase = prompt_passphrase()?;
    VeilDbCore::init(db, passphrase).map_err(|e| anyhow!("Failed to open database: {e}"))
}

fn cmd_init(db: &PathBuf) -> Result<()> {
    if db.exists() {
        return Err(anyhow!("Database already exists: {}", db.display()));
    }
    let passphrase = prompt_passphrase()?;
    let core = VeilDbCore::init(db, passphrase)
        .map_err(|e| anyhow!("Failed to initialize database: {e}"))?;
    let status = core.status()?;
    println!("Database initialized: {}", db.display());
    println!("  DB ID: {}", hex(&status.db_id));
    println!("  Device ID: {}", hex(&status.self_device_id));
    println!("  Key version: {}", status.key_version);
    Ok(())
}

fn cmd_put(db: &PathBuf, key: &str, value: &[u8]) -> Result<()> {
    let mut core = open_core(db)?;
    let op_id = core.put(key, value)?;
    println!(
        "Stored '{}' (op {}.{})",
        key,
        hex(&op_id.device_id),
        op_id.sequence
    );
    Ok(())
}

fn cmd_get(db: &PathBuf, key: &str) -> Result<()> {
    let core = open_core(db)?;
    let value = core.get(key)?;
    println!("{}", String::from_utf8_lossy(&value));
    Ok(())
}

fn cmd_sync(db: &PathBuf, backend: &str, addr: Option<String>, listen: bool) -> Result<()> {
    let mut core = open_core(db)?;
    let addr_opt = addr.clone();
    let backend_kind = match backend {
        "mock" => SyncBackendKind::Mock,
        "lan" => {
            let addr = addr_opt
                .clone()
                .ok_or_else(|| anyhow!("--addr is required for LAN backend"))?;
            if listen {
                SyncBackendKind::Listen { addr }
            } else {
                SyncBackendKind::Lan { addr }
            }
        }
        other => return Err(anyhow!("Unknown backend: {other}")),
    };

    let rt = tokio::runtime::Runtime::new()?;
    let report = if listen {
        let bind_addr = addr
            .clone()
            .ok_or_else(|| anyhow!("--addr is required for --listen"))?;
        rt.block_on(core.sync_listen_once_with(&bind_addr, || {
            println!("listening on {bind_addr}");
            use std::io::Write;
            std::io::stdout().flush().ok();
        }))?
    } else {
        rt.block_on(core.sync(backend_kind))?
    };
    println!("Sync report:");
    println!("  Received: {} ops", report.operations_received);
    println!("  Sent: {} ops", report.operations_sent);
    println!("  Merged: {} ops", report.operations_merged);
    println!("  Merkle root: {}", hex(&report.merkle_root));
    println!("  Status: {}", if report.success { "OK" } else { "FAILED" });
    println!("  Message: {}", report.message);
    Ok(())
}

fn cmd_discover(db: &PathBuf, timeout_ms: u64) -> Result<()> {
    let core = open_core(db)?;
    let rt = tokio::runtime::Runtime::new()?;
    let peers = rt.block_on(core.discover_peers(timeout_ms))?;
    if peers.is_empty() {
        println!("No peers discovered.");
        return Ok(());
    }
    println!("Discovered {} peer(s):", peers.len());
    for p in &peers {
        println!(
            "  {} @ {} (key {})",
            hex(&p.device_id),
            p.sync_addr,
            hex_short(&p.public_key)
        );
    }
    Ok(())
}

fn cmd_merges(db: &PathBuf) -> Result<()> {
    let core = open_core(db)?;
    let entries = core.merge_log()?;
    if entries.is_empty() {
        println!("No merge-log entries recorded.");
        return Ok(());
    }
    println!("{:<20} {:<22} {:<22} {:<28}", "Key", "Winner", "Loser", "Rule");
    for e in &entries {
        println!(
            "{:<20} {:<22} {:<22} {:<28}",
            e.key,
            format!("{}.{}", hex_short(&e.winner.device_id), e.winner.sequence),
            e.loser
                .map(|l| format!("{}.{}", hex_short(&l.device_id), l.sequence))
                .unwrap_or_else(|| "-".to_string()),
            e.rule,
        );
    }
    Ok(())
}

fn cmd_verify(db: &PathBuf) -> Result<()> {
    let core = open_core(db)?;
    let status = core.verify_integrity()?;
    match status {
        IntegrityStatus::Verified => {
            println!("Integrity: VERIFIED");
            Ok(())
        }
        IntegrityStatus::Tampered => {
            println!("Integrity: TAMPERED");
            Err(anyhow!("Database integrity check failed: TAMPERED"))
        }
        IntegrityStatus::Unverified => {
            println!("Integrity: UNVERIFIED");
            Err(anyhow!("Database integrity check failed: UNVERIFIED"))
        }
    }
}

fn cmd_log(db: &PathBuf, at: Option<String>) -> Result<()> {
    let core = open_core(db)?;
    let clock = match at {
        Some(s) => Some(parse_clock(&s)?),
        None => None,
    };
    let log = core.log(clock)?;
    println!(
        "{:<10} {:<20} {:<20} {:<8} {}",
        "Seq", "Device", "Hash", "Parents", "Clock"
    );
    for entry in &log {
        println!(
            "{:<10} {:<20} {:<20} {:<8} {}",
            entry.id.sequence,
            hex(&entry.device_id),
            hex(&entry.hash),
            entry.parent_count,
            format_clock(&entry.clock),
        );
    }
    Ok(())
}

fn cmd_device(db: &PathBuf, action: DeviceAction) -> Result<()> {
    let mut core = open_core(db)?;
    match action {
        DeviceAction::List => {
            let devices = core.list_devices()?;
            println!(
                "{:<40} {:<40} {:<10} {:<40}",
                "Device ID", "Public Key", "Trusted", "Approved By"
            );
            for d in &devices {
                println!(
                    "{:<40} {:<40} {:<10} {:<40}",
                    hex(&d.device_id),
                    hex_short(&d.public_key),
                    if d.trusted { "YES" } else { "NO" },
                    d.approved_by
                        .map(|a| hex(&a))
                        .unwrap_or_else(|| "-".to_string()),
                );
            }
            Ok(())
        }
        DeviceAction::Trust { pubkey } => {
            let key = parse_hex(&pubkey)?;
            let entry = core.trust_device(&key)?;
            println!("Device trusted: {}", hex(&entry.device_id));
            Ok(())
        }
        DeviceAction::Revoke { device_id } => {
            let id = parse_hex(&device_id)?;
            core.revoke_device(&id)?;
            println!("Device revoked: {}", hex(&id));
            Ok(())
        }
        DeviceAction::ExportPairing { output } => {
            let bundle = core.export_pairing()?;
            std::fs::write(&output, bundle.to_json()?)?;
            println!("Pairing bundle written: {}", output.display());
            println!("  DB ID: {}", hex(&bundle.db_id));
            println!("  Approver device: {}", hex(&bundle.device_id));
            Ok(())
        }
        DeviceAction::ImportPairing { file } => {
            let json = std::fs::read_to_string(&file)?;
            let bundle = veildb_core::PairingBundle::from_json(&json)?;
            let entry = core.import_pairing(&bundle)?;
            println!("Pairing bundle imported and device approved:");
            println!("  Device ID: {}", hex(&entry.device_id));
            println!("  Public key: {}", hex_short(&entry.public_key));
            Ok(())
        }
        DeviceAction::RotateKey => {
            let new_version = core.rotate_key()?;
            println!("Key rotated to version {}", new_version);
            Ok(())
        }
    }
}

fn cmd_share(db: &PathBuf, key: &str, to: &str) -> Result<()> {
    let mut core = open_core(db)?;
    let device_id = parse_hex(to)?;
    let blob = core.share(key, &device_id)?;
    println!("Shared key '{}' with device {}", key, hex(&blob.to_device));
    println!("  Key: {}", blob.key);
    Ok(())
}

fn cmd_backup(db: &PathBuf, output: &PathBuf) -> Result<()> {
    let core = open_core(db)?;
    let archive = core.backup(output)?;
    println!("Backup created: {}", output.display());
    println!("  Format version: {}", archive.format_version);
    println!("  Merkle root: {}", hex(&archive.merkle_root));
    Ok(())
}

fn cmd_restore(db: &PathBuf, archive: &PathBuf) -> Result<()> {
    let mut core = open_core(db)?;
    core.restore(archive)?;
    println!("Restore completed: {}", archive.display());
    Ok(())
}

fn cmd_status(db: &PathBuf) -> Result<()> {
    let core = open_core(db)?;
    let status = core.status()?;
    println!("VeilDB Status");
    println!("  DB ID: {}", hex(&status.db_id));
    println!("  Operations: {}", status.operation_count);
    println!("  Merkle root: {}", hex(&status.merkle_root));
    println!("  Logical clock: {}", format_clock(&status.logical_clock));
    println!(
        "  Snapshot ID: {}",
        status
            .latest_snapshot_id
            .map(|i| i.to_string())
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "  Snapshot Merkle root: {}",
        status
            .snapshot_merkle_root
            .map(|r| hex(&r))
            .unwrap_or_else(|| "none".to_string())
    );
    println!("  Devices: {}", status.device_count);
    println!("  This device: {}", hex(&status.self_device_id));
    println!("  Key version: {}", status.key_version);
    println!("  Format version: {}", status.format_version);
    println!(
        "  Bootstrapped: {}",
        if status.bootstrapped { "YES" } else { "NO" }
    );
    Ok(())
}

fn cmd_snapshot(db: &PathBuf) -> Result<()> {
    let mut core = open_core(db)?;
    let id = core.snapshot()?;
    println!("Snapshot created: {}", id);
    Ok(())
}

fn parse_clock(s: &str) -> Result<veildb_core::LogicalClock> {
    let mut clock = veildb_core::LogicalClock::new();
    for part in s.split(',') {
        let (device, counter) = part
            .split_once(':')
            .ok_or_else(|| anyhow!("Invalid clock format: {part}"))?;
        let device_bytes = parse_hex(device)?;
        let counter: u64 = counter.parse()?;
        clock.entries.push((device_bytes, counter));
    }
    clock.entries.sort();
    Ok(clock)
}

fn format_clock(clock: &veildb_core::LogicalClock) -> String {
    clock
        .entries
        .iter()
        .map(|(d, c)| format!("{}:{}", hex(d), c))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_hex(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(anyhow!("Expected 64 hex chars, got {}", s.len()));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow!("Invalid hex: {e}"))?;
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_short(bytes: &[u8]) -> String {
    let h = hex(bytes);
    if h.len() > 16 {
        format!("{}...{}", &h[..8], &h[h.len() - 8..])
    } else {
        h
    }
}