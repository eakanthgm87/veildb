//! End-to-end multi-device sync tests across real OS processes.
//!
//! Each "device" is a real `veildb` CLI process with its own SQLite
//! database, signing key, and passphrase. Devices pair, sync over real
//! TCP, and their operation logs, merged state, and merge logs are
//! compared for convergence.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use tempfile::TempDir;

const PASSPHRASE: &str = "test-passphrase-1234";

struct Device {
    dir: TempDir,
    db: PathBuf,
}

fn run_cli(db: &Path, args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_veildb"))
        .arg("--db")
        .arg(db)
        .arg("--passphrase")
        .arg(PASSPHRASE)
        .args(args)
        .output()
        .expect("failed to spawn veildb process");

    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

fn init_device(tag: &str) -> Device {
    let dir = tempfile::Builder::new()
        .prefix(&format!("veildb-{tag}-"))
        .tempdir()
        .unwrap();
    let db = dir.path().join("device.vdb");
    let (ok, out) = run_cli(&db, &["init"]);
    assert!(ok, "init failed for {tag}: {out}");
    Device { dir, db }
}

fn get_value(dev: &Device, key: &str) -> String {
    let (ok, out) = run_cli(&dev.db, &["get", key]);
    assert!(ok, "get {key} failed: {out}");
    out.trim().to_string()
}

fn device_id(dev: &Device) -> String {
    let (ok, out) = run_cli(&dev.db, &["status"]);
    assert!(ok, "status failed: {out}");
    out.lines()
        .find(|l| l.contains("This device:"))
        .map(|l| l.split_whitespace().last().unwrap().to_string())
        .expect("device id in status output")
}

/// Reserve an ephemeral port by binding and closing.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Exchange pairing bundles so both devices trust each other and B
/// adopts A's database identity.
///
/// Order matters: A exports first; B imports it (adopting A's db_id
/// and salt while B's database is still empty) and approves A; then B
/// exports (now stamped with the adopted identity) and A imports it,
/// approving B.
fn pair(a: &Device, b: &Device) {
    let bundle_a = a.db.parent().unwrap().join("bundle-a.json");
    let bundle_b = b.db.parent().unwrap().join("bundle-b.json");
    let (ok, out) = run_cli(&a.db, &["device", "export-pairing", bundle_a.to_str().unwrap()]);
    assert!(ok, "export-pairing on A failed: {out}");
    let (ok, out) = run_cli(&b.db, &["device", "import-pairing", bundle_a.to_str().unwrap()]);
    assert!(ok, "import-pairing on B failed: {out}");
    let (ok, out) = run_cli(&b.db, &["device", "export-pairing", bundle_b.to_str().unwrap()]);
    assert!(ok, "export-pairing on B failed: {out}");
    let (ok, out) = run_cli(&a.db, &["device", "import-pairing", bundle_b.to_str().unwrap()]);
    assert!(ok, "import-pairing on A failed: {out}");
}

/// Run `sync --listen` on `server` in a background thread and dial it
/// from `client`. The listener's stdout is watched for the
/// "listening on" readiness marker before dialing, so the probe
/// connection is never mistaken for a sync session.
/// Returns (client_ok, client_out, listener_ok, listener_out).
fn sync_round(server: &Device, client: &Device) -> (bool, String, bool, String) {
    use std::io::BufRead;
    use std::process::Stdio;

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");

    let mut child = Command::new(env!("CARGO_BIN_EXE_veildb"))
        .arg("--db")
        .arg(&server.db)
        .arg("--passphrase")
        .arg(PASSPHRASE)
        .args(["sync", "--backend", "lan", "--listen", "--addr", &addr])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn listener process");

    // Watch stdout on a helper thread for the readiness marker, then
    // keep draining output so the listener never hits a closed pipe.
    // The thread signals `true` the moment the marker line is read, so
    // the test can dial immediately, and `false` once the process exits.
    let stdout = child.stdout.take().expect("piped stdout");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();
    let reader = std::thread::spawn(move || {
        let mut collected = String::new();
        for line in std::io::BufReader::new(stdout).lines() {
            match line {
                Ok(l) => {
                    if l.contains("listening on") {
                        let _ = ready_tx.send(true);
                    }
                    collected.push_str(&l);
                    collected.push('\n');
                }
                Err(_) => break,
            }
        }
        let _ = ready_tx.send(false); // EOF: never became ready
        collected
    });

    let ready = ready_rx.recv_timeout(Duration::from_secs(10)).unwrap_or(false);
    if !ready {
        // Give the reader a moment to collect the listener's output
        // and surface it before failing.
        std::thread::sleep(Duration::from_millis(500));
        let collected = reader.join().unwrap_or_default();
        panic!("listener never reported readiness on {addr}; output:\n{collected}");
    }

    let (ok, out) = run_cli(client.db.as_path(), &["sync", "--backend", "lan", "--addr", &addr]);
    let status = child.wait().expect("listener to exit");
    let listener_ok = status.success();
    let listener_out = reader.join().expect("reader thread");
    if !listener_ok {
        eprintln!("listener output: {listener_out}");
    }
    (ok, out, listener_ok, listener_out)
}

#[test]
fn two_processes_pair_and_sync_converge() {
    let a = init_device("a");
    let b = init_device("b");

    // Pairing first: exchange bundles so both trust each other and B
    // adopts A's database identity.
    pair(&a, &b);

    // Each device writes its own data.
    let (ok, out) = run_cli(&a.db, &["put", "greeting", "hello-from-a"]);
    assert!(ok, "put on A failed: {out}");
    let (ok, out) = run_cli(&b.db, &["put", "farewell", "bye-from-b"]);
    assert!(ok, "put on B failed: {out}");

    // Sync over real TCP: A listens, B dials.
    let (ok, out, listener_ok, _listener_out) = sync_round(&a, &b);
    assert!(ok && listener_ok, "sync failed: {out}");

    // Both devices must now hold both keys with identical values.
    assert_eq!(get_value(&a, "farewell"), "bye-from-b");
    assert_eq!(get_value(&b, "greeting"), "hello-from-a");

    // Merge logs must be queryable (empty here: no conflicting writes).
    let (ok_a, _) = run_cli(&a.db, &["merges"]);
    let (ok_b, _) = run_cli(&b.db, &["merges"]);
    assert!(ok_a && ok_b, "merges command failed");

    // A second sync round must transfer nothing (idempotent CRDT).
    let (ok, out, listener_ok, _listener_out) = sync_round(&a, &b);
    assert!(ok && listener_ok, "second sync failed: {out}");
    assert!(
        out.contains("Received: 0 ops"),
        "second sync should transfer nothing: {out}"
    );

    a.dir.close().unwrap();
    b.dir.close().unwrap();
}

#[test]
fn concurrent_writes_resolve_deterministically() {
    let a = init_device("c");
    let b = init_device("d");

    pair(&a, &b);

    // Concurrent writes to the SAME key before any sync.
    let (ok, _) = run_cli(&a.db, &["put", "conflict", "written-on-a"]);
    assert!(ok);
    let (ok, _) = run_cli(&b.db, &["put", "conflict", "written-on-b"]);
    assert!(ok);

    // A -> B sync, then B -> A sync.
    let (ok, out, listener_ok, _listener_out) = sync_round(&a, &b);
    assert!(ok && listener_ok, "sync B->A failed: {out}");
    let (ok, out, listener_ok, _listener_out) = sync_round(&b, &a);
    assert!(ok && listener_ok, "sync A->B failed: {out}");

    // Convergence: both devices see the same resolved value.
    let value_a = get_value(&a, "conflict");
    let value_b = get_value(&b, "conflict");
    assert_eq!(
        value_a, value_b,
        "concurrent writes did not converge to one value"
    );
    assert!(
        value_a == "written-on-a" || value_a == "written-on-b",
        "resolved value is not one of the original writes: {value_a}"
    );

    // The merge log records the resolution deterministically on both.
    let (ok_a, out_a) = run_cli(&a.db, &["merges"]);
    let (ok_b, out_b) = run_cli(&b.db, &["merges"]);
    assert!(ok_a && ok_b);
    assert!(
        out_a.contains("conflict") && out_a.contains("concurrent-device-tiebreak"),
        "merge log on A missing conflict entry: {out_a}"
    );
    assert!(
        out_b.contains("conflict") && out_b.contains("concurrent-device-tiebreak"),
        "merge log on B missing conflict entry: {out_b}"
    );

    a.dir.close().unwrap();
    b.dir.close().unwrap();
}

#[test]
fn revoked_device_is_rejected_immediately() {
    let a = init_device("e");
    let b = init_device("f");

    pair(&a, &b);

    // A writes something and syncs with B (allowed at this point).
    let (ok, _) = run_cli(&a.db, &["put", "secret", "shared-data"]);
    assert!(ok);

    let (ok, out, listener_ok, _listener_out) = sync_round(&a, &b);
    assert!(ok && listener_ok, "initial sync failed: {out}");

    // A revokes B. The next sync attempt from B must be refused,
    // proving the live trust check (not a stale snapshot) is used.
    let b_id = device_id(&b);
    let (ok, out) = run_cli(&a.db, &["device", "revoke", &b_id]);
    assert!(ok, "revoke failed: {out}");

    let (ok, out, listener_ok, _listener_out) = sync_round(&a, &b);
    assert!(!ok, "revoked device sync should have failed: {out}");
    // The trust rejection happens on the listener (A) side, which
    // drops the connection; the client (B) may observe either a clean
    // "not trusted" error or an aborted connection (os error 10053).
    // Either way the sync must not succeed. Surface the outputs for
    // debugging.
    if out.contains("not trusted") || out.contains("revoked") || out.contains("trust") {
        eprintln!("client saw trust rejection: {out}");
    } else {
        eprintln!("client saw raw failure (connection abort is expected): {out}");
    }
        assert!(!listener_ok, "listener should have errored on revoked peer");

    a.dir.close().unwrap();
    b.dir.close().unwrap();
}
