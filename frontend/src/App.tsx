import { useState, useEffect, useMemo, useRef } from "react";
import logoUrl from "./assets/veildb-logo.png";
import { api } from "./mockApi";
import { open } from "@tauri-apps/plugin-dialog";
import UserDemo from "./UserDemo";
import type {
  DbStatus,
  DeviceInfo,
  OperationSummary,
  PairingBundle,
  DiscoveredPeer,
  MergeEntry,
  SyncInfo,
} from "./types";

type Tab =
  | "dashboard"
  | "devices"
  | "sync"
  | "time-travel"
  | "backup"
  | "keys"
  | "graph"
  | "merkle"
  | "tamper"
  | "users"
  | "how-it-works";

interface IntegrityResult {
  status: string;
  verified: boolean;
}

interface DagNode {
  id: string;
  device_id: string;
  sequence: number;
  hash: string;
  parents: string[];
  signature_status: string;
  clock: string[];
}

interface DagEdge {
  from: string;
  to: string;
}

interface MerkleNode {
  id: string;
  hash: string;
  level: number;
  index: number;
  is_leaf: boolean;
}

interface MerkleTreeData {
  root: string;
  leaves: MerkleNode[];
  internal_nodes: MerkleNode[];
}

function hex(bytes: Uint8Array | string): string {
  if (typeof bytes === "string") {
    return bytes;
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Deterministic color per device_id.
// Vivid, well-separated palette so each device reads distinctly on AMOLED black.
const DEVICE_COLORS = [
  "#a78bfa", "#46e3b7", "#f472b6", "#fbbf24",
  "#60a5fa", "#f87171", "#c084fc", "#34d399",
  "#fb923c", "#38bdf8", "#e879f9", "#a3e635",
];
function deviceColor(deviceId: string): string {
  let hash = 0;
  for (let i = 0; i < deviceId.length; i++) {
    hash = (hash * 31 + deviceId.charCodeAt(i)) >>> 0;
  }
  return DEVICE_COLORS[hash % DEVICE_COLORS.length];
}

function VeilLogo({ size = 40 }: { size?: number }) {
  return (
    <img src={logoUrl} alt="VeilDB" className="object-contain shrink-0"
      style={{ width: size, height: size }} />
  );
}

function App() {
  const [dbPath, setDbPath] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [status, setStatus] = useState<DbStatus | null>(null);
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [operations, setOperations] = useState<OperationSummary[]>([]);
  const [activeTab, setActiveTab] = useState<Tab>("dashboard");
  const [error, setError] = useState<string | null>(null);
  const [integrity, setIntegrity] = useState<IntegrityResult | null>(null);
  const [syncLog, setSyncLog] = useState<string[]>([]);
  const [syncing, setSyncing] = useState(false);

  // Pairing state.
  const [pairingBundle, setPairingBundle] = useState<PairingBundle | null>(null);
  const [pairingJson, setPairingJson] = useState("");

  // Peer discovery state.
  const [discoveredPeers, setDiscoveredPeers] = useState<DiscoveredPeer[]>([]);
  const [discovering, setDiscovering] = useState(false);

  // Merge log state.
  const [merges, setMerges] = useState<MergeEntry[]>([]);

  // Sync peer address (optional — empty = auto-discover).
  const [syncAddr, setSyncAddr] = useState("127.0.0.1:8443");
  // Sync endpoint info for this machine.
  const [syncInfo, setSyncInfo] = useState<SyncInfo | null>(null);

  // Developer mode toggle (React state only, not persisted).
  const [devMode, setDevMode] = useState(false);

  // Key/value form state.
  const [keyInput, setKeyInput] = useState("");
  const [valueInput, setValueInput] = useState("");
  const [lookupKey, setLookupKey] = useState("");
  const [lookupValue, setLookupValue] = useState<string | null>(null);

  // Device trust form state.
  const [newPubkey, setNewPubkey] = useState("");

  // Time travel state.
  const [clockInput, setClockInput] = useState("");
  const [timeTravelEntries, setTimeTravelEntries] = useState<
    { key: string; value: string }[]
  >([]);

  // Backup state.
  const [backupPath, setBackupPath] = useState("");
  const [restorePath, setRestorePath] = useState("");

  // DAG / Merkle state.
  const [dagNodes, setDagNodes] = useState<DagNode[]>([]);
  const [dagEdges, setDagEdges] = useState<DagEdge[]>([]);
  const [merkleTree, setMerkleTree] = useState<MerkleTreeData | null>(null);
  const [selectedNode, setSelectedNode] = useState<DagNode | null>(null);
  const [tamperedHashes, setTamperedHashes] = useState<Set<string>>(new Set());

  // Tamper test state.
  const [tamperDeviceId, setTamperDeviceId] = useState("");
  const [tamperSequence, setTamperSequence] = useState("");
  const [tamperResult, setTamperResult] = useState<string | null>(null);

  // On mount (incl. returning from the #demo site, which remounts App),
  // restore the open DB so the user lands on the dashboard, not the open screen.
  useEffect(() => {
    const saved = localStorage.getItem("veildb.dbPath");
    if (saved) setDbPath(saved);
    refreshStatus();
  }, []);

  async function initDb() {
    setError(null);
    if (!dbPath) {
      setError("Select a database path first");
      return;
    }
    try {
      const result = await api.init(dbPath, passphrase);
      if (result.success) {
        localStorage.setItem("veildb.dbPath", dbPath);
        await refreshStatus();
      } else {
        setError(result.error?.message || "Init failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function openDb() {
    setError(null);
    if (!dbPath) {
      setError("Select a database path first");
      return;
    }
    try {
      const result = await api.open(dbPath, passphrase);
      if (result.success) {
        localStorage.setItem("veildb.dbPath", dbPath);
        await refreshStatus();
      } else {
        setError(result.error?.message || "Open failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function closeDb() {
    try {
      await api.close();
      localStorage.removeItem("veildb.dbPath");
      setStatus(null);
      setDevices([]);
      setOperations([]);
      setIntegrity(null);
      setDbPath(null);
      setDagNodes([]);
      setDagEdges([]);
      setMerkleTree(null);
      setSelectedNode(null);
      setTamperedHashes(new Set());
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function refreshStatus() {
    try {
      const result = await api.status();
      if (result.success && result.data) {
        setStatus(result.data);
      }
    } catch (e: any) {
      // ignore
    }
  }

  async function refreshDevices() {
    try {
      const result = await api.listDevices();
      if (result.success && result.data) {
        setDevices(result.data.devices || []);
      }
    } catch (e: any) {
      // ignore
    }
  }

  async function refreshOperations() {
    try {
      const result = await api.log();
      if (result.success && result.data) {
        setOperations(result.data.operations || []);
      }
    } catch (e: any) {
      // ignore
    }
  }

  async function refreshDag() {
    try {
      const result = await api.getDag();
      if (result.success && result.data) {
        setDagNodes(result.data.nodes || []);
        setDagEdges(result.data.edges || []);
      }
    } catch (e: any) {
      // ignore
    }
  }

  async function refreshMerkle() {
    try {
      const result = await api.getMerkleTree();
      if (result.success && result.data) {
        setMerkleTree(result.data);
      }
    } catch (e: any) {
      // ignore
    }
  }

  async function handlePut() {
    setError(null);
    try {
      const result = await api.put(keyInput, valueInput);
      if (result.success) {
        setKeyInput("");
        setValueInput("");
        refreshOperations();
        refreshStatus();
        refreshDag();
        refreshMerkle();
      } else {
        setError(result.error?.message || "Put failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleGet() {
    setError(null);
    setLookupValue(null);
    try {
      const result = await api.get(lookupKey);
      if (result.success && result.data !== undefined) {
        setLookupValue(result.data);
      } else {
        setError(result.error?.message || "Get failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleVerify() {
    setError(null);
    try {
      const result = await api.verify();
      if (result.success && result.data) {
        setIntegrity(result.data);
        // If tampered, highlight the failed hashes in the Merkle view.
        if (!result.data.verified) {
          const dag = await api.getDag();
          if (dag.success && dag.data) {
            const hashes = new Set<string>();
            (dag.data.nodes || []).forEach((n: DagNode) => {
              // In a real implementation, the verify response would
              // include failed hashes. For now, we highlight all nodes
              // when tampered.
              hashes.add(n.hash);
            });
            setTamperedHashes(hashes);
          }
        } else {
          setTamperedHashes(new Set());
        }
      } else {
        setError(result.error?.message || "Verify failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleTrust() {
    setError(null);
    try {
      const result = await api.trustDevice(newPubkey);
      if (result.success) {
        setNewPubkey("");
        refreshDevices();
        refreshStatus();
      } else {
        setError(result.error?.message || "Trust failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleRevoke(deviceId: string) {
    setError(null);
    try {
      const result = await api.revokeDevice(deviceId);
      if (result.success) {
        refreshDevices();
        refreshStatus();
      } else {
        setError(result.error?.message || "Revoke failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleBackup() {
    setError(null);
    if (!backupPath) {
      setError("Enter backup path");
      return;
    }
    try {
      const result = await api.backup(backupPath);
      if (result.success) {
        setBackupPath("");
        alert("Backup created successfully");
      } else {
        setError(result.error?.message || "Backup failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleRestore() {
    setError(null);
    if (!restorePath) {
      setError("Enter restore path");
      return;
    }
    try {
      const result = await api.restore(restorePath);
      if (result.success) {
        setRestorePath("");
        refreshStatus();
        refreshDevices();
        refreshOperations();
        refreshDag();
        refreshMerkle();
        alert("Restore completed");
      } else {
        setError(result.error?.message || "Restore failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleSnapshot() {
    setError(null);
    try {
      const result = await api.snapshot();
      if (result.success && result.data !== undefined) {
        alert(`Snapshot created: ${result.data}`);
        refreshStatus();
      } else {
        setError(result.error?.message || "Snapshot failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleSync() {
    setError(null);
    setSyncing(true);
    setSyncLog([]);
    try {
      // One-click: empty address = auto-discover + dial the first peer.
      const addr = syncAddr.trim() || null;
      const result = await api.syncNow(addr);
      if (result.success && result.data) {
        const d = result.data;
        if (d.success) {
          const lines: string[] = [];
          if (d.paired) lines.push(d.adopted ? "Auto-paired (joined the peer's database) + synced ✓" : "Auto-paired + synced ✓");
          else lines.push(`Sync completed: ${d.message}`);
          if (d.operations_received != null) lines.push(`Received: ${d.operations_received} ops`);
          if (d.operations_sent != null) lines.push(`Sent: ${d.operations_sent} ops`);
          if (d.operations_merged != null) lines.push(`Merged: ${d.operations_merged} ops`);
          if (d.merkle_root) lines.push(`Merkle root: ${d.merkle_root}`);
          lines.push("The other device also has a sync listener running, so no extra steps are needed.");
          setSyncLog(lines);
          refreshStatus();
          refreshDag();
          refreshMerkle();
          refreshDevices();
        } else {
          // Auto-discovery found nothing, or databases are different.
          setError(d.message || "Sync failed");
        }
      } else {
        const msg = result.error?.message || "Sync failed";
        if (
          msg.includes("reset by peer") ||
          msg.includes("broken pipe") ||
          msg.includes("No database is open") ||
          msg.includes("older version")
        ) {
          // These are NOT fire-and-forget connection failures: the peer
          // accepted the TCP connection, so the fault is on their side.
          setError(msg);
        } else if (msg.includes("refused") || msg.includes("10061") || msg.includes("connection")) {
          setError(`Could not connect to peer at ${syncAddr}. Make sure VeilDB is running with the database OPEN on the peer, then try again.`);
        } else {
          setError(msg);
        }
      }
    } catch (e: any) {
      const msg = e.message || String(e);
      if (
        msg.includes("reset by peer") ||
        msg.includes("broken pipe") ||
        msg.includes("No database is open") ||
        msg.includes("older version")
      ) {
        setError(msg);
      } else if (msg.includes("refused") || msg.includes("10061") || msg.includes("connection")) {
        setError(`Could not connect to peer at ${syncAddr}. Make sure VeilDB is running with the database OPEN on the peer, then try again.`);
      } else {
        setError(msg);
      }
    } finally {
      setSyncing(false);
    }
  }

  async function handleSyncInfo() {
    try {
      const result = await api.syncInfo();
      if (result.success && result.data) {
        setSyncInfo(result.data);
      }
    } catch {
      // Non-fatal: the sync tab still works without endpoint info.
    }
  }

  async function handleExportPairing() {
    setError(null);
    try {
      const result = await api.exportPairing();
      if (result.success && result.data) {
        setPairingBundle(result.data);
      } else {
        setError(result.error?.message || "Export pairing failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleImportPairing() {
    setError(null);
    if (!pairingJson.trim()) {
      setError("Paste a pairing bundle JSON first");
      return;
    }
    try {
      const result = await api.importPairing(pairingJson.trim());
      if (result.success) {
        setPairingJson("");
        setPairingBundle(null);
        refreshDevices();
        refreshStatus();
      } else {
        setError(result.error?.message || "Import pairing failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleDiscover() {
    setError(null);
    setDiscovering(true);
    setDiscoveredPeers([]);
    try {
      const result = await api.discoverPeers(2000);
      if (result.success && result.data) {
        setDiscoveredPeers(result.data.peers || []);
      } else {
        setError(result.error?.message || "Discovery failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    } finally {
      setDiscovering(false);
    }
  }

  async function handleListMerges() {
    setError(null);
    try {
      const result = await api.listMerges();
      if (result.success && result.data) {
        setMerges(result.data.entries || []);
      } else {
        setError(result.error?.message || "List merges failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleTimeTravel() {
    setError(null);
    if (!clockInput) {
      setError("Enter a logical clock");
      return;
    }
    try {
      const result = await api.queryAt(clockInput);
      if (result.success && result.data) {
        setTimeTravelEntries(result.data.entries || []);
      } else {
        setError(result.error?.message || "Query failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleRotateKey() {
    setError(null);
    try {
      const result = await api.rotateKey();
      if (result.success && result.data) {
        alert(`Key rotated to version ${result.data.key_version}`);
        refreshStatus();
      } else {
        setError(result.error?.message || "Rotate key failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  async function handleCorrupt() {
    setError(null);
    setTamperResult(null);
    if (!tamperDeviceId || !tamperSequence) {
      setError("Enter device ID and sequence");
      return;
    }
    try {
      const result = await api.devCorruptOperation(
        tamperDeviceId,
        parseInt(tamperSequence)
      );
      if (result.success) {
        setTamperResult("Operation corrupted. Run Verify to check integrity.");
        refreshDag();
        refreshMerkle();
      } else {
        setError(result.error?.message || "Corrupt failed");
      }
    } catch (e: any) {
      setError(e.message || String(e));
    }
  }

  // When DB opens or tab changes, refresh data.
  useEffect(() => {
    if (status) {
      refreshDevices();
      refreshOperations();
      refreshDag();
      refreshMerkle();
    }
  }, [status]);

  // Refresh local sync endpoint info once on mount.
  useEffect(() => {
    handleSyncInfo();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // File picker for the database file. Picks an existing .vdb file (Open);
  // for a brand-new database just type the path, or pick a folder's file.
  async function pickDbPath() {
    try {
      const selected = await open({
        defaultPath: dbPath || undefined,
        directory: false,
        multiple: false,
        title: "Select database file",
        filters: [{ name: "VeilDB", extensions: ["vdb"] }],
      });
      if (selected && typeof selected === "string") {
        setDbPath(selected);
      }
    } catch (e: any) {
      // Dialog unavailable (e.g. plain browser mock mode): keep the field
      // editable and surface why, rather than failing silently.
      setError(
        "File dialog unavailable — type the database path manually. (" +
          (e?.message || String(e)) +
          ")"
      );
    }
  }

  async function pickBackupPath() {
    try {
      const selected = await open({
        defaultPath: backupPath || undefined,
        directory: false,
        multiple: false,
      });
      if (selected && typeof selected === "string") {
        setBackupPath(selected);
      }
    } catch {
      const selected = prompt("Enter backup path:", "backup.vdb");
      if (selected) {
        setBackupPath(selected);
      }
    }
  }

  async function pickRestorePath() {
    try {
      const selected = await open({
        defaultPath: restorePath || undefined,
        directory: false,
        multiple: false,
      });
      if (selected && typeof selected === "string") {
        setRestorePath(selected);
      }
    } catch {
      const selected = prompt("Enter restore path:", "backup.vdb");
      if (selected) {
        setRestorePath(selected);
      }
    }
  }

  return (
    <div className="min-h-screen text-slate-200">
      <header className="glass-strong border-b border-slate-700 px-6 py-3.5 flex justify-between items-center sticky top-0 z-20">
        <div className="flex items-center gap-3">
          <VeilLogo size={44} />
          <p className="text-xs text-slate-400 leading-tight hidden sm:block">
            Privacy-first · zero-trust database
          </p>
        </div>
        {status && (
          <div className="flex items-center gap-3">
            <a
              href="#demo"
              className="group inline-flex items-center gap-2 text-sm font-medium text-slate-200 border border-white/15 hover:border-primary-400/70 hover:bg-primary-500/10 hover:text-white px-3.5 py-1.5 transition-colors"
            >
              <span className="h-1.5 w-1.5 rounded-full bg-mint-400 shadow-[0_0_8px_#46e3b7]" />
              Demo Site
              <span className="transition-transform group-hover:translate-x-0.5">→</span>
            </a>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={devMode}
                onChange={(e) => setDevMode(e.target.checked)}
                className="accent-red-500"
              />
              <span className={devMode ? "text-red-400 font-bold" : "text-slate-400"}>
                Developer Mode
              </span>
            </label>
          </div>
        )}
      </header>

      {!status ? (
        /* Centered, premium open/init card. */
        <div className="min-h-[calc(100vh-65px)] px-6 py-12 flex items-center">
          <div className="mx-auto w-full max-w-5xl grid lg:grid-cols-2 gap-12 items-center">
            {/* Left: hero */}
            <div className="space-y-7">
              <div className="inline-flex items-center gap-2 px-3 py-1 border border-primary-500/30 bg-primary-500/10 text-xs font-medium text-primary-300 uppercase tracking-wider">
                <span className="h-1.5 w-1.5 rounded-full bg-mint-400" />
                Local-first · End-to-end encrypted
              </div>
              <h1 className="text-5xl font-bold tracking-tight leading-[1.05]">
                A zero-trust database
                <br />
                <span className="gradient-text">that stays yours.</span>
              </h1>
              <p className="text-base text-slate-400 max-w-md leading-relaxed">
                Every write is encrypted, signed, and hash-chained into a verifiable
                Merkle tree. Sync across your devices with no server to trust.
              </p>
              <ul className="space-y-3.5">
                {[
                  ["#8b5cf6", "Encrypted key-value storage", "Encrypted at rest — your passphrase never leaves the device."],
                  ["#a78bfa", "Tamper-evident integrity", "Signed CRDT operations verified against a Merkle root."],
                  ["#46e3b7", "Serverless LAN sync", "Discover peers and converge automatically — no cloud."],
                ].map(([c, t, d]) => (
                  <li key={t} className="flex gap-3">
                    <span className="mt-1.5 h-1.5 w-1.5 rounded-full shrink-0" style={{ background: c }} />
                    <div>
                      <p className="text-sm font-medium text-slate-200">{t}</p>
                      <p className="text-xs text-slate-500">{d}</p>
                    </div>
                  </li>
                ))}
              </ul>
              <div className="font-mono text-xs glass p-4 max-w-md">
                <p className="text-slate-500"># open an encrypted database</p>
                <p className="mt-1">
                  <span className="text-mint-400">$</span>{" "}
                  <span className="text-slate-300">veildb open</span>{" "}
                  <span className="text-primary-300">./veildb.vdb</span>
                </p>
              </div>
            </div>

            {/* Right: open/init form */}
            <div className="glass p-8 shadow-glow">
              <h2 className="text-2xl font-bold tracking-tight mb-1">
                <span className="gradient-text">Open your database</span>
              </h2>
              <p className="text-sm text-slate-400 mb-6">
                Initialize a new encrypted database or open an existing one.
              </p>
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-medium uppercase tracking-wider text-slate-400 mb-1.5">
                    Database Path
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={dbPath || ""}
                      onChange={(e) => setDbPath(e.target.value)}
                      placeholder="veildb.vdb"
                      className="flex-1 field px-3 py-2 text-sm"
                    />
                    <button onClick={pickDbPath} className="btn-ghost text-sm px-4">
                      Browse
                    </button>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium uppercase tracking-wider text-slate-400 mb-1.5">
                    Passphrase
                  </label>
                  <input
                    type="password"
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                    placeholder="Enter passphrase"
                    className="w-full field px-3 py-2 text-sm"
                  />
                </div>
                {error && (
                  <div className="text-sm text-red-300 bg-red-500/10 border border-red-500/40 px-3 py-2">
                    {error}
                  </div>
                )}
                <div className="flex gap-3 pt-1">
                  <button onClick={initDb} className="btn-cta px-6 py-2.5 text-sm">
                    Initialize
                  </button>
                  <button onClick={openDb} className="btn-ghost px-6 py-2.5 text-sm font-medium">
                    Open
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
      <div className="flex">
        {/* Sidebar */}
        <nav className="w-64 bg-black/30 backdrop-blur-sm border-r border-white/10 min-h-[calc(100vh-65px)] p-4">
            <>
              <div className="mb-4 p-3 bg-black rounded-none border border-white/10">
                <p className="text-xs text-slate-400 mb-1">Database</p>
                <p className="text-sm font-mono truncate">{dbPath}</p>
                <p className="text-xs text-slate-400 mt-2">Device</p>
                <p className="text-sm font-mono truncate">
                  {hex(status.self_device_id)}
                </p>
                <button
                  onClick={closeDb}
                  className="mt-3 w-full text-xs btn-danger px-2 py-1"
                >
                  Close
                </button>
              </div>
              <div className="space-y-1">
                <TabButton
                  active={activeTab === "dashboard"}
                  onClick={() => setActiveTab("dashboard")}
                >
                  Dashboard
                </TabButton>
                <TabButton
                  active={activeTab === "keys"}
                  onClick={() => setActiveTab("keys")}
                >
                  Keys
                </TabButton>
                <TabButton
                  active={activeTab === "devices"}
                  onClick={() => setActiveTab("devices")}
                >
                  Devices
                </TabButton>
                <TabButton
                  active={activeTab === "sync"}
                  onClick={() => setActiveTab("sync")}
                >
                  Sync
                </TabButton>
                <TabButton
                  active={activeTab === "time-travel"}
                  onClick={() => setActiveTab("time-travel")}
                >
                  Time Travel
                </TabButton>
                <TabButton
                  active={activeTab === "backup"}
                  onClick={() => setActiveTab("backup")}
                >
                  Backup / Restore
                </TabButton>
                <TabButton
                  active={activeTab === "graph"}
                  onClick={() => setActiveTab("graph")}
                >
                  Operation Graph
                </TabButton>
                <TabButton
                  active={activeTab === "merkle"}
                  onClick={() => setActiveTab("merkle")}
                >
                  Merkle Tree
                </TabButton>
                {devMode && (
                  <TabButton
                    active={activeTab === "tamper"}
                    onClick={() => setActiveTab("tamper")}
                  >
                    <span className="text-red-400">Tamper Test</span>
                  </TabButton>
                )}
                <TabButton
                  active={activeTab === "users"}
                  onClick={() => setActiveTab("users")}
                >
                  User Demo
                </TabButton>
                <TabButton
                  active={activeTab === "how-it-works"}
                  onClick={() => setActiveTab("how-it-works")}
                >
                  How It Works
                </TabButton>
              </div>
            </>
        </nav>

        {/* Main content */}
        <main className="flex-1 min-w-0 p-6">
          {error && (
            <div className="mb-4 p-3 bg-red-950/50 border border-red-800/60 text-red-300 rounded-lg">
              {error}
            </div>
          )}

          {status && (
            <>
              {activeTab === "dashboard" && (
                <Dashboard
                  status={status}
                  integrity={integrity}
                  onVerify={handleVerify}
                  onSnapshot={handleSnapshot}
                  onRotateKey={handleRotateKey}
                  operations={operations}
                  onViewMerkle={() => setActiveTab("merkle")}
                />
              )}
              {activeTab === "keys" && (
                <Keys
                  keyInput={keyInput}
                  valueInput={valueInput}
                  lookupKey={lookupKey}
                  lookupValue={lookupValue}
                  onKeyChange={setKeyInput}
                  onValueChange={setValueInput}
                  onLookupKeyChange={setLookupKey}
                  onPut={handlePut}
                  onGet={handleGet}
                />
              )}
              {activeTab === "devices" && (
                <Devices
                  devices={devices}
                  newPubkey={newPubkey}
                  onNewPubkeyChange={setNewPubkey}
                  onTrust={handleTrust}
                  onRevoke={handleRevoke}
                />
              )}
              {activeTab === "sync" && (
                <Sync
                  syncing={syncing}
                  syncLog={syncLog}
                  syncAddr={syncAddr}
                  onSyncAddrChange={setSyncAddr}
                  onSync={handleSync}
                  onViewGraph={() => setActiveTab("graph")}
                  syncInfo={syncInfo}
                  pairingBundle={pairingBundle}
                  pairingJson={pairingJson}
                  onPairingJsonChange={setPairingJson}
                  onExportPairing={handleExportPairing}
                  onImportPairing={handleImportPairing}
                  discoveredPeers={discoveredPeers}
                  discovering={discovering}
                  onDiscover={handleDiscover}
                  merges={merges}
                  onListMerges={handleListMerges}
                />
              )}
              {activeTab === "time-travel" && (
                <TimeTravel
                  clockInput={clockInput}
                  entries={timeTravelEntries}
                  onClockChange={setClockInput}
                  onQuery={handleTimeTravel}
                />
              )}
              {activeTab === "backup" && (
                <Backup
                  backupPath={backupPath}
                  restorePath={restorePath}
                  onBackupPathChange={setBackupPath}
                  onRestorePathChange={setRestorePath}
                  onBackup={handleBackup}
                  onRestore={handleRestore}
                  onPickBackup={pickBackupPath}
                  onPickRestore={pickRestorePath}
                />
              )}
              {activeTab === "graph" && (
                <OperationGraph
                  nodes={dagNodes}
                  edges={dagEdges}
                  selectedNode={selectedNode}
                  onSelectNode={setSelectedNode}
                  tamperedHashes={tamperedHashes}
                />
              )}
              {activeTab === "merkle" && (
                <MerkleView
                  tree={merkleTree}
                  tamperedHashes={tamperedHashes}
                />
              )}
              {activeTab === "tamper" && devMode && (
                <TamperTest
                  operations={operations}
                  tamperDeviceId={tamperDeviceId}
                  tamperSequence={tamperSequence}
                  tamperResult={tamperResult}
                  onDeviceIdChange={setTamperDeviceId}
                  onSequenceChange={setTamperSequence}
                  onCorrupt={handleCorrupt}
                  onVerify={handleVerify}
                  integrity={integrity}
                />
              )}
              {activeTab === "users" && (
                <UserDemo />
              )}
              {activeTab === "how-it-works" && (
                <HowItWorks />
              )}
            </>
          )}
        </main>
      </div>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`group relative w-full text-left pl-4 pr-3 py-2.5 text-sm font-medium transition-colors ${active
          ? "text-white bg-primary-500/10"
          : "text-slate-400 hover:text-slate-100 hover:bg-white/[0.04]"
        }`}
    >
      <span
        className={`absolute left-0 top-1/2 -translate-y-1/2 w-0.5 rounded-full transition-all ${active
            ? "h-5 bg-primary-400"
            : "h-0 bg-slate-600 group-hover:h-4"
          }`}
      />
      {children}
    </button>
  );
}

function sparkSeries(n: number): number[] {
  // Rising cumulative series — an honest "operations over time" line.
  const points = Math.min(Math.max(n, 2), 24);
  return Array.from({ length: points }, (_, i) => i + 1);
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const w = 120, h = 30;
  const max = Math.max(...values), min = Math.min(...values);
  const span = max - min || 1;
  const pts = values
    .map((v, i) => `${(i / (values.length - 1)) * w},${h - ((v - min) / span) * (h - 4) - 2}`)
    .join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="mt-3 w-full h-8">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

function StatCard({ label, value, accent, series }: {
  label: string; value: number; accent: string; series?: number[];
}) {
  return (
    <div className="glass p-5">
      <div className="flex items-center gap-2">
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: accent }} />
        <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{label}</p>
      </div>
      <p className="text-3xl font-bold mt-1.5 tabular-nums">{value}</p>
      {series && <Sparkline values={series} color={accent} />}
    </div>
  );
}

function PageHeader({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div>
      <h2 className="text-3xl font-bold tracking-tight gradient-text">{title}</h2>
      <p className="text-sm text-slate-400 mt-1.5 max-w-2xl">{subtitle}</p>
    </div>
  );
}

function Dashboard({
  status,
  integrity,
  onVerify,
  onSnapshot,
  onRotateKey,
  operations,
  onViewMerkle,
}: {
  status: DbStatus;
  integrity: IntegrityResult | null;
  onVerify: () => void;
  onSnapshot: () => void;
  onRotateKey: () => void;
  operations: OperationSummary[];
  onViewMerkle: () => void;
}) {
  return (
    <div className="space-y-8">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">
          <span className="gradient-text">Dashboard</span>
        </h2>
        <p className="text-sm text-slate-400 mt-1">
          Live state of your encrypted, zero-trust database.
        </p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Operations" value={status.operation_count} accent="#8b5cf6" series={sparkSeries(operations.length)} />
        <StatCard label="Devices" value={status.device_count} accent="#46e3b7" />
        <StatCard label="Key Version" value={status.key_version} accent="#a78bfa" />
        <StatCard label="Format Version" value={status.format_version} accent="#8a8a93" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass p-5 flex flex-col">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400 mb-3">Integrity</p>
          {integrity ? (
            <div className="flex items-center gap-3 mt-auto">
              <span
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-sm cursor-pointer border ${integrity.verified
                    ? "text-mint-400 border-mint-400/30 bg-mint-400/10"
                    : "text-red-300 border-red-500/40 bg-red-500/10"
                  }`}
                onClick={onViewMerkle}
                title="Click to view Merkle tree"
              >
                {integrity.verified ? "●" : "▲"} {integrity.status}
              </span>
              <button onClick={onVerify} className="btn-ghost text-xs px-3 py-1.5">Re-verify</button>
            </div>
          ) : (
            <button onClick={onVerify} className="btn-cta text-xs px-4 py-2 mt-auto self-start">
              Verify Integrity
            </button>
          )}
        </div>

        <div className="glass p-5 flex flex-col">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400 mb-3">Key Management</p>
          <button onClick={onRotateKey} className="btn-ghost text-xs px-3 py-1.5 self-start">Rotate Key</button>
          <p className="text-xs text-slate-500 mt-auto pt-3">Current version: {status.key_version}</p>
        </div>

        <div className="glass p-5 flex flex-col">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400 mb-3">Snapshot</p>
          <button onClick={onSnapshot} className="btn-ghost text-xs px-3 py-1.5 self-start">Create Snapshot</button>
          {status.latest_snapshot_id && (
            <p className="text-xs text-slate-500 mt-auto pt-3">Latest: #{status.latest_snapshot_id}</p>
          )}
        </div>
      </div>

      <div className="glass p-5">
        <p className="text-xs font-medium uppercase tracking-wider text-slate-400 mb-2">Merkle Root</p>
        <p className="font-mono text-xs break-all text-slate-300">{hex(status.merkle_root)}</p>
      </div>

      <div className="glass p-5">
        <p className="text-xs font-medium uppercase tracking-wider text-slate-400 mb-3">Recent Operations</p>
        <div className="space-y-1.5 max-h-60 overflow-y-auto">
          {operations.length === 0 && (
            <p className="text-sm text-slate-500">No operations yet</p>
          )}
          {operations.map((op) => (
            <div
              key={`${op.device_id}-${op.sequence}`}
              className="text-xs flex justify-between items-center border-b border-slate-700/50 pb-1.5"
            >
              <span className="font-mono text-slate-300">#{op.sequence}</span>
              <span className="font-mono text-slate-500">
                {hex(op.device_id).slice(0, 16)}…
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Keys({
  keyInput,
  valueInput,
  lookupKey,
  lookupValue,
  onKeyChange,
  onValueChange,
  onLookupKeyChange,
  onPut,
  onGet,
}: {
  keyInput: string;
  valueInput: string;
  lookupKey: string;
  lookupValue: string | null;
  onKeyChange: (v: string) => void;
  onValueChange: (v: string) => void;
  onLookupKeyChange: (v: string) => void;
  onPut: () => void;
  onGet: () => void;
}) {
  const labelCls = "block text-[11px] font-medium uppercase tracking-wider text-slate-400 mb-1.5";
  const titleCls = "text-lg font-semibold flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full";
  return (
    <div className="space-y-6">
      <PageHeader title="Keys" subtitle="Store and retrieve encrypted key-value pairs — every write becomes a signed, hash-chained operation." />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
        {/* Put */}
        <div className="glass p-6 flex flex-col">
          <h3 className={titleCls}>Put Key-Value</h3>
          <div className="space-y-4 mt-5">
            <div>
              <label className={labelCls}>Key</label>
              <input
                type="text"
                value={keyInput}
                onChange={(e) => onKeyChange(e.target.value)}
                placeholder="user:alice"
                className="w-full field px-3.5 py-2.5 text-sm font-mono"
              />
            </div>
            <div>
              <label className={labelCls}>Value</label>
              <textarea
                value={valueInput}
                onChange={(e) => onValueChange(e.target.value)}
                placeholder={`{"role":"admin"}`}
                rows={4}
                className="w-full field px-3.5 py-2.5 text-sm font-mono resize-none"
              />
            </div>
          </div>
          <div className="flex justify-end mt-auto pt-5">
            <button onClick={onPut} className="btn-cta px-6 py-2.5 text-sm">Store</button>
          </div>
        </div>

        {/* Get */}
        <div className="glass p-6 flex flex-col">
          <h3 className={titleCls}>Get Value</h3>
          <div className="mt-5">
            <label className={labelCls}>Key</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={lookupKey}
                onChange={(e) => onLookupKeyChange(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") onGet(); }}
                placeholder="user:alice"
                className="flex-1 min-w-0 field px-3.5 py-2.5 text-sm font-mono"
              />
              <button onClick={onGet} className="btn-cta px-6 py-2.5 text-sm whitespace-nowrap">Retrieve</button>
            </div>
          </div>
          <div className="mt-5 flex-1 flex flex-col">
            <label className={labelCls}>Value</label>
            <div className={`field px-3.5 py-3 text-sm font-mono break-all flex-1 min-h-[6rem] ${lookupValue !== null ? "text-mint-300" : "text-slate-600"}`}>
              {lookupValue !== null ? lookupValue : "No value retrieved yet."}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Devices({
  devices,
  newPubkey,
  onNewPubkeyChange,
  onTrust,
  onRevoke,
}: {
  devices: DeviceInfo[];
  newPubkey: string;
  onNewPubkeyChange: (v: string) => void;
  onTrust: () => void;
  onRevoke: (id: string) => void;
}) {
  return (
    <div className="space-y-6">
      <PageHeader title="Devices" subtitle="Trust other devices by public key so they can sync and co-author this database." />

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Trust New Device</h3>
        <div className="space-y-2">
          <input
            type="text"
            value={newPubkey}
            onChange={(e) => onNewPubkeyChange(e.target.value)}
            placeholder="Public key (64 hex chars)"
            className="w-full field px-3 py-2 text-sm font-mono"
          />
          <button
            onClick={onTrust}
            className="btn-cta px-5 py-2.5 text-sm"
          >
            Trust Device
          </button>
        </div>
      </div>

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Trusted Devices</h3>
        <div className="space-y-2">
          {devices.map((d) => (
            <div
              key={d.device_id}
              className="flex items-center justify-between bg-dark-900 rounded border border-slate-700 p-2"
            >
              <div>
                <p className="text-sm font-mono">{hex(d.device_id)}</p>
                <p className="text-xs text-slate-400">
                  {d.trusted ? "Trusted" : "Revoked"}
                </p>
              </div>
              {d.trusted && (
                <button
                  onClick={() => onRevoke(d.device_id)}
                  className="text-xs btn-danger px-2 py-1"
                >
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Sync({
  syncing,
  syncLog,
  syncAddr,
  onSyncAddrChange,
  onSync,
  onViewGraph,
  syncInfo,
  pairingBundle,
  pairingJson,
  onPairingJsonChange,
  onExportPairing,
  onImportPairing,
  discoveredPeers,
  discovering,
  onDiscover,
  merges,
  onListMerges,
}: {
  syncing: boolean;
  syncLog: string[];
  syncAddr: string;
  onSyncAddrChange: (v: string) => void;
  onSync: () => void;
  onViewGraph: () => void;
  syncInfo?: SyncInfo | null;
  pairingBundle: PairingBundle | null;
  pairingJson: string;
  onPairingJsonChange: (v: string) => void;
  onExportPairing: () => void;
  onImportPairing: () => void;
  discoveredPeers: DiscoveredPeer[];
  discovering: boolean;
  onDiscover: () => void;
  merges: MergeEntry[];
  onListMerges: () => void;
}) {
  return (
    <div className="space-y-6">
      <PageHeader title="Sync" subtitle="Discover peers and converge databases over your LAN — no central server required." />

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">LAN Sync — one click</h3>
        <p className="text-xs text-slate-400 mb-2">
          VeilDB runs a background sync listener and broadcasts its
          presence on the LAN automatically.{syncInfo ? " " : ""}
          {syncInfo && (
            <span className="text-emerald-400">
              This device: {syncInfo.local_ip}:{syncInfo.sync_port}
              {syncInfo.beacon_running ? " · beacon on" : " · beacon off"}
            </span>
          )}
        </p>
        <div className="space-y-2">
          <div>
            <label className="block text-xs text-slate-400 mb-1">
              Peer IP (leave empty to auto-discover on the LAN)
            </label>
            <input
              type="text"
              value={syncAddr}
              onChange={(e) => onSyncAddrChange(e.target.value)}
              placeholder="Leave empty to find peers automatically, or 192.168.1.106:8443"
              className="w-full field px-3 py-2 text-sm font-mono"
            />
          </div>
          <button
            onClick={onSync}
            disabled={syncing}
            className="btn-cta disabled:opacity-50 px-5 py-2.5 text-sm font-semibold"
          >
            {syncing ? "Syncing…" : "⚡ Sync Data Now"}
          </button>
          <p className="text-xs text-slate-500">
            No listener setup needed on either device — pressing the button
            discovers peers, pairs automatically (same passphrase), merges
            with no conflicts, and converges both databases.
          </p>
          <button
            onClick={onViewGraph}
            className="btn-ghost px-5 py-2.5 text-sm"
          >
            View Operation Graph
          </button>
        </div>
      </div>

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Pairing</h3>
        <p className="text-xs text-slate-400 mb-2">
          Export a pairing bundle to let another device join this database, or
          paste a bundle you received to join an existing one.
        </p>
        <div className="space-y-2">
          <button
            onClick={onExportPairing}
            className="btn-cta px-5 py-2.5 text-sm"
          >
            Export Pairing Bundle
          </button>
          {pairingBundle && (
            <div className="bg-dark-900 border border-slate-700 rounded p-2">
              <p className="text-xs text-slate-400 mb-1">
                Bundle (give this to the joining device):
              </p>
              <pre className="text-xs font-mono break-all whitespace-pre-wrap max-h-40 overflow-y-auto">
                {pairingBundle.json}
              </pre>
              <button
                onClick={() => navigator.clipboard?.writeText(pairingBundle.json)}
                className="mt-1 text-xs text-primary-400 hover:text-primary-300"
              >
                Copy to clipboard
              </button>
            </div>
          )}
          <textarea
            value={pairingJson}
            onChange={(e) => onPairingJsonChange(e.target.value)}
            placeholder="Paste a pairing bundle JSON here, then click Import..."
            rows={4}
            className="w-full field px-3 py-2 text-xs font-mono"
          />
          <button
            onClick={onImportPairing}
            className="btn-cta px-5 py-2.5 text-sm"
          >
            Import Pairing Bundle
          </button>
        </div>
      </div>

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Peer Discovery</h3>
        <div className="space-y-2">
          <button
            onClick={onDiscover}
            disabled={discovering}
            className="btn-cta disabled:opacity-50 px-5 py-2.5 text-sm"
          >
            {discovering ? "Discovering..." : "Discover LAN Peers"}
          </button>
          {discoveredPeers.length > 0 ? (
            <div className="space-y-1">
              {discoveredPeers.map((p) => (
                <div
                  key={p.device_id}
                  className="flex items-center justify-between bg-dark-900 rounded border border-slate-700 p-2"
                >
                  <div>
                    <p className="text-xs font-mono">
                      {hex(p.device_id)}{" "}
                      {p.same_db && (
                        <span className="text-emerald-400">· same DB</span>
                      )}
                      {p.same_db === false && (
                        <span className="text-amber-400">· auto-join</span>
                      )}
                    </p>
                    <p className="text-xs text-slate-400 font-mono">
                      {p.sync_addr}
                    </p>
                  </div>
                  <button
                    onClick={() => {
                      onSyncAddrChange(p.sync_addr);
                      onSync();
                    }}
                    className="text-xs btn-cta px-2 py-1"
                  >
                    Sync
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-400">
              No peers found yet. Press "Sync Data Now" with an empty address
              to auto-discover on the local network.
              {syncInfo?.local_ip
                ? ` Your IP: ${syncInfo.local_ip}:${syncInfo.sync_port}`
                : ""}
            </p>
          )}
        </div>
      </div>

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Merge Log</h3>
        <div className="space-y-2">
          <button
            onClick={onListMerges}
            className="btn-cta px-5 py-2.5 text-sm"
          >
            View Merge Log
          </button>
          {merges.length > 0 ? (
            <div className="space-y-1">
              {merges.map((m, i) => (
                <div
                  key={i}
                  className="bg-dark-900 rounded border border-slate-700 p-2"
                >
                  <p className="text-xs font-mono">
                    {m.key} → {hex(m.winner_value)}
                  </p>
                  <p className="text-xs text-slate-400">
                    winner: {hex(m.winner_device_id)} · resolved:{" "}
                    {m.resolved_at}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-400">
              No conflict merges recorded yet.
            </p>
          )}
        </div>
      </div>

      {syncLog.length > 0 && (
        <div className="glass p-5">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Sync Log</h3>
          <div className="space-y-1">
            {syncLog.map((line, i) => (
              <p key={i} className="text-sm font-mono">
                {line}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function TimeTravel({
  clockInput,
  entries,
  onClockChange,
  onQuery,
}: {
  clockInput: string;
  entries: { key: string; value: string }[];
  onClockChange: (v: string) => void;
  onQuery: () => void;
}) {
  return (
    <div className="space-y-6">
      <PageHeader title="Time Travel" subtitle="Reconstruct the exact database state at any point in the logical-clock history." />

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">
          Query at Logical Clock
        </h3>
        <div className="space-y-2">
          <input
            type="text"
            value={clockInput}
            onChange={(e) => onClockChange(e.target.value)}
            placeholder='e.g. "device_id:counter"'
            className="w-full field px-3 py-2 text-sm font-mono"
          />
          <button
            onClick={onQuery}
            className="btn-cta px-5 py-2.5 text-sm"
          >
            Query
          </button>
        </div>
      </div>

      {entries.length > 0 && (
        <div className="glass p-5">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">State at Clock</h3>
          <div className="space-y-1 max-h-96 overflow-y-auto">
            {entries.map((e, i) => (
              <div
                key={i}
                className="flex justify-between bg-dark-900 rounded border border-slate-700 p-2"
              >
                <span className="text-sm">{e.key}</span>
                <span className="text-sm text-slate-400">{e.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Backup({
  backupPath,
  restorePath,
  onBackupPathChange,
  onRestorePathChange,
  onBackup,
  onRestore,
  onPickBackup,
  onPickRestore,
}: {
  backupPath: string;
  restorePath: string;
  onBackupPathChange: (v: string) => void;
  onRestorePathChange: (v: string) => void;
  onBackup: () => void;
  onRestore: () => void;
  onPickBackup: () => void;
  onPickRestore: () => void;
}) {
  return (
    <div className="space-y-6">
      <PageHeader title="Backup / Restore" subtitle="Create encrypted archive snapshots, or restore the database from one." />

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Backup</h3>
        <div className="space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={backupPath}
              onChange={(e) => onBackupPathChange(e.target.value)}
              placeholder="backup.vdb"
              className="flex-1 field px-3 py-2 text-sm"
            />
            <button
              onClick={onPickBackup}
              className="text-sm btn-ghost px-3 py-2"
            >
              Browse
            </button>
          </div>
          <button
            onClick={onBackup}
            className="btn-cta px-5 py-2.5 text-sm"
          >
            Create Backup
          </button>
        </div>
      </div>

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Restore</h3>
        <div className="space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={restorePath}
              onChange={(e) => onRestorePathChange(e.target.value)}
              placeholder="backup.vdb"
              className="flex-1 field px-3 py-2 text-sm"
            />
            <button
              onClick={onPickRestore}
              className="text-sm btn-ghost px-3 py-2"
            >
              Browse
            </button>
          </div>
          <button
            onClick={onRestore}
            className="btn-danger px-5 py-2.5 text-sm"
          >
            Restore (overwrites current DB)
          </button>
        </div>
      </div>
    </div>
  );
}

// Zoomable / pannable SVG viewport: drag to pan, +/- buttons to zoom, double-click to reset.
function ZoomPanSvg({
  box,
  height,
  children,
}: {
  box: { x: number; y: number; w: number; h: number };
  height: number;
  children: React.ReactNode;
}) {
  const [vb, setVb] = useState(box);
  const [dragging, setDragging] = useState(false);
  const svgRef = useRef<SVGSVGElement>(null);
  const drag = useRef<{ cx: number; cy: number; vx: number; vy: number } | null>(null);

  // Reset when the underlying data (box) changes.
  useEffect(() => { setVb(box); }, [box.x, box.y, box.w, box.h]);

  // Pinch-to-zoom: trackpad (wheel + ctrlKey) and two-finger touch; one-finger touch pans.
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const clampW = (w: number) => Math.max(40, Math.min(w, box.w * 6));
    const clampH = (h: number) => Math.max(40, Math.min(h, box.h * 6));
    const rect = () => el.getBoundingClientRect();
    const toSvg = (cx: number, cy: number, v: typeof box) => {
      const r = rect();
      return { x: v.x + ((cx - r.left) / r.width) * v.w, y: v.y + ((cy - r.top) / r.height) * v.h };
    };
    const zoomAt = (cx: number, cy: number, f: number) =>
      setVb((v) => {
        const p = toSvg(cx, cy, v);
        const nw = clampW(v.w * f), nh = clampH(v.h * f);
        return { x: p.x - (p.x - v.x) * (nw / v.w), y: p.y - (p.y - v.y) * (nh / v.h), w: nw, h: nh };
      });

    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey) return; // only the trackpad pinch gesture; leave normal scroll alone
      e.preventDefault();
      zoomAt(e.clientX, e.clientY, e.deltaY < 0 ? 0.9 : 1 / 0.9);
    };

    const dist = (t: TouchList) => Math.hypot(t[0].clientX - t[1].clientX, t[0].clientY - t[1].clientY);
    const mid = (t: TouchList) => ({ x: (t[0].clientX + t[1].clientX) / 2, y: (t[0].clientY + t[1].clientY) / 2 });
    let pd = 0; // last pinch distance
    let tp: { x: number; y: number } | null = null; // last one-finger point

    const onTouchStart = (e: TouchEvent) => {
      if (e.touches.length === 2) { pd = dist(e.touches); tp = null; }
      else if (e.touches.length === 1) { tp = { x: e.touches[0].clientX, y: e.touches[0].clientY }; }
    };
    const onTouchMove = (e: TouchEvent) => {
      if (e.touches.length === 2 && pd) {
        e.preventDefault();
        const nd = dist(e.touches), m = mid(e.touches), f = pd / nd;
        pd = nd;
        zoomAt(m.x, m.y, f);
      } else if (e.touches.length === 1 && tp) {
        e.preventDefault();
        const t = e.touches[0], r = rect();
        const dx = t.clientX - tp.x, dy = t.clientY - tp.y;
        tp = { x: t.clientX, y: t.clientY };
        setVb((v) => ({ ...v, x: v.x - (dx / r.width) * v.w, y: v.y - (dy / r.height) * v.h }));
      }
    };
    const onTouchEnd = (e: TouchEvent) => {
      if (e.touches.length < 2) pd = 0;
      if (e.touches.length === 0) tp = null;
    };

    el.addEventListener("wheel", onWheel, { passive: false });
    el.addEventListener("touchstart", onTouchStart, { passive: false });
    el.addEventListener("touchmove", onTouchMove, { passive: false });
    el.addEventListener("touchend", onTouchEnd);
    return () => {
      el.removeEventListener("wheel", onWheel);
      el.removeEventListener("touchstart", onTouchStart);
      el.removeEventListener("touchmove", onTouchMove);
      el.removeEventListener("touchend", onTouchEnd);
    };
  }, [box.w, box.h, box.x, box.y]);

  const zoom = (f: number) =>
    setVb((v) => {
      const cx = v.x + v.w / 2, cy = v.y + v.h / 2;
      const nw = Math.max(40, Math.min(v.w * f, box.w * 6));
      const nh = Math.max(40, Math.min(v.h * f, box.h * 6));
      return { x: cx - nw / 2, y: cy - nh / 2, w: nw, h: nh };
    });

  const zBtn = "h-8 w-8 flex items-center justify-center bg-black/70 border border-white/15 text-slate-200 hover:border-primary-400/70 hover:text-white text-lg leading-none transition-colors";

  return (
    <div className="relative" style={{ overflow: "hidden" }}>
      <svg
        ref={svgRef}
        width="100%"
        height={height}
        viewBox={`${vb.x} ${vb.y} ${vb.w} ${vb.h}`}
        className="block select-none touch-none"
        style={{ cursor: dragging ? "grabbing" : "grab" }}
        onMouseDown={(e) => { drag.current = { cx: e.clientX, cy: e.clientY, vx: vb.x, vy: vb.y }; setDragging(true); }}
        onMouseMove={(e) => {
          const d = drag.current;
          if (!d || !svgRef.current) return;
          const r = svgRef.current.getBoundingClientRect();
          const dx = ((e.clientX - d.cx) / r.width) * vb.w;
          const dy = ((e.clientY - d.cy) / r.height) * vb.h;
          setVb((v) => ({ ...v, x: d.vx - dx, y: d.vy - dy }));
        }}
        onMouseUp={() => { drag.current = null; setDragging(false); }}
        onMouseLeave={() => { drag.current = null; setDragging(false); }}
        onDoubleClick={() => setVb(box)}
      >
        {children}
      </svg>
      <div className="absolute top-2 right-2 flex flex-col gap-1">
        <button onClick={() => zoom(0.8)} className={zBtn} title="Zoom in">+</button>
        <button onClick={() => zoom(1 / 0.8)} className={zBtn} title="Zoom out">−</button>
        <button onClick={() => setVb(box)} className={zBtn} title="Reset view">⤢</button>
      </div>
    </div>
  );
}

function OperationGraph({
  nodes,
  edges,
  selectedNode,
  onSelectNode,
  tamperedHashes,
}: {
  nodes: DagNode[];
  edges: DagEdge[];
  selectedNode: DagNode | null;
  onSelectNode: (n: DagNode | null) => void;
  tamperedHashes: Set<string>;
}) {
  const devices = Array.from(new Set(nodes.map((n) => n.device_id)));

  // Layout: single device → organic force graph; multiple devices → swimlanes
  // (each device aligned along the same left→right path by sequence, offset into
  // its own colored lane so synced operations line up vertically).
  const graph = useMemo(() => {
    const P = new Map<string, { x: number; y: number; vx: number; vy: number }>();
    const devs = Array.from(new Set(nodes.map((n) => n.device_id)));
    const deg = new Map<string, number>();
    edges.forEach((e) => { deg.set(e.from, (deg.get(e.from) || 0) + 1); deg.set(e.to, (deg.get(e.to) || 0) + 1); });

    if (nodes.length === 0) return { P, deg, box: { x: 0, y: 0, w: 800, h: 500 }, labels: [] as { d: string; x: number; y: number; color: string }[] };

    // --- Multi-device: aligned swimlanes ---
    if (devs.length > 1) {
      const lane = new Map(devs.map((d, i) => [d, i]));
      const minSeq = Math.min(...nodes.map((n) => n.sequence));
      const COL = 120, LANE = 132, PADX = 90, PADY = 86;
      nodes.forEach((n) => {
        P.set(n.hash, { x: PADX + (n.sequence - minSeq) * COL, y: PADY + lane.get(n.device_id)! * LANE, vx: 0, vy: 0 });
      });
      const xs = Array.from(P.values()).map((p) => p.x), ys = Array.from(P.values()).map((p) => p.y);
      const pad = 60;
      const minX = Math.min(...xs) - pad, minY = Math.min(...ys) - pad;
      const w = Math.max(...xs) - minX + pad, h = Math.max(...ys) - minY + pad;
      const labels = devs.map((d) => {
        const pts = nodes.filter((n) => n.device_id === d).map((n) => P.get(n.hash)!);
        const left = pts.reduce((a, b) => (a.x < b.x ? a : b));
        return { d, x: left.x, y: left.y - 24, color: deviceColor(d) };
      });
      return { P, deg, box: { x: minX, y: minY, w, h }, labels };
    }

    // --- Single device: force-directed (Obsidian-style) ---
    const W = 820, H = 520;
    nodes.forEach((n, i) => {
      const a = (i / Math.max(nodes.length, 1)) * Math.PI * 2;
      const s = (parseInt(n.hash.slice(0, 4), 16) || 0) / 65535;
      P.set(n.hash, { x: W / 2 + Math.cos(a) * (130 + s * 70), y: H / 2 + Math.sin(a) * (120 + s * 60), vx: 0, vy: 0 });
    });
    const E = edges.filter((e) => P.has(e.from) && P.has(e.to));
    for (let it = 0; it < 200; it++) {
      const a = Array.from(P.values());
      for (let i = 0; i < a.length; i++)
        for (let j = i + 1; j < a.length; j++) {
          const p = a[i], q = a[j];
          const dx = p.x - q.x, dy = p.y - q.y;
          const d2 = dx * dx + dy * dy || 0.01, d = Math.sqrt(d2);
          const rep = 2600 / d2, fx = (dx / d) * rep, fy = (dy / d) * rep;
          p.vx += fx; p.vy += fy; q.vx -= fx; q.vy -= fy;
        }
      E.forEach((e) => {
        const p = P.get(e.from)!, q = P.get(e.to)!;
        const dx = q.x - p.x, dy = q.y - p.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.01, f = (d - 104) * 0.045;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        p.vx += fx; p.vy += fy; q.vx -= fx; q.vy -= fy;
      });
      P.forEach((p) => {
        p.vx += (W / 2 - p.x) * 0.005; p.vy += (H / 2 - p.y) * 0.005;
        p.x += Math.max(-14, Math.min(14, p.vx)); p.y += Math.max(-14, Math.min(14, p.vy));
        p.vx *= 0.82; p.vy *= 0.82;
      });
    }
    const xs = Array.from(P.values()).map((p) => p.x), ys = Array.from(P.values()).map((p) => p.y);
    const pad = 60;
    const minX = Math.min(...xs, 0) - pad, minY = Math.min(...ys, 0) - pad;
    const vw = Math.max(...xs, W) + pad - minX, vh = Math.max(...ys, H) + pad - minY;
    return { P, deg, box: { x: minX, y: minY, w: vw, h: vh }, labels: [] as { d: string; x: number; y: number; color: string }[] };
  }, [nodes, edges]);

  const rOf = (h: string) => 7 + Math.min(7, (graph.deg.get(h) || 0) * 1.6);

  return (
    <div className="space-y-6">
      <PageHeader title="Operation Graph" subtitle="Multi-parent operation DAG, color-coded by device. Click a node for details." />

      <div className="glass p-5">
        {/* Legend + interaction hint */}
        <div className="flex items-center justify-between gap-4 mb-2 flex-wrap">
          <div className="flex gap-4 flex-wrap">
            {devices.map((d) => (
              <div key={d} className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: deviceColor(d), boxShadow: `0 0 8px ${deviceColor(d)}` }} />
                <span className="text-xs font-mono text-slate-400">{d.slice(0, 8)}…</span>
              </div>
            ))}
          </div>
          <span className="text-[11px] text-slate-600">pinch or +/− to zoom · drag to pan · double-click to reset</span>
        </div>

        {nodes.length === 0 ? (
          <p className="text-sm text-slate-500">No operations yet.</p>
        ) : (
          <ZoomPanSvg box={graph.box} height={520}>
            <defs>
              <filter id="dag-glow" x="-120%" y="-120%" width="340%" height="340%">
                <feGaussianBlur stdDeviation="4" result="b" />
                <feMerge>
                  <feMergeNode in="b" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
              <marker id="dag-arrow" markerWidth="9" markerHeight="9" refX="6.5" refY="4" orient="auto">
                <path d="M1,1 L7,4 L1,7" fill="none" stroke="#c4b5fd" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
              </marker>
            </defs>

            {/* Edges — directed links between dots */}
            {edges.map((e, i) => {
              const a = graph.P.get(e.from), b = graph.P.get(e.to);
              if (!a || !b) return null;
              const ra = rOf(e.from), rb = rOf(e.to);
              let dx = b.x - a.x, dy = b.y - a.y;
              const d = Math.hypot(dx, dy) || 1, ux = dx / d, uy = dy / d;
              return (
                <line key={i}
                  x1={a.x + ux * (ra + 2)} y1={a.y + uy * (ra + 2)}
                  x2={b.x - ux * (rb + 6)} y2={b.y - uy * (rb + 6)}
                  stroke="rgba(167,139,250,0.35)" strokeWidth={1.4} markerEnd="url(#dag-arrow)" />
              );
            })}

            {/* Nodes — glowing dots with labels */}
            {nodes.map((n) => {
              const p = graph.P.get(n.hash);
              if (!p) return null;
              const c = deviceColor(n.device_id);
              const tampered = tamperedHashes.has(n.hash);
              const sel = selectedNode?.hash === n.hash;
              const r = rOf(n.hash);
              const fill = tampered ? "#ef4444" : c;
              return (
                <g key={n.hash} transform={`translate(${p.x},${p.y})`}
                  onClick={() => onSelectNode(n)} style={{ cursor: "pointer" }}>
                  {sel && <circle r={r + 6} fill="none" stroke="#e4e4e7" strokeWidth="1.5" opacity="0.8" />}
                  <circle r={r} fill={fill} filter="url(#dag-glow)"
                    stroke={sel ? "#fff" : "rgba(0,0,0,0.5)"} strokeWidth={sel ? 2 : 1} />
                  <circle r={Math.max(r - 3, 2)} fill="rgba(255,255,255,0.25)" />
                  <text y={r + 14} textAnchor="middle" fontFamily="JetBrains Mono, monospace"
                    fontSize="11" fontWeight={sel ? 700 : 500} fill={sel ? "#e4e4e7" : "#8a8a93"}>
                    {n.id}
                  </text>
                  {tampered && (
                    <text y={r + 26} textAnchor="middle" fontSize="9" fontWeight="700" fill="#fca5a5">TAMPERED</text>
                  )}
                </g>
              );
            })}

            {/* Device cluster labels */}
            {graph.labels.map((l) => (
              <text key={l.d} x={l.x} y={l.y} textAnchor="middle" fontFamily="JetBrains Mono, monospace"
                fontSize="11" fontWeight="700" fill={l.color} opacity="0.9">
                {l.d.slice(0, 8)}…
              </text>
            ))}
          </ZoomPanSvg>
        )}
      </div>

      {/* Side panel */}
      {selectedNode && (
        <div className="glass p-5">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Operation Details</h3>
          <div className="space-y-2 text-sm">
            <p><span className="text-slate-400">ID:</span> <span className="font-mono">{selectedNode.id}</span></p>
            <p><span className="text-slate-400">Device:</span> <span className="font-mono">{selectedNode.device_id}</span></p>
            <p><span className="text-slate-400">Sequence:</span> {selectedNode.sequence}</p>
            <p><span className="text-slate-400">Hash:</span> <span className="font-mono break-all">{selectedNode.hash}</span></p>
            <p><span className="text-slate-400">Parents:</span> <span className="font-mono">{selectedNode.parents.length}</span></p>
            <p><span className="text-slate-400">Signature:</span> {selectedNode.signature_status}</p>
            <p><span className="text-slate-400">Clock:</span> <span className="font-mono">{selectedNode.clock.join(", ")}</span></p>
            <button onClick={() => onSelectNode(null)} className="btn-ghost mt-2 px-3 py-1.5 text-sm">
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function MerkleView({
  tree,
  tamperedHashes,
}: {
  tree: MerkleTreeData | null;
  tamperedHashes: Set<string>;
}) {
  if (!tree) {
    return (
      <div className="space-y-6">
        <PageHeader title="Merkle Tree" subtitle="No tree data available yet — store a key to build the first leaves." />
      </div>
    );
  }

  // Group nodes by level (0 = leaves at the bottom).
  const maxLevel = Math.max(
    ...tree.leaves.map((l) => l.level),
    ...tree.internal_nodes.map((n) => n.level),
    0
  );
  const levels: MerkleNode[][] = [];
  for (let l = 0; l <= maxLevel; l++) {
    levels.push(
      [...tree.leaves, ...tree.internal_nodes]
        .filter((n) => n.level === l)
        .sort((a, b) => a.index - b.index)
    );
  }

  const LEVELH = 112, PADX = 48, PADY = 64;
  const maxCount = Math.max(...levels.map((l) => l.length), 1);
  const W = Math.max(620, maxCount * 140) + PADX * 2;
  const height = PADY * 2 + maxLevel * LEVELH;
  const cx = (level: number, index: number) =>
    PADX + ((index + 0.5) * (W - PADX * 2)) / levels[level].length;
  const cy = (level: number) => PADY + (maxLevel - level) * LEVELH;
  const kind = (level: number, hash: string) =>
    hash === tree.root ? "root" : level === 0 ? "leaf" : "int";
  const colorOf = (k: string, tampered: boolean) =>
    tampered ? "#ef4444" : k === "root" ? "#a78bfa" : k === "leaf" ? "#46e3b7" : "#8b5cf6";
  const radOf = (k: string) => (k === "root" ? 13 : k === "leaf" ? 8 : 10);

  return (
    <div className="space-y-6">
      <PageHeader title="Merkle Tree" subtitle="Root at top, branching down to the operation-hash leaves." />

      <div className="glass p-5 overflow-hidden">
        <div className="flex justify-end mb-1">
          <span className="text-[11px] text-slate-600">pinch or +/− to zoom · drag to pan · double-click to reset</span>
        </div>
        <ZoomPanSvg box={{ x: 0, y: 0, w: W, h: height }} height={520}>
          <defs>
            <filter id="mk-glow" x="-150%" y="-150%" width="400%" height="400%">
              <feGaussianBlur stdDeviation="4" result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <marker id="mk-arrow" markerWidth="9" markerHeight="9" refX="6.5" refY="4" orient="auto">
              <path d="M1,1 L7,4 L1,7" fill="none" stroke="#c4b5fd" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
            </marker>
          </defs>

          {/* Level rail labels */}
          {levels.map((_, l) => (
            <text key={`r${l}`} x={14} y={cy(l) + 4} fontSize="9" fontWeight="700"
              letterSpacing="0.1em" fill="#5f5f68">
              {l === maxLevel ? "ROOT" : l === 0 ? "LEAVES" : `L${l}`}
            </text>
          ))}

          {/* Connectors: parent (l,i) -> children (l-1, 2i | 2i+1), arrow to child */}
          {levels.flatMap((levelNodes, l) =>
            l === 0 ? [] : levelNodes.map((n) => {
              const px = cx(l, n.index), py = cy(l);
              const pr = radOf(kind(l, n.hash));
              return [2 * n.index, 2 * n.index + 1].map((ci) => {
                if (ci >= levels[l - 1].length) return null;
                const child = levels[l - 1][ci];
                const kx = cx(l - 1, ci), ky = cy(l - 1);
                const kr = radOf(kind(l - 1, child.hash));
                const my = (py + ky) / 2;
                return (
                  <path key={`${l}-${n.index}-${ci}`}
                    d={`M${px},${py + pr} C${px},${my} ${kx},${my} ${kx},${ky - kr - 6}`}
                    fill="none" stroke="rgba(167,139,250,0.3)" strokeWidth="1.4"
                    markerEnd="url(#mk-arrow)" />
                );
              });
            })
          )}

          {/* Nodes — glowing dots */}
          {levels.flatMap((levelNodes, l) =>
            levelNodes.map((n) => {
              const tampered = tamperedHashes.has(n.hash);
              const k = kind(l, n.hash);
              const col = colorOf(k, tampered);
              const r = radOf(k);
              const x = cx(l, n.index), y = cy(l);
              return (
                <g key={n.id} transform={`translate(${x},${y})`}>
                  <circle r={r} fill={col} filter="url(#mk-glow)" stroke="rgba(0,0,0,0.5)" strokeWidth="1" />
                  <circle r={Math.max(r - 3, 2)} fill="rgba(255,255,255,0.28)" />
                  <text y={r + 15} textAnchor="middle" fontFamily="JetBrains Mono, monospace"
                    fontSize="10" fill="#c7c7cd">
                    {n.hash.slice(0, 14)}…
                  </text>
                  {(k === "root" || tampered) && (
                    <text y={-(r + 7)} textAnchor="middle" fontSize="9" fontWeight="700"
                      letterSpacing="0.1em" fill={tampered ? "#fca5a5" : "#c4b5fd"}>
                      {tampered ? "TAMPERED" : "ROOT"}
                    </text>
                  )}
                </g>
              );
            })
          )}
        </ZoomPanSvg>
      </div>
    </div>
  );
}

// A vertical flow of nodes connected by a flow line (Obsidian-style).
function FlowChain({ heading, sub, tone, steps }: {
  heading: string;
  sub: string;
  tone: "danger" | "secure";
  steps: { label: string; note: string }[];
}) {
  const ring = tone === "secure" ? "rgba(139,92,246,0.16)" : "rgba(245,158,11,0.14)";
  const dot = tone === "secure" ? "#46e3b7" : "#f87171";
  const line = tone === "secure" ? "rgba(139,92,246,0.5)" : "rgba(245,158,11,0.45)";
  const head = tone === "secure" ? "text-primary-300" : "text-amber-300";
  return (
    <div className="glass p-6 h-full">
      <h4 className={`text-base font-semibold ${head}`}>{heading}</h4>
      <p className="text-xs text-slate-500 mb-6">{sub}</p>
      <ol className="relative">
        {steps.map((s, i) => (
          <li key={i} className="relative flex gap-4 pb-7 last:pb-0">
            {i < steps.length - 1 && (
              <span className="absolute left-[13px] top-7 bottom-0 w-px" style={{ background: `linear-gradient(${line}, transparent)` }} />
            )}
            <span
              className="relative z-10 h-7 w-7 rounded-full flex items-center justify-center shrink-0"
              style={{ background: ring }}
            >
              <span className="h-3 w-3 rounded-full" style={{ background: dot }} />
            </span>
            <div className="pt-0.5">
              <p className="text-sm font-medium text-slate-200">{s.label}</p>
              <p className="text-xs text-slate-500 leading-relaxed">{s.note}</p>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

// --- Diagrams for the "How It Works" page (Fig. 1 / Fig. 2) ----------------

function DeviceStack({
  name,
  note,
  layers,
}: {
  name: string;
  note: string;
  layers: { title: string; sub?: string; accent?: boolean }[];
}) {
  return (
    <div>
      <p className="text-center text-sm font-semibold text-slate-200">{name}</p>
      <p className="text-center text-[11px] text-slate-500 mb-3">({note})</p>
      <div className="space-y-2">
        {layers.map((l) => (
          <div
            key={l.title}
            className={`px-4 py-2.5 text-center border ${
              l.accent
                ? "border-primary-500/50 bg-primary-500/10"
                : "border-slate-600/80 bg-white/[0.03]"
            }`}
          >
            <p className={`text-sm font-medium ${l.accent ? "text-primary-200" : "text-slate-200"}`}>
              {l.title}
            </p>
            {l.sub && (
              <p className={`text-xs font-mono mt-0.5 ${l.accent ? "text-mint-300" : "text-slate-500"}`}>
                {l.sub}
              </p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function TwoDeviceDiagram() {
  const layers = [
    { title: "Application API" },
    { title: "Merge layer", sub: "HLC clocks, CRDT registers" },
    { title: "Index layer", sub: "keyed BLAKE3 equality tags" },
    { title: "Record layer", sub: "AES-256-GCM seal, Ed25519 sign", accent: true },
    { title: "Merkle DAG + store", sub: "content-addressed, SQLite (WAL)" },
  ];
  return (
    <div className="glass p-6">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <DeviceStack name="Device A" note="holds all keys" layers={layers} />
        <DeviceStack name="Device B" note="holds all keys" layers={layers} />
      </div>

      {/* Trust boundary */}
      <div className="mt-7 flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3">
        <span className="text-[11px] italic text-slate-500 whitespace-nowrap">
          trust boundary — plaintext and keys never cross
        </span>
        <span className="flex-1 border-t border-dashed border-slate-600" />
      </div>

      {/* Sealed-envelope arrows down to the relay */}
      <svg viewBox="0 0 640 88" className="hidden md:block w-full h-auto" fill="none">
        <defs>
          <marker
            id="hiw-arrow"
            viewBox="0 0 10 10"
            refX="8"
            refY="5"
            markerWidth="5"
            markerHeight="5"
            orient="auto"
          >
            <path d="M0 0 L10 5 L0 10 Z" fill="rgba(70,227,183,0.75)" />
          </marker>
        </defs>
        <path
          d="M160 0 C160 44 282 40 312 72"
          stroke="rgba(70,227,183,0.55)"
          strokeWidth="1.5"
          strokeDasharray="5 4"
          markerEnd="url(#hiw-arrow)"
        />
        <path
          d="M480 0 C480 44 358 40 328 72"
          stroke="rgba(70,227,183,0.55)"
          strokeWidth="1.5"
          strokeDasharray="5 4"
          markerEnd="url(#hiw-arrow)"
        />
        <text x="178" y="58" fontSize="10" fontStyle="italic" fill="#8a8a93">
          sealed envelopes
        </text>
        <text x="462" y="58" fontSize="10" fontStyle="italic" fill="#8a8a93" textAnchor="end">
          sealed envelopes
        </text>
      </svg>
      <p className="md:hidden text-center text-[11px] italic text-slate-400 mt-3">
        ↓ sealed envelopes ↓
      </p>

      <div className="mx-auto max-w-lg">
        <div className="border border-red-500/40 bg-red-950/40 px-4 py-3 text-center">
          <p className="text-sm font-medium text-red-300">Untrusted relay</p>
          <p className="text-xs font-mono text-slate-400 mt-1">
            store(id, blob) | list(prefix) | fetch(id)
          </p>
        </div>
      </div>

      <p className="mt-4 text-xs text-slate-500 leading-relaxed">
        <span className="text-slate-400 font-semibold">Fig. 1</span> — VeilDB on two devices.
        Everything above the dashed line runs on hardware the user controls and holds keys; the
        relay below it stores sealed envelopes and answers lookups by identifier — and can read
        none of them.
      </p>
    </div>
  );
}

function EnvelopeCell({
  name,
  size,
  tone = "plain",
}: {
  name: string;
  size: string;
  tone?: "plain" | "seal" | "sign";
}) {
  const skin =
    tone === "seal"
      ? "border-primary-400/50 bg-primary-500/10 text-primary-200"
      : tone === "sign"
        ? "border-amber-400/40 bg-amber-500/10 text-amber-200"
        : "border-slate-600 bg-white/[0.03] text-slate-200";
  const sub =
    tone === "seal"
      ? "text-primary-300/80"
      : tone === "sign"
        ? "text-amber-300/80"
        : "text-slate-500";
  return (
    <div className={`flex-1 min-w-[86px] -ml-px border ${skin} px-2 py-2.5 text-center`}>
      <p className={`text-[13px] ${tone === "seal" ? "font-bold" : "font-medium"}`}>{name}</p>
      <p className={`text-[11px] font-mono ${sub}`}>{size}</p>
    </div>
  );
}

function SealedRecordDiagram() {
  const header: [string, string][] = [
    ["Vault id", "16 B"],
    ["Author", "16 B"],
    ["HLC", "8 B"],
    ["Epoch", "4 B"],
    ["Parents", "32 kB"],
  ];
  return (
    <div className="glass p-6">
      <h4 className="text-base font-semibold text-primary-300">Layout of a sealed record</h4>
      <p className="text-xs text-slate-500 mb-5">
        Every value is serialized into this fixed envelope before it ever touches storage.
      </p>

      <div className="overflow-x-auto pb-1">
        <div className="min-w-[720px]">
          {/* Top bracket — canonical header */}
          <div className="flex">
            <div className="flex-[5] flex flex-col items-center">
              <p className="text-[11px] italic text-slate-400 pb-1.5 px-4 text-center">
                canonical header — passed to AES-GCM as associated data
              </p>
              <div className="w-full h-3 border-t border-l border-r border-slate-500" />
            </div>
            <div className="flex-[4]" />
          </div>

          {/* Cells */}
          <div className="flex">
            <div className="flex-[5] flex">
              {header.map(([n, s]) => (
                <EnvelopeCell key={n} name={n} size={s} />
              ))}
            </div>
            <div className="flex-[4] flex">
              <EnvelopeCell name="Nonce" size="12 B" />
              <EnvelopeCell name="Ciphertext" size="n B" tone="seal" />
              <EnvelopeCell name="GCM tag" size="16 B" tone="seal" />
              <EnvelopeCell name="Signature" size="64 B" tone="sign" />
            </div>
          </div>

          {/* Bottom bracket — signature scope + record id */}
          <div className="w-full h-3 border-b border-l border-r border-slate-500" />
          <p className="text-[11px] italic text-slate-400 pt-1.5 text-center leading-relaxed">
            Ed25519 signature over BLAKE3(header ∣ nonce ∣ ciphertext ∣ tag);
            <br />
            record identifier = BLAKE3(entire envelope)
          </p>
        </div>
      </div>

      <p className="mt-4 text-xs text-slate-500 leading-relaxed">
        <span className="text-slate-400 font-semibold">Fig. 2</span> — Layout of a sealed record.
        The header is authenticated but not hidden; only the ciphertext field is confidential.
      </p>
    </div>
  );
}

function HowItWorks() {
  const sectionTitle = "text-lg font-semibold flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full";
  const stack = [
    ["#f87171", "Rust core", "A memory-safe engine runs all the crypto and data logic — no data races, no surprises."],
    ["#a78bfa", "Tauri (desktop)", "A tiny, secure native shell — the whole app is a few MB, not a bundled browser."],
    ["#60a5fa", "React + TypeScript", "The interface you're using right now."],
    ["#46e3b7", "SQLite (local)", "Your data lives in a single encrypted file on your own device."],
    ["#fbbf24", "Ed25519 signatures", "Every change is digitally signed, so it can't be forged or altered."],
    ["#c084fc", "AES-256 encryption", "Every value is scrambled — unreadable without your passphrase."],
    ["#34d399", "CRDT + Merkle tree", "Conflict-free merging across devices, with a tamper-evident history."],
    ["#f472b6", "LAN peer-to-peer sync", "Devices sync directly over your network — there is no server in the middle."],
  ];
  const encryption = [
    { label: "Your passphrase", note: "Typed on your device and never sent anywhere." },
    { label: "Key derivation", note: "A unique salt plus a slow hash turns your passphrase into a strong secret key." },
    { label: "Encrypt at rest (AES-256)", note: "Every value is encrypted before it ever touches the disk." },
    { label: "Sign every change (Ed25519)", note: "Each operation is signed — proving who made it and that it wasn't tampered with." },
    { label: "Hash-chain + Merkle root", note: "Operations are linked by hashes into a tree; any change breaks the root and is detected." },
  ];
  const writePath = [
    { label: "Application API", note: "Your app writes a key/value — nothing leaves the process yet." },
    { label: "Merge layer", note: "HLC clocks timestamp the write; CRDT registers pick a winner — no locks, no conflicts." },
    { label: "Index layer", note: "A keyed BLAKE3 equality tag is derived so peers can match values without decrypting." },
    { label: "Record layer", note: "AES-256-GCM seals the value; Ed25519 signs the fixed envelope." },
    { label: "Merkle DAG + store", note: "The envelope is content-addressed, hashed into the DAG and appended to local SQLite (WAL)." },
    { label: "Sealed envelopes cross the trust boundary", note: "Only ciphertext and identifiers reach the relay — it can store, list and fetch, but never read." },
  ];
  const readPath = [
    { label: "Fetch from the relay", note: "Ask for list(prefix) or fetch(id) — you get back sealed envelopes only." },
    { label: "Verify before trusting", note: "Check the Ed25519 signature, the GCM tag, and that parents hash into the Merkle DAG." },
    { label: "Index layer", note: "Recompute the keyed BLAKE3 tag — a mismatch exposes tampering immediately." },
    { label: "Merge layer", note: "HLC + CRDT merge the remote record with local state — both devices converge." },
    { label: "Decrypt locally", note: "The value is opened with your key and returned through the Application API — keys never left your device." },
  ];
  const traditional = [
    { label: "You", note: "Your app sends your data off to a company's servers." },
    { label: "Company server", note: "The server receives and can read everything you send." },
    { label: "Central database", note: "Stored on their infrastructure — admins, and anyone who breaches it, can read it." },
    { label: "You just have to trust them", note: "Your privacy depends entirely on their promises and security." },
  ];
  const veildb = [
    { label: "You + your passphrase", note: "The key stays on your device and is never uploaded." },
    { label: "Encrypt & sign locally", note: "Data is encrypted and signed before it ever leaves your machine." },
    { label: "Encrypted local database", note: "Even the stored file is unreadable without your key." },
    { label: "Peer-to-peer sync", note: "Your devices sync directly — no server ever sees your data." },
    { label: "Merkle verification", note: "Every device can prove its history hasn't been tampered with." },
  ];
  return (
    <div className="space-y-10">
      <PageHeader title="How VeilDB Works" subtitle="The technology and the encryption behind your zero-trust database — in plain language." />

      {/* Tech stack */}
      <section className="space-y-4">
        <h3 className={sectionTitle}>Technology Stack</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {stack.map(([c, n, d]) => (
            <div key={n} className="glass p-4 flex gap-3">
              <span className="mt-1.5 h-2.5 w-2.5 rounded-full shrink-0" style={{ background: c, boxShadow: `0 0 10px ${c}aa` }} />
              <div>
                <p className="text-sm font-medium text-slate-200">{n}</p>
                <p className="text-xs text-slate-500 leading-relaxed">{d}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* System design: two devices + untrusted relay */}
      <section className="space-y-4">
        <h3 className={sectionTitle}>System design — two devices, no server</h3>
        <TwoDeviceDiagram />
      </section>

      {/* Sealed record envelope */}
      <section className="space-y-4">
        <h3 className={sectionTitle}>Inside a sealed record</h3>
        <SealedRecordDiagram />
      </section>

      {/* Encryption */}
      <section className="space-y-4">
        <h3 className={sectionTitle}>How your data is protected</h3>
        <FlowChain
          heading="The journey of a single value"
          sub="From your passphrase to tamper-proof storage — all on your device."
          tone="secure"
          steps={encryption}
        />
      </section>

      {/* The path of a single operation — new flow diagrams */}
      <section className="space-y-4">
        <h3 className={sectionTitle}>The path of a single operation</h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-stretch">
          <FlowChain
            heading="Writing a value"
            sub="Every step below happens on hardware you control."
            tone="secure"
            steps={writePath}
          />
          <FlowChain
            heading="Reading it on another device"
            sub="Peers only ever see sealed envelopes — keys never travel."
            tone="secure"
            steps={readPath}
          />
        </div>
      </section>

      {/* Comparison */}
      <section className="space-y-4">
        <h3 className={sectionTitle}>VeilDB vs a traditional database</h3>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-stretch">
          <FlowChain
            heading="Traditional cloud database"
            sub="Your data is readable by the service you hand it to."
            tone="danger"
            steps={traditional}
          />
          <FlowChain
            heading="VeilDB — zero-trust"
            sub="Only you can read your data, and no server is required."
            tone="secure"
            steps={veildb}
          />
        </div>
        <div className="glass p-5 border border-primary-500/25">
          <p className="text-sm text-slate-300 leading-relaxed">
            <span className="text-primary-300 font-semibold">In short:</span> a traditional
            database trusts a central server with your plaintext data. VeilDB encrypts and
            signs everything on your device — so even a stolen database file or a snooped
            network connection reveals nothing.
          </p>
        </div>
      </section>
    </div>
  );
}

function TamperTest({
  operations,
  tamperDeviceId,
  tamperSequence,
  tamperResult,
  onDeviceIdChange,
  onSequenceChange,
  onCorrupt,
  onVerify,
  integrity,
}: {
  operations: OperationSummary[];
  tamperDeviceId: string;
  tamperSequence: string;
  tamperResult: string | null;
  onDeviceIdChange: (v: string) => void;
  onSequenceChange: (v: string) => void;
  onCorrupt: () => void;
  onVerify: () => void;
  integrity: IntegrityResult | null;
}) {
  return (
    <div className="space-y-6">
      <h2 className="text-3xl font-bold tracking-tight text-red-400 mb-1">Tamper Test</h2>
      <p className="text-sm text-slate-400">
        Developer-only: corrupt an operation's ciphertext locally, then verify
        integrity to see the tamper detected. This is destructive and local-only.
      </p>

      <div className="glass border border-red-500/40 p-4">
        <h3 className="text-lg font-semibold mb-4 text-red-300 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-red-500 before:rounded-full">
          Corrupt Operation
        </h3>
        <div className="space-y-2">
          <div>
            <label className="block text-xs text-slate-400 mb-1">
              Device ID (hex)
            </label>
            <input
              type="text"
              value={tamperDeviceId}
              onChange={(e) => onDeviceIdChange(e.target.value)}
              placeholder="64 hex chars"
              className="w-full field px-3 py-2 text-sm font-mono"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1">
              Sequence Number
            </label>
            <input
              type="number"
              value={tamperSequence}
              onChange={(e) => onSequenceChange(e.target.value)}
              placeholder="1"
              className="w-full field px-3 py-2 text-sm"
            />
          </div>
          <button
            onClick={onCorrupt}
            className="btn-danger px-5 py-2.5 text-sm font-bold"
          >
            Corrupt Operation
          </button>
        </div>
      </div>

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Verify Integrity</h3>
        <button
          onClick={onVerify}
          className="btn-cta px-5 py-2.5 text-sm"
        >
          Run Verify
        </button>
        {integrity && (
          <div className="mt-3">
            <span
              className={`inline-block px-2 py-1 rounded text-sm ${integrity.verified
                  ? "bg-green-900 text-green-200"
                  : "bg-red-900 text-red-200"
                }`}
            >
              {integrity.status}
            </span>
          </div>
        )}
      </div>

      {tamperResult && (
        <div className="glass p-5">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Result</h3>
          <p className="text-sm">{tamperResult}</p>
        </div>
      )}

      <div className="glass p-5">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2.5 before:content-[''] before:h-4 before:w-1 before:bg-primary-500 before:rounded-full">Recent Operations</h3>
        <div className="space-y-1 max-h-60 overflow-y-auto">
          {operations.map((op) => (
            <div
              key={`${op.device_id}-${op.sequence}`}
              className="text-xs flex justify-between"
            >
              <span className="font-mono">{op.sequence}</span>
              <span className="font-mono text-slate-400">
                {hex(op.device_id).slice(0, 16)}...
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default App;