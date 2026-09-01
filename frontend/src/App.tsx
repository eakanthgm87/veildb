import { useState, useEffect } from "react";
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
  | "users";

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
function deviceColor(deviceId: string): string {
  let hash = 0;
  for (let i = 0; i < deviceId.length; i++) {
    hash = (hash * 31 + deviceId.charCodeAt(i)) >>> 0;
  }
  const hue = hash % 360;
  return `hsl(${hue}, 70%, 50%)`;
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

  async function initDb() {
    setError(null);
    if (!dbPath) {
      setError("Select a database path first");
      return;
    }
    try {
      const result = await api.init(dbPath, passphrase);
      if (result.success) {
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
        if (msg.includes("refused") || msg.includes("10061") || msg.includes("connection")) {
          setError(`Could not connect to peer at ${syncAddr}. Make sure VeilDB is running with the database OPEN on the peer, then try again.`);
        } else {
          setError(msg);
        }
      }
    } catch (e: any) {
      const msg = e.message || String(e);
      if (msg.includes("refused") || msg.includes("10061") || msg.includes("connection")) {
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

  // File picker for DB path.
  async function pickDbPath() {
    try {
      const selected = await open({
        defaultPath: dbPath || undefined,
        directory: true,
        multiple: false,
        title: "Select database folder",
      });
      if (selected && typeof selected === "string") {
        // Append default filename to the selected directory
        const sep = selected.includes("/") ? "/" : "\\";
        setDbPath(selected + sep + "veildb.vdb");
      }
    } catch {
      const selected = prompt("Enter database path:", dbPath || "veildb.vdb");
      if (selected) {
        setDbPath(selected);
      }
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
    <div className="min-h-screen bg-dark-900 text-slate-200">
      <header className="bg-dark-800 border-b border-slate-700 px-6 py-4 flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-primary-400">VeilDB</h1>
          <p className="text-sm text-slate-400">
            Privacy-first, local-first, zero-trust database
          </p>
        </div>
        {status && (
          <div className="flex items-center gap-3">
            <a
              href="#demo"
              className="text-sm bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-1.5 rounded"
            >
              Demo Site →
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

      <div className="flex">
        {/* Sidebar */}
        <nav className="w-64 bg-dark-800 border-r border-slate-700 min-h-[calc(100vh-64px)] p-4">
          {!status ? (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">
                  Database Path
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={dbPath || ""}
                    onChange={(e) => setDbPath(e.target.value)}
                    placeholder="veildb.vdb"
                    className="flex-1 bg-dark-900 border border-slate-600 rounded px-2 py-1 text-sm"
                  />
                  <button
                    onClick={pickDbPath}
                    className="text-xs bg-dark-700 hover:bg-dark-600 px-2 py-1 rounded"
                  >
                    Browse
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">
                  Passphrase
                </label>
                <input
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Enter passphrase"
                  className="w-full bg-dark-900 border border-slate-600 rounded px-2 py-1 text-sm"
                />
              </div>
              <div className="flex gap-2">
                <button
                  onClick={initDb}
                  className="flex-1 bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
                >
                  Init
                </button>
                <button
                  onClick={openDb}
                  className="flex-1 bg-dark-700 hover:bg-dark-600 rounded px-3 py-2 text-sm"
                >
                  Open
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="mb-4 p-3 bg-dark-900 rounded border border-slate-700">
                <p className="text-xs text-slate-400 mb-1">Database</p>
                <p className="text-sm font-mono truncate">{dbPath}</p>
                <p className="text-xs text-slate-400 mt-2">Device</p>
                <p className="text-sm font-mono truncate">
                  {hex(status.self_device_id)}
                </p>
                <button
                  onClick={closeDb}
                  className="mt-3 w-full text-xs bg-red-900 hover:bg-red-800 text-red-200 rounded px-2 py-1"
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
              </div>
            </>
          )}
        </nav>

        {/* Main content */}
        <main className="flex-1 p-6">
          {error && (
            <div className="mb-4 p-3 bg-red-900 border border-red-700 text-red-200 rounded">
              {error}
            </div>
          )}

          {!status ? (
            <div className="text-center text-slate-400 mt-20">
              <p className="text-lg">No database open</p>
              <p className="text-sm mt-2">
                Initialize a new database or open an existing one.
              </p>
            </div>
          ) : (
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
            </>
          )}
        </main>
      </div>
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
      className={`w-full text-left px-3 py-2 rounded text-sm ${active
          ? "bg-primary-700 text-white"
          : "text-slate-300 hover:bg-dark-700"
        }`}
    >
      {children}
    </button>
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
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Dashboard</h2>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <p className="text-sm text-slate-400">Operations</p>
          <p className="text-2xl font-bold">{status.operation_count}</p>
        </div>
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <p className="text-sm text-slate-400">Devices</p>
          <p className="text-2xl font-bold">{status.device_count}</p>
        </div>
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <p className="text-sm text-slate-400">Key Version</p>
          <p className="text-2xl font-bold">{status.key_version}</p>
        </div>
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <p className="text-sm text-slate-400">Format Version</p>
          <p className="text-2xl font-bold">{status.format_version}</p>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <p className="text-sm text-slate-400 mb-2">Integrity</p>
        {integrity ? (
          <div className="flex items-center gap-3">
            <span
              className={`inline-block px-2 py-1 rounded text-sm cursor-pointer ${integrity.verified
                  ? "bg-green-900 text-green-200"
                  : "bg-red-900 text-red-200"
                }`}
              onClick={onViewMerkle}
              title="Click to view Merkle tree"
            >
              {integrity.status}
            </span>
            <button
              onClick={onVerify}
              className="bg-dark-700 hover:bg-dark-600 px-3 py-1 rounded text-sm"
            >
              Re-verify
            </button>
          </div>
        ) : (
          <button
            onClick={onVerify}
            className="bg-primary-600 hover:bg-primary-700 px-3 py-1 rounded text-sm"
          >
            Verify Integrity
          </button>
        )}
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <p className="text-sm text-slate-400 mb-2">Key Management</p>
        <button
          onClick={onRotateKey}
          className="bg-dark-700 hover:bg-dark-600 px-3 py-1 rounded text-sm"
        >
          Rotate Key
        </button>
        <p className="text-xs text-slate-400 mt-2">
          Current version: {status.key_version}
        </p>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <p className="text-sm text-slate-400 mb-2">Snapshot</p>
        <button
          onClick={onSnapshot}
          className="bg-dark-700 hover:bg-dark-600 px-3 py-1 rounded text-sm"
        >
          Create Snapshot
        </button>
        {status.latest_snapshot_id && (
          <p className="text-xs text-slate-400 mt-2">
            Latest: #{status.latest_snapshot_id}
          </p>
        )}
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <p className="text-sm text-slate-400 mb-2">Merkle Root</p>
        <p className="font-mono text-xs break-all">{hex(status.merkle_root)}</p>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <p className="text-sm text-slate-400 mb-2">Recent Operations</p>
        <div className="space-y-1 max-h-60 overflow-y-auto">
          {operations.length === 0 && (
            <p className="text-sm text-slate-500">No operations yet</p>
          )}
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
  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Keys</h2>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Put Key-Value</h3>
        <div className="space-y-2">
          <input
            type="text"
            value={keyInput}
            onChange={(e) => onKeyChange(e.target.value)}
            placeholder="Key"
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
          />
          <input
            type="text"
            value={valueInput}
            onChange={(e) => onValueChange(e.target.value)}
            placeholder="Value"
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
          />
          <button
            onClick={onPut}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
          >
            Store
          </button>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Get Value</h3>
        <div className="space-y-2">
          <input
            type="text"
            value={lookupKey}
            onChange={(e) => onLookupKeyChange(e.target.value)}
            placeholder="Key"
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
          />
          <button
            onClick={onGet}
            className="w-full bg-dark-700 hover:bg-dark-600 rounded px-3 py-2 text-sm"
          >
            Retrieve
          </button>
          {lookupValue !== null && (
            <div className="mt-2 p-2 bg-dark-900 rounded border border-slate-600">
              <p className="text-sm font-mono break-all">{lookupValue}</p>
            </div>
          )}
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
      <h2 className="text-xl font-semibold">Devices</h2>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Trust New Device</h3>
        <div className="space-y-2">
          <input
            type="text"
            value={newPubkey}
            onChange={(e) => onNewPubkeyChange(e.target.value)}
            placeholder="Public key (64 hex chars)"
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm font-mono"
          />
          <button
            onClick={onTrust}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
          >
            Trust Device
          </button>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Trusted Devices</h3>
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
                  className="text-xs bg-red-900 hover:bg-red-800 text-red-200 px-2 py-1 rounded"
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
      <h2 className="text-xl font-semibold">Sync</h2>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">LAN Sync — one click</h3>
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
              className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm font-mono"
            />
          </div>
          <button
            onClick={onSync}
            disabled={syncing}
            className="w-full bg-emerald-600 hover:bg-emerald-700 disabled:bg-slate-600 text-white rounded px-3 py-2 text-base font-semibold"
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
            className="w-full bg-dark-700 hover:bg-dark-600 rounded px-3 py-2 text-sm"
          >
            View Operation Graph
          </button>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Pairing</h3>
        <p className="text-xs text-slate-400 mb-2">
          Export a pairing bundle to let another device join this database, or
          paste a bundle you received to join an existing one.
        </p>
        <div className="space-y-2">
          <button
            onClick={onExportPairing}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
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
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-xs font-mono"
          />
          <button
            onClick={onImportPairing}
            className="w-full bg-dark-700 hover:bg-dark-600 rounded px-3 py-2 text-sm"
          >
            Import Pairing Bundle
          </button>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Peer Discovery</h3>
        <div className="space-y-2">
          <button
            onClick={onDiscover}
            disabled={discovering}
            className="w-full bg-primary-600 hover:bg-primary-700 disabled:bg-slate-600 text-white rounded px-3 py-2 text-sm"
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
                    className="text-xs bg-primary-600 hover:bg-primary-700 px-2 py-1 rounded"
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

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Merge Log</h3>
        <div className="space-y-2">
          <button
            onClick={onListMerges}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
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
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <h3 className="text-lg font-medium mb-3">Sync Log</h3>
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
      <h2 className="text-xl font-semibold">Time Travel</h2>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">
          Query at Logical Clock
        </h3>
        <div className="space-y-2">
          <input
            type="text"
            value={clockInput}
            onChange={(e) => onClockChange(e.target.value)}
            placeholder='e.g. "device_id:counter"'
            className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm font-mono"
          />
          <button
            onClick={onQuery}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
          >
            Query
          </button>
        </div>
      </div>

      {entries.length > 0 && (
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <h3 className="text-lg font-medium mb-3">State at Clock</h3>
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
      <h2 className="text-xl font-semibold">Backup / Restore</h2>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Backup</h3>
        <div className="space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={backupPath}
              onChange={(e) => onBackupPathChange(e.target.value)}
              placeholder="backup.vdb"
              className="flex-1 bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            />
            <button
              onClick={onPickBackup}
              className="text-sm bg-dark-700 hover:bg-dark-600 px-3 py-2 rounded"
            >
              Browse
            </button>
          </div>
          <button
            onClick={onBackup}
            className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
          >
            Create Backup
          </button>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Restore</h3>
        <div className="space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={restorePath}
              onChange={(e) => onRestorePathChange(e.target.value)}
              placeholder="backup.vdb"
              className="flex-1 bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            />
            <button
              onClick={onPickRestore}
              className="text-sm bg-dark-700 hover:bg-dark-600 px-3 py-2 rounded"
            >
              Browse
            </button>
          </div>
          <button
            onClick={onRestore}
            className="w-full bg-red-900 hover:bg-red-800 text-red-200 rounded px-3 py-2 text-sm"
          >
            Restore (overwrites current DB)
          </button>
        </div>
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
  // Simple layered layout: group nodes by device, then by sequence.
  const devices = Array.from(new Set(nodes.map((n) => n.device_id)));
  const deviceIndex = new Map<string, number>();
  devices.forEach((d, i) => deviceIndex.set(d, i));

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Operation Graph</h2>
      <p className="text-sm text-slate-400">
        Multi-parent operation DAG. Color-coded by device. Click a node for details.
      </p>

      <div className="bg-dark-800 border border-slate-700 rounded p-4 overflow-x-auto">
        <div className="min-w-[600px]">
          {/* Legend */}
          <div className="flex gap-4 mb-4 flex-wrap">
            {devices.map((d) => (
              <div key={d} className="flex items-center gap-2">
                <span
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: deviceColor(d) }}
                />
                <span className="text-xs font-mono">
                  {d.slice(0, 8)}...
                </span>
              </div>
            ))}
          </div>

          {/* Nodes */}
          <div className="space-y-4">
            {devices.map((device) => (
              <div key={device}>
                <p className="text-xs text-slate-500 mb-2 font-mono">
                  Device {device.slice(0, 8)}...
                </p>
                <div className="flex gap-3 flex-wrap">
                  {nodes
                    .filter((n) => n.device_id === device)
                    .map((n) => {
                      const isTampered = tamperedHashes.has(n.hash);
                      return (
                        <div
                          key={n.hash}
                          onClick={() => onSelectNode(n)}
                          className={`cursor-pointer rounded border p-2 min-w-[100px] text-center ${isTampered
                              ? "bg-red-900 border-red-600 text-red-200"
                              : "bg-dark-900 border-slate-600"
                            }`}
                          style={{
                            borderLeft: `4px solid ${deviceColor(device)}`,
                          }}
                        >
                          <p className="text-xs font-mono">
                            {n.id}
                          </p>
                          <p className="text-[10px] text-slate-400">
                            {n.signature_status}
                          </p>
                          {isTampered && (
                            <p className="text-[10px] text-red-300 font-bold">
                              TAMPERED
                            </p>
                          )}
                        </div>
                      );
                    })}
                </div>
              </div>
            ))}
          </div>

          {/* Edges */}
          <div className="mt-4">
            <p className="text-xs text-slate-500 mb-2">Parent Links</p>
            <div className="space-y-1 max-h-40 overflow-y-auto">
              {edges.map((e, i) => (
                <p key={i} className="text-[10px] font-mono text-slate-500">
                  {e.from.slice(0, 12)}... → {e.to.slice(0, 12)}...
                </p>
              ))}
              {edges.length === 0 && (
                <p className="text-xs text-slate-600">No edges yet</p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Side panel */}
      {selectedNode && (
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <h3 className="text-lg font-medium mb-3">Operation Details</h3>
          <div className="space-y-2 text-sm">
            <p><span className="text-slate-400">ID:</span> <span className="font-mono">{selectedNode.id}</span></p>
            <p><span className="text-slate-400">Device:</span> <span className="font-mono">{selectedNode.device_id}</span></p>
            <p><span className="text-slate-400">Sequence:</span> {selectedNode.sequence}</p>
            <p><span className="text-slate-400">Hash:</span> <span className="font-mono break-all">{selectedNode.hash}</span></p>
            <p><span className="text-slate-400">Parents:</span> <span className="font-mono">{selectedNode.parents.length}</span></p>
            <p><span className="text-slate-400">Signature:</span> {selectedNode.signature_status}</p>
            <p><span className="text-slate-400">Clock:</span> <span className="font-mono">{selectedNode.clock.join(", ")}</span></p>
            <button
              onClick={() => onSelectNode(null)}
              className="mt-2 bg-dark-700 hover:bg-dark-600 px-3 py-1 rounded text-sm"
            >
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
        <h2 className="text-xl font-semibold">Merkle Tree</h2>
        <p className="text-sm text-slate-400">No tree data available.</p>
      </div>
    );
  }

  // Group nodes by level.
  const maxLevel = Math.max(
    ...tree.leaves.map((l) => l.level),
    ...tree.internal_nodes.map((n) => n.level),
    0
  );

  const levels: MerkleNode[][] = [];
  for (let l = 0; l <= maxLevel; l++) {
    const levelNodes = [
      ...tree.leaves.filter((n) => n.level === l),
      ...tree.internal_nodes.filter((n) => n.level === l),
    ];
    levels.push(levelNodes);
  }

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Merkle Tree</h2>
      <p className="text-sm text-slate-400">
        Root at top, branching down to operation-hash leaves.
      </p>

      <div className="bg-dark-800 border border-slate-700 rounded p-4 overflow-x-auto">
        <div className="min-w-[600px]">
          {/* Root */}
          <div className="text-center mb-4">
            <div className="inline-block bg-primary-900 border border-primary-600 rounded px-3 py-2">
              <p className="text-xs text-slate-400">ROOT</p>
              <p className="font-mono text-xs break-all">{tree.root}</p>
            </div>
          </div>

          {/* Levels */}
          {levels.map((levelNodes, li) => (
            <div key={li} className="mb-4">
              <p className="text-xs text-slate-500 mb-2">
                Level {li} {li === 0 ? "(leaves)" : ""}
              </p>
              <div className="flex gap-2 flex-wrap justify-center">
                {levelNodes.map((n) => {
                  const isTampered = tamperedHashes.has(n.hash);
                  return (
                    <div
                      key={n.id}
                      className={`rounded border px-2 py-1 text-center ${isTampered
                          ? "bg-red-900 border-red-600"
                          : "bg-dark-900 border-slate-600"
                        }`}
                    >
                      <p className="text-[10px] font-mono break-all max-w-[120px]">
                        {n.hash.slice(0, 16)}...
                      </p>
                      {isTampered && (
                        <p className="text-[10px] text-red-300 font-bold">
                          TAMPERED
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
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
      <h2 className="text-xl font-semibold text-red-400">Tamper Test</h2>
      <p className="text-sm text-slate-400">
        Developer-only: corrupt an operation's ciphertext locally, then verify
        integrity to see the tamper detected. This is destructive and local-only.
      </p>

      <div className="bg-dark-800 border border-red-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3 text-red-300">
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
              className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm font-mono"
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
              className="w-full bg-dark-900 border border-slate-600 rounded px-3 py-2 text-sm"
            />
          </div>
          <button
            onClick={onCorrupt}
            className="w-full bg-red-900 hover:bg-red-800 text-red-200 rounded px-3 py-2 text-sm font-bold"
          >
            Corrupt Operation
          </button>
        </div>
      </div>

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Verify Integrity</h3>
        <button
          onClick={onVerify}
          className="w-full bg-primary-600 hover:bg-primary-700 text-white rounded px-3 py-2 text-sm"
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
        <div className="bg-dark-800 border border-slate-700 rounded p-4">
          <h3 className="text-lg font-medium mb-3">Result</h3>
          <p className="text-sm">{tamperResult}</p>
        </div>
      )}

      <div className="bg-dark-800 border border-slate-700 rounded p-4">
        <h3 className="text-lg font-medium mb-3">Recent Operations</h3>
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