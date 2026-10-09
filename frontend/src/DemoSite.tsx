import React, { useState, useEffect } from "react";
import logoUrl from "./assets/veildb-logo.png";
import { api } from "./mockApi";

/* ─── Types ─── */
interface UserEntry {
  username: string;
  email: string;
  role: string;
  createdAt: string;
  /** SHA-256 hex of the password. Never store the plaintext. */
  passwordHash?: string;
}

/* ─── Helpers ─── */

/** Hash a password to hex. Uses Web Crypto; falls back if unavailable. */
async function sha256Hex(s: string): Promise<string> {
  try {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } catch {
    // Non-cryptographic fallback — still avoids persisting the plaintext.
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return "x" + h.toString(16);
  }
}

interface VdbStats {
  operationCount: number;
  merkleRoot: string;
  deviceCount: number;
  dbId: string;
}

/* ─── Helpers ─── */

/* VeilDB logo mark. */
function VeilLogo({ size = 40 }: { size?: number }) {
  return (
    <img src={logoUrl} alt="VeilDB" style={{ width: size, height: size, objectFit: "contain", flexShrink: 0 }} />
  );
}

/* Accent dot for stat labels. */
function Dot({ c }: { c: string }) {
  return (
    <span style={{
      display: "inline-block", width: 6, height: 6, borderRadius: 999,
      background: c, marginRight: 7, verticalAlign: "middle",
    }} />
  );
}

/* Tiny inline sparkline — rising "operations over time" line. */
function Spark({ n, color }: { n: number; color: string }) {
  const w = 120, h = 28;
  const points = Math.min(Math.max(n, 2), 24);
  const pts = Array.from({ length: points }, (_, i) =>
    `${(i / (points - 1)) * w},${h - (i / (points - 1)) * (h - 4) - 2}`,
  ).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none"
      style={{ width: "100%", height: 24, marginTop: 8 }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"
        strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

/* ============================================================
   DemoSite — A standalone auth website powered by VeilDB
   Stores all user credentials as real KV pairs in VeilDB.
   ============================================================ */
export default function DemoSite() {
  /* — State — */
  const [view, setView] = useState<"login" | "register" | "dashboard">("login");
  const [currentUser, setCurrentUser] = useState<UserEntry | null>(null);
  const [users, setUsers] = useState<UserEntry[]>([]);
  const [stats, setStats] = useState<VdbStats | null>(null);
  const [rawKv, setRawKv] = useState<{ key: string; value: string }[]>([]);

  // Form state
  const [regUsername, setRegUsername] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regRole, setRegRole] = useState("user");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");

  // UI state
  const [loading, setLoading] = useState(false);
  const [alert, setAlert] = useState<{
    type: "success" | "error" | "info";
    msg: string;
  } | null>(null);

  function showAlert(type: "success" | "error" | "info", msg: string) {
    setAlert({ type, msg });
    setTimeout(() => setAlert(null), 5000);
  }

  /* — Data fetching — */
  async function fetchUsers(): Promise<UserEntry[]> {
    const res = await api.get("users:index");
    if (!res.success || !res.data) return [];
    const index: string[] = JSON.parse(res.data);
    const entries: UserEntry[] = [];
    for (const uname of index) {
      const r = await api.get(`user:${uname}`);
      if (r.success && r.data && r.data !== "") {
        entries.push(JSON.parse(r.data));
      }
    }
    return entries;
  }

  async function fetchStats(): Promise<VdbStats> {
    const res = await api.status();
    if (res.success && res.data) {
      return {
        operationCount: res.data.operation_count ?? 0,
        merkleRoot: res.data.merkle_root ?? "—",
        deviceCount: res.data.device_count ?? 0,
        dbId: res.data.db_id ?? "—",
      };
    }
    return { operationCount: 0, merkleRoot: "—", deviceCount: 0, dbId: "—" };
  }

  async function fetchRawKv(): Promise<{ key: string; value: string }[]> {
    const keys: { key: string; value: string }[] = [];
    const res = await api.get("users:index");
    if (res.success && res.data) {
      keys.push({ key: "users:index", value: res.data });
      const index: string[] = JSON.parse(res.data);
      for (const uname of index) {
        const r = await api.get(`user:${uname}`);
        if (r.success && r.data) {
          keys.push({ key: `user:${uname}`, value: r.data });
        }
      }
    }
    return keys;
  }

  async function refreshDashboard() {
    const [u, s, kv] = await Promise.all([
      fetchUsers(),
      fetchStats(),
      fetchRawKv(),
    ]);
    setUsers(u);
    setStats(s);
    setRawKv(kv);
  }

  /* — Handlers — */
  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    if (!regUsername || !regEmail || !regPassword) {
      showAlert("error", "All fields are required");
      return;
    }
    if (regUsername.length < 3) {
      showAlert("error", "Username must be at least 3 characters");
      return;
    }
    setLoading(true);
    try {
      // Check if user exists
      let index: string[] = [];
      const idxRes = await api.get("users:index");
      if (idxRes.success && idxRes.data) {
        index = JSON.parse(idxRes.data);
      }
      if (index.includes(regUsername)) {
        showAlert("error", "Username already exists");
        setLoading(false);
        return;
      }

      // Store user in VeilDB as key-value (password kept only as a hash).
      const user: UserEntry = {
        username: regUsername,
        email: regEmail,
        role: regRole,
        createdAt: new Date().toISOString(),
        passwordHash: await sha256Hex(regPassword),
      };

      // vdb_put("user:<username>", JSON)
      const putRes = await api.put(
        `user:${regUsername}`,
        JSON.stringify(user)
      );
      if (!putRes.success) {
        showAlert("error", putRes.error?.message || "Failed to store user");
        setLoading(false);
        return;
      }

      // vdb_put("users:index", updated array)
      index.push(regUsername);
      await api.put("users:index", JSON.stringify(index));

      setCurrentUser(user);
      setRegUsername("");
      setRegEmail("");
      setRegPassword("");
      setRegRole("user");
      showAlert(
        "success",
        `Account "${user.username}" created! 2 VeilDB operations recorded.`
      );
      await refreshDashboard();
      setTimeout(() => setView("dashboard"), 800);
    } catch (err: any) {
      showAlert("error", err.message || String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    if (!loginUsername || !loginPassword) {
      showAlert("error", "All fields are required");
      return;
    }
    setLoading(true);
    try {
      // vdb_get("user:<username>") then verify the password hash.
      const res = await api.get(`user:${loginUsername}`);
      if (res.success && res.data && res.data !== "") {
        const user: UserEntry = JSON.parse(res.data);
        const hash = await sha256Hex(loginPassword);
        if (user.passwordHash && user.passwordHash === hash) {
          setCurrentUser(user);
          setLoginPassword("");
          showAlert("success", `Welcome back, ${user.username}!`);
          await refreshDashboard();
          setTimeout(() => setView("dashboard"), 600);
        } else {
          showAlert("error", "Invalid username or password");
        }
      } else {
        showAlert("error", "Invalid username or password");
      }
    } catch (err: any) {
      showAlert("error", err.message || String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(username: string) {
    try {
      // Overwrite with empty to "delete"
      await api.put(`user:${username}`, "");
      const idxRes = await api.get("users:index");
      if (idxRes.success && idxRes.data) {
        let index: string[] = JSON.parse(idxRes.data);
        index = index.filter((u) => u !== username);
        await api.put("users:index", JSON.stringify(index));
      }
      showAlert("info", `User "${username}" deleted — 2 ops recorded`);
      await refreshDashboard();
    } catch (err: any) {
      showAlert("error", err.message || String(err));
    }
  }

  function handleLogout() {
    setCurrentUser(null);
    setView("login");
  }

  // Make the demo self-contained: if no database is open, open (or
  // create) a dedicated demo database so login/register actually persist.
  async function ensureDb() {
    try {
      const st = await api.status();
      if (st.success) return; // a database is already open
    } catch {
      /* status errors when nothing is open — fall through to open it */
    }
    const path = "demo.vdb";
    const pass = "veildb-demo";
    const opened = await api.open(path, pass);
    if (!opened.success) {
      const created = await api.init(path, pass);
      if (!created.success) {
        showAlert(
          "error",
          created.error?.message || "Could not open the demo database"
        );
      }
    }
  }

  useEffect(() => {
    ensureDb();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (view === "dashboard") refreshDashboard();
  }, [view]);

  /* ─── Render ─── */
  return (
    <div style={S.page}>
      {/* Background gradient */}
      <div style={S.bgGlow} />

      {/* Header */}
      <header style={S.header}>
        <div style={S.logoGroup}>
          <VeilLogo size={44} />
        </div>
        <nav style={S.nav}>
          <button
            onClick={() => setView("login")}
            style={{
              ...S.navBtn,
              ...(view === "login" ? S.navBtnActive : {}),
            }}
          >
            Sign In
          </button>
          <button
            onClick={() => setView("register")}
            style={{
              ...S.navBtn,
              ...(view === "register" ? S.navBtnActive : {}),
            }}
          >
            Sign Up
          </button>
          <button
            onClick={() => {
              if (currentUser) {
                setView("dashboard");
              } else {
                showAlert("info", "Sign in first");
                setView("login");
              }
            }}
            style={{
              ...S.navBtn,
              ...(view === "dashboard" ? S.navBtnActive : {}),
            }}
          >
            Dashboard
          </button>
          <a
            href="#"
            onClick={(e) => {
              e.preventDefault();
              window.location.hash = "";
              window.location.reload();
            }}
            style={{ ...S.navBtn, textDecoration: "none", fontSize: "0.8rem" }}
          >
            ← Back to VeilDB
          </a>
        </nav>
      </header>

      {/* Alert */}
      {alert && (
        <div
          style={{
            ...S.alert,
            ...(alert.type === "success"
              ? S.alertSuccess
              : alert.type === "error"
              ? S.alertError
              : S.alertInfo),
          }}
        >
          {alert.type === "success"
            ? "✓ "
            : alert.type === "error"
            ? "✕ "
            : "ℹ "}
          {alert.msg}
        </div>
      )}

      {/* Main */}
      <main style={S.main}>
        {view === "login" && (
          <div style={S.card}>
            <h2 style={S.cardTitle}>Welcome Back</h2>
            <p style={S.cardSub}>
              Sign in — credentials retrieved from VeilDB via{" "}
              <code style={S.code}>vdb_get</code>
            </p>
            <form onSubmit={handleLogin}>
              <div style={S.field}>
                <label style={S.label}>Username</label>
                <input
                  style={S.input}
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  placeholder="Enter your username"
                />
              </div>
              <div style={S.field}>
                <label style={S.label}>Password</label>
                <input
                  type="password"
                  style={S.input}
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  placeholder="Enter your password"
                />
              </div>
              <button type="submit" style={S.btnPrimary} disabled={loading}>
                {loading ? "Signing in..." : "Sign In"}
              </button>
            </form>
            <p style={S.toggleText}>
              Don't have an account?{" "}
              <a
                style={S.link}
                onClick={() => setView("register")}
              >
                Create one
              </a>
            </p>
          </div>
        )}

        {view === "register" && (
          <div style={S.card}>
            <h2 style={S.cardTitle}>Create Account</h2>
            <p style={S.cardSub}>
              Credentials stored in VeilDB via{" "}
              <code style={S.code}>vdb_put</code> as encrypted key-value pairs
            </p>
            <form onSubmit={handleRegister}>
              <div style={S.field}>
                <label style={S.label}>Username</label>
                <input
                  style={S.input}
                  value={regUsername}
                  onChange={(e) => setRegUsername(e.target.value)}
                  placeholder="Choose a username"
                />
              </div>
              <div style={S.field}>
                <label style={S.label}>Email</label>
                <input
                  type="email"
                  style={S.input}
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                  placeholder="you@example.com"
                />
              </div>
              <div style={S.field}>
                <label style={S.label}>Role</label>
                <select
                  style={S.input}
                  value={regRole}
                  onChange={(e) => setRegRole(e.target.value)}
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                  <option value="moderator">Moderator</option>
                </select>
              </div>
              <div style={S.field}>
                <label style={S.label}>Password</label>
                <input
                  type="password"
                  style={S.input}
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                  placeholder="Create a strong password"
                />
              </div>
              <button type="submit" style={S.btnPrimary} disabled={loading}>
                {loading ? "Creating..." : "Create Account → vdb_put"}
              </button>
            </form>
            <p style={S.toggleText}>
              Already have an account?{" "}
              <a style={S.link} onClick={() => setView("login")}>
                Sign in
              </a>
            </p>
          </div>
        )}

        {view === "dashboard" && currentUser && (
          <div style={S.dashboard}>
            {/* Dashboard header */}
            <div style={S.dashHeader}>
              <div>
                <h2 style={{ ...S.logoText, fontSize: "1.9rem", margin: 0 }}>
                  Dashboard
                </h2>
                <p style={{ color: "#94a3b8", margin: "4px 0 0" }}>
                  Welcome, <strong>{currentUser.username}</strong>
                </p>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={S.roleBadge}>{currentUser.role}</span>
                <button onClick={handleLogout} style={S.btnSecondary}>
                  Sign Out
                </button>
              </div>
            </div>

            {/* VeilDB Stats */}
            {stats && (
              <div style={S.statsGrid}>
                <div style={S.statCard}>
                  <div style={S.statLabel}><Dot c="#8b5cf6" />TOTAL USERS</div>
                  <div style={S.statValue}>{users.length}</div>
                </div>
                <div style={S.statCard}>
                  <div style={S.statLabel}><Dot c="#a78bfa" />VDB OPERATIONS</div>
                  <div style={S.statValue}>{stats.operationCount}</div>
                  <Spark n={stats.operationCount} color="#a78bfa" />
                </div>
                <div style={S.statCard}>
                  <div style={S.statLabel}><Dot c="#fbbf24" />MERKLE ROOT</div>
                  <div style={{ ...S.statValue, fontSize: "0.85rem", fontFamily: "monospace" }}>
                    {typeof stats.merkleRoot === "string"
                      ? stats.merkleRoot.slice(0, 16) + "…"
                      : "—"}
                  </div>
                </div>
                <div style={S.statCard}>
                  <div style={S.statLabel}><Dot c="#46e3b7" />DEVICES</div>
                  <div style={S.statValue}>{stats.deviceCount}</div>
                </div>
              </div>
            )}

            {/* Users table */}
            <div style={S.section}>
              <h3 style={S.sectionTitle}>📋 Stored Users</h3>
              {users.length === 0 ? (
                <p style={{ color: "#64748b", textAlign: "center", padding: "2rem" }}>
                  No users yet — create an account above.
                </p>
              ) : (
                <table style={S.table}>
                  <thead>
                    <tr>
                      <th style={S.th}>User</th>
                      <th style={S.th}>Role</th>
                      <th style={S.th}>VeilDB Key</th>
                      <th style={S.th}>Created</th>
                      <th style={S.th}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((u, i) => (
                      <tr key={i}>
                        <td style={S.td}>
                          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                            <div
                              style={{
                                ...S.avatar,
                                background: ["#3b82f6", "#8b5cf6", "#22c55e", "#f59e0b", "#ef4444"][i % 5],
                              }}
                            >
                              {u.username[0].toUpperCase()}
                            </div>
                            <div>
                              <div style={{ fontWeight: 500 }}>{u.username}</div>
                              <div style={{ fontSize: "0.75rem", color: "#64748b" }}>
                                {u.email}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td style={S.td}>
                          <span style={S.roleBadge}>{u.role}</span>
                        </td>
                        <td style={S.td}>
                          <code style={{ fontSize: "0.75rem", color: "#fbbf24" }}>
                            user:{u.username}
                          </code>
                        </td>
                        <td style={{ ...S.td, color: "#94a3b8" }}>
                          {u.createdAt
                            ? new Date(u.createdAt).toLocaleDateString()
                            : "—"}
                        </td>
                        <td style={S.td}>
                          {u.username !== currentUser?.username && (
                            <button
                              onClick={() => handleDelete(u.username)}
                              style={S.btnDanger}
                            >
                              Delete
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Raw KV pairs */}
            {rawKv.length > 0 && (
              <div style={S.section}>
                <h3 style={{ ...S.sectionTitle, color: "#fbbf24" }}>
                  🔑 Raw Key-Value Pairs in VeilDB
                </h3>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {rawKv.map((kv, i) => (
                    <div key={i} style={S.kvBox}>
                      <div>
                        <span style={{ color: "#fbbf24" }}>Key: </span>
                        <span style={{ color: "#a78bfa" }}>{kv.key}</span>
                      </div>
                      <div style={{ marginTop: 4 }}>
                        <span style={{ color: "#fbbf24" }}>Val: </span>
                        <span style={{ color: "#4ade80", wordBreak: "break-all" as const }}>
                          {kv.value}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer style={S.footer}>
        All user data is stored in a{" "}
        <span style={{ color: "#a78bfa", fontWeight: 500 }}>
          VeilDB encrypted key-value store
        </span>{" "}
        — privacy-first, local-first, zero-trust.
      </footer>
    </div>
  );
}

/* ─── Inline Styles (self-contained, no CSS file needed) ─── */
const S: Record<string, React.CSSProperties> = {
  page: {
    minHeight: "100vh",
    background: "#000",
    color: "#e8edf5",
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    display: "flex",
    flexDirection: "column",
  },
  bgGlow: {
    position: "fixed",
    inset: 0,
    background:
      "radial-gradient(ellipse 80% 60% at 0% -8%, rgba(124,58,237,0.22), transparent 62%), radial-gradient(ellipse 70% 60% at 100% 108%, rgba(139,92,246,0.14), transparent 60%), linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px) 0 0/64px 64px, linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px) 0 0/64px 64px",
    pointerEvents: "none",
    zIndex: 0,
  },
  header: {
    position: "sticky",
    top: 0,
    zIndex: 50,
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "1rem 2rem",
    borderBottom: "1px solid rgba(255,255,255,0.1)",
    backdropFilter: "blur(16px)",
    background: "rgba(6,4,12,0.82)",
  },
  logoGroup: { display: "flex", alignItems: "center", gap: 10 },
  logoIcon: {
    width: 36,
    height: 36,
    borderRadius: 2,
    background: "linear-gradient(100deg,#8b5cf6,#a78bfa,#46e3b7)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "1.1rem",
    fontWeight: 800,
    color: "white",
    boxShadow: "0 4px 16px rgba(139,92,246,0.3)",
  },
  logoText: {
    fontSize: "1.35rem",
    fontWeight: 700,
    background: "linear-gradient(100deg,#8b5cf6,#a78bfa,#46e3b7)",
    WebkitBackgroundClip: "text",
    WebkitTextFillColor: "transparent",
  },
  badge: {
    fontSize: "0.65rem",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.08em",
    padding: "2px 8px",
    borderRadius: 20,
    background: "rgba(34,197,94,0.15)",
    color: "#4ade80",
    border: "1px solid rgba(34,197,94,0.3)",
  },
  nav: { display: "flex", gap: 4 },
  navBtn: {
    background: "transparent",
    border: "1px solid transparent",
    color: "#94a3b8",
    padding: "6px 14px",
    borderRadius: 2,
    fontSize: "0.85rem",
    fontWeight: 500,
    cursor: "pointer",
    fontFamily: "inherit",
  },
  navBtnActive: {
    color: "#a78bfa",
    background: "rgba(139,92,246,0.12)",
    borderColor: "rgba(139,92,246,0.2)",
  },
  main: {
    flex: 1,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "2rem",
    position: "relative",
    zIndex: 1,
  },
  card: {
    width: "100%",
    maxWidth: 440,
    background: "linear-gradient(145deg, rgba(14,14,16,0.7), rgba(4,4,6,0.92))",
    border: "1px solid rgba(255,255,255,0.12)",
    borderRadius: 2,
    padding: "2.5rem",
    boxShadow: "0 8px 32px rgba(0,0,0,0.3), 0 0 40px rgba(139,92,246,0.08)",
    backdropFilter: "blur(20px)",
  },
  cardTitle: { fontSize: "1.5rem", fontWeight: 700, textAlign: "center", margin: "0 0 8px" },
  cardSub: { textAlign: "center", color: "#94a3b8", fontSize: "0.85rem", margin: "0 0 24px" },
  field: { marginBottom: 16 },
  label: { display: "block", fontSize: "0.8rem", fontWeight: 500, color: "#94a3b8", marginBottom: 5 },
  input: {
    width: "100%",
    padding: "10px 12px",
    background: "rgba(10,16,32,0.8)",
    border: "1px solid rgba(255,255,255,0.12)",
    borderRadius: 2,
    color: "#e8edf5",
    fontSize: "0.9rem",
    fontFamily: "inherit",
    outline: "none",
    boxSizing: "border-box",
  },
  code: {
    background: "rgba(139,92,246,0.15)",
    color: "#a78bfa",
    padding: "1px 6px",
    borderRadius: 4,
    fontSize: "0.8em",
    fontFamily: "monospace",
  },
  btnPrimary: {
    width: "100%",
    padding: "12px",
    background: "linear-gradient(100deg,#8b5cf6,#a78bfa,#46e3b7)",
    border: "none",
    borderRadius: 2,
    color: "white",
    fontSize: "0.9rem",
    fontWeight: 600,
    cursor: "pointer",
    fontFamily: "inherit",
    boxShadow: "0 4px 16px rgba(139,92,246,0.25)",
    marginTop: 8,
  },
  btnSecondary: {
    padding: "6px 14px",
    background: "rgba(139,92,246,0.1)",
    border: "1px solid rgba(139,92,246,0.2)",
    borderRadius: 2,
    color: "#a78bfa",
    fontSize: "0.8rem",
    fontWeight: 500,
    cursor: "pointer",
    fontFamily: "inherit",
  },
  btnDanger: {
    padding: "4px 10px",
    background: "rgba(239,68,68,0.15)",
    border: "1px solid rgba(239,68,68,0.25)",
    borderRadius: 2,
    color: "#fca5a5",
    fontSize: "0.75rem",
    cursor: "pointer",
    fontFamily: "inherit",
  },
  toggleText: { textAlign: "center", marginTop: 20, fontSize: "0.85rem", color: "#94a3b8" },
  link: { color: "#a78bfa", cursor: "pointer", fontWeight: 500 },
  alert: {
    position: "fixed",
    top: 80,
    left: "50%",
    transform: "translateX(-50%)",
    padding: "10px 20px",
    borderRadius: 2,
    fontSize: "0.85rem",
    zIndex: 100,
    maxWidth: 500,
    textAlign: "center",
  },
  alertSuccess: {
    background: "rgba(34,197,94,0.15)",
    border: "1px solid rgba(34,197,94,0.3)",
    color: "#86efac",
  },
  alertError: {
    background: "rgba(239,68,68,0.15)",
    border: "1px solid rgba(239,68,68,0.3)",
    color: "#fca5a5",
  },
  alertInfo: {
    background: "rgba(139,92,246,0.15)",
    border: "1px solid rgba(139,92,246,0.3)",
    color: "#a78bfa",
  },
  dashboard: { width: "100%", maxWidth: 900 },
  dashHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: 24,
  },
  statsGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(4, 1fr)",
    gap: 12,
    marginBottom: 24,
  },
  statCard: {
    background: "linear-gradient(145deg, rgba(14,14,16,0.7), rgba(4,4,6,0.92))",
    border: "1px solid rgba(255,255,255,0.12)",
    borderRadius: 2,
    padding: 16,
  },
  statLabel: {
    fontSize: "0.7rem",
    color: "#64748b",
    textTransform: "uppercase",
    letterSpacing: "0.05em",
    marginBottom: 6,
  },
  statValue: {
    fontSize: "1.75rem",
    fontWeight: 700,
    background: "linear-gradient(100deg,#8b5cf6,#a78bfa,#46e3b7)",
    WebkitBackgroundClip: "text",
    WebkitTextFillColor: "transparent",
  },
  roleBadge: {
    display: "inline-block",
    padding: "3px 10px",
    borderRadius: 20,
    fontSize: "0.75rem",
    fontWeight: 500,
    background: "rgba(139,92,246,0.15)",
    color: "#a78bfa",
    border: "1px solid rgba(139,92,246,0.25)",
  },
  infoBox: {
    background: "rgba(30,41,59,0.5)",
    border: "1px solid rgba(99,102,241,0.2)",
    borderRadius: 2,
    padding: 16,
    marginBottom: 24,
  },
  section: {
    background: "linear-gradient(145deg, rgba(14,14,16,0.7), rgba(4,4,6,0.92))",
    border: "1px solid rgba(255,255,255,0.12)",
    borderRadius: 2,
    padding: 20,
    marginBottom: 20,
  },
  sectionTitle: { fontSize: "1.1rem", fontWeight: 600, margin: "0 0 12px" },
  table: { width: "100%", borderCollapse: "collapse" as const },
  th: {
    textAlign: "left",
    padding: "10px 12px",
    fontSize: "0.7rem",
    fontWeight: 600,
    color: "#64748b",
    textTransform: "uppercase",
    letterSpacing: "0.05em",
    borderBottom: "1px solid rgba(255,255,255,0.12)",
  },
  td: {
    padding: "10px 12px",
    fontSize: "0.85rem",
    borderBottom: "1px solid rgba(255,255,255,0.06)",
  },
  avatar: {
    width: 32,
    height: 32,
    borderRadius: "50%",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: 600,
    fontSize: "0.8rem",
    color: "white",
  },
  kvBox: {
    background: "rgba(10,16,32,0.6)",
    border: "1px solid rgba(255,255,255,0.1)",
    borderRadius: 2,
    padding: 10,
    fontFamily: "monospace",
    fontSize: "0.75rem",
  },
  footer: {
    textAlign: "center",
    padding: "1.5rem",
    fontSize: "0.8rem",
    color: "#64748b",
    borderTop: "1px solid rgba(255,255,255,0.12)",
    position: "relative",
    zIndex: 1,
  },
};
