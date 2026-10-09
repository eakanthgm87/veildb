import React, { useState, useEffect } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import DemoSite from "./DemoSite";
import "./index.css";

function showFatal(e: unknown) {
  const msg =
    e instanceof Error ? e.stack || e.message : String(e);
  console.error("[VeilDB fatal]", e);
  const el = document.getElementById("root");
  if (el && !el.hasChildNodes()) {
    el.innerHTML =
      `<div style="padding:24px;font-family:monospace;color:#fca5a5;background:#0f172a;min-height:100vh">` +
      `<h2>VeilDB failed to start</h2><pre style="white-space:pre-wrap">${String(msg).replace(/</g, "&lt;")}</pre></div>`;
  }
}

window.addEventListener("error", (ev) => showFatal(ev.error ?? ev.message));
window.addEventListener("unhandledrejection", (ev) =>
  showFatal(ev.reason)
);

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: unknown }
> {
  state = { error: null as unknown };
  static getDerivedStateFromError(error: unknown) {
    return { error };
  }
  componentDidCatch(error: unknown) {
    showFatal(error);
  }
  render() {
    if (this.state.error) {
      const msg =
        this.state.error instanceof Error
          ? this.state.error.stack || this.state.error.message
          : String(this.state.error);
      return (
        <div
          style={{
            padding: 24,
            fontFamily: "monospace",
            color: "#fca5a5",
            background: "#0f172a",
            minHeight: "100vh",
          }}
        >
          <h2>VeilDB crashed</h2>
          <pre style={{ whiteSpace: "pre-wrap" }}>{msg}</pre>
        </div>
      );
    }
    return this.props.children;
  }
}

function Router() {
  const [route, setRoute] = useState(window.location.hash);

  useEffect(() => {
    const onHash = () => setRoute(window.location.hash);
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  // If hash is #demo, show the standalone demo site
  if (route === "#demo") {
    return <DemoSite />;
  }

  // Otherwise show the main VeilDB dashboard
  return <App />;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <Router />
    </ErrorBoundary>
  </React.StrictMode>,
);