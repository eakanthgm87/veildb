import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  // Relative asset paths so the built bundle loads under Tauri's custom
  // protocol. Absolute "/assets/..." + crossorigin fails to load in the
  // packaged webview and leaves a blank white screen.
  base: "./",
  clearScreen: false,
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/node_modules/**"],
    },
  },
});
