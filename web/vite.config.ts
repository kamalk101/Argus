import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The dashboard talks to the local agent over loopback with a bearer token. In development it runs
// on a different origin from the agent, so `/api` is proxied; in the packaged WebView2 shell the app
// is served by the agent itself and the proxy is unused. `ARGUS_AGENT` overrides the target when the
// agent picked an ephemeral port (`--port 0`, which is how `scripts/dashboard-fixtures.ps1` runs it).
const agent = process.env.ARGUS_AGENT ?? 'http://127.0.0.1:5180';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      // changeOrigin rewrites Host to the agent's own 127.0.0.1:<port>: the agent rejects any other
      // Host header by design, and a dashboard-only dev proxy is not a reason to weaken that.
      '/api': {
        target: agent,
        changeOrigin: true,
        // The agent rejects any Origin that is not its own, and a browser always sends one on a POST
        // (the stream-ticket request). Rewrite it to the agent's origin for the dev proxy only; in the
        // packaged shell the dashboard is served by the agent, so it is same-origin and unaffected.
        configure: (proxy) => {
          proxy.on('proxyReq', (request) => request.setHeader('Origin', agent));
        },
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
