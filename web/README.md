# Argus dashboard

Phase 4 of [`../PLAN.md`](../PLAN.md): eight data screens over the agent's own API plus a read-only
Settings screen, dark-first, dense.
React 19 + Vite + TypeScript + Tailwind v4, virtualised tables, no UI kit.

## Run it against a live agent

**Normally the agent serves the built dashboard itself** (`npm run build`, then the agent finds
`web/dist`), so this is one origin and no dev server is involved:

```powershell
dotnet run --project ..\src\Argus.Agent -- --port 0
# prints {"port":…,"token":…}; also written to --ready-file
# open http://127.0.0.1:<port>/?token=<token>
```

From there "Monitor an application" launches a target through the agent, so `--target` is optional.
`src/Argus.Desktop` does exactly this and opens the result in a WebView2 window.

For UI work, the dev server with HMR is still useful — it proxies `/api` to the agent, rewriting `Host`
and `Origin` to the agent's own, because the agent rejects anything else by design:

```powershell
dotnet run --project ..\src\Argus.Agent -- --port 5180
```

```bash
ARGUS_AGENT=http://127.0.0.1:5180 npm run dev
# open http://localhost:5173/?token=<the token the agent printed>
```

The token is stored in `localStorage` and sent as `Authorization: Bearer …`; the stream trades it for a
single-use ticket (see `src/Argus.Agent/StreamTickets.cs`), because `EventSource` cannot send headers
and the token must not appear in a URL.

## Run it against captured payloads

`?fixtures=benign` or `?fixtures=flagged` renders recorded agent responses instead of a live agent —
no elevation, no Windows. `scripts/dashboard-fixtures.ps1` (repo root) captures them:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ..\scripts\dashboard-fixtures.ps1 -FixtureName flagged `
  -Target C:\Windows\System32\cmd.exe -TargetArgs '/c C:\path\to\demo.bat'
```

```bash
npm run dev -- --open "/?fixtures=flagged"
```

## Checks

```bash
npm run build    # tsc --noEmit + vite build
npm test         # 20 fixture Playwright tests: nine routes, observability badges, evidence chain,
                 # keyboard, 100k-row scroll, launch dialog, settings, report export
                 # (+ 8 live tests that skip without a token)
npm run shots    # writes .shots/*.png for review (no assertions)
```

Playwright serves `dist/` with `vite preview`, so `npm run build` must be run before `npm test`.

Live mode runs against the agent's own origin, so no proxy is needed — point it at the agent's port:

```bash
ARGUS_LIVE_URL=http://127.0.0.1:5180 ARGUS_LIVE_TOKEN=<token> npm test -- e2e/live.spec.ts
```

The eight live tests cover the shell, a client-side route surviving a reload, **launch → preview →
session** (which stops any session left by a previous run first), the ticket-authenticated stream, the
sensor counters in the stats frame, a non-existent path being refused before anything launches, **report
export** (the download arrives and the saved file references no external asset) and **settings** (the bound
port and config digest match what `/api/settings` answers).

## Layout

```
src/api/client.ts      the only data door: live bearer fetches or fixture reads, same types
src/api/types.ts       the payload contract, copied from src/Argus.Agent/AgentJson.cs
src/components/        EventTable (virtualised), RiskChart (SVG), badges, panels, state notes
src/screens/           the eight data routes + Settings
src/session.tsx        one loaded session for the whole shell, so screens cannot disagree
e2e/routes.spec.ts     the definition-of-done assertions
e2e/live.spec.ts       the same claims against a real agent (ARGUS_LIVE_TOKEN)
```

Every screen renders loading, empty and error separately, and the coverage banner is not dismissible:
a session with collection gaps is weaker evidence, and the score alone cannot say so.
