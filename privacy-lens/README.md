# Privacy Lens

Tracking forensics browser extension — see who is tracking you, how, and
where the data goes. Merge of Person 1's network-layer detectors (ETag
reuse, aggressive-cache tokens, CNAME cloaking, third-party beacons) and
Person 2's browser-fingerprint hooks (canvas, WebGL, AudioContext, fonts,
storage/cookies/beacons), integrated behind one shared `TrackingEvent`
schema. See `docs/ARCHITECTURE_LOCK.md` (with integration addendum) and
`docs/EVENT_SCHEMA_REFERENCE.md` (with resolved schema-drift section) for
the full story of how the two halves fit together.

## Setup

```
npm install
npm run build     # bundles fingerprint/main-world.js and content/content-bridge.js into dist/
```

## Load the extension

1. Open `chrome://extensions`, enable Developer Mode.
2. "Load unpacked" → select this `privacy-lens/` folder directly (not a
   subfolder — `manifest.json` lives at the repo root).
3. Click the extension icon to open the side panel — Person 3's Live Feed /
   dashboard / per-site analysis UI (`ui/sidepanel.html`), wired to the real
   detector pipeline. Events persist across panel opens/closes.

## Try it out

- `tracker-lab/tier1-test.html` — triggers every fingerprint hook (canvas,
  WebGL, audio, storage, fonts, beacons). Open directly in a tab with the
  extension enabled.
- `tracker-lab/cache-token.html` — triggers the cache-token detector.
  Needs a real HTTP server (can't fake response headers from `file://`):
  ```
  node tracker-lab/cache-token-server.js
  # then open http://localhost:5051/cache-token.html
  ```
- Browsing any normal site with third-party trackers/analytics will
  exercise the network detectors (ETag reuse needs 2+ visits to the same
  tracker to fire — it requires repeat sightings, not just one).

## Tests

```
npm test    # node tests/test-hooks.js — fingerprint hook + batching/dedup checks
node tests/test-event-display.js   # canonical event -> UI display mapping checks
```
