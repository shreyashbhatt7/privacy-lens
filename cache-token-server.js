// tracker-lab/cache-token-server.js
//
// A tiny local HTTP server that deterministically triggers the
// cache-detector.js logic: serves a resource at a token-looking path
// with an aggressive Cache-Control header. You can't fake response
// headers from a file:// page, so this is a real (if minimal) server.
//
// Run:   node tracker-lab/cache-token-server.js
// Then:  open http://localhost:5051/cache-token.html in Chrome with the
//        Privacy Lens extension enabled, and check the panel for a
//        category=identifier, subtype=cache-token event.

import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 5051;

// Long hex-looking run in the path — this is what TOKEN_LIKE in
// cache-detector.js is watching for (16+ hex chars, or 24+ base64-ish chars).
const TOKEN_PATH = "/assets/a3f9c2e1b7d84f0a9c1e2b3d4f5a6b7c.js";

const server = http.createServer((req, res) => {
  if (req.url === "/cache-token.html") {
    const html = readFileSync(path.join(__dirname, "cache-token.html"));
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
    return;
  }

  if (req.url === TOKEN_PATH) {
    res.writeHead(200, {
      "Content-Type": "application/javascript",
      // This is the aggressive-caching signal the detector looks for.
      "Cache-Control": "public, max-age=31536000, immutable",
    });
    res.end("// synthetic tracker-style asset, deliberately cached forever\n");
    return;
  }

  res.writeHead(404);
  res.end("not found");
});

server.listen(PORT, () => {
  console.log(`[tracker-lab] cache-token server running at http://localhost:${PORT}/cache-token.html`);
  console.log(`[tracker-lab] token-path resource: http://localhost:${PORT}${TOKEN_PATH}`);
});
