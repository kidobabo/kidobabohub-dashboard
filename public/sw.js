// public/sw.js
// Kido & Babo Hub — Safe Offline Service Worker
// ✅ Caches only small "app shell" assets
// ✅ NEVER intercepts Range requests (critical for big PDFs)
// ✅ NEVER caches PDFs automatically (prevents "can't be opened, refresh" issues)

const CACHE_NAME = "kb-offline-v3";

// Keep this list SMALL. Don't include PDFs or large audio here.
const CORE_ASSETS = [
  "/",                    // optional: caches the root if you have a stable index.html
  "/readaloud.html",
  "/reader.html",
  "/storybooks.pdf/books.json",
  "/sounds/page-flip.mp3",
  "/logo.jpg"
];

// Helper: safe cache put
async function safeCachePut(req, res) {
  try {
    if (!res || !res.ok) return;
    const cache = await caches.open(CACHE_NAME);
    await cache.put(req, res.clone());
  } catch (e) {}
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE_NAME);
      await cache.addAll(CORE_ASSETS);
      await self.skipWaiting();
    })()
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      // Remove old caches
      const keys = await caches.keys();
      await Promise.all(keys.map((k) => (k !== CACHE_NAME ? caches.delete(k) : Promise.resolve())));
      await self.clients.claim();
    })()
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);

  // Only handle same-origin
  if (url.origin !== self.location.origin) return;

  // ✅ CRITICAL: Do NOT handle Range requests (PDF streaming depends on this)
  if (req.headers.has("range")) {
    event.respondWith(fetch(req));
    return;
  }

  // ✅ Do NOT cache PDFs automatically (prevents broken PDF viewing)
  if (url.pathname.toLowerCase().endsWith(".pdf")) {
    event.respondWith(fetch(req));
    return;
  }

  // Cache-first for CORE + small assets, network fallback
  event.respondWith(
    (async () => {
      const cached = await caches.match(req);
      if (cached) return cached;

      try {
        const res = await fetch(req);

        // Only cache small-ish static assets (avoid caching huge blobs)
        const ct = (res.headers.get("content-type") || "").toLowerCase();
        const isStatic =
          ct.includes("text/") ||
          ct.includes("javascript") ||
          ct.includes("json") ||
          ct.includes("image/") ||
          ct.includes("font/") ||
          ct.includes("audio/");

        if (isStatic) {
          await safeCachePut(req, res);
        }

        return res;
      } catch (e) {
        // Offline fallback: if we have a cached version, use it; otherwise show a basic response
        const fallback = await caches.match(req);
        if (fallback) return fallback;

        return new Response("Offline. Please reconnect and try again.", {
          status: 503,
          headers: { "Content-Type": "text/plain; charset=utf-8" }
        });
      }
    })()
  );
});