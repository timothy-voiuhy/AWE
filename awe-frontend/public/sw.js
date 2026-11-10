// Existing installations still receive updates. Let the browser fetch current
// HTML and bundles directly; the old worker could cache an HTML SPA fallback as
// JavaScript or CSS after a deployment removed a hashed bundle.
self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key.startsWith('awe-')) await caches.delete(key);
    }
    await self.clients.claim();
  })());
});
