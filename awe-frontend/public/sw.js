// AWE service worker — installability + fast loads. Runtime caching only:
// built asset names are content-hashed, so there is no static precache list.
// The API and live sockets are never touched by the cache.
const VERSION = 'awe-v1';
const SHELL = `${VERSION}-shell`;
const ASSETS = `${VERSION}-assets`;
const OFFLINE_URL = '/index.html';

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(SHELL);
    // Cache what we know by stable name; hashed bundles are cached on first use.
    await cache.addAll([
      '/', OFFLINE_URL, '/manifest.webmanifest',
      '/assets/icons/awe-icon-192.png', '/assets/icons/awe-icon-512.png',
    ].map((u) => new Request(u, { cache: 'reload' }))).catch(() => {});
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keep = new Set([SHELL, ASSETS]);
    for (const key of await caches.keys()) {
      if (!keep.has(key)) await caches.delete(key);
    }
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // Same-origin only; never cache the API or anything cross-origin.
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;

  // Navigations: network-first, fall back to the cached app shell when offline.
  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        const fresh = await fetch(req);
        const cache = await caches.open(SHELL);
        cache.put(OFFLINE_URL, fresh.clone()).catch(() => {});
        return fresh;
      } catch {
        return (await caches.match(OFFLINE_URL)) || (await caches.match('/')) || Response.error();
      }
    })());
    return;
  }

  // Static assets: stale-while-revalidate for instant loads with background refresh.
  if (/\.(?:js|css|png|svg|jpg|jpeg|gif|webp|ico|woff2?|ttf|json|webmanifest)$/i.test(url.pathname)
      || url.pathname.startsWith('/assets/')) {
    event.respondWith((async () => {
      const cache = await caches.open(ASSETS);
      const cached = await cache.match(req);
      const network = fetch(req).then((res) => {
        if (res && res.status === 200 && res.type === 'basic') cache.put(req, res.clone());
        return res;
      }).catch(() => cached);
      return cached || network;
    })());
  }
});
