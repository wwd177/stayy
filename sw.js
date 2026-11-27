const SCOPE_SLUG = new URL(self.registration.scope).pathname.replace(/[^a-zA-Z0-9_-]/g, '_');
const CACHE_PREFIX = 'stayy-ios-shell-' + SCOPE_SLUG + '-';
const CACHE_NAME = CACHE_PREFIX + 'v3';
const REQUIRED_SHELL = ['./', './index.html'];
const OPTIONAL_ASSETS = ['./apple-touch-icon.png', './icon-192.png', './icon-512.png', './manifest.json'];

async function cacheUrlStrict(cache, assetUrl) {
  const res = await fetch(assetUrl, { cache: 'no-cache' });
  if (!res || !res.ok) throw new Error('SHELL_PRECACHE_FAILED:' + assetUrl);
  await cache.put(assetUrl, res);
}

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      await Promise.all(REQUIRED_SHELL.map((u) => cacheUrlStrict(cache, u)));
      await Promise.allSettled(OPTIONAL_ASSETS.map((u) => cacheUrlStrict(cache, u)));
      await self.skipWaiting();
    })
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k.startsWith(CACHE_PREFIX) && k !== CACHE_NAME)
          .map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

function fetchWithTimeout(req, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  return fetch(req, { cache: 'no-store', signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin || url.pathname.endsWith('/beacon.json')) {
    return;
  }
  const isNavShell = e.request.mode === 'navigate'
    || url.pathname.endsWith('/')
    || url.pathname.endsWith('/index.html');

  if (isNavShell) {
    e.respondWith(
      fetchWithTimeout(e.request, 3200)
        .then((res) => {
          if (!res || !res.ok) throw new Error('HTTP_' + (res ? res.status : 0));
          const clone = res.clone();
          e.waitUntil(caches.open(CACHE_NAME).then((c) => c.put(e.request, clone)).catch(() => {}));
          return res;
        })
        .catch(() =>
          caches.open(CACHE_NAME)
            .then((c) => c.match(e.request).then((m) => m || c.match('./index.html')))
            .then((m) => m || caches.match('./index.html'))
        )
    );
    return;
  }

  e.respondWith(
    caches.open(CACHE_NAME).then((cache) =>
      cache.match(e.request).then((cached) => {
        const netUpdate = fetchWithTimeout(e.request, 3500)
          .then((res) => {
            if (res && res.ok) {
              return cache.put(e.request, res.clone()).catch(() => {}).then(() => res);
            }
            return cached || res;
          })
          .catch(() => cached);
        if (cached) {
          e.waitUntil(netUpdate);
          return cached;
        }
        return netUpdate;
      })
    )
  );
});
