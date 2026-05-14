var CACHE = 'destiny-v1';
var PRECACHE = ['/', '/heroes', '/arsenal', '/destiny.png', '/manifest.json'];

self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE).then(function(c) { return c.addAll(PRECACHE); })
      .then(function() { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.filter(function(k) { return k !== CACHE; }).map(function(k) { return caches.delete(k); })
      );
    }).then(function() { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function(e) {
  var req = e.request;
  if (req.method !== 'GET') return;

  var url = new URL(req.url);

  // Never cache Railway API calls
  if (url.hostname !== self.location.hostname) return;
  if (url.pathname.startsWith('/api/')) return;

  // Navigation requests: network first, fall back to cached index
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req).catch(function() {
        return caches.match('/') || caches.match('/index.html');
      })
    );
    return;
  }

  // Static assets: cache first, update cache in background
  e.respondWith(
    caches.match(req).then(function(cached) {
      var networkFetch = fetch(req).then(function(res) {
        if (res && res.status === 200 && res.type === 'basic') {
          caches.open(CACHE).then(function(c) { c.put(req, res.clone()); });
        }
        return res;
      }).catch(function() { return cached; });
      return cached || networkFetch;
    })
  );
});
