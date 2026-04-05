// ── INCREMENT THIS VERSION NUMBER EVERY TIME YOU DEPLOY ──────
const CACHE_VERSION = 'stockroom-v5';
const CACHE_NAME    = CACHE_VERSION;

const CACHE_URLS = [
  './',
  './index.html',
  './manifest.json',
];

const SYNC_TAG = 'stockroom-sync';

// ── Install: cache core files ─────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => {
      return cache.addAll(CACHE_URLS).catch(e => {
        console.warn('SW: cache failed for some files:', e);
      });
    })
  );
  // Don't auto-activate — wait for the app to send SKIP_WAITING
  // so the user can choose when to refresh
});

// ── Activate: clean up old caches ────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => {
        console.log('SW: removing old cache', k);
        return caches.delete(k);
      }))
    )
  );
  self.clients.claim();
});

// ── Message: handle SKIP_WAITING and sync requests ───────────
self.addEventListener('message', event => {
  if (event.data?.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  if (event.data?.type === 'REMINDER_REPLACED') {
    // Already handled by notificationclick — nothing extra needed
  }
});

// ── Background Sync: fires when connectivity returns ─────────
// Registered by the app whenever a save happens while offline.
// The browser/OS guarantees this fires even if the app is closed.
self.addEventListener('sync', event => {
  if (event.tag === SYNC_TAG) {
    event.waitUntil(triggerAppSync());
  }
});

async function triggerAppSync() {
  // Try to find an open app window and tell it to sync
  const clientList = await clients.matchAll({ type: 'window', includeUncontrolled: true });
  const appClient  = clientList.find(c => c.url.includes('stockroom'));

  if (appClient) {
    // App is open — post a message to trigger syncAll()
    appClient.postMessage({ type: 'BG_SYNC' });
    console.log('SW: background sync — notified open app client');
  } else {
    // App is closed — we can't run syncAll() here (no access to Drive token/IndexedDB app state)
    // Set a flag in SW storage so the app syncs immediately on next open
    console.log('SW: background sync — app closed, flagging for sync on next open');
    // Use the Cache API as a lightweight flag store (no extra permissions needed)
    const cache = await caches.open('stockroom-flags');
    await cache.put('pending-sync', new Response('1'));
  }
}

// ── Fetch: cache-first for app shell, network-first for APIs ─
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // Let API calls go straight to the network
  if (
    url.hostname.includes('googleapis.com')    ||
    url.hostname.includes('dropboxapi.com')    ||
    url.hostname.includes('dropbox.com')       ||
    url.hostname.includes('workers.dev')       ||
    url.hostname.includes('deno.net')          ||
    url.hostname.includes('resend.com')        ||
    url.hostname.includes('openfoodfacts.org') ||
    url.hostname.includes('openbeautyfacts.org')
  ) {
    return;
  }

  // Cache-first for app shell
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        if (response.ok && url.origin === self.location.origin) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      }).catch(() => {
        if (event.request.mode === 'navigate') {
          return caches.match('./index.html');
        }
      });
    })
  );
});

// ── Fetch: cache-first for app shell, network-first for APIs ─
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;

  const url = new URL(event.request.url);

  // Let API calls go straight to the network
  if (
    url.hostname.includes('googleapis.com')    ||
    url.hostname.includes('dropboxapi.com')    ||
    url.hostname.includes('dropbox.com')       ||
    url.hostname.includes('workers.dev')       ||
    url.hostname.includes('deno.net')          ||
    url.hostname.includes('resend.com')        ||
    url.hostname.includes('openfoodfacts.org') ||
    url.hostname.includes('openbeautyfacts.org')
  ) {
    return;
  }

  // Cache-first for app shell
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        if (response.ok && url.origin === self.location.origin) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      }).catch(() => {
        if (event.request.mode === 'navigate') {
          return caches.match('./index.html');
        }
      });
    })
  );
});

// ── Notification click: handle Replaced action or open app ───
self.addEventListener('notificationclick', event => {
  event.notification.close();

  const data       = event.notification.data || {};
  const action     = event.action;
  const reminderId = data.reminderId;
  const token      = data.token;
  const workerUrl  = data.workerUrl;
  const appUrl     = data.url || './';

  if (action === 'replaced' && reminderId && token && workerUrl) {
    // Mark as replaced directly from the notification — no app visit needed
    event.waitUntil(
      fetch(`${workerUrl}/reminder-done?id=${encodeURIComponent(reminderId)}&token=${encodeURIComponent(token)}&name=${encodeURIComponent(data.reminderName || '')}&source=push`)
        .then(res => res.json())
        .then(result => {
          const date = result.date || new Date().toISOString().slice(0, 10);
          // Post message to any open app windows so they can update locally
          return clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
            clientList.forEach(client => {
              client.postMessage({
                type:       'REMINDER_REPLACED',
                reminderId,
                date,
                token,
              });
            });
          });
        })
        .catch(() => {
          // Network failed — open the app so user can mark manually
          return clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
            for (const client of clientList) {
              if (client.url.includes('stockroom') && 'focus' in client) return client.focus();
            }
            if (clients.openWindow) return clients.openWindow(appUrl);
          });
        })
    );
    return;
  }

  // Default: 'open' action or notification body tap — focus or open app
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      for (const client of clientList) {
        if (client.url.includes('stockroom') && 'focus' in client) return client.focus();
      }
      if (clients.openWindow) return clients.openWindow(appUrl);
    })
  );
});
