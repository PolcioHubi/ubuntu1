const CACHE_NAME = 'mobywatel-cache-v1';
const urlsToCache = [
  '/',
  '/static/dashboard.html',
  '/static/main.css',
  '/static/jquery-3.6.0.min.js',
  '/static/manifest.json'
  // Dodaj inne kluczowe zasoby statyczne, jeśli są
];

// Instalacja Service Workera
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
});

// Aktywacja Service Workera i czyszczenie starych cache
self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// Przechwytywanie żądań sieciowych
self.addEventListener('fetch', event => {
  // Obsługujemy tylko żądania GET i ignorujemy żądania chrome-extension
  if (event.request.method !== 'GET' || event.request.url.startsWith('chrome-extension://')) {
    return;
  }

  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // Jeśli zasób jest w cache, zwróć go
        if (response) {
          return response;
        }

        // W przeciwnym razie, pobierz z sieci
        return fetch(event.request).then(
          networkResponse => {
            // Sprawdź, czy otrzymaliśmy prawidłową odpowiedź
            if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
              return networkResponse;
            }

            // Sklonuj odpowiedź, ponieważ może być użyta tylko raz
            const responseToCache = networkResponse.clone();

            caches.open(CACHE_NAME)
              .then(cache => {
                // Zapisz nowo pobrany zasób w cache
                // UWAGA: To obejmuje dynamiczne strony HTML, jak dowodnowy.html
                cache.put(event.request, responseToCache);
              });

            return networkResponse;
          }
        ).catch(() => {
          // Opcjonalnie: zwróć stronę offline, jeśli pobieranie z sieci się nie powiedzie
          // return caches.match('/static/offline.html');
        });
      })
  );
});
