// BullrunIQ service worker — installability + offline shell.
var VERSION = "briq-v1";
var SHELL = ["/", "/platform", "/manifest.json", "/icon-192.png", "/icon-512.png"];

self.addEventListener("install", function (e) {
  e.waitUntil(
    caches.open(VERSION).then(function (c) { return c.addAll(SHELL); }).catch(function () {})
  );
  self.skipWaiting();
});

self.addEventListener("activate", function (e) {
  e.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.filter(function (k) { return k !== VERSION; }).map(function (k) { return caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener("fetch", function (e) {
  var url;
  try { url = new URL(e.request.url); } catch (x) { return; }
  if (url.origin !== self.location.origin) return;
  if (url.pathname.indexOf("/api/") === 0 || url.pathname.indexOf("/.netlify/") === 0) return;
  if (e.request.method !== "GET") return;

  if (e.request.mode === "navigate") {
    e.respondWith(
      fetch(e.request).then(function (r) {
        var cp = r.clone();
        caches.open(VERSION).then(function (c) { c.put(e.request, cp); }).catch(function () {});
        return r;
      }).catch(function () {
        return caches.match(e.request).then(function (m) { return m || caches.match("/platform"); });
      })
    );
    return;
  }

  e.respondWith(
    caches.match(e.request).then(function (m) {
      var f = fetch(e.request).then(function (r) {
        var cp = r.clone();
        caches.open(VERSION).then(function (c) { c.put(e.request, cp); }).catch(function () {});
        return r;
      }).catch(function () { return m; });
      return m || f;
    })
  );
});
