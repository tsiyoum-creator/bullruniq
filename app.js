/* ================================================================
   #IWill — app.js
   ================================================================ */

// Firebase client config is intentionally public — it is a project identifier,
// not a secret. Access is controlled by Firebase Security Rules on the server.
// See: https://firebase.google.com/docs/projects/api-keys
const FIREBASE_CONFIG = {
  apiKey:            "AIzaSyAn0deVxcR66YOEiIYD05hyDnzrrroUUvM",
  authDomain:        "iwill-challenge.firebaseapp.com",
  projectId:         "iwill-challenge",
  storageBucket:     "iwill-challenge.firebasestorage.app",
  messagingSenderId: "684886358059",
  appId:             "1:684886358059:web:4e15e02f501b113880126e"
};

const FIREBASE_READY = FIREBASE_CONFIG.apiKey !== "YOUR_API_KEY";
let db = null;

if (FIREBASE_READY) {
  firebase.initializeApp(FIREBASE_CONFIG);
  db = firebase.firestore();
  document.getElementById('firebaseNotice').classList.remove('show');
} else {
  document.getElementById('firebaseNotice').classList.add('show');
}

/* NAV */
const nav       = document.getElementById('nav');
const navToggle = document.getElementById('navToggle');
const navLinks  = document.getElementById('navLinks');

window.addEventListener('scroll', () => {
  nav.classList.toggle('scrolled', window.scrollY > 50);
}, { passive: true });

navToggle.addEventListener('click', () => navLinks.classList.toggle('open'));
navLinks.querySelectorAll('a').forEach(a => a.addEventListener('click', () => navLinks.classList.remove('open')));

/* PARTICLES */
(function () {
  const container = document.getElementById('particles');
  for (let i = 0; i < 12; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    const size = (Math.random() * 2 + 1).toFixed(1);
    const opacity = (Math.random() * 0.25 + 0.1).toFixed(2);
    p.style.cssText = `left:${(Math.random()*100).toFixed(1)}%;animation-delay:${(Math.random()*14).toFixed(2)}s;animation-duration:${(Math.random()*12+14).toFixed(2)}s;width:${size}px;height:${size}px;background:rgba(192,72,37,${opacity});border-radius:50%;font-size:0;`;
    container.appendChild(p);
  }
})();

/* SCROLL FADE */
const fadeObs = new IntersectionObserver(entries => {
  entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); });
}, { threshold: 0.08 });
document.querySelectorAll('.fade-in').forEach(el => fadeObs.observe(el));

/* COUNTDOWN */
const DEADLINE = new Date('2026-05-28T18:00:00-04:00');
function pad(n) { return String(n).padStart(2, '0'); }
function tick() {
  const diff = DEADLINE - Date.now();
  if (diff <= 0) {
    ['days','hours','minutes','seconds'].forEach(id => document.getElementById(id).textContent = '00');
    document.querySelector('.countdown-note').textContent = '🎉 Challenge closed — winners being announced!';
    return;
  }
  document.getElementById('days').textContent    = pad(Math.floor(diff / 86400000));
  document.getElementById('hours').textContent   = pad(Math.floor((diff % 86400000) / 3600000));
  document.getElementById('minutes').textContent = pad(Math.floor((diff % 3600000) / 60000));
  document.getElementById('seconds').textContent = pad(Math.floor((diff % 60000) / 1000));
}
tick();
setInterval(tick, 1000);

/* GLOBE */
const globeEl = document.getElementById('globe-container');
const pins = [];
let pinTotal = 0;
const countrySet = new Set();

function animateCount(id, target) {
  const el = document.getElementById(id);
  const start = parseInt(el.textContent, 10) || 0;
  const dur = 600, t0 = performance.now();
  const step = ts => {
    const p = Math.min((ts - t0) / dur, 1);
    el.textContent = Math.round(start + (target - start) * easeOut(p));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

const myGlobe = Globe({ animateIn: true, rendererConfig: { antialias: true, alpha: true } })
  .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-day.jpg')
  .bumpImageUrl(null)
  .backgroundImageUrl(null)
  .showGraticules(false)
  .showAtmosphere(true)
  .atmosphereColor('rgba(120,190,255,0.9)')
  .atmosphereAltitude(0.22)
  .pointsData(pins)
  .pointLat('lat')
  .pointLng('lng')
  .pointColor(() => '#C04825')
  .pointRadius(0.5)
  .pointAltitude(0.012)
  .pointsMerge(false)
  .pointLabel(d => `
    <div style="background:rgba(255,255,255,0.96);border:1px solid rgba(192,72,37,0.35);border-radius:8px;padding:10px 14px;font-family:Inter,sans-serif;pointer-events:none;box-shadow:0 4px 20px rgba(0,0,0,0.12)">
      <div style="font-family:'Bebas Neue',sans-serif;font-size:14px;letter-spacing:.08em;color:#0a0404">${escHtml(d.username || '?')}</div>
      <div style="font-size:11px;color:rgba(192,72,37,0.9);margin-top:3px">📍 ${escHtml(d.city || 'Somewhere on Earth')}</div>
      <div style="font-size:10px;color:rgba(192,72,37,0.5);margin-top:4px;font-family:'Bebas Neue',sans-serif;letter-spacing:.12em">#IWill</div>
    </div>
  `)
  (globeEl);

myGlobe.pointOfView({ lat: 22, lng: 10, altitude: 2.5 });
const globeControls = myGlobe.controls();
globeControls.autoRotate = true;
globeControls.autoRotateSpeed = 0.4;
globeControls.enableDamping = true;
globeControls.dampingFactor = 0.08;
globeControls.minDistance = 200;
globeControls.maxDistance = 900;

(function handleResize() {
  const resize = () => myGlobe.width(globeEl.offsetWidth).height(globeEl.offsetHeight);
  resize();
  window.addEventListener('resize', resize, { passive: true });
})();

function addMapPin(data) {
  pinTotal++;
  pins.push(data);
  myGlobe.pointsData([...pins]);
  if (data.country) countrySet.add(data.country);
  animateCount('mapStatPins', pinTotal);
  animateCount('mapStatCountries', countrySet.size);
  document.getElementById('pinNumber').textContent = pinTotal;
}

if (db) {
  db.collection('map_pins').orderBy('timestamp', 'asc').onSnapshot(snapshot => {
    snapshot.docChanges().forEach(change => {
      if (change.type === 'added') addMapPin(change.doc.data());
    });
  });
} else {
  const demoPins = [
    { lat: 33.749,  lng: -84.388,  username: '@ATLreppin',      city: 'Atlanta, USA',      country: 'USA' },
    { lat: 40.712,  lng: -74.006,  username: '@NYC_vibes',       city: 'New York, USA',     country: 'USA' },
    { lat: 25.761,  lng: -80.191,  username: '@305heat',         city: 'Miami, USA',        country: 'USA' },
    { lat: 34.052,  lng: -118.243, username: '@LAflex',          city: 'Los Angeles, USA',  country: 'USA' },
    { lat: 29.760,  lng: -95.369,  username: '@HoustonStrong',   city: 'Houston, USA',      country: 'USA' },
    { lat: 41.881,  lng: -87.627,  username: '@ChiTownLit',      city: 'Chicago, USA',      country: 'USA' },
    { lat: 51.507,  lng: -0.128,   username: '@LondonCheck',     city: 'London, UK',        country: 'UK' },
    { lat: 48.856,  lng: 2.352,    username: '@ParisFire',       city: 'Paris, France',     country: 'France' },
    { lat: -33.868, lng: 151.210,  username: '@SydneyChallenge', city: 'Sydney, Australia', country: 'Australia' },
    { lat: 1.352,   lng: 103.820,  username: '@SingaporeVibes',  city: 'Singapore',         country: 'Singapore' },
    { lat: -23.550, lng: -46.633,  username: '@SaoPauloMove',    city: 'São Paulo, Brazil', country: 'Brazil' },
    { lat: 6.524,   lng: 3.379,    username: '@LagosReppin',     city: 'Lagos, Nigeria',    country: 'Nigeria' },
    { lat: 28.613,  lng: 77.209,   username: '@DelhiDancer',     city: 'New Delhi, India',  country: 'India' },
    { lat: 35.689,  lng: 139.692,  username: '@TokyoFlow',       city: 'Tokyo, Japan',      country: 'Japan' },
    { lat: 55.751,  lng: 37.617,   username: '@MoscowBeat',      city: 'Moscow, Russia',    country: 'Russia' },
    { lat: 19.432,  lng: -99.133,  username: '@MexicoCityFire',  city: 'Mexico City, MX',   country: 'Mexico' },
  ];
  demoPins.forEach((p, i) => setTimeout(() => addMapPin(p), i * 120));
}

myGlobe.onGlobeClick(({ lat, lng }) => {
  if (!waitingClick) return;
  waitingClick = false;
  mapHint.textContent = '';
  pendingLat = lat;
  pendingLng = lng;
  locationStatus.textContent = '✓ Location set on globe!';
  locationStatus.style.color = '#22c55e';
  globeControls.autoRotate = true;
  pinModal.classList.add('active');
});

const pinModal       = document.getElementById('pinModal');
const pinNameInput   = document.getElementById('pinName');
const pinCityInput   = document.getElementById('pinCity');
const locationStatus = document.getElementById('locationStatus');
const mapHint        = document.getElementById('mapHint');
let pendingLat = null, pendingLng = null, waitingClick = false;

document.getElementById('dropPinBtn').addEventListener('click', () => {
  waitingClick = false;
  pendingLat = pendingLng = null;
  locationStatus.textContent = '';
  locationStatus.style.color = '';
  pinModal.classList.add('active');
});

document.getElementById('autoLocateBtn').addEventListener('click', () => {
  if (!navigator.geolocation) { startGlobeClick(); return; }
  locationStatus.textContent = '🔍 Detecting your location…';
  locationStatus.style.color = 'var(--muted)';
  navigator.geolocation.getCurrentPosition(
    pos => {
      pendingLat = pos.coords.latitude;
      pendingLng = pos.coords.longitude;
      locationStatus.textContent = '✓ Location detected!';
      locationStatus.style.color = '#22c55e';
    },
    () => startGlobeClick()
  );
});

function startGlobeClick() {
  pinModal.classList.remove('active');
  waitingClick = true;
  globeControls.autoRotate = false;
  mapHint.textContent = '👆 Click anywhere on the globe to drop your pin';
}

document.getElementById('cancelPin').addEventListener('click', () => {
  pinModal.classList.remove('active');
  waitingClick = false;
  globeControls.autoRotate = true;
  mapHint.textContent = '';
});

document.getElementById('confirmPin').addEventListener('click', async () => {
  const username = pinNameInput.value.trim();
  const city     = pinCityInput.value.trim();
  if (!username) { pinNameInput.focus(); return; }
  if (pendingLat === null) {
    locationStatus.textContent = '⚠ Tap "Use My Location" or click the globe first.';
    locationStatus.style.color = 'var(--amber)';
    return;
  }
  const data = { username, city: city || 'Somewhere on Earth', lat: pendingLat, lng: pendingLng };
  if (db) {
    await db.collection('map_pins').add({ ...data, timestamp: firebase.firestore.FieldValue.serverTimestamp() });
  } else {
    addMapPin(data);
  }
  myGlobe.pointOfView({ lat: pendingLat, lng: pendingLng, altitude: 1.8 }, 1400);
  pinModal.classList.remove('active');
  pinNameInput.value = pinCityInput.value = '';
  pendingLat = pendingLng = null;
  locationStatus.textContent = '';
});

/* VIDEO SUBMISSIONS */
const videosGrid      = document.getElementById('videosGrid');
const videosEmpty     = document.getElementById('videosEmpty');
const videoNumberEl   = document.getElementById('videoNumber');
const videoUsernameIn = document.getElementById('videoUsername');
const videoUrlIn      = document.getElementById('videoUrl');
const submitVideoBtn  = document.getElementById('submitVideoBtn');
const videoError      = document.getElementById('videoError');
let videoCount = 0;

function extractTikTokId(url) {
  const m = url.match(/tiktok\.com\/@[^/]+\/video\/(\d+)/);
  return m ? m[1] : null;
}
function isShortTikTokLink(url) {
  return /tiktok\.com\/t\/[A-Za-z0-9]+/i.test(url);
}
async function resolveTikTokId(url) {
  if (extractTikTokId(url)) return extractTikTokId(url);
  if (isShortTikTokLink(url)) {
    try {
      const res  = await fetch(`https://www.tiktok.com/oembed?url=${encodeURIComponent(url)}`);
      const json = await res.json();
      return json.embed_product_id || null;
    } catch { return null; }
  }
  return null;
}

function addVideoCard(data) {
  videosEmpty.style.display = 'none';
  videoCount++;
  videoNumberEl.textContent = videoCount;
  const card = document.createElement('div');
  card.className = 'video-card fade-in';
  card.innerHTML = `
    <div class="video-embed-wrap">
      <iframe src="https://www.tiktok.com/embed/v2/${data.videoId}?loop=1" allow="fullscreen" allowfullscreen loading="lazy"></iframe>
      <div class="tt-loop-overlay"></div>
    </div>
    <div class="video-card-footer">
      <span class="video-card-user">${escHtml(data.username)}</span>
      <a class="video-card-link" href="${escHtml(data.url)}" target="_blank" rel="noopener">
        <svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor"><path d="M19.59 6.69a4.83 4.83 0 01-3.77-4.25V2h-3.45v13.67a2.89 2.89 0 01-2.88 2.5 2.89 2.89 0 01-2.89-2.89 2.89 2.89 0 012.89-2.89c.28 0 .54.04.79.1V9.01a6.27 6.27 0 00-.79-.05 6.34 6.34 0 00-6.34 6.34 6.34 6.34 0 006.34 6.34 6.34 6.34 0 006.33-6.34V8.69a8.18 8.18 0 004.79 1.54V6.79a4.85 4.85 0 01-1.02-.1z"/></svg>
        View on TikTok
      </a>
    </div>`;
  videosGrid.appendChild(card);
  setTimeout(() => card.classList.add('visible'), 50);
}

if (db) {
  db.collection('video_submissions').orderBy('timestamp', 'desc').onSnapshot(snapshot => {
    snapshot.docChanges().forEach(change => {
      if (change.type === 'added') addVideoCard(change.doc.data());
    });
  });
}

submitVideoBtn.addEventListener('click', async () => {
  videoError.textContent = '';
  const username = videoUsernameIn.value.trim();
  const url      = videoUrlIn.value.trim();
  if (!username) { videoError.textContent = '⚠ Enter your TikTok @username.'; return; }
  if (!url)      { videoError.textContent = '⚠ Paste your TikTok video link.'; return; }
  submitVideoBtn.textContent = 'Submitting…';
  submitVideoBtn.disabled = true;
  const videoId = await resolveTikTokId(url);
  if (!videoId) {
    videoError.textContent = '⚠ Paste your TikTok link — short links (tiktok.com/t/…) and full links both work.';
    submitVideoBtn.textContent = 'Submit Entry';
    submitVideoBtn.disabled = false;
    return;
  }
  const data = { username, url, videoId };
  if (db) {
    await db.collection('video_submissions').add({ ...data, timestamp: firebase.firestore.FieldValue.serverTimestamp() });
  } else {
    addVideoCard(data);
  }
  videoUsernameIn.value = videoUrlIn.value = '';
  submitVideoBtn.textContent = 'Submit Entry';
  submitVideoBtn.disabled = false;
});

/* CHAT */
const chatMessages  = document.getElementById('chatMessages');
const chatInput     = document.getElementById('chatInput');
const chatUsername  = document.getElementById('chatUsername');
const sendBtn       = document.getElementById('sendBtn');

const savedName = localStorage.getItem('iwill_username');
if (savedName) chatUsername.value = savedName;
chatUsername.addEventListener('blur', () => localStorage.setItem('iwill_username', chatUsername.value.trim()));

function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

function renderMessage(data, isOwn) {
  const wrap = document.createElement('div');
  wrap.className = `message ${isOwn ? 'message-own' : 'message-other'}`;
  const ts = data.timestamp
    ? new Date(data.timestamp.toDate()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : 'just now';
  wrap.innerHTML = `
    <div class="message-meta">
      <span class="message-user">${escHtml(data.username || 'Anonymous')}</span>
      <span class="message-time">${ts}</span>
    </div>
    <div class="message-text">${escHtml(data.message)}</div>`;
  chatMessages.appendChild(wrap);
  chatMessages.scrollTop = chatMessages.scrollHeight;
}

if (db) {
  db.collection('chat_messages').orderBy('timestamp', 'asc').limitToLast(80)
    .onSnapshot(snapshot => {
      snapshot.docChanges().forEach(change => {
        if (change.type === 'added') {
          const d = change.doc.data();
          renderMessage(d, d.username === (chatUsername.value.trim() || localStorage.getItem('iwill_username')));
        }
      });
    });
} else {
  const now = { toDate: () => new Date() };
  [
    { username: '@ATLreppin',   message: 'This beat is HARD 🔥🔥',                  timestamp: now },
    { username: '@NYC_vibes',   message: 'Already working on my video 👀',           timestamp: now },
    { username: '@LAflex',      message: 'Hotblock Jmoe x Jacquees?? Insane collab', timestamp: now },
    { username: '@305heat',     message: '$500 and I NEED that 💰💰 LFG!!',       timestamp: now },
    { username: '@LondonCheck', message: 'Came all the way from the UK for this 🇬🇧🔥', timestamp: now },
  ].forEach(m => renderMessage(m, false));
}

async function sendMessage() {
  const message  = chatInput.value.trim();
  const username = chatUsername.value.trim() || 'Anonymous';
  if (!message) return;
  chatInput.value = '';
  localStorage.setItem('iwill_username', username);
  if (db) {
    await db.collection('chat_messages').add({
      username, message,
      timestamp: firebase.firestore.FieldValue.serverTimestamp()
    });
  } else {
    renderMessage({ username, message, timestamp: { toDate: () => new Date() } }, true);
  }
}

sendBtn.addEventListener('click', sendMessage);
chatInput.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } });

/* TIKTOK LOOP */
function restartTikTokIframe(iframe) {
  try {
    iframe.contentWindow.postMessage(JSON.stringify({ type: 'seek', offset: 0 }), 'https://www.tiktok.com');
    iframe.contentWindow.postMessage(JSON.stringify({ type: 'play' }), 'https://www.tiktok.com');
  } catch { }
  const wrap    = iframe.parentElement;
  const src     = iframe.getAttribute('src');
  const overlay = wrap.querySelector('.tt-loop-overlay');
  if (overlay) overlay.classList.add('active');
  wrap.removeChild(iframe);
  const fresh = document.createElement('iframe');
  fresh.src = src;
  fresh.allow = 'fullscreen';
  fresh.allowFullscreen = true;
  fresh.loading = 'lazy';
  fresh.addEventListener('load', () => { if (overlay) overlay.classList.remove('active'); }, { once: true });
  wrap.insertBefore(fresh, overlay);
}

window.addEventListener('message', e => {
  if (!String(e.origin).includes('tiktok.com')) return;
  try {
    const raw = typeof e.data === 'string' ? JSON.parse(e.data) : e.data;
    const str = JSON.stringify(raw).toLowerCase();
    if (!str.includes('ended') && !str.includes('onend')) return;
    const iframes = Array.from(document.querySelectorAll('.video-embed-wrap iframe'));
    if (e.source === null) { iframes.forEach(restartTikTokIframe); return; }
    const target = iframes.find(f => f.contentWindow === e.source);
    if (target) restartTikTokIframe(target);
  } catch { }
});
