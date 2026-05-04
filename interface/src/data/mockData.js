// ============================================================
//  DNS TUNNEL SENTINEL — Mock Data Engine
// ============================================================

const CLEAN_DOMAINS = [
  'google.com', 'cloudflare.com', 'microsoft.com', 'github.com',
  'amazon.com', 'netflix.com', 'apple.com', 'cdn.jsdelivr.net',
  'fonts.googleapis.com', 'ajax.googleapis.com', 'api.github.com',
  'updates.microsoft.com', 'time.windows.com', 'ocsp.digicert.com',
  'tools.google.com', 'mail.google.com', 'drive.google.com',
  'stackoverflow.com', 'reddit.com', 'wikipedia.org',
];

const SUSPICIOUS_SUBDOMAINS = [
  'aGVsbG8gd29ybGQ=', 'dGhpcyBpcyBhIHRlc3Q=', 'cGF5bG9hZA==',
  'ZXhmaWx0cmF0aW9u', 'c2VjcmV0ZGF0YQ==', 'bWFsd2FyZWM=',
  'dHVubmVsZGF0YQ==', 'YmVhY29uaW5n', 'Y29tbWFuZA==',
  'cmV2ZXJzZXNoZWxs',
];

const SUSPICIOUS_DOMAINS = [
  'evil-c2.xyz', 'malware-beacon.ru', 'exfil-tunnel.io',
  'apt-staging.cn', 'backdoor-ctrl.net', 'dns-covert.xyz',
  'c2-server.biz', 'botnet-dns.tk', 'payload-drop.ml',
];

const QUERY_TYPES = ['A', 'TXT', 'MX', 'NULL', 'AAAA', 'CNAME', 'PTR'];
const SUSPICIOUS_TYPES = ['TXT', 'NULL'];

// Use a large random start offset to avoid duplicate IDs across strict-mode double renders
let _id = Math.floor(Math.random() * 1_000_000) + 1;

const IPS = Array.from({ length: 40 }, (_, i) => {
  const octets = [
    [10, 192, 172, 203, 185][i % 5],
    Math.floor(Math.random() * 254) + 1,
    Math.floor(Math.random() * 254) + 1,
    Math.floor(Math.random() * 254) + 1,
  ];
  return octets.join('.');
});

// Pre-generate to keep IPs stable per session
const SESSION_IPS = IPS.slice();

export const GEO_DOTS = SESSION_IPS.slice(0, 18).map((ip, i) => ({
  ip,
  x: 5 + Math.random() * 90,
  y: 5 + Math.random() * 90,
  threat: i < 5,
}));

function randItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function calcEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  return -Object.values(freq)
    .reduce((acc, f) => acc + (f / len) * Math.log2(f / len), 0);
}

function generatePacket() {
  const id = _id++;
  const isMalicious = Math.random() < 0.22;
  const isSuspicious = !isMalicious && Math.random() < 0.14;

  let domain, subdomain, queryType, status, detectionRule;

  if (isMalicious) {
    subdomain = randItem(SUSPICIOUS_SUBDOMAINS);
    domain = `${subdomain}.${randItem(SUSPICIOUS_DOMAINS)}`;
    queryType = randItem(SUSPICIOUS_TYPES);
    status = 'BLOCKED';
    detectionRule = randItem([
      'HIGH ENTROPY SUBDOMAIN',
      'PAYLOAD ENCODING DETECTED',
      'BEACONING PATTERN',
      'KNOWN C2 DOMAIN',
      'NULL QUERY ANOMALY',
    ]);
  } else if (isSuspicious) {
    subdomain = randItem(SUSPICIOUS_SUBDOMAINS).slice(0, 8);
    domain = `${subdomain}.${randItem(CLEAN_DOMAINS)}`;
    queryType = randItem(QUERY_TYPES);
    status = 'SUSPICIOUS';
    detectionRule = randItem([
      'ABNORMAL QUERY LENGTH',
      'HIGH FREQUENCY PATTERN',
      'ENCODED SUBDOMAIN',
      'IRREGULAR TTL',
    ]);
  } else {
    const base = randItem(CLEAN_DOMAINS);
    subdomain = randItem(['www', 'api', 'cdn', 'mail', 'static', 'assets', '']);
    domain = subdomain ? `${subdomain}.${base}` : base;
    queryType = randItem(QUERY_TYPES);
    status = 'CLEAN';
    detectionRule = null;
  }

  const domainLabel = domain.split('.')[0];
  const entropy = parseFloat(calcEntropy(domainLabel).toFixed(2));
  const byteSize = isMalicious
    ? 180 + Math.floor(Math.random() * 320)
    : 40 + Math.floor(Math.random() * 120);

  const now = new Date();
  const ts = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}.${String(now.getMilliseconds()).padStart(3,'0')}`;

  return {
    id,
    timestamp: ts,
    sourceIp: randItem(SESSION_IPS),
    domain,
    queryType,
    byteSize,
    status,
    entropy,
    detectionRule,
  };
}

// ---- Public API ----
export function getInitialPackets(count = 20) {
  return Array.from({ length: count }, generatePacket);
}

export function getNewPacket() {
  return generatePacket();
}

// ---- Detection rule labels for analysis panel ----
export const DETECTION_RULES = [
  'HIGH ENTROPY SUBDOMAIN',
  'PAYLOAD ENCODING DETECTED',
  'BEACONING PATTERN',
  'KNOWN C2 DOMAIN',
  'NULL QUERY ANOMALY',
  'ABNORMAL QUERY LENGTH',
  'HIGH FREQUENCY PATTERN',
  'ENCODED SUBDOMAIN',
  'IRREGULAR TTL',
];
