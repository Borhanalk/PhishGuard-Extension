// ===================== CONFIG =====================
const SERVER_URL = "http://localhost:3000/check";
const BLOCK_THRESHOLD = 70;
const TEMP_ALLOW_TTL = 5 * 60 * 1000; // 5 minutes

console.log("[PhishGuard] Extension loaded");

// ===================== TEMP ALLOW SYSTEM =====================
const tempAllowed = new Map();

function allowTemporarily(hostname) {
  tempAllowed.set(hostname, Date.now());
}

function isTemporarilyAllowed(hostname) {
  if (!tempAllowed.has(hostname)) return false;

  const savedTime = tempAllowed.get(hostname);

  if (Date.now() - savedTime > TEMP_ALLOW_TTL) {
    tempAllowed.delete(hostname);
    return false;
  }

  return true;
}

// ===================== PROTECTED BRANDS =====================
const PROTECTED_BRANDS = [
  "facebook.com",
  "google.com",
  "amazon.com",
  "paypal.com",
  "instagram.com",
  "twitter.com",
  "linkedin.com",
  "microsoft.com",
  "apple.com",
  "netflix.com",
  "github.com",
  "binance.com"
];

// ===================== DOMAIN HELPERS =====================
function getBaseDomain(hostname) {
  hostname = hostname.toLowerCase().replace(/^www\./, "");
  const parts = hostname.split(".");
  return parts.slice(-2).join(".");
}

function levenshtein(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b[i - 1] === a[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

function detectDomainImpersonation(hostname) {
  hostname = hostname.toLowerCase().replace(/^www\./, "");
  const baseDomain = getBaseDomain(hostname);
  const sld = baseDomain.split(".")[0];

  for (const brand of PROTECTED_BRANDS) {
    const brandBase = getBaseDomain(brand);
    const brandName = brandBase.split(".")[0];

    // Official domain
    if (baseDomain === brandBase) {
      return { suspicious: false };
    }

    // Contains brand name + extra words
    if (sld.includes(brandName) && sld !== brandName) {
      return {
        suspicious: true,
        reason: `Domain impersonates "${brandName}" using extra words`
      };
    }

    // Typosquatting
    const distance = levenshtein(sld, brandName);
    if (distance > 0 && distance <= 2) {
      return {
        suspicious: true,
        reason: `Domain is very similar to "${brandName}" (typosquatting)`
      };
    }
  }

  return { suspicious: false };
}

// ===================== HTTPS CHECK =====================
function checkHttps(tabUrl) {
  try {
    const u = new URL(tabUrl);
    return { isHttps: u.protocol === "https:" };
  } catch {
    return { isHttps: false };
  }
}

// ===================== SAFE BROWSING VIA SERVER =====================
async function safeBrowsingCheckViaServer(urlToCheck) {
  try {
    const res = await fetch(`${SERVER_URL}?url=${encodeURIComponent(urlToCheck)}`);
    if (!res.ok) return { ok: false };

    const data = await res.json();
    const score = data?.result?.risk?.score || 0;

    return score === 100
      ? { ok: true, blacklisted: true }
      : { ok: true, blacklisted: false };

  } catch {
    console.warn("[PhishGuard] Safe Browsing server error");
    return { ok: false };
  }
}

// ===================== RISK CALCULATION =====================
function buildRiskScore({ https, sb, impersonation }) {

  let score = 0;
  const reasons = [];

  // Google Blacklist (highest priority)
  if (sb?.blacklisted) {
    return {
      score: 100,
      verdict: "DANGEROUS",
      reasons: ["🚨 Listed in Google Safe Browsing"]
    };
  }

  // Impersonation
  if (impersonation?.suspicious) {
    score = 100;
    reasons.push(`🚨 ${impersonation.reason}`);
  }

  // HTTP
  if (!https?.isHttps) {
    score = 100;
    reasons.push("🔓 Unencrypted connection (HTTP)");
  }

  const verdict =
    score >= 70 ? "DANGEROUS" :
    score >= 40 ? "SUSPICIOUS" :
    "SAFE";

  return { score, verdict, reasons };
}

// ===================== BLOCK STORAGE =====================
async function setBlocked(tabId, payload) {
  await chrome.storage.session.set({ [`blocked:${tabId}`]: payload });
}

async function getBlocked(tabId) {
  const obj = await chrome.storage.session.get(`blocked:${tabId}`);
  return obj[`blocked:${tabId}`] || null;
}

async function clearBlocked(tabId) {
  await chrome.storage.session.remove(`blocked:${tabId}`);
}

// ===================== MAIN NAVIGATION LISTENER =====================
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {

  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http")) return;
  if (details.url.startsWith(chrome.runtime.getURL(""))) return;

  const urlObj = new URL(details.url);
  const hostname = urlObj.hostname;

  // ✅ Temporary Allow Check
  if (isTemporarilyAllowed(hostname)) {
    console.log("[PhishGuard] Temporarily allowed:", hostname);
    return;
  }

  const impersonation = detectDomainImpersonation(hostname);
  const https = checkHttps(details.url);
  const sb = await safeBrowsingCheckViaServer(details.url);

  const risk = buildRiskScore({
    https,
    sb,
    impersonation
  });

  if (risk.score >= BLOCK_THRESHOLD) {

    await setBlocked(details.tabId, {
      originalUrl: details.url,
      hostname,
      analysis: { risk }
    });

    const warningUrl = chrome.runtime.getURL(`warning.html?tabId=${details.tabId}`);
    await chrome.tabs.update(details.tabId, { url: warningUrl });
  }

});

// ===================== MESSAGE HANDLING =====================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // Popup Info
  if (msg.type === "GET_SITE_INFO" && msg.url) {
    (async () => {
      try {
        const u = new URL(msg.url);
        const hostname = u.hostname;

        const impersonation = detectDomainImpersonation(hostname);
        const https = checkHttps(msg.url);
        const sb = await safeBrowsingCheckViaServer(msg.url);

        const risk = buildRiskScore({
          https,
          sb,
          impersonation
        });

        sendResponse({
          ok: true,
          result: {
            url: msg.url,
            hostname,
            https,
            risk
          }
        });

      } catch {
        sendResponse({ ok: false, error: "INVALID_URL" });
      }
    })();

    return true;
  }

  // Warning Page Info
  if (msg.type === "GET_BLOCKED_INFO") {
    getBlocked(msg.tabId).then(data => {
      sendResponse({ ok: true, data });
    });
    return true;
  }

  // Continue Anyway (Temporary Allow)
  if (msg.type === "CONTINUE_NAV") {
    getBlocked(msg.tabId).then(async (data) => {
      if (data) {

        const hostname = new URL(data.originalUrl).hostname;

        // ✅ Allow temporarily
        allowTemporarily(hostname);

        await clearBlocked(msg.tabId);
        await chrome.tabs.update(msg.tabId, { url: data.originalUrl });
      }

      sendResponse({ ok: true });
    });

    return true;
  }

  // Cancel Navigation
  if (msg.type === "CANCEL_NAV") {
    clearBlocked(msg.tabId).then(() => {
      chrome.tabs.update(msg.tabId, { url: "about:blank" });
      sendResponse({ ok: true });
    });
    return true;
  }

});
