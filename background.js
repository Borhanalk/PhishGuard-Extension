// ======================================================
// ===================== CONFIG =========================
// ======================================================

const SERVER_URL = "http://localhost:3000/check";
const BLOCK_THRESHOLD = 70;
const TEMP_ALLOW_TTL = 5 * 60 * 1000; // 5 minutes

console.log("[PhishGuard] Extension loaded");

// ======================================================
// ================= TEMP ALLOW SYSTEM ==================
// ======================================================

const tempAllowed = new Map();

function allowTemporarily(hostname) {
  tempAllowed.set(hostname, Date.now());
  console.log("[PhishGuard] Temporarily allowing:", hostname);
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

// ======================================================
// ================= PROTECTED BRANDS ===================
// ======================================================

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

// ======================================================
// ================= DOMAIN HELPERS =====================
// ======================================================

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
      matrix[i][j] =
        b[i - 1] === a[j - 1]
          ? matrix[i - 1][j - 1]
          : Math.min(
              matrix[i - 1][j - 1] + 1,
              matrix[i][j - 1] + 1,
              matrix[i - 1][j] + 1
            );
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

    // Official
    if (baseDomain === brandBase) {
      return { suspicious: false };
    }

    // Brand inside domain
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

// ======================================================
// ================= HTTPS CHECK ========================
// ======================================================

function checkHttps(url) {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

// ======================================================
// ============== SAFE BROWSING VIA SERVER =============
// ======================================================

async function safeBrowsingCheckViaServer(url) {
  try {
    const res = await fetch(`${SERVER_URL}?url=${encodeURIComponent(url)}`);
    if (!res.ok) return { blacklisted: false };

    const data = await res.json();
    return {
      blacklisted: data?.result?.risk?.score === 100
    };
  } catch {
    console.warn("[PhishGuard] Safe Browsing server error");
    return { blacklisted: false };
  }
}

// ======================================================
// ================= RISK CALCULATION ===================
// ======================================================

function buildRiskScore({ https, sb, impersonation }) {

  if (sb?.blacklisted) {
    return {
      score: 100,
      verdict: "DANGEROUS",
      reasons: ["🚨 Listed in Google Safe Browsing"]
    };
  }

  let score = 0;
  const reasons = [];

  if (impersonation?.suspicious) {
    score = 100;
    reasons.push(`🚨 ${impersonation.reason}`);
  }

  if (!https) {
    score = 100;
    reasons.push("🔓 Unencrypted connection (HTTP)");
  }

  return {
    score,
    verdict: score >= 70 ? "DANGEROUS" : "SAFE",
    reasons
  };
}

// ======================================================
// ================= BLOCK STORAGE ======================
// ======================================================

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

// ======================================================
// ================= NAVIGATION LISTENER ================
// ======================================================

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {

  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http")) return;
  if (details.url.startsWith(chrome.runtime.getURL(""))) return;

  const hostname = new URL(details.url).hostname;

  if (isTemporarilyAllowed(hostname)) return;

  const impersonation = detectDomainImpersonation(hostname);
  const https = checkHttps(details.url);
  const sb = await safeBrowsingCheckViaServer(details.url);

  const risk = buildRiskScore({ https, sb, impersonation });

  if (risk.score >= BLOCK_THRESHOLD) {

    await setBlocked(details.tabId, {
      originalUrl: details.url,
      hostname,
      analysis: { risk }
    });

    const warningUrl =
      chrome.runtime.getURL(`warning.html?tabId=${details.tabId}`);

    try {
      await chrome.tabs.update(details.tabId, { url: warningUrl });
    } catch {
      console.warn("[PhishGuard] Tab closed before blocking");
    }
  }
});

// ======================================================
// ================= MESSAGE HANDLING ===================
// ======================================================

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // GET BLOCK DATA
  if (msg.type === "GET_BLOCKED_INFO") {
    getBlocked(msg.tabId).then((data) => {
      sendResponse({ ok: true, data });
    });
    return true;
  }

  // CONTINUE
  if (msg.type === "CONTINUE_NAV") {

    getBlocked(msg.tabId).then(async (data) => {

      if (!data) {
        sendResponse({ ok: false });
        return;
      }

      const originalUrl = data.originalUrl;
      const hostname = new URL(originalUrl).hostname;

      allowTemporarily(hostname);
      await clearBlocked(msg.tabId);

      try {
        await chrome.tabs.update(msg.tabId, { url: originalUrl });
      } catch {
        console.warn("[PhishGuard] Tab closed before continue");
      }

      sendResponse({ ok: true });

    });

    return true;
  }

  // CANCEL
  if (msg.type === "CANCEL_NAV") {

    clearBlocked(msg.tabId).then(async () => {

      try {
        await chrome.tabs.update(msg.tabId, { url: "about:blank" });
      } catch {
        console.warn("[PhishGuard] Tab closed before cancel");
      }

      sendResponse({ ok: true });

    });

    return true;
  }
});
