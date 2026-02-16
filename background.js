// ======================================================
// ===================== CONFIG =========================
// ======================================================

const SERVER_URL = "http://localhost:3000/check";
const BLOCK_THRESHOLD = 50;
const TEMP_ALLOW_TTL = 5 * 60 * 1000;

console.log("[PhishGuard] Extension loaded");

// ======================================================
// ================= TEMP ALLOW SYSTEM ==================
// ======================================================

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

    if (baseDomain === brandBase) {
      return { suspicious: false };
    }

    if (sld.includes(brandName) && sld !== brandName) {
      return {
        suspicious: true,
        reason: `Domain impersonates "${brandName}" using extra words`
      };
    }

    const distance = levenshtein(sld, brandName);
    if (distance > 0 && distance <= 2) {
      return {
        suspicious: true,
        reason: `Domain very similar to "${brandName}" (typosquatting)`
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
// ================= SAFE BROWSING ======================
// ======================================================

async function safeBrowsingCheckViaServer(url) {
  try {
    const res = await fetch(`${SERVER_URL}?url=${encodeURIComponent(url)}`);
    if (!res.ok) return { blacklisted: false, ageDays: null };

    const data = await res.json();

    return {
      blacklisted: data?.result?.risk?.score === 100,
      ageDays: data?.result?.age?.ageDays ?? null
    };
  } catch {
    return { blacklisted: false, ageDays: null };
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
    score += 60;
    reasons.push(`🚨 ${impersonation.reason}`);
  }

  if (!https) {
    score += 40;
    reasons.push("🔓 Unencrypted connection (HTTP)");
  }

  if (sb?.ageDays !== null && sb.ageDays < 30) {
    score += 40;
    reasons.push("⚠️ Domain registered recently (< 30 days)");
  }

  return {
    score,
    verdict: score >= BLOCK_THRESHOLD ? "DANGEROUS" : "SAFE",
    reasons
  };
}

// ======================================================
// ================= NAVIGATION LISTENER ================
// ======================================================

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {

  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http")) return;

  const hostname = new URL(details.url).hostname;

  if (isTemporarilyAllowed(hostname)) return;

  const impersonation = detectDomainImpersonation(hostname);
  const https = checkHttps(details.url);
  const sb = await safeBrowsingCheckViaServer(details.url);

  const risk = buildRiskScore({ https, sb, impersonation });

  if (risk.score >= BLOCK_THRESHOLD) {

    const warningUrl =
      chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(details.url)}`);

    try {
      await chrome.tabs.update(details.tabId, { url: warningUrl });
    } catch {}
  }
});

// ======================================================
// ================= MESSAGE HANDLING ===================
// ======================================================

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // 🔥 IGNORE AND CONTINUE HANDLER
  if (msg.type === "IGNORE_AND_CONTINUE") {

    try {
      const originalUrl = msg.url;
      const hostname = new URL(originalUrl).hostname;

      allowTemporarily(hostname);

      chrome.tabs.update(sender.tab.id, { url: originalUrl });

    } catch {}

    return;
  }

  // SITE INFO HANDLER
  if (msg.type === "GET_SITE_INFO") {

    (async () => {
      try {

        const url = msg.url;
        const hostname = new URL(url).hostname;

        const impersonation = detectDomainImpersonation(hostname);
        const https = checkHttps(url);
        const sb = await safeBrowsingCheckViaServer(url);

        const risk = buildRiskScore({ https, sb, impersonation });

        sendResponse({
          ok: true,
          domain: hostname,
          riskScore: risk.score,
          verdict: risk.verdict,
          reasons: risk.reasons,
          age: {
            ageDays: sb.ageDays
          }
        });

      } catch {
        sendResponse({ ok: false });
      }
    })();

    return true;
  }
});
