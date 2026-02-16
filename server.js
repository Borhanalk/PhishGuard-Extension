require("dotenv").config();

const express = require("express");
const axios = require("axios");
const whois = require("whois-json");

const app = express();
const PORT = 3000;

// ===============================
// CONFIG
// ===============================
const GOOGLE_API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

if (!GOOGLE_API_KEY) {
  console.error("❌ GOOGLE_SAFE_BROWSING_KEY not found in .env");
  process.exit(1);
}

console.log("✅ Safe Browsing key loaded");

// ===============================
// Utilities
// ===============================
function isValidUrl(url) {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

function clampScore(score) {
  return Math.max(0, Math.min(100, score));
}

// ===============================
// Google Safe Browsing
// ===============================
async function checkGoogleBlacklist(url) {
  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
      {
        client: {
          clientId: "phishguard",
          clientVersion: "1.0"
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION"
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      }
    );

    return !!response.data.matches;

  } catch (err) {
    console.warn("Safe Browsing check failed");
    return false;
  }
}

// ===============================
// Main Endpoint
// ===============================
app.get("/check", async (req, res) => {

  try {
    const url = req.query.url;

    if (!url || !isValidUrl(url)) {
      return res.status(400).json({
        ok: false,
        error: "Valid URL required"
      });
    }

    const hostname = new URL(url).hostname;

    let score = 0;
    let reasons = [];
    let ageDays = null;

    // ===============================
    // 1️⃣ HTTP Risk
    // ===============================
    if (url.startsWith("http://")) {
      score += 60;
      reasons.push("Unencrypted connection (HTTP)");
    }

    // ===============================
    // 2️⃣ Domain Age
    // ===============================
    try {
      const data = await whois(hostname);

      const creation =
        data.creationDate ||
        data.created ||
        data["Creation Date"] ||
        null;

      if (creation) {
        const creationDate = new Date(creation);
        ageDays = Math.floor(
          (Date.now() - creationDate.getTime()) /
          (1000 * 60 * 60 * 24)
        );

        if (!isNaN(ageDays)) {
          if (ageDays < 30) {
            score += 60;
            reasons.push("Domain registered very recently (< 30 days)");
          }
          else if (ageDays < 180) {
            score += 40;
            reasons.push("Domain registered recently (< 6 months)");
          }
        }
      }

    } catch (err) {
      console.warn("WHOIS lookup failed");
    }

    // ===============================
    // 3️⃣ Google Safe Browsing
    // ===============================
    const isBlacklisted = await checkGoogleBlacklist(url);

    if (isBlacklisted) {
      score = 100;
      reasons.push("Flagged by Google Safe Browsing");
    }

    score = clampScore(score);

    // ===============================
    // Risk Level
    // ===============================
    let level = "Low";
    if (score >= 50) level = "High";
    else if (score >= 40) level = "Medium";

    res.json({
      ok: true,
      result: {
        hostname,
        age: {
          ageDays
        },
        risk: {
          score,
          level,
          reasons
        }
      }
    });

  } catch (error) {
    console.error("Server error:", error.message);

    res.status(500).json({
      ok: false,
      error: "Internal server error"
    });
  }
});

// ===============================
app.listen(PORT, () => {
  console.log(`🚀 PhishGuard server running on http://localhost:${PORT}`);
});
