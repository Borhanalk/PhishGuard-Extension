require("dotenv").config();

const express = require("express");
const axios = require("axios");
const whois = require("whois-json");

const app = express();

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
// Google Safe Browsing Check
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

    if (response.data && response.data.matches) {
      return true;
    }

    return false;

  } catch (err) {

    if (err.response) {
      console.error("Safe Browsing API error:", err.response.data);
    } else {
      console.error("Safe Browsing error:", err.message);
    }

    return false;
  }
}

// ===============================
// Validate URL
// ===============================
function isValidUrl(url) {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

// ===============================
// Main Check Endpoint
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
      score = 100;
      reasons.push("Unencrypted connection (HTTP)");
    }

    // ===============================
    // 2️⃣ Domain Age Check
    // ===============================
    try {
      const data = await whois(hostname);

      if (data.creationDate) {
        const creationDate = new Date(data.creationDate);
        ageDays = (Date.now() - creationDate) / (1000 * 60 * 60 * 24);

        if (ageDays < 180) {
          score += 40;
          reasons.push("Domain is newly registered (< 6 months)");
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

    // ===============================
    // Risk Level
    // ===============================
    let level = "Low";
    if (score >= 70) level = "High";
    else if (score >= 40) level = "Medium";

    res.json({
      ok: true,
      result: {
        hostname,
        age: {
          ageDays: ageDays ? Math.floor(ageDays) : null
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
app.listen(3000, () => {
  console.log("🚀 PhishGuard server running on http://localhost:3000");
});
