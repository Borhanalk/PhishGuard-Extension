document.addEventListener("DOMContentLoaded", () => {

  const statusBox = document.getElementById("status-box");
  const domainEl = document.getElementById("domain");
  const scoreEl = document.getElementById("score");
  const ageEl = document.getElementById("age");
  const issuesList = document.getElementById("issues-list");

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {

    if (!tabs || !tabs[0] || !tabs[0].url) {
      statusBox.innerText = "No active tab";
      return;
    }

    const currentUrl = tabs[0].url;

    if (currentUrl.startsWith("chrome://")) {
      statusBox.innerText = "Cannot scan this page";
      return;
    }

    chrome.runtime.sendMessage(
      { type: "GET_SITE_INFO", url: currentUrl },
      (res) => {

        if (chrome.runtime.lastError) {
          console.error("[PhishGuard]", chrome.runtime.lastError.message);
          statusBox.innerText = "Extension Error";
          return;
        }

        if (!res || !res.ok) {
          statusBox.innerText = "Scan failed";
          return;
        }

        // ======================
        // Extract Data
        // ======================

        const hostname = res.domain ?? "Unknown";
        const score = res.riskScore ?? 0;
        const verdict = res.verdict ?? "SAFE";
        const reasons = res.reasons ?? [];
        const ageDays = res.age?.ageDays ?? null;

        // ======================
        // Update Basic Info
        // ======================

        domainEl.innerText = hostname;
        scoreEl.innerText = score;

        if (ageDays !== null) {
          ageEl.innerText = `${ageDays} days`;
        } else {
          ageEl.innerText = "Unknown";
        }

        // ======================
        // Status Color
        // ======================

        statusBox.className = "status";

        if (verdict === "DANGEROUS") {
          statusBox.innerText = "High Risk";
          statusBox.classList.add("dangerous");
        }
        else if (score >= 40) {
          statusBox.innerText = "Medium Risk";
          statusBox.classList.add("suspicious");
        }
        else {
          statusBox.innerText = "Safe";
          statusBox.classList.add("safe");
        }

        // ======================
        // Reasons
        // ======================

        if (Array.isArray(reasons) && reasons.length > 0) {
          issuesList.innerHTML = reasons
            .map(reason => `<div class="issue-item">• ${reason}</div>`)
            .join("");
        } else {
          issuesList.innerHTML =
            `<div class="issue-item">No security issues detected</div>`;
        }

      }
    );

  });

});
