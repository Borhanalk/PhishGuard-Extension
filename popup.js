document.addEventListener("DOMContentLoaded", () => {

  const statusBox = document.getElementById("status-box");
  const domainEl = document.getElementById("domain");
  const scoreEl = document.getElementById("score");
  const ageEl = document.getElementById("age");
  const issuesList = document.getElementById("issues-list");

  // Get current active tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {

    if (!tabs || !tabs[0] || !tabs[0].url) {
      statusBox.innerText = "No active tab";
      return;
    }

    const currentUrl = tabs[0].url;

    // Ignore chrome internal pages
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

        if (!res || !res.ok || !res.result) {
          statusBox.innerText = "Scan failed";
          return;
        }

        const data = res.result;
        const score = data?.risk?.score ?? 0;
        const verdict = data?.risk?.verdict ?? "SAFE";

        // ======================
        // Update Basic Info
        // ======================
        domainEl.innerText = data.hostname || "Unknown";
        scoreEl.innerText = score;

        if (data.age?.ageDays != null) {
          ageEl.innerText = `${data.age.ageDays} days`;
        } else {
          ageEl.innerText = "Unknown";
        }

        // ======================
        // Status Color
        // ======================
        statusBox.className = "status";

        if (verdict === "DANGEROUS") {
          statusBox.innerText = "Dangerous";
          statusBox.classList.add("dangerous");
        }
        else if (verdict === "SUSPICIOUS") {
          statusBox.innerText = "Suspicious";
          statusBox.classList.add("suspicious");
        }
        else {
          statusBox.innerText = "Safe";
          statusBox.classList.add("safe");
        }

        // ======================
        // Display Reasons
        // ======================
        if (Array.isArray(data?.risk?.reasons) && data.risk.reasons.length > 0) {
          issuesList.innerHTML = data.risk.reasons
            .map(reason => `<div class="issue-item">• ${reason}</div>`)
            .join("");
        } else {
          issuesList.innerHTML = `<div class="issue-item">No security issues detected</div>`;
        }

      }
    );

  });

});
