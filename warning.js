// ===================== GET TAB ID =====================

const urlParams = new URLSearchParams(window.location.search);
const tabId = parseInt(urlParams.get("tabId"));

const reasonText = document.getElementById("reason-text");
const proceedBtn = document.getElementById("proceed");

// ===================== VALIDATION =====================

if (!Number.isInteger(tabId)) {
  reasonText.innerText = "Invalid tab ID.";
  proceedBtn.disabled = true;
} else {

  // ===================== LOAD BLOCK INFO =====================

  chrome.runtime.sendMessage(
    { type: "GET_BLOCKED_INFO", tabId: tabId },
    (response) => {

      if (chrome.runtime.lastError) {
        console.error("[PhishGuard] Error:", chrome.runtime.lastError.message);
        reasonText.innerText = "Error loading block information.";
        return;
      }

      if (response && response.ok && response.data) {

        const analysis = response.data.analysis;
        const reasons = analysis?.risk?.reasons || [];

        // عرض الأسباب
        if (reasons.length > 0) {
          reasonText.innerHTML = reasons
            .map(r => `<div>• ${r}</div>`)
            .join("");
        } else {
          reasonText.innerText = "Unknown security risk detected.";
        }

        // تغيير عنوان الصفحة
        document.title = `Blocked: ${response.data.hostname}`;

      } else {
        reasonText.innerText = "Blocking data not found.";
      }
    }
  );

  // ===================== CONTINUE BUTTON =====================

  proceedBtn.addEventListener("click", () => {

    const confirmLeave = confirm(
      "⚠️ WARNING!\n\nThis website may steal your data.\nAre you sure you want to continue?"
    );

    if (!confirmLeave) return;

    chrome.runtime.sendMessage(
      { type: "CONTINUE_NAV", tabId: tabId },
      (response) => {

        if (chrome.runtime.lastError) {
          console.error("[PhishGuard] Error:", chrome.runtime.lastError.message);
          alert("Navigation failed.");
        }
      }
    );
  });
}
