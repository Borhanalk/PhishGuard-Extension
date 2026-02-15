document.addEventListener("DOMContentLoaded", () => {

  // ===================== GET TAB ID =====================
  const urlParams = new URLSearchParams(window.location.search);
  const tabId = parseInt(urlParams.get("tabId"));

  const reasonText = document.getElementById("reason-text");
  const proceedBtn = document.getElementById("proceed");

  function showError(message) {
    reasonText.innerText = message;
    if (proceedBtn) proceedBtn.disabled = true;
  }

  // ===================== VALIDATION =====================
  if (!Number.isInteger(tabId)) {
    showError("Invalid tab ID.");
    return;
  }

  // ===================== LOAD BLOCK INFO =====================
  chrome.runtime.sendMessage(
    { type: "GET_BLOCKED_INFO", tabId },
    (response) => {

      if (chrome.runtime.lastError) {
        console.error("[PhishGuard] Runtime error:", chrome.runtime.lastError.message);
        showError("Error loading block information.");
        return;
      }

      if (!response || !response.ok || !response.data) {
        showError("Blocking data not found.");
        return;
      }

      const analysis = response.data.analysis;
      const reasons = analysis?.risk?.reasons || [];

      if (reasons.length > 0) {
        reasonText.innerHTML = reasons
          .map(r => `<div>• ${r}</div>`)
          .join("");
      } else {
        reasonText.innerText = "Unknown security risk detected.";
      }

      document.title = `Blocked: ${response.data.hostname}`;
    }
  );

  // ===================== CONTINUE BUTTON =====================
  if (proceedBtn) {
    proceedBtn.addEventListener("click", () => {

      const confirmLeave = confirm(
        "⚠️ WARNING!\n\nThis website may steal your data.\nAre you sure you want to continue?"
      );

      if (!confirmLeave) return;

      chrome.runtime.sendMessage(
        { type: "CONTINUE_NAV", tabId },
        (response) => {

          if (chrome.runtime.lastError) {
            console.error("[PhishGuard] Continue error:", chrome.runtime.lastError.message);
            alert("Navigation failed.");
          }
        }
      );
    });
  }

});
