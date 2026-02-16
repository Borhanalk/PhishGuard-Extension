document.addEventListener("DOMContentLoaded", () => {

  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get("url");

  const reasonText = document.getElementById("reason-text");
  const proceedBtn = document.getElementById("proceed");

  if (!blockedUrl) {
    reasonText.innerText = "Blocked URL not found.";
    if (proceedBtn) proceedBtn.disabled = true;
    return;
  }

  // ===================== LOAD SITE INFO =====================

  chrome.runtime.sendMessage(
    { type: "GET_SITE_INFO", url: blockedUrl },
    (response) => {

      if (chrome.runtime.lastError || !response?.ok) {
        reasonText.innerText = "Error loading analysis data.";
        return;
      }

      const reasons = response.reasons || [];

      if (reasons.length > 0) {
        reasonText.innerHTML = reasons
          .map(r => `<div>• ${r}</div>`)
          .join("");
      } else {
        reasonText.innerText = "Unknown security risk detected.";
      }

      document.title = `Blocked: ${response.domain}`;
    }
  );

  // ===================== CONTINUE BUTTON =====================

  if (proceedBtn) {
    proceedBtn.addEventListener("click", () => {

      const confirmLeave = confirm(
        "⚠️ WARNING!\n\nThis website may steal your data.\nAre you sure you want to continue?"
      );

      if (!confirmLeave) return;

      chrome.runtime.sendMessage({
        type: "IGNORE_AND_CONTINUE",
        url: blockedUrl
      });

    });
  }

});
