"use strict";
document.getElementById("reset").addEventListener("click", () => {
  const button = document.getElementById("reset");
  button.disabled = true;
  chrome.runtime.sendMessage({ type: "reset-preferences" }, (res) => {
    document.getElementById("result").textContent =
      !chrome.runtime.lastError && res?.ok
        ? "Default guards restored. All saved site exceptions were removed."
        : "Could not reset. Reopen PHProtect and try again.";
    button.disabled = false;
  });
});
