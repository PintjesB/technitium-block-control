(() => {
  function apply(mode) {
    try {
      if (mode === "dark") {
        document.documentElement.dataset.theme = "dark";
      } else if (mode === "gray") {
        document.documentElement.dataset.theme = "gray";
      } else if (mode === "light") {
        document.documentElement.dataset.theme = "light";
      } else {
        // "auto" follows the system preference via prefers-color-scheme.
        delete document.documentElement.dataset.theme;
      }
    } catch {
      // Ignore theme application errors.
    }
  }

  async function init() {
    try {
      const data = await chrome.storage.local.get({ uiTheme: "auto" });
      apply(data.uiTheme || "auto");
    } catch {
      // Ignore theme initialization errors.
    }
  }

  // Expose a minimal API for immediate previews on the options page.
  window.TAC_THEME = { init, apply };

  // Initialize without waiting for the result.
  init();
})();
