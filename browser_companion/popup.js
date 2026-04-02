const defaults = {
  backendUrl: "http://127.0.0.1:8000",
  userName: "primary_user",
  browserName: "chrome.exe",
  captureEnabled: true
};

const backendUrlInput = document.getElementById("backendUrl");
const userNameInput = document.getElementById("userName");
const browserNameSelect = document.getElementById("browserName");
const captureEnabledInput = document.getElementById("captureEnabled");
const saveButton = document.getElementById("saveButton");
const captureButton = document.getElementById("captureButton");
const statusText = document.getElementById("statusText");

async function loadSettings() {
  const stored = await chrome.storage.local.get({
    ...defaults,
    lastSyncAt: null,
    lastError: "",
    lastStoredCount: 0
  });

  backendUrlInput.value = stored.backendUrl;
  userNameInput.value = stored.userName;
  browserNameSelect.value = stored.browserName;
  captureEnabledInput.checked = Boolean(stored.captureEnabled);
  renderStatus(stored);
}

function renderStatus(state) {
  if (state.lastError) {
    statusText.textContent = `Last error: ${state.lastError}`;
    return;
  }
  if (state.lastSyncAt) {
    statusText.textContent =
      `Last sync: ${new Date(state.lastSyncAt).toLocaleTimeString()} | ` +
      `stored: ${state.lastStoredCount ?? 0}`;
    return;
  }
  statusText.textContent = "No sync yet.";
}

async function saveSettings() {
  await chrome.storage.local.set({
    backendUrl: backendUrlInput.value.trim() || defaults.backendUrl,
    userName: userNameInput.value.trim() || defaults.userName,
    browserName: browserNameSelect.value,
    captureEnabled: captureEnabledInput.checked
  });
  statusText.textContent = "Settings saved.";
}

async function captureNow() {
  statusText.textContent = "Capturing active tab...";
  const result = await chrome.runtime.sendMessage({ type: "capture-now" });
  if (!result?.ok) {
    statusText.textContent = result?.error || "Capture failed.";
    return;
  }
  await loadSettings();
}

saveButton.addEventListener("click", saveSettings);
captureButton.addEventListener("click", captureNow);

loadSettings();
