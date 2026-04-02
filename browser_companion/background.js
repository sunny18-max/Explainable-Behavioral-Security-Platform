const DEFAULT_SETTINGS = {
  backendUrl: "http://127.0.0.1:8000",
  userName: "primary_user",
  browserName: "chrome.exe",
  captureEnabled: true
};

let eventQueue = [];
let lastSignature = "";
let lastCapturedAt = 0;

async function getSettings() {
  const stored = await chrome.storage.local.get({
    backendUrl: DEFAULT_SETTINGS.backendUrl,
    userName: DEFAULT_SETTINGS.userName,
    browserName: DEFAULT_SETTINGS.browserName,
    captureEnabled: DEFAULT_SETTINGS.captureEnabled,
    lastSyncAt: null,
    lastError: ""
  });
  return stored;
}

function eventSignature(tab, browserName) {
  return `${browserName}|${tab.windowId}|${tab.id}|${tab.title || ""}|${tab.url || ""}`;
}

function shouldCaptureTab(tab) {
  if (!tab || !tab.active) {
    return false;
  }
  if (!tab.url) {
    return false;
  }
  return !tab.url.startsWith("chrome-extension://");
}

async function enqueueActiveTab(reason = "activity") {
  const settings = await getSettings();
  if (!settings.captureEnabled) {
    return;
  }

  const [tab] = await chrome.tabs.query({
    active: true,
    lastFocusedWindow: true
  });

  if (!shouldCaptureTab(tab)) {
    return;
  }

  const signature = eventSignature(tab, settings.browserName);
  const now = Date.now();
  if (signature === lastSignature && now - lastCapturedAt < 5000) {
    return;
  }

  lastSignature = signature;
  lastCapturedAt = now;

  eventQueue.push({
    observed_at: new Date().toISOString(),
    browser_name: settings.browserName,
    tab_title: tab.title || "",
    url: tab.url || "",
    tab_id: tab.id ?? null,
    window_id: tab.windowId ?? null,
    source: "browser_companion",
    reason
  });

  if (eventQueue.length >= 5) {
    await flushQueue();
  }
}

async function flushQueue() {
  if (!eventQueue.length) {
    return { ok: true, stored_count: 0 };
  }

  const settings = await getSettings();
  const payload = {
    user_name: settings.userName,
    browser_name: settings.browserName,
    source: "browser_companion",
    events: [...eventQueue]
  };

  try {
    const response = await fetch(`${settings.backendUrl}/api/extension/browser-events`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Sync failed: ${response.status}`);
    }

    const result = await response.json();
    eventQueue = [];
    await chrome.storage.local.set({
      lastSyncAt: new Date().toISOString(),
      lastError: "",
      lastStoredCount: result.stored_count ?? 0
    });
    return result;
  } catch (error) {
    await chrome.storage.local.set({
      lastError: String(error)
    });
    return { ok: false, error: String(error) };
  }
}

function bootstrap() {
  chrome.alarms.create("flush-browser-events", {
    periodInMinutes: 0.1
  });
}

chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.set(DEFAULT_SETTINGS);
  bootstrap();
});

chrome.runtime.onStartup.addListener(() => {
  bootstrap();
});

chrome.tabs.onActivated.addListener(async () => {
  await enqueueActiveTab("activated");
});

chrome.tabs.onUpdated.addListener(async (_tabId, changeInfo, tab) => {
  if (!tab.active) {
    return;
  }
  if (changeInfo.status === "complete" || changeInfo.title || changeInfo.url) {
    await enqueueActiveTab("updated");
  }
});

chrome.windows.onFocusChanged.addListener(async (windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) {
    return;
  }
  await enqueueActiveTab("focus");
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "flush-browser-events") {
    await flushQueue();
  }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    if (message?.type === "capture-now") {
      await enqueueActiveTab("manual");
      sendResponse(await flushQueue());
      return;
    }
    if (message?.type === "flush") {
      sendResponse(await flushQueue());
      return;
    }
    if (message?.type === "status") {
      const settings = await getSettings();
      sendResponse({
        queueLength: eventQueue.length,
        lastSyncAt: settings.lastSyncAt,
        lastError: settings.lastError,
        lastStoredCount: settings.lastStoredCount ?? 0
      });
      return;
    }
    sendResponse({ ok: false, error: "Unsupported message" });
  })();
  return true;
});

bootstrap();
