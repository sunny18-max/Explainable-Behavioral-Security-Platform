export const BRAND = {
  name: "CogniShield",
  label: "Explainable Behavioral Security",
  tagline: "Human-readable detection and analytics for real-time Windows user behavior."
};

export const INITIAL_SCENARIO = "combined_attack";

export const CHART_COLORS = [
  "#2056df",
  "#0f9f6e",
  "#f59e0b",
  "#ef4444",
  "#7c3aed",
  "#64748b"
];

const API_BASES = (() => {
  const localBackend = "http://127.0.0.1:8000";
  if (typeof window === "undefined") {
    return [localBackend];
  }
  if (window.location.origin === localBackend) {
    return [localBackend];
  }
  return ["", localBackend];
})();

export function apiHref(path) {
  const localBackend = "http://127.0.0.1:8000";
  return `${localBackend}${path}`;
}

export function formatTimestamp(value) {
  if (!value) {
    return "No data";
  }
  return new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
}

export function formatMaybeNumber(value, suffix = "") {
  if (value === null || value === undefined || value === "") {
    return "Learning";
  }
  if (typeof value === "number") {
    return `${value.toFixed(1)}${suffix}`;
  }
  return `${value}${suffix}`;
}

export function uniqueStrings(values) {
  return [...new Set((values ?? []).filter(Boolean))];
}

export function statusTone(current) {
  if (!current) {
    return "neutral";
  }
  if (current.training_mode) {
    return "watch";
  }
  return current.is_anomaly ? "critical" : "safe";
}

export async function apiRequest(path, options = {}) {
  let lastError = null;

  for (const base of API_BASES) {
    const url = `${base}${path}`;
    try {
      const response = await fetch(url, options);
      if (response.status === 404) {
        lastError = new Error("Control request failed: 404");
        continue;
      }
      if (response.status === 405) {
        lastError = new Error(
          "The running backend does not support this action yet. Restart `python server.py` so the API matches the current dashboard."
        );
        continue;
      }
      if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
      }
      return response;
    } catch (requestError) {
      lastError = requestError;
    }
  }

  throw lastError ?? new Error("Unable to reach the backend API.");
}
