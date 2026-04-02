import { startTransition, useEffect, useState } from "react";
import AOS from "aos";
import "aos/dist/aos.css";

import { DashboardView } from "./components/DashboardView.jsx";
import { LandingPage } from "./components/LandingPage.jsx";
import { INITIAL_SCENARIO, apiRequest } from "./lib/dashboard.js";

function App() {
  const [view, setView] = useState("landing");
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [mutating, setMutating] = useState(false);
  const [error, setError] = useState("");
  const [draftUser, setDraftUser] = useState("primary_user");
  const [scenario, setScenario] = useState(INITIAL_SCENARIO);

  const refreshDashboard = async () => {
    try {
      const response = await apiRequest("/api/dashboard");
      const data = await response.json();
      startTransition(() => {
        setDashboard(data);
        setDraftUser((currentDraft) => currentDraft || data.runtime?.user_name || "primary_user");
      });
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshDashboard();
    const intervalId = window.setInterval(refreshDashboard, 2000);
    return () => window.clearInterval(intervalId);
  }, []);

  useEffect(() => {
    AOS.init({
      duration: 520,
      easing: "ease-out-cubic",
      once: true,
      mirror: false,
      offset: 24
    });
  }, []);

  useEffect(() => {
    AOS.refreshHard();
  }, [view]);

  const callControl = async (endpoint, payload = {}) => {
    setMutating(true);
    try {
      const response = await apiRequest(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });
      const data = await response.json();
      startTransition(() => setDashboard(data.snapshot ?? data));
      setError("");
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setMutating(false);
    }
  };

  const openDashboard = () => {
    setView("dashboard");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const goHome = () => {
    setView("landing");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div className="app-shell">
      <div className="canvas canvas-left" />
      <div className="canvas canvas-right" />

      {view === "landing" ? (
        <LandingPage onOpenDashboard={openDashboard} />
      ) : (
        <DashboardView
          dashboard={dashboard}
          draftUser={draftUser}
          setDraftUser={setDraftUser}
          scenario={scenario}
          setScenario={setScenario}
          mutating={mutating}
          callControl={callControl}
          onBackHome={goHome}
          error={error}
        />
      )}

      {loading ? <div className="loading-scrim">Loading workspace...</div> : null}
    </div>
  );
}

export default App;
