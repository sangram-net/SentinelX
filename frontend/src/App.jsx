import { useState } from "react";
import "./App.css";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const analyzeLog = async () => {
    if (!file) return;

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_URL}/api/logs/upload`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("API request failed");
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      console.error(err);
      setError(
        "Unable to connect to SentinelX API. Make sure the backend is running."
      );
    } finally {
      setLoading(false);
    }
  };

  const events = result?.events || [];
  const threats = result?.threats || [];

  const highSeverity = threats.filter(
    (threat) => String(threat.severity).toUpperCase() === "HIGH"
  ).length;

  const getSource = (threat) => {
    return threat.source || "Unknown";
  };

  const getThreatStory = (threat) => {
    const type = String(threat.type || "Suspicious Activity");

    if (type.toLowerCase().includes("brute")) {
      return `A source generated ${
        threat.count || "multiple"
      } failed authentication attempts. SentinelX grouped these events as a possible SSH brute-force attack.`;
    }

    if (type.toLowerCase().includes("spray")) {
      return `A single source targeted multiple user accounts with failed authentication attempts. This pattern is consistent with password spraying.`;
    }

    if (type.toLowerCase().includes("sql")) {
      return `SentinelX identified a suspicious SQL-related payload in the request data. The activity may represent an SQL injection attempt.`;
    }

    if (type.toLowerCase().includes("scan")) {
      return `Multiple paths or endpoints were accessed from the same source in a short period, indicating possible reconnaissance or web scanning activity.`;
    }

    return `SentinelX identified ${
      threat.count || "suspicious"
    } related security events and grouped them into a potential ${type.toLowerCase()} incident.`;
  };

  const getRecommendation = (threat) => {
    const type = String(threat.type || "").toLowerCase();

    if (type.includes("brute") || type.includes("spray")) {
      return "Investigate the source IP, review affected accounts, enforce rate limiting, and temporarily block the source if confirmed malicious.";
    }

    if (type.includes("sql")) {
      return "Inspect the affected endpoint, review application logs, validate input handling, and investigate the source IP.";
    }

    if (type.includes("scan")) {
      return "Review requested paths, identify the source, and investigate whether reconnaissance preceded another attack.";
    }

    return "Investigate the source and surrounding events before taking containment action.";
  };

  const getTimelineEventType = (event) => {
    const type = String(event.event_type || "").toLowerCase();

    if (type.includes("failed")) return "FAILED AUTHENTICATION";
    if (type.includes("login")) return "LOGIN EVENT";
    if (type.includes("sql")) return "SQL INJECTION";
    if (type.includes("scan")) return "WEB SCAN";

    return "SECURITY EVENT";
  };

  const getTimelineTime = (event) => {
    if (!event.timestamp) return "--:--:--";

    try {
      const date = new Date(event.timestamp);

      if (Number.isNaN(date.getTime())) {
        return String(event.timestamp);
      }

      return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
    } catch {
      return String(event.timestamp);
    }
  };

  return (
    <div className="app">

      {/* HEADER */}
      <header className="header">
        <div className="brand">
          <div className="logo">X</div>

          <div>
            <h2>SentinelX</h2>
            <span>LOCAL SMART LOG SENTINEL</span>
          </div>
        </div>

        <div className="api-status">
          <span></span>
          API ONLINE
        </div>
      </header>

      {/* MAIN */}
      <main className="container">

        {/* HERO */}
        <section className="hero">

          <div className="hero-text">
            <p className="eyebrow">SECURITY OPERATIONS</p>

            <h1>
              Turn logs into insights.
              <br />
              <strong>Detect threats.</strong> Stay ahead.
            </h1>

            <p className="description">
              Analyze authentication and web logs, detect suspicious activity,
              and turn raw events into understandable security incidents.
            </p>
          </div>

          {/* UPLOAD */}
          <div className="upload-card">

            <div className="upload-icon">↑</div>

            <h3>Analyze Security Logs</h3>

            <p>
              Upload a .log or .txt file to begin analysis.
            </p>

            <label className="file-input">
              {file ? file.name : "Choose Log File"}

              <input
                type="file"
                accept=".log,.txt"
                onChange={(e) => {
                  setFile(e.target.files[0]);
                  setResult(null);
                  setError("");
                }}
              />
            </label>

            <button
              onClick={analyzeLog}
              disabled={!file || loading}
            >
              {loading ? "Analyzing..." : "Analyze Log"}
            </button>

          </div>
        </section>

        {/* ERROR */}
        {error && (
          <div className="error">
            ⚠ {error}
          </div>
        )}

        {/* STATS */}
        <section className="stats">

          <div className="stat-card">
            <span>TOTAL EVENTS</span>
            <strong>{events.length}</strong>
          </div>

          <div className="stat-card">
            <span>THREATS DETECTED</span>
            <strong>{threats.length}</strong>
          </div>

          <div className="stat-card">
            <span>HIGH SEVERITY</span>
            <strong className="orange">
              {highSeverity}
            </strong>
          </div>

          <div className="stat-card">
            <span>INCIDENTS</span>
            <strong>{threats.length}</strong>
          </div>

        </section>

        {/* INCIDENTS */}
        <section className="results">

          <div className="results-header">
            <div>
              <p className="eyebrow">DETECTION ENGINE</p>
              <h2>Recent Incidents</h2>
            </div>

            <div className="live">
              <span></span>
              LIVE
            </div>
          </div>

          {!result && !loading && (
            <div className="empty">
              <div className="empty-icon">⌁</div>

              <h3>No incidents detected</h3>

              <p>
                Upload a security log to start analyzing suspicious activity.
              </p>
            </div>
          )}

          {loading && (
            <div className="empty">

              <div className="spinner"></div>

              <h3>Analyzing security logs...</h3>

              <p>
                SentinelX detection engine is processing your events.
              </p>

            </div>
          )}

          {result && threats.length === 0 && (
            <div className="empty">

              <div className="success-icon">✓</div>

              <h3>No threats detected</h3>

              <p>
                SentinelX analyzed {events.length} events and found no
                suspicious activity.
              </p>

            </div>
          )}

          {/* THREAT CARDS */}
          {threats.length > 0 && (
            <div className="threat-list">

              {threats.map((threat, index) => (

                <div className="threat-card" key={index}>

                  <div className="threat-top">

                    <div>
                      <span className="incident-number">
                        INCIDENT #{String(index + 1).padStart(3, "0")}
                      </span>

                      <h3>
                        {threat.type || "Suspicious Activity"}
                      </h3>
                    </div>

                    <span
                      className={`severity ${String(
                        threat.severity || "MEDIUM"
                      ).toLowerCase()}`}
                    >
                      {threat.severity || "MEDIUM"}
                    </span>

                  </div>

                  <div className="threat-details">

                    <div>
                      <span>COUNT</span>
                      <strong>{threat.count || 0}</strong>
                    </div>

                    <div>
                      <span>SOURCE</span>
                      <strong>{getSource(threat)}</strong>
                    </div>

                  </div>

                  <div className="evidence">

                    <span>EVIDENCE</span>

                    <p>
                      {threat.evidence ||
                        threat.message ||
                        "Suspicious activity detected."}
                    </p>

                  </div>

                  <div className="explanation">

                    <span>WHY DETECTED</span>

                    <p>
                      {threat.message ||
                        "Multiple related security events matched a detection rule."}
                    </p>

                  </div>

                  <div className="attack-story">

                    <span>ATTACK STORY</span>

                    <p>
                      {getThreatStory(threat)}
                    </p>

                  </div>

                  <div className="recommendation">

                    <span>RECOMMENDED RESPONSE</span>

                    <p>
                      {getRecommendation(threat)}
                    </p>

                  </div>

                </div>

              ))}

            </div>
          )}

        </section>

        {/* ATTACK TIMELINE */}
        {result && events.length > 0 && (
          <section className="events">

            <div className="results-header">

              <div>
                <p className="eyebrow">EVENT CORRELATION</p>
                <h2>Attack Timeline</h2>
              </div>

              <div className="live">
                <span></span>
                CORRELATED
              </div>

            </div>

            <div
              style={{
                padding: "25px 10px 10px",
                position: "relative",
              }}
            >

              {/* TIMELINE LINE */}
              <div
                style={{
                  position: "absolute",
                  left: "34px",
                  top: "30px",
                  bottom: "35px",
                  width: "1px",
                  background: "#3a3a3a",
                }}
              ></div>

              {events.map((event, index) => (

                <div
                  key={index}
                  style={{
                    display: "grid",
                    gridTemplateColumns: "50px 110px 1fr",
                    gap: "15px",
                    alignItems: "start",
                    position: "relative",
                    marginBottom: "28px",
                  }}
                >

                  {/* TIMELINE DOT */}
                  <div
                    style={{
                      width: "10px",
                      height: "10px",
                      borderRadius: "50%",
                      background: "#ff7a00",
                      boxShadow: "0 0 12px rgba(255,122,0,0.45)",
                      marginTop: "5px",
                      marginLeft: "29px",
                      position: "relative",
                      zIndex: 2,
                    }}
                  ></div>

                  {/* TIME */}
                  <div
                    style={{
                      fontSize: "11px",
                      color: "#888",
                      fontFamily: "monospace",
                      paddingTop: "1px",
                    }}
                  >
                    {getTimelineTime(event)}
                  </div>

                  {/* EVENT */}
                  <div
                    style={{
                      border: "1px solid #252525",
                      background: "#0c0c0c",
                      borderRadius: "6px",
                      padding: "12px 14px",
                    }}
                  >

                    <div
                      style={{
                        fontSize: "9px",
                        letterSpacing: "1.5px",
                        color: "#ff7a00",
                        marginBottom: "6px",
                      }}
                    >
                      {getTimelineEventType(event)}
                    </div>

                    <strong
                      style={{
                        display: "block",
                        color: "#f1f1f1",
                        fontSize: "13px",
                        marginBottom: "5px",
                      }}
                    >
                      {event.event_type || "Security Event"}
                    </strong>

                    <p
                      style={{
                        margin: 0,
                        color: "#777",
                        fontSize: "11px",
                        lineHeight: "1.5",
                      }}
                    >
                      {event.raw || "No raw event data available."}
                    </p>

                    {(event.username || event.source) && (
                      <div
                        style={{
                          marginTop: "8px",
                          color: "#555",
                          fontSize: "10px",
                        }}
                      >
                        {event.username
                          ? `Account: ${event.username}`
                          : ""}
                        {event.username && event.source
                          ? " · "
                          : ""}
                        {event.source
                          ? `Source: ${event.source}`
                          : ""}
                      </div>
                    )}

                  </div>

                </div>

              ))}

              {/* CORRELATION RESULT */}
              {threats.length > 0 && (
                <div
                  style={{
                    marginTop: "10px",
                    marginLeft: "50px",
                    border: "1px solid #4b260c",
                    background: "rgba(255,122,0,0.05)",
                    borderRadius: "6px",
                    padding: "16px",
                  }}
                >

                  <div
                    style={{
                      fontSize: "9px",
                      letterSpacing: "1.5px",
                      color: "#ff7a00",
                      marginBottom: "8px",
                    }}
                  >
                    CORRELATION RESULT
                  </div>

                  <strong
                    style={{
                      color: "#f1f1f1",
                      fontSize: "14px",
                    }}
                  >
                    {threats.length} security incident
                    {threats.length !== 1 ? "s" : ""} correlated
                  </strong>

                  <p
                    style={{
                      color: "#777",
                      fontSize: "11px",
                      lineHeight: "1.5",
                      marginBottom: 0,
                    }}
                  >
                    SentinelX correlated the observed events and identified
                    suspicious activity requiring investigation.
                  </p>

                </div>
              )}

            </div>

          </section>
        )}

        {/* ATTACK OVERVIEW */}
        {result && threats.length > 0 && (
          <section className="events">

            <div className="results-header">

              <div>
                <p className="eyebrow">INCIDENT ANALYSIS</p>
                <h2>Attack Overview</h2>
              </div>

            </div>

            <div className="event-list">

              {threats.map((threat, index) => (

                <div className="event" key={index}>

                  <div className="event-number">
                    {String(index + 1).padStart(2, "0")}
                  </div>

                  <div className="event-content">

                    <strong>
                      {threat.type || "Security Incident"}
                    </strong>

                    <p>
                      Source: {getSource(threat)} · Events:{" "}
                      {threat.count || 0} · Severity:{" "}
                      {threat.severity || "UNKNOWN"}
                    </p>

                  </div>

                  <div className="event-user">
                    {threat.severity || "UNKNOWN"}
                  </div>

                </div>

              ))}

            </div>

          </section>
        )}

        {/* RAW TELEMETRY */}
        {result && events.length > 0 && (
          <section className="events">

            <div className="results-header">

              <div>
                <p className="eyebrow">RAW TELEMETRY</p>
                <h2>Analyzed Events</h2>
              </div>

            </div>

            <div className="event-list">

              {events.map((event, index) => (

                <div className="event" key={index}>

                  <div className="event-number">
                    {String(index + 1).padStart(2, "0")}
                  </div>

                  <div className="event-content">

                    <strong>
                      {event.event_type || "Security Event"}
                    </strong>

                    <p>
                      {event.raw}
                    </p>

                  </div>

                  <div className="event-user">
                    {event.username ||
                      event.source ||
                      "Unknown"}
                  </div>

                </div>

              ))}

            </div>

          </section>
        )}

      </main>

      {/* FOOTER */}
      <footer>
        SentinelX · Local Smart Log Sentinel
      </footer>

    </div>
  );
}

export default App;