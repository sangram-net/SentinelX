import { useRef, useState } from "react";
import "./App.css";

const API_URL = "https://sentinelx-htw7.onrender.com";

const formatNumber = (value) => Number(value || 0).toLocaleString();

function App() {
  const fileInputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [dragActive, setDragActive] = useState(false);

  const events = result?.events || [];
  const threats = result?.threats || [];
  const highSeverity = threats.filter(
    (threat) => String(threat.severity || "").toUpperCase() === "HIGH"
  ).length;
  const mediumSeverity = threats.filter(
    (threat) => String(threat.severity || "").toUpperCase() === "MEDIUM"
  ).length;

  const selectFile = (selectedFile) => {
    if (!selectedFile) return;

    const name = selectedFile.name.toLowerCase();
    if (!name.endsWith(".log") && !name.endsWith(".txt")) {
      setError("Unsupported file type. Please choose a .log or .txt file.");
      setFile(null);
      return;
    }

    if (selectedFile.size > 10 * 1024 * 1024) {
      setError("File is too large. Please upload a log file under 10 MB.");
      setFile(null);
      return;
    }

    setFile(selectedFile);
    setResult(null);
    setError("");
  };

  const analyzeLog = async () => {
    if (!file || loading) return;

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
        throw new Error(`API returned ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      console.error(err);
      setError(
        "SentinelX could not reach the analysis engine. Check that the FastAPI backend is running and try again."
      );
    } finally {
      setLoading(false);
    }
  };

  const resetAnalysis = () => {
    setFile(null);
    setResult(null);
    setError("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const getSource = (threat) => threat.source || "Unknown source";

  const getThreatStory = (threat) => {
    const type = String(threat.type || "Suspicious activity");
    const lower = type.toLowerCase();

    if (lower.includes("brute")) {
      return `A source generated ${threat.count || "multiple"} failed authentication attempts. SentinelX grouped these events as a possible SSH brute-force attack.`;
    }
    if (lower.includes("spray")) {
      return "A single source targeted multiple user accounts with failed authentication attempts. This pattern is consistent with password spraying.";
    }
    if (lower.includes("sql")) {
      return "SentinelX identified a suspicious SQL-related payload in request data. The activity may represent an SQL injection attempt.";
    }
    if (lower.includes("scan")) {
      return "Multiple paths or endpoints were accessed from the same source in a short period, indicating possible reconnaissance or web scanning activity.";
    }
    return `SentinelX correlated ${threat.count || "multiple"} related security events into a potential ${type.toLowerCase()} incident.`;
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
    const date = new Date(event.timestamp);
    if (Number.isNaN(date.getTime())) return String(event.timestamp);
    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const getSeverityClass = (severity) =>
    String(severity || "MEDIUM").toLowerCase();

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-inner">
          <div className="brand">
            <div className="brand-mark">
              <img src="/src/assets/sentinelx-logo.png" alt="SentinelX logo" />
            </div>
            <div className="brand-copy">
              <strong>SentinelX</strong>
              <span>LOCAL SMART LOG SENTINEL</span>
            </div>
          </div>

          <div className="topbar-right">
            <span className="environment-badge">LOCAL ANALYSIS</span>
            <span className="api-indicator">
              <i /> ENGINE READY
            </span>
          </div>
        </div>
      </header>

      <main className="page">
        <section className="hero-section">
          <div className="hero-copy">
            <div className="section-kicker">
              <span className="kicker-line" /> SECURITY OPERATIONS
            </div>
            <h1>
              Turn raw logs into
              <span>security intelligence.</span>
            </h1>
            <p>
              SentinelX parses authentication and web logs, detects suspicious
              patterns, correlates related events, and explains what happened
              in a security-operator friendly view.
            </p>

            <div className="hero-points">
              <div>
                <b>01</b>
                <span>Detect</span>
              </div>
              <div>
                <b>02</b>
                <span>Correlate</span>
              </div>
              <div>
                <b>03</b>
                <span>Explain</span>
              </div>
            </div>
          </div>

          <div className="analysis-panel">
            <div className="panel-topline">
              <div>
                <span className="panel-label">ANALYSIS CONSOLE</span>
                <h2>Inspect a log file</h2>
              </div>
              <span className="panel-code">SX / 01</span>
            </div>

            <div
              className={`drop-zone ${dragActive ? "drag-active" : ""} ${
                file ? "has-file" : ""
              }`}
              onDragOver={(event) => {
                event.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={(event) => {
                event.preventDefault();
                setDragActive(false);
                selectFile(event.dataTransfer.files?.[0]);
              }}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".log,.txt"
                onChange={(event) => selectFile(event.target.files?.[0])}
              />
              <div className="drop-icon">
                <span>+</span>
              </div>
              <strong>{file ? file.name : "Drop a security log here"}</strong>
              <p>
                {file
                  ? `${(file.size / 1024).toFixed(1)} KB ready for analysis`
                  : "or click to browse from your computer"}
              </p>
              <small>SUPPORTED: .LOG · .TXT · MAX 10 MB</small>
            </div>

            <div className="console-actions">
              <button
                className="primary-button"
                onClick={analyzeLog}
                disabled={!file || loading}
              >
                <span>{loading ? "ANALYZING" : "ANALYZE LOG"}</span>
                <b>{loading ? "…" : "→"}</b>
              </button>
              {file && (
                <button className="secondary-button" onClick={resetAnalysis}>
                  Clear
                </button>
              )}
            </div>

            <div className="console-note">
              <span>●</span>
              Your selected log is sent only to the configured SentinelX API
              for analysis.
            </div>
          </div>
        </section>

        {error && (
          <div className="error-banner">
            <div className="error-symbol">!</div>
            <div>
              <strong>ANALYSIS UNAVAILABLE</strong>
              <p>{error}</p>
            </div>
          </div>
        )}

        <section className="metric-grid">
          <div className="metric-card">
            <span>EVENTS ANALYZED</span>
            <strong>{formatNumber(events.length)}</strong>
            <small>parsed telemetry</small>
          </div>
          <div className="metric-card accent">
            <span>THREATS DETECTED</span>
            <strong>{formatNumber(threats.length)}</strong>
            <small>correlated findings</small>
          </div>
          <div className="metric-card danger">
            <span>HIGH SEVERITY</span>
            <strong>{formatNumber(highSeverity)}</strong>
            <small>requires attention</small>
          </div>
          <div className="metric-card">
            <span>MEDIUM SEVERITY</span>
            <strong>{formatNumber(mediumSeverity)}</strong>
            <small>investigate context</small>
          </div>
        </section>

        <section className="section-block">
          <div className="section-heading">
            <div>
              <span className="section-kicker">DETECTION ENGINE</span>
              <h2>Incident intelligence</h2>
              <p>
                Correlated findings with evidence, reasoning, attack narrative,
                and a suggested defensive response.
              </p>
            </div>
            <div className="live-badge">
              <i /> {result ? "ANALYSIS COMPLETE" : "WAITING FOR LOG"}
            </div>
          </div>

          {!result && !loading && (
            <div className="empty-state">
              <div className="empty-orbit">SX</div>
              <span>NO TELEMETRY LOADED</span>
              <h3>Ready for your first investigation.</h3>
              <p>
                Upload a sanitized authentication or web log above to populate
                the detection workspace.
              </p>
            </div>
          )}

          {loading && (
            <div className="empty-state loading-state">
              <div className="loader-ring" />
              <span>DETECTION ENGINE ACTIVE</span>
              <h3>Correlating security events…</h3>
              <p>
                Parsing telemetry and evaluating SentinelX detection rules.
              </p>
            </div>
          )}

          {result && threats.length === 0 && (
            <div className="empty-state clean-state">
              <div className="clean-check">✓</div>
              <span>NO MATCHING THREATS</span>
              <h3>Environment looks quiet.</h3>
              <p>
                SentinelX analyzed {formatNumber(events.length)} events and
                found no suspicious activity matching the current rules.
              </p>
            </div>
          )}

          {threats.length > 0 && (
            <div className="incident-grid">
              {threats.map((threat, index) => (
                <article className="incident-card" key={index}>
                  <div className="incident-header">
                    <div>
                      <span className="incident-id">
                        INCIDENT / {String(index + 1).padStart(3, "0")}
                      </span>
                      <h3>{threat.type || "Suspicious Activity"}</h3>
                    </div>
                    <span className={`severity ${getSeverityClass(threat.severity)}`}>
                      {threat.severity || "MEDIUM"}
                    </span>
                  </div>

                  <div className="incident-meta">
                    <div>
                      <span>EVENTS</span>
                      <b>{threat.count || 0}</b>
                    </div>
                    <div>
                      <span>SOURCE</span>
                      <b>{getSource(threat)}</b>
                    </div>
                  </div>

                  <div className="intel-block evidence-block">
                    <span>EVIDENCE</span>
                    <p>
                      {threat.evidence ||
                        threat.message ||
                        "Suspicious activity detected."}
                    </p>
                  </div>

                  <div className="intel-block">
                    <span>WHY SENTINELX FLAGGED IT</span>
                    <p>
                      {threat.message ||
                        "Multiple related security events matched a detection rule."}
                    </p>
                  </div>

                  <div className="intel-block story-block">
                    <span>ATTACK STORY</span>
                    <p>{getThreatStory(threat)}</p>
                  </div>

                  <div className="response-block">
                    <span>RECOMMENDED RESPONSE</span>
                    <p>{getRecommendation(threat)}</p>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>

        {result && events.length > 0 && (
          <>
            <section className="section-block timeline-section">
              <div className="section-heading compact">
                <div>
                  <span className="section-kicker">EVENT CORRELATION</span>
                  <h2>Attack timeline</h2>
                </div>
                <span className="live-badge"><i /> CORRELATED</span>
              </div>

              <div className="timeline">
                {events.map((event, index) => (
                  <div className="timeline-row" key={index}>
                    <div className="timeline-marker">
                      <span />
                    </div>
                    <time>{getTimelineTime(event)}</time>
                    <div className="timeline-event">
                      <span>{getTimelineEventType(event)}</span>
                      <strong>{event.event_type || "Security Event"}</strong>
                      <p>{event.raw || "No raw event data available."}</p>
                      {(event.username || event.source) && (
                        <small>
                          {event.username ? `Account: ${event.username}` : ""}
                          {event.username && event.source ? " · " : ""}
                          {event.source ? `Source: ${event.source}` : ""}
                        </small>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {threats.length > 0 && (
              <section className="overview-strip">
                <div>
                  <span className="section-kicker">CORRELATION RESULT</span>
                  <h2>
                    {threats.length} security incident
                    {threats.length !== 1 ? "s" : ""} correlated.
                  </h2>
                </div>
                <p>
                  SentinelX connected observed telemetry into explainable
                  findings instead of presenting isolated log lines.
                </p>
              </section>
            )}

            <section className="section-block telemetry-section">
              <div className="section-heading compact">
                <div>
                  <span className="section-kicker">RAW TELEMETRY</span>
                  <h2>Analyzed events</h2>
                </div>
                <span className="event-count">{events.length} EVENTS</span>
              </div>

              <div className="telemetry-list">
                {events.map((event, index) => (
                  <div className="telemetry-row" key={index}>
                    <span className="telemetry-number">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <div>
                      <strong>{event.event_type || "Security Event"}</strong>
                      <p>{event.raw || "No raw event data available."}</p>
                    </div>
                    <span className="telemetry-source">
                      {event.username || event.source || "Unknown"}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          </>
        )}
      </main>

      <footer className="footer">
        <div>
          <strong>SentinelX</strong>
          <span>LOCAL SMART LOG SENTINEL</span>
        </div>
        <p>Analyze responsibly. Use sanitized logs and authorized data only.</p>
      </footer>
    </div>
  );
}

export default App;
