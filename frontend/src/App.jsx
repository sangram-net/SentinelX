import { useState } from "react";
import "./App.css";

const DETECTION_RULES = {
  ssh: {
    name: "SSH Brute Force",
    severity: "HIGH",
    pattern:
      /(failed password|authentication failure|failed login|invalid user).*(sshd|ssh)/i,
    fallbackPattern: /(failed password|authentication failure|invalid user)/i,
  },

  passwordSpraying: {
    name: "Password Spraying",
    severity: "HIGH",
  },

  sqli: {
    name: "SQL Injection Attempt",
    severity: "HIGH",
    pattern:
      /('|%27|--|%2d%2d|union\s+select|select\s+.*\s+from|or\s+1\s*=\s*1|and\s+1\s*=\s*1|drop\s+table|insert\s+into)/i,
  },

  scanning: {
    name: "Web Scanning",
    severity: "MEDIUM",
    pattern:
      /(GET|POST|HEAD|OPTIONS)\s+\/(wp-admin|wp-login|admin|login|phpmyadmin|\.env|server-status|robots\.txt|favicon\.ico)/i,
  },
};

const SEVERITY_ORDER = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

function extractIp(line) {
  const match = line.match(
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/
  );

  return match ? match[0] : "Unknown";
}

function extractTimestamp(line) {
  const match = line.match(
    /\[([^\]]+)\]/
  );

  if (match) return match[1];

  const iso = line.match(
    /\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/
  );

  return iso ? iso[0] : "Unknown";
}

function extractUsername(line) {
  const patterns = [
    /for invalid user\s+([a-zA-Z0-9._-]+)/i,
    /for\s+([a-zA-Z0-9._-]+)\s+from/i,
    /user[=:]\s*([a-zA-Z0-9._-]+)/i,
    /username[=:]\s*([a-zA-Z0-9._-]+)/i,
  ];

  for (const pattern of patterns) {
    const match = line.match(pattern);
    if (match) return match[1];
  }

  return "Unknown";
}

function normalizeLine(line, index) {
  return {
    id: index + 1,
    raw: line,
    source: extractIp(line),
    timestamp: extractTimestamp(line),
    username: extractUsername(line),
  };
}

function detectLine(line) {
  const detections = [];

  if (
    DETECTION_RULES.ssh.pattern.test(line) ||
    DETECTION_RULES.ssh.fallbackPattern.test(line)
  ) {
    detections.push("SSH Brute Force");
  }

  if (DETECTION_RULES.sqli.pattern.test(line)) {
    detections.push("SQL Injection Attempt");
  }

  if (DETECTION_RULES.scanning.pattern.test(line)) {
    detections.push("Web Scanning");
  }

  return detections;
}

function analyzeLogs(logText) {
  const lines = logText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const events = [];
  const detectionMap = new Map();

  lines.forEach((line, index) => {
    const event = normalizeLine(line, index);
    const detections = detectLine(line);

    detections.forEach((type) => {
      events.push({
        ...event,
        type,
        severity:
          type === "Web Scanning" ? "MEDIUM" : "HIGH",
      });

      const key = `${type}|${event.source}`;

      if (!detectionMap.has(key)) {
        detectionMap.set(key, {
          type,
          source: event.source,
          count: 0,
          events: [],
        });
      }

      const incident = detectionMap.get(key);
      incident.count += 1;
      incident.events.push(event);
    });
  });

  /*
   * Password spraying:
   * Multiple usernames targeted from the same source.
   */
  const sourceUsers = new Map();

  events
    .filter((event) => event.type === "SSH Brute Force")
    .forEach((event) => {
      if (!sourceUsers.has(event.source)) {
        sourceUsers.set(event.source, new Set());
      }

      if (event.username !== "Unknown") {
        sourceUsers.get(event.source).add(event.username);
      }
    });

  sourceUsers.forEach((users, source) => {
    if (users.size >= 2) {
      const key = `Password Spraying|${source}`;

      const relatedEvents = events.filter(
        (event) =>
          event.source === source &&
          event.type === "SSH Brute Force"
      );

      detectionMap.set(key, {
        type: "Password Spraying",
        source,
        count: relatedEvents.length,
        events: relatedEvents,
      });
    }
  });

  const incidents = Array.from(detectionMap.values())
    .map((incident) => {
      const severity =
        incident.type === "Web Scanning"
          ? "MEDIUM"
          : "HIGH";

      return {
        ...incident,
        severity,
        evidence: buildEvidence(incident),
        why: buildWhyDetected(incident),
        story: buildAttackStory(incident),
        response: buildResponse(incident),
      };
    })
    .sort(
      (a, b) =>
        SEVERITY_ORDER[b.severity] -
        SEVERITY_ORDER[a.severity]
    );

  return {
    totalLines: lines.length,
    analyzedEvents: events,
    incidents,
    stats: {
      events: events.length,
      incidents: incidents.length,
      high: incidents.filter(
        (i) => i.severity === "HIGH"
      ).length,
      medium: incidents.filter(
        (i) => i.severity === "MEDIUM"
      ).length,
    },
  };
}

function buildEvidence(incident) {
  const firstEvent = incident.events[0];

  if (!firstEvent) {
    return "No supporting evidence available.";
  }

  if (incident.type === "SSH Brute Force") {
    return `${incident.count} failed authentication attempt${
      incident.count === 1 ? "" : "s"
    } from ${incident.source}.`;
  }

  if (incident.type === "Password Spraying") {
    const users = [
      ...new Set(
        incident.events
          .map((event) => event.username)
          .filter((username) => username !== "Unknown")
      ),
    ];

    return users.length
      ? `${incident.count} authentication failures targeting multiple accounts: ${users.join(
          ", "
        )}.`
      : `${incident.count} authentication failures from ${incident.source}.`;
  }

  if (incident.type === "SQL Injection Attempt") {
    return `Suspicious SQL syntax detected in request activity from ${incident.source}.`;
  }

  if (incident.type === "Web Scanning") {
    return `${incident.count} suspicious web reconnaissance request${
      incident.count === 1 ? "" : "s"
    } detected from ${incident.source}.`;
  }

  return "Suspicious activity detected.";
}

function buildWhyDetected(incident) {
  if (incident.type === "SSH Brute Force") {
    return "Repeated authentication failures from the same source indicate a possible brute-force login attempt.";
  }

  if (incident.type === "Password Spraying") {
    return "The same source attempted authentication against multiple accounts, matching password-spraying behavior.";
  }

  if (incident.type === "SQL Injection Attempt") {
    return "The request contains SQL control characters or SQL keywords commonly associated with injection attempts.";
  }

  if (incident.type === "Web Scanning") {
    return "The source requested common administrative, authentication, or sensitive web paths associated with reconnaissance.";
  }

  return "The activity matched a SentinelX detection rule.";
}

function buildAttackStory(incident) {
  if (incident.type === "SSH Brute Force") {
    return [
      "Source generated repeated authentication failures.",
      "Multiple login attempts were observed against the system.",
      "Activity was correlated into a single SSH brute-force incident.",
    ];
  }

  if (incident.type === "Password Spraying") {
    return [
      "A single source targeted multiple user accounts.",
      "Authentication failures were observed across those accounts.",
      "SentinelX correlated the activity as password spraying.",
    ];
  }

  if (incident.type === "SQL Injection Attempt") {
    return [
      "A web request contained suspicious SQL syntax.",
      "The request originated from the same external source.",
      "SentinelX classified the activity as a SQL injection attempt.",
    ];
  }

  if (incident.type === "Web Scanning") {
    return [
      "A source requested sensitive or commonly scanned web paths.",
      "The requests indicate reconnaissance activity.",
      "SentinelX grouped the requests into a web-scanning incident.",
    ];
  }

  return ["Suspicious activity detected and correlated by SentinelX."];
}

function buildResponse(incident) {
  if (incident.type === "SSH Brute Force") {
    return "Review the targeted account, enforce strong authentication, consider MFA, and temporarily block or rate-limit the source if the activity continues.";
  }

  if (incident.type === "Password Spraying") {
    return "Review affected accounts, enforce MFA, check for compromised credentials, and investigate the source IP.";
  }

  if (incident.type === "SQL Injection Attempt") {
    return "Review the affected endpoint, validate and parameterize database queries, inspect application logs, and block repeated malicious requests.";
  }

  if (incident.type === "Web Scanning") {
    return "Review the requested paths, check for exposed services or sensitive files, and rate-limit or block repeated reconnaissance traffic.";
  }

  return "Investigate the source and review surrounding log activity.";
}

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
      const logText = await file.text();

      if (!logText.trim()) {
        throw new Error("The selected log file is empty.");
      }

      /*
       * SentinelX now analyzes the log locally.
       * No Render API or external backend is required.
       */
      const analysis = analyzeLogs(logText);

      setResult(analysis);
    } catch (err) {
      setError(
        err?.message ||
          "Unable to analyze the selected log file."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleFileChange = (event) => {
    const selectedFile = event.target.files?.[0];

    if (!selectedFile) return;

    setFile(selectedFile);
    setResult(null);
    setError("");
  };

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <div className="logo">SX</div>

          <div>
            <h1>SentinelX</h1>
            <p>Local Smart Log Sentinel</p>
          </div>
        </div>

        <div className="api-status">
          <span className="status-dot" />
          LOCAL ANALYZER ONLINE
        </div>
      </header>

      <main className="container">
        <section className="hero">
          <div className="hero-text">
            <span className="eyebrow">
              LOCAL SECURITY INTELLIGENCE
            </span>

            <h2>
              Turn logs into insights.
              <br />
              Detect threats. Stay ahead.
            </h2>

            <p className="description">
              SentinelX analyzes security logs directly in
              your browser and turns suspicious activity
              into explainable security incidents.
            </p>
          </div>

          <div className="upload-card">
            <div className="upload-icon">↑</div>

            <h3>Analyze a log file</h3>

            <p>
              Upload a .log or .txt file. Analysis happens
              locally in your browser.
            </p>

            <label className="file-input">
              <input
                type="file"
                accept=".log,.txt,text/plain"
                onChange={handleFileChange}
              />

              <span>
                {file ? file.name : "Choose log file"}
              </span>
            </label>

            {file && (
              <button
                className="analyze-button"
                onClick={analyzeLog}
                disabled={loading}
              >
                {loading
                  ? "ANALYZING..."
                  : "ANALYZE LOG"}
              </button>
            )}

            {error && (
              <div className="error">
                {error}
              </div>
            )}
          </div>
        </section>

        {result && (
          <>
            <section className="stats">
              <div className="stat-card">
                <span>LOG EVENTS</span>
                <strong>{result.totalLines}</strong>
              </div>

              <div className="stat-card">
                <span>DETECTED EVENTS</span>
                <strong>{result.stats.events}</strong>
              </div>

              <div className="stat-card">
                <span>HIGH SEVERITY</span>
                <strong className="orange">
                  {result.stats.high}
                </strong>
              </div>

              <div className="stat-card">
                <span>INCIDENTS</span>
                <strong>
                  {result.stats.incidents}
                </strong>
              </div>
            </section>

            <section className="results">
              <div className="results-header">
                <div>
                  <span className="eyebrow">
                    SECURITY ANALYSIS
                  </span>

                  <h2>Detected Incidents</h2>
                </div>

                <span className="live">
                  ● LIVE ANALYSIS
                </span>
              </div>

              {result.incidents.length === 0 ? (
                <div className="empty">
                  <div className="empty-icon">✓</div>

                  <h3>No threats detected</h3>

                  <p>
                    SentinelX did not find activity matching
                    its current detection rules.
                  </p>
                </div>
              ) : (
                <div className="incident-list">
                  {result.incidents.map((incident, index) => (
                    <article
                      className="incident-card"
                      key={`${incident.type}-${incident.source}-${index}`}
                    >
                      <div className="incident-top">
                        <div>
                          <span
                            className={`severity ${incident.severity.toLowerCase()}`}
                          >
                            {incident.severity}
                          </span>

                          <h3>{incident.type}</h3>

                          <p className="incident-meta">
                            Source:{" "}
                            <strong>
                              {incident.source}
                            </strong>
                            {" · "}
                            Events:{" "}
                            <strong>
                              {incident.count}
                            </strong>
                          </p>
                        </div>
                      </div>

                      <div className="incident-grid">
                        <div className="detail-block">
                          <span>EVIDENCE</span>
                          <p>{incident.evidence}</p>
                        </div>

                        <div className="detail-block">
                          <span>WHY DETECTED</span>
                          <p>{incident.why}</p>
                        </div>
                      </div>

                      <div className="story">
                        <span>ATTACK STORY</span>

                        <div className="timeline">
                          {incident.story.map(
                            (step, stepIndex) => (
                              <div
                                className="timeline-item"
                                key={stepIndex}
                              >
                                <div className="timeline-dot">
                                  {stepIndex + 1}
                                </div>

                                <p>{step}</p>
                              </div>
                            )
                          )}
                        </div>
                      </div>

                      <div className="response">
                        <span>
                          RECOMMENDED RESPONSE
                        </span>

                        <p>{incident.response}</p>
                      </div>
                    </article>
                  ))}
                </div>
              )}
            </section>

            <section className="results">
              <div className="results-header">
                <div>
                  <span className="eyebrow">
                    RAW TELEMETRY
                  </span>

                  <h2>Analyzed Events</h2>
                </div>
              </div>

              <div className="events">
                {result.analyzedEvents.map(
                  (event, index) => (
                    <div
                      className="event-row"
                      key={`${event.id}-${index}`}
                    >
                      <div>
                        <span
                          className={`severity ${event.severity.toLowerCase()}`}
                        >
                          {event.severity}
                        </span>
                      </div>

                      <div className="event-main">
                        <strong>{event.type}</strong>

                        <span>
                          {event.source} ·{" "}
                          {event.timestamp}
                        </span>
                      </div>

                      <code>{event.raw}</code>
                    </div>
                  )
                )}
              </div>
            </section>
          </>
        )}

        {!result && !loading && !error && (
          <section className="empty">
            <div className="empty-icon">⌁</div>

            <h3>Ready for analysis</h3>

            <p>
              Upload a security log to begin local threat
              detection.
            </p>
          </section>
        )}

        {loading && (
          <section className="empty">
            <div className="spinner" />

            <h3>Analyzing telemetry...</h3>

            <p>
              SentinelX is parsing and correlating the
              selected log locally.
            </p>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
