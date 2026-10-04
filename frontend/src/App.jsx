import { useState } from "react";
import { jsPDF } from "jspdf";
import "./App.css";
import sentinelxLogo from "./assets/sentinelx-logo.png";

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
          type === "Web Scanning"
            ? "MEDIUM"
            : "HIGH",
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
    .filter(
      (event) => event.type === "SSH Brute Force"
    )
    .forEach((event) => {
      if (!sourceUsers.has(event.source)) {
        sourceUsers.set(event.source, new Set());
      }

      if (event.username !== "Unknown") {
        sourceUsers
          .get(event.source)
          .add(event.username);
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
          .filter(
            (username) => username !== "Unknown"
          )
      ),
    ];

    return users.length
      ? `${incident.count} authentication failures targeting multiple accounts: ${users.join(
          ", "
        )}.`
      : `${incident.count} authentication failures from ${incident.source}.`;
  }

  if (
    incident.type === "SQL Injection Attempt"
  ) {
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

  if (
    incident.type === "SQL Injection Attempt"
  ) {
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

  if (
    incident.type === "SQL Injection Attempt"
  ) {
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

  return [
    "Suspicious activity detected and correlated by SentinelX.",
  ];
}

function buildResponse(incident) {
  if (incident.type === "SSH Brute Force") {
    return "Review the targeted account, enforce strong authentication, consider MFA, and temporarily block or rate-limit the source if the activity continues.";
  }

  if (incident.type === "Password Spraying") {
    return "Review affected accounts, enforce MFA, check for compromised credentials, and investigate the source IP.";
  }

  if (
    incident.type === "SQL Injection Attempt"
  ) {
    return "Review the affected endpoint, validate and parameterize database queries, inspect application logs, and block repeated malicious requests.";
  }

  if (incident.type === "Web Scanning") {
    return "Review the requested paths, check for exposed services or sensitive files, and rate-limit or block repeated reconnaissance traffic.";
  }

  return "Investigate the source and review surrounding log activity.";
}

/* ------------------------------------------------------------------
   PDF REPORT
------------------------------------------------------------------- */

function addWrappedText(doc, text, x, y, maxWidth, lineHeight = 5) {
  const lines = doc.splitTextToSize(
    String(text || ""),
    maxWidth
  );

  doc.text(lines, x, y);

  return y + lines.length * lineHeight;
}

function ensurePageSpace(doc, y, required = 20) {
  if (y + required > 280) {
    doc.addPage();
    return 18;
  }

  return y;
}

function addPdfSectionTitle(doc, title, y) {
  y = ensurePageSpace(doc, y, 18);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(180, 75, 25);
  doc.text(title, 15, y);

  return y + 8;
}

function generateAnalyticsPdf(result, fileName) {
  const doc = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4",
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;

  let y = 18;

  const addFooter = () => {
    const pageCount = doc.internal.getNumberOfPages();

    for (let page = 1; page <= pageCount; page++) {
      doc.setPage(page);

      doc.setDrawColor(225, 225, 225);
      doc.line(
        margin,
        pageHeight - 13,
        pageWidth - margin,
        pageHeight - 13
      );

      doc.setFont("helvetica", "normal");
      doc.setFontSize(7);
      doc.setTextColor(110, 110, 110);

      doc.text(
        "SentinelX - Local Smart Log Sentinel",
        margin,
        pageHeight - 8
      );

      doc.text(
        `WCC Launchpad 30 - Page ${page} of ${pageCount}`,
        pageWidth - margin,
        pageHeight - 8,
        { align: "right" }
      );
    }
  };

  /* Header */
  doc.setFillColor(15, 15, 15);
  doc.rect(0, 0, pageWidth, 38, "F");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(24);
  doc.setTextColor(239, 147, 98);
  doc.text("SENTINELX", margin, 17);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(215, 215, 215);
  doc.text(
    "LOCAL SMART LOG SENTINEL",
    margin,
    25
  );

  doc.setFontSize(8);
  doc.text(
    "SECURITY ANALYTICS REPORT",
    pageWidth - margin,
    18,
    { align: "right" }
  );

  doc.text(
    "Browser-local analysis",
    pageWidth - margin,
    25,
    { align: "right" }
  );

  y = 48;

  /* Report metadata */
  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.setTextColor(25, 25, 25);
  doc.text("Analysis Summary", margin, y);

  y += 9;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(75, 75, 75);

  y = addWrappedText(
    doc,
    `Source file: ${fileName || "Unknown"}`,
    margin,
    y,
    contentWidth
  );

  y = addWrappedText(
    doc,
    `Generated: ${new Date().toLocaleString()}`,
    margin,
    y + 1,
    contentWidth
  );

  y += 5;

  /* Statistics */
  y = addPdfSectionTitle(
    doc,
    "Detection Statistics",
    y
  );

  const stats = [
    ["LOG EVENTS", result.totalLines],
    ["DETECTED EVENTS", result.stats.events],
    ["HIGH SEVERITY", result.stats.high],
    ["MEDIUM SEVERITY", result.stats.medium],
    ["INCIDENTS", result.stats.incidents],
  ];

  const boxWidth = (contentWidth - 8) / 3;
  const boxHeight = 21;

  stats.forEach(([label, value], index) => {
    const row = Math.floor(index / 3);
    const col = index % 3;

    const x =
      margin + col * (boxWidth + 4);
    const boxY =
      y + row * (boxHeight + 5);

    doc.setFillColor(247, 247, 247);
    doc.setDrawColor(225, 225, 225);
    doc.roundedRect(
      x,
      boxY,
      boxWidth,
      boxHeight,
      2,
      2,
      "FD"
    );

    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(100, 100, 100);
    doc.text(label, x + 4, boxY + 7);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.setTextColor(
      label === "HIGH SEVERITY"
        ? 190
        : 30,
      label === "HIGH SEVERITY"
        ? 70
        : 30,
      label === "HIGH SEVERITY"
        ? 25
        : 30
    );

    doc.text(
      String(value),
      x + 4,
      boxY + 16
    );
  });

  y +=
    Math.ceil(stats.length / 3) *
      (boxHeight + 5) +
    6;

  /* Incidents */
  y = addPdfSectionTitle(
    doc,
    "Detected Incidents",
    y
  );

  if (result.incidents.length === 0) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(70, 70, 70);

    y = addWrappedText(
      doc,
      "No threats were detected by the current SentinelX detection rules.",
      margin,
      y,
      contentWidth
    );

    y += 5;
  } else {
    result.incidents.forEach(
      (incident, index) => {
        y = ensurePageSpace(doc, y, 58);

        doc.setFillColor(250, 250, 250);
        doc.setDrawColor(225, 225, 225);
        doc.roundedRect(
          margin,
          y - 3,
          contentWidth,
          8,
          2,
          2,
          "FD"
        );

        doc.setFont("helvetica", "bold");
        doc.setFontSize(10);

        doc.setTextColor(
          incident.severity === "HIGH"
            ? 190
            : 180,
          incident.severity === "HIGH"
            ? 65
            : 100,
          30
        );

        doc.text(
          `[${incident.severity}] ${incident.type}`,
          margin + 4,
          y + 2
        );

        y += 12;

        doc.setFont("helvetica", "normal");
        doc.setFontSize(8);
        doc.setTextColor(80, 80, 80);

        doc.text(
          `Source: ${incident.source}    Events: ${incident.count}`,
          margin,
          y
        );

        y += 7;

        const blocks = [
          ["Evidence", incident.evidence],
          ["Why Detected", incident.why],
          [
            "Attack Story",
            incident.story
              .map(
                (step, stepIndex) =>
                  `${stepIndex + 1}. ${step}`
              )
              .join(" "),
          ],
          ["Recommended Response", incident.response],
        ];

        blocks.forEach(([title, text]) => {
          y = ensurePageSpace(doc, y, 15);

          doc.setFont("helvetica", "bold");
          doc.setFontSize(8);
          doc.setTextColor(40, 40, 40);
          doc.text(title.toUpperCase(), margin, y);

          y += 4;

          doc.setFont("helvetica", "normal");
          doc.setFontSize(8);
          doc.setTextColor(75, 75, 75);

          y = addWrappedText(
            doc,
            text,
            margin,
            y,
            contentWidth,
            4
          );

          y += 4;
        });

        if (
          index <
          result.incidents.length - 1
        ) {
          doc.setDrawColor(235, 235, 235);
          doc.line(
            margin,
            y,
            pageWidth - margin,
            y
          );

          y += 8;
        }
      }
    );
  }

  /* Raw telemetry */
  y = ensurePageSpace(doc, y, 25);

  doc.addPage();
  y = 18;

  y = addPdfSectionTitle(
    doc,
    "Raw Telemetry",
    y
  );

  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.setTextColor(90, 90, 90);

  y = addWrappedText(
    doc,
    `${result.analyzedEvents.length} detected event records included in this report.`,
    margin,
    y,
    contentWidth
  );

  y += 5;

  if (result.analyzedEvents.length === 0) {
    y = addWrappedText(
      doc,
      "No detected event records were generated.",
      margin,
      y,
      contentWidth
    );
  } else {
    result.analyzedEvents.forEach(
      (event, index) => {
        y = ensurePageSpace(doc, y, 26);

        doc.setFont("helvetica", "bold");
        doc.setFontSize(8);
        doc.setTextColor(
          event.severity === "HIGH"
            ? 190
            : 180,
          event.severity === "HIGH"
            ? 65
            : 100,
          30
        );

        doc.text(
          `${index + 1}. ${event.severity} - ${event.type}`,
          margin,
          y
        );

        y += 4;

        doc.setFont("helvetica", "normal");
        doc.setFontSize(7);
        doc.setTextColor(90, 90, 90);

        doc.text(
          `Source: ${event.source} | Time: ${event.timestamp}`,
          margin,
          y
        );

        y += 4;

        doc.setFont("courier", "normal");
        doc.setFontSize(7);
        doc.setTextColor(55, 55, 55);

        y = addWrappedText(
          doc,
          event.raw,
          margin,
          y,
          contentWidth,
          3.5
        );

        y += 5;
      }
    );
  }

  /* Final note */
  y = ensurePageSpace(doc, y, 30);

  y += 5;

  doc.setFillColor(250, 244, 240);
  doc.setDrawColor(235, 210, 195);
  doc.roundedRect(
    margin,
    y,
    contentWidth,
    22,
    2,
    2,
    "FD"
  );

  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(150, 65, 25);

  doc.text(
    "SENTINELX ANALYSIS NOTE",
    margin + 5,
    y + 7
  );

  doc.setFont("helvetica", "normal");
  doc.setFontSize(7);
  doc.setTextColor(90, 75, 70);

  addWrappedText(
    doc,
    "This report contains findings generated by SentinelX's current local detection rules. Results are intended for security analysis and educational use and should be validated against the original system context.",
    margin + 5,
    y + 12,
    contentWidth - 10,
    3.5
  );

  addFooter();

  const safeName =
    (fileName || "sentinelx-analysis")
      .replace(/\.[^/.]+$/, "")
      .replace(/[^a-z0-9_-]/gi, "_");

  doc.save(
    `${safeName}-SentinelX-Analytics.pdf`
  );
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
        throw new Error(
          "The selected log file is empty."
        );
      }

      /*
       * SentinelX analyzes the log locally.
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
    const selectedFile =
      event.target.files?.[0];

    if (!selectedFile) return;

    setFile(selectedFile);
    setResult(null);
    setError("");
  };

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <div className="logo">
            <img
              src={sentinelxLogo}
              alt="SentinelX logo"
            />
          </div>

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
              SentinelX analyzes security logs directly
              in your browser and turns suspicious
              activity into explainable security
              incidents.
            </p>
          </div>

          <div className="upload-card">
            <div className="upload-icon">↑</div>

            <h3>Analyze a log file</h3>

            <p>
              Upload a .log or .txt file. Analysis
              happens locally in your browser.
            </p>

            <label className="file-input">
              <input
                type="file"
                accept=".log,.txt,text/plain"
                onChange={handleFileChange}
              />

              <span>
                {file
                  ? file.name
                  : "Choose log file"}
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
                <strong>
                  {result.totalLines}
                </strong>
              </div>

              <div className="stat-card">
                <span>DETECTED EVENTS</span>
                <strong>
                  {result.stats.events}
                </strong>
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

                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    flexWrap: "wrap",
                    justifyContent: "flex-end",
                  }}
                >
                  <button
                    className="analyze-button"
                    onClick={() =>
                      generateAnalyticsPdf(
                        result,
                        file?.name
                      )
                    }
                    type="button"
                  >
                    DOWNLOAD ANALYTICS PDF
                  </button>

                  <span className="live">
                    ● LIVE ANALYSIS
                  </span>
                </div>
              </div>

              {result.incidents.length === 0 ? (
                <div className="empty">
                  <div className="empty-icon">
                    ✓
                  </div>

                  <h3>No threats detected</h3>

                  <p>
                    SentinelX did not find activity
                    matching its current detection
                    rules.
                  </p>
                </div>
              ) : (
                <div className="incident-list">
                  {result.incidents.map(
                    (incident, index) => (
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

                            <h3>
                              {incident.type}
                            </h3>

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
                            <span>
                              EVIDENCE
                            </span>

                            <p>
                              {incident.evidence}
                            </p>
                          </div>

                          <div className="detail-block">
                            <span>
                              WHY DETECTED
                            </span>

                            <p>
                              {incident.why}
                            </p>
                          </div>
                        </div>

                        <div className="story">
                          <span>
                            ATTACK STORY
                          </span>

                          <div className="timeline">
                            {incident.story.map(
                              (
                                step,
                                stepIndex
                              ) => (
                                <div
                                  className="timeline-item"
                                  key={
                                    stepIndex
                                  }
                                >
                                  <div className="timeline-dot">
                                    {stepIndex +
                                      1}
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

                          <p>
                            {incident.response}
                          </p>
                        </div>
                      </article>
                    )
                  )}
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
                        <strong>
                          {event.type}
                        </strong>

                        <span>
                          {event.source} ·{" "}
                          {event.timestamp}
                        </span>
                      </div>

                      <code>
                        {event.raw}
                      </code>
                    </div>
                  )
                )}
              </div>
            </section>
          </>
        )}

        {!result &&
          !loading &&
          !error && (
            <section className="empty">
              <div className="empty-icon">
                ⌁
              </div>

              <h3>Ready for analysis</h3>

              <p>
                Upload a security log to begin
                local threat detection.
              </p>
            </section>
          )}

        {loading && (
          <section className="empty">
            <div className="spinner" />

            <h3>Analyzing telemetry...</h3>

            <p>
              SentinelX is parsing and correlating
              the selected log locally.
            </p>
          </section>
        )}
      </main>

      <footer className="footer">
        <div className="footer-inner">
          <div className="footer-brand">
            <img
              src={sentinelxLogo}
              alt="SentinelX"
              className="footer-logo"
            />

            <div>
              <strong>SentinelX</strong>

              <span>
                Local Smart Log Sentinel
              </span>
            </div>
          </div>

          <div className="footer-socials">
            <span className="social-label">
              CONNECT
            </span>

            <a
              className="social-link"
              href="https://www.instagram.com/cyber_sangram"
              target="_blank"
              rel="noreferrer"
            >
              Instagram
            </a>

            <a
              className="social-link"
              href="https://www.linkedin.com/in/sangramcloud"
              target="_blank"
              rel="noreferrer"
            >
              LinkedIn
            </a>

            <a
              className="social-link"
              href="https://github.com/sangram-net"
              target="_blank"
              rel="noreferrer"
            >
              GitHub
            </a>
          </div>
        </div>

        <div className="footer-bottom">
          <span>
            SentinelX · Local Smart Log Sentinel
          </span>

          <span>
            Built for WCC Launchpad 30 · Open
            Innovation
          </span>
        </div>
      </footer>
    </div>
  );
}

export default App;
