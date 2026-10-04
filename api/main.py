from collections import defaultdict
from datetime import datetime
import re

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


app = FastAPI(
    title="SentinelX API",
    version="1.1.0",
    description="Local Smart Log Sentinel",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LogPayload(BaseModel):
    log_text: str
    filename: str = "uploaded.log"


@app.get("/")
def root():
    return {
        "name": "SentinelX",
        "status": "online",
        "message": "Local Smart Log Sentinel API",
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "sentinelx-api",
        "timestamp": datetime.now().astimezone().isoformat(),
    }


def parse_log_line(line: str):
    line = line.strip()

    if not line:
        return None

    event = {
        "raw": line,
        "timestamp": datetime.now().astimezone().isoformat(),
        "source": "unknown",
        "event_type": "security_event",
        "username": None,
    }

    ssh_match = re.search(
        r"Failed password for (?:invalid user )?(\w+)\s+from\s+([\d.]+)",
        line,
        re.IGNORECASE,
    )

    if ssh_match:
        event["username"] = ssh_match.group(1)
        event["source"] = ssh_match.group(2)
        event["event_type"] = "ssh_failed_login"
        return event

    invalid_match = re.search(
        r"Invalid user\s+(\w+)\s+from\s+([\d.]+)",
        line,
        re.IGNORECASE,
    )

    if invalid_match:
        event["username"] = invalid_match.group(1)
        event["source"] = invalid_match.group(2)
        event["event_type"] = "ssh_invalid_user"
        return event

    web_match = re.search(
        r"\b(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(/[^\s]*)",
        line,
        re.IGNORECASE,
    )

    if web_match:
        method = web_match.group(1).upper()
        path = web_match.group(2)

        ip_match = re.search(
            r"\b(?:from|src=|client=|ip=)\s*([\d.]+)",
            line,
            re.IGNORECASE,
        )

        if ip_match:
            event["source"] = ip_match.group(1)

        event["event_type"] = "web_request"
        event["method"] = method
        event["path"] = path

        sql_patterns = [
            r"'\s*or\s*1\s*=\s*1",
            r"union\s+select",
            r"select\s+.*\s+from",
            r"drop\s+table",
            r"insert\s+into",
            r"delete\s+from",
            r"--",
            r"/\*",
            r"\*/",
            r"sleep\s*\(",
            r"benchmark\s*\(",
        ]

        for pattern in sql_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                event["event_type"] = "sql_injection_probe"
                break

        return event

    ip_match = re.search(
        r"\b(?:from|src=|client=|ip=)\s*([\d.]+)",
        line,
        re.IGNORECASE,
    )

    if ip_match:
        event["source"] = ip_match.group(1)

    return event


def detect_bruteforce(events):
    failed = [
        event for event in events
        if event["event_type"] in ("ssh_failed_login", "ssh_invalid_user")
    ]

    grouped = defaultdict(list)

    for event in failed:
        grouped[event["source"]].append(event)

    threats = []

    for source, source_events in grouped.items():
        count = len(source_events)

        if count >= 3:
            usernames = list(dict.fromkeys(
                event["username"]
                for event in source_events
                if event.get("username")
            ))

            threats.append({
                "type": "SSH Brute Force",
                "severity": "HIGH",
                "count": count,
                "source": source,
                "evidence": source_events[0]["raw"],
                "message": (
                    f"{count} failed SSH login attempts from {source} "
                    f"targeting {len(usernames)} account(s)."
                ),
                "attack_story": (
                    f"A source generated {count} failed authentication "
                    "attempts. SentinelX grouped these events as a "
                    "possible SSH brute-force attack."
                ),
                "recommendation": (
                    "Investigate the source IP, review affected accounts, "
                    "enforce rate limiting, and temporarily block the "
                    "source if confirmed malicious."
                ),
            })

    return threats


def detect_password_spraying(events):
    failed = [
        event for event in events
        if event["event_type"] in ("ssh_failed_login", "ssh_invalid_user")
    ]

    grouped = defaultdict(list)

    for event in failed:
        grouped[event["source"]].append(event)

    threats = []

    for source, source_events in grouped.items():
        usernames = list(dict.fromkeys(
            event["username"]
            for event in source_events
            if event.get("username")
        ))

        if len(usernames) >= 3:
            threats.append({
                "type": "Password Spraying",
                "severity": "HIGH",
                "count": len(source_events),
                "source": source,
                "evidence": f"Multiple usernames targeted from {source}",
                "message": (
                    f"Multiple accounts were targeted from the same "
                    f"source IP ({source})."
                ),
                "attack_story": (
                    "A single source targeted multiple user accounts "
                    "with failed authentication attempts. This pattern "
                    "is consistent with password spraying."
                ),
                "recommendation": (
                    "Review the targeted accounts, enforce rate limiting, "
                    "enable MFA where possible, and investigate the "
                    "source IP."
                ),
            })

    return threats


def detect_sql_injection(events):
    patterns = [
        r"'\s*or\s*1\s*=\s*1",
        r"union\s+select",
        r"select\s+.*\s+from",
        r"drop\s+table",
        r"insert\s+into",
        r"delete\s+from",
        r"--",
        r"/\*",
        r"\*/",
        r"sleep\s*\(",
        r"benchmark\s*\(",
    ]

    threats = []

    for event in events:
        if event["event_type"] != "sql_injection_probe":
            continue

        raw = event["raw"]

        for pattern in patterns:
            if re.search(pattern, raw, re.IGNORECASE):
                threats.append({
                    "type": "SQL Injection Attempt",
                    "severity": "HIGH",
                    "count": 1,
                    "source": event.get("source", "unknown"),
                    "evidence": raw,
                    "message": "Possible SQL injection payload detected.",
                    "attack_story": (
                        "SentinelX identified a suspicious SQL-related "
                        "payload in the request data. The activity may "
                        "represent an SQL injection attempt."
                    ),
                    "recommendation": (
                        "Inspect the affected endpoint, review application "
                        "logs, validate input handling, and investigate "
                        "the source IP."
                    ),
                })
                break

    return threats


def detect_web_scanning(events):
    grouped_paths = defaultdict(set)

    for event in events:
        if event["event_type"] not in (
            "web_request",
            "sql_injection_probe",
        ):
            continue

        path = event.get("path")
        if not path:
            continue

        source = event.get("source", "unknown")
        grouped_paths[source].add(path)

    threats = []

    for source, paths in grouped_paths.items():
        if len(paths) >= 5:
            threats.append({
                "type": "Web Scanning",
                "severity": "MEDIUM",
                "count": len(paths),
                "source": source,
                "evidence": (
                    f"{len(paths)} unique paths requested from {source}"
                ),
                "message": (
                    "Multiple unique web paths were requested from "
                    "the same source."
                ),
                "attack_story": (
                    f"The source requested {len(paths)} unique web paths, "
                    "indicating possible reconnaissance or automated "
                    "scanning."
                ),
                "recommendation": (
                    "Review requested paths, rate-limit the source, and "
                    "investigate whether the requests match known "
                    "scanning activity."
                ),
            })

    return threats


def detect_auth_burst(events):
    failed = [
        event for event in events
        if event["event_type"] in ("ssh_failed_login", "ssh_invalid_user")
    ]

    if len(failed) >= 5:
        sources = list(dict.fromkeys(event["source"] for event in failed))

        return [{
            "type": "Authentication Burst",
            "severity": "MEDIUM",
            "count": len(failed),
            "source": ", ".join(sources),
            "evidence": (
                f"{len(failed)} failed authentication events were observed."
            ),
            "message": (
                "A high number of authentication failures was observed "
                "in the analyzed log."
            ),
            "attack_story": (
                "SentinelX identified a concentrated burst of "
                "authentication failures that may indicate automated "
                "attack activity."
            ),
            "recommendation": (
                "Review authentication logs, check affected accounts, "
                "and apply rate limiting or MFA."
            ),
        }]

    return []


def analyze_events(events):
    threats = []
    threats.extend(detect_bruteforce(events))
    threats.extend(detect_password_spraying(events))
    threats.extend(detect_sql_injection(events))
    threats.extend(detect_web_scanning(events))
    threats.extend(detect_auth_burst(events))
    return threats


def build_analysis(text: str, filename: str):
    lines = text.splitlines()

    events = []
    for line in lines:
        event = parse_log_line(line)
        if event:
            events.append(event)

    threats = analyze_events(events)

    unique_threats = []
    seen = set()

    for threat in threats:
        key = (
            threat["type"],
            threat.get("source"),
            threat.get("evidence"),
        )

        if key not in seen:
            seen.add(key)
            unique_threats.append(threat)

    threats = unique_threats

    high_count = sum(
        1 for threat in threats
        if threat["severity"] == "HIGH"
    )

    medium_count = sum(
        1 for threat in threats
        if threat["severity"] == "MEDIUM"
    )

    return {
        "filename": filename,
        "total_lines": len(lines),
        "events": events,
        "threats": threats,
        "summary": {
            "total_events": len(events),
            "total_threats": len(threats),
            "high_severity": high_count,
            "medium_severity": medium_count,
            "incidents": len(threats),
        },
        "analysis": {
            "engine": "SentinelX Detection Engine",
            "status": "completed",
            "timestamp": datetime.now().astimezone().isoformat(),
        },
    }


# JSON endpoint — preferred for public deployment.
@app.post("/api/analyze")
def analyze_log(payload: LogPayload):
    return build_analysis(payload.log_text, payload.filename)


# Multipart endpoint — retained for local compatibility.
@app.post("/api/logs/upload")
async def upload_log(file: UploadFile = File(...)):
    content = await file.read()

    text = content.decode(
        "utf-8",
        errors="ignore",
    )

    return build_analysis(
        text,
        file.filename or "uploaded.log",
    )
