import re


SQLI_PATTERNS = [
    r"' OR 1=1",
    r"UNION SELECT",
    r"SELECT .* FROM",
    r"DROP TABLE",
    r"INSERT INTO",
    r"--",
]


def detect_threats(events):
    threats = []

    # SSH brute force
    failed_logins = [
        event
        for event in events
        if event["event_type"] == "ssh_failed_login"
    ]

    if len(failed_logins) >= 3:
        source_ips = list({
            event["source"]
            for event in failed_logins
        })

        usernames = list({
            event["username"]
            for event in failed_logins
        })

        threats.append({
            "type": "SSH Brute Force",
            "severity": "HIGH",
            "count": len(failed_logins),
            "source_ips": source_ips,
            "targeted_users": usernames,
            "message": (
                f"{len(failed_logins)} failed SSH login attempts "
                f"detected."
            ),
        })

    # SQL injection
    for event in events:
        raw = event["raw"]

        for pattern in SQLI_PATTERNS:
            if re.search(pattern, raw, re.IGNORECASE):
                threats.append({
                    "type": "SQL Injection Attempt",
                    "severity": "HIGH",
                    "count": 1,
                    "source": event.get("source"),
                    "evidence": raw,
                    "message": "Possible SQL injection payload detected.",
                })
                break

    return threats