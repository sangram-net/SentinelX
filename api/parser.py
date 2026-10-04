import re
from datetime import datetime


def parse_log_line(line: str) -> dict:
    line = line.strip()

    if not line:
        return {}

    event = {
        "raw": line,
        "timestamp": datetime.now().isoformat(),
        "source": "unknown",
        "event_type": "unknown",
        "username": None,
    }

    # Detect SSH failed login
    ssh_match = re.search(
        r"Failed password for (?:invalid user )?(\w+) from ([\d.]+)",
        line,
        re.IGNORECASE,
    )

    if ssh_match:
        event["event_type"] = "ssh_failed_login"
        event["username"] = ssh_match.group(1)
        event["source"] = ssh_match.group(2)

    return event