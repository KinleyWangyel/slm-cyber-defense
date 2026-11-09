from collections import defaultdict
from datetime import datetime

def check_login_attempts(logs):
    """Find three failed logins within any 60-second window."""
    groups = defaultdict(list)
    invalid_lines = 0

    for line in logs.splitlines():
        if not line.strip():
            continue

        try:
            parts = line.split()
            timestamp = datetime.fromisoformat(
                parts[0].replace("Z", "+00:00")
            )
            if timestamp.tzinfo is None:
                raise ValueError("Timestamp needs a timezone")

            fields = dict(
                part.split("=", 1) for part in parts[1:]
            )
            event = fields["event"]
            source = fields["source"]
            device = fields["device"]

            if event == "login_failed":
                groups[(source, device)].append(
                    (timestamp, line)
                )
        except (ValueError, KeyError, IndexError):
            invalid_lines += 1

    findings = []

    for (source, device), events in groups.items():
        events.sort(key=lambda event: event[0])
        left = 0

        for right in range(len(events)):
            while (
                events[right][0] - events[left][0]
            ).total_seconds() > 60:
                left += 1

            window = events[left:right + 1]

            if len(window) >= 3:
                findings.append({
                    "verdict": "suspicious",
                    "source": source,
                    "device": device,
                    "failed_attempts": len(window),
                    "window_seconds": (
                       window[-1][0] - window[0][0]
                    ).total_seconds(),
                    "evidence": [
                        event[1] for event in window
                    ],
                })
                break

    return {
        "findings": findings,
        "invalid_lines": invalid_lines,
    }
