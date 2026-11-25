from pathlib import Path
import json
import os
import subprocess
from mcp.server import MCPServer

# Create the MCP server that an AI agent can connect to.
server = MCPServer("Blue Team Tools")

@server.tool()
def list_network_connections() -> str:
    """Show TCP and UDP connections and listening ports on this Ubuntu VM."""

    # ss = Linux tool for viewing network connections.
    # -t = TCP, -u = UDP, -n = show numeric addresses and ports.
    connections = subprocess.run(
        ["ss", "-tuna"],
        capture_output=True,
        text=True,
        timeout=10,
   )

    if connections.returncode != 0:
         return f"Could not read connections: {connections.stderr}"

    return connections.stdout


# Start the server when this file is run directly
@server.tool()
def read_iot_logs() -> str:
    """Read the last 50 lines from the  IoT log file."""

    log_file = Path(__file__).parent / "logs" / "iot.log"

    try:
        lines = log_file.read_text().splitlines()
        return "\n".join(lines[-50:]) or "The log file is empty."
    except OSError as error:
        raise RuntimeError(f"Could not read IoT logs: {error}") from error

@server.tool()
def read_suricata_alert() -> str:
    """Read the latest alert from a Suricata JSONL file."""
    default_file = Path(__file__).parent / "logs" / "suricata-demo.jsonl"
    alert_file = Path(os.environ.get("BLUE_TEAM_SURICATA_FILE", str(default_file)))
    latest = None

    with alert_file.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("event_type") == "alert":
                latest = line.strip()

    if latest is None:
        raise RuntimeError(f"No Suricata alerts found in {alert_file}")
    return latest

if __name__ == "__main__":
    server.run()
