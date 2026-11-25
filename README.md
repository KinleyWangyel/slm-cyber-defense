# SLM Cyber Defense

Blue-team prototype for detecting and explaining events in an authorized lab.

## Components

- `server.py`: read-only MCP tools for logs, network connections, and saved Suricata alerts.
- `rules.py` and `detector.py`: Python detection of repeated failed logins in synthetic IoT logs, followed by a model explanation.
- `suricata/core-http.rules`: HTTP and possible OGNL injection detection rules.
- `suricata_demo.py`: MCP retrieval and model explanation of a saved Suricata alert.

The model explains evidence. Suricata rules make the network detection decision.

## Requirements and setup

Python with the packages in `requirements.txt` is required. The CORE experiment also used Kali Linux, tcpdump, Suricata 8.0.6, and the authorized CORE lab.

    python3 -m venv .venv
    ./.venv/bin/python -m pip install -r requirements.txt

The demos use the endpoint in `BLUE_TEAM_MODEL_URL`. Without that variable, they use Ollama with `qwen2.5:1.5b`.

## Run the synthetic IoT log demo

    BLUE_TEAM_MODEL_URL=http://grain.utep.edu:11434/v1/chat/completions ./.venv/bin/python detector.py

The Python rule flags at least three failed logins from the same source to the same device within 60 seconds. These logs are synthetic practice data.

## Run the saved Suricata alert demo

After generating an EVE alert file in the lab:

    BLUE_TEAM_SURICATA_FILE=/tmp/core-suricata-ognl/eve.json BLUE_TEAM_MODEL_URL=http://grain.utep.edu:11434/v1/chat/completions ./.venv/bin/python suricata_demo.py

Replace the `/tmp` path with the location of your own EVE file. The program prints alert facts and a model explanation.

## CORE experiment

In the simple CORE homelab, Kali at `10.0.0.21` sent requests to `172.16.1.20:8080`. We replayed two saved captures through the same Suricata rules. Each capture contained nine packets.

| Capture | HTTP rule 1000002 | OGNL rule 1000003 |
| --- | ---: | ---: |
| Ordinary HTTP | 1 alert | 0 alerts |
| Controlled OGNL | 0 alerts | 1 alert |

These are two test cases, not a general detection-rate estimate. The OGNL alert action was `allowed`: the traffic was detected but not blocked.

## Limitations

The CORE test used saved captures, not continuous monitoring. Firewall blocking and integration with the proposed segmented business scenario were not tested. Check model explanations against the original Suricata alert.
