# SLM Cyber Defense

Blue-team prototype for AI-assisted analysis of IoT logs.

## Current features
- List TCP and UDP connections on the Ubuntu VM through MCP.
- Read the last 50 lines of an IoT log file through MCP.
- Analyze sysnthetic login events using local Qwen2.5 1.5B.
- Display and save the analysis.

## Requirements
- Ubuntu with Python 3.10 or later
- ss command
- Ollama installed and running

## Setup
'''bash
source .venv/bin/activate
python test_client.py
python detector.py

## Save an analysis
'''bash
mkdir -p results
python detector.py | tee results/oit-practice-analysis.txt

## Detection policy
Three or more failed logins from the same source IP to the
same device within 60 seconds are considered suspicious.

## Limitations

The included logs are synthetic practice data.
The model can make factual mistakes; review its evidence.
Python verification, continuous monitoring, and real IoT
log integration are not implemented yet.
