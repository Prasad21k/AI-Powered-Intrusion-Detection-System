# AI-Powered Intrusion Detection System

## Project Overview

This project implements a real-time Intrusion Detection System (IDS)
designed to monitor network traffic and identify suspicious activity.

The system combines packet inspection, adaptive baseline learning,
rule-based threat detection, attacker profiling, risk scoring,
automatic blacklisting, incident reporting, and a real-time dashboard.

## Main Features

- Real-time packet capture using Scapy
- DDoS detection
- SYN flood detection
- Port scan detection
- ICMP attack detection
- Adaptive traffic baseline
- Threat classification
- Risk and threat scoring
- Attacker profiling
- Automatic IP blacklisting
- SQLite database logging
- CSV logging
- Incident report generation
- Forensic summary generation
- Performance monitoring
- Memory usage monitoring
- Real-time graphical dashboard

## Detection Workflow

Network Traffic
       ↓
Packet Capture
       ↓
Packet Inspection
       ↓
Feature / Traffic Analysis
       ↓
Baseline Comparison
       ↓
Threat Detection
       ↓
Attack Classification
       ↓
Risk & Threat Scoring
       ↓
Attacker Profiling
       ↓
Alert / Blacklisting
       ↓
Logging & Forensic Reporting
       ↓
Real-Time Dashboard

## Technologies Used

- Python
- Scapy
- Tkinter
- Matplotlib
- SQLite
- CSV
- Tracemalloc

## Attack Types Detected

1. DDoS
2. SYN Flood
3. Port Scan
4. ICMP-based suspicious traffic

## Testing

The IDS was tested using generated network traffic and packet
capture data.

During testing, the system successfully detected high-volume
traffic and classified suspicious activity as threats.

The system also generated attacker profiles, risk scores,
incident reports and forensic summaries.

## Project Output

The system produces:

- Real-time alerts
- Traffic statistics
- Threat percentage
- Attack classification
- Attacker intelligence
- Performance metrics
- Incident reports
- Forensic summaries
- Database and CSV logs

## Limitations

The current implementation uses adaptive baseline analysis,
packet-level inspection and rule-based detection rather than
a trained machine-learning classifier.

The local testing environment also means that addresses such
as 127.0.0.1 represent locally generated test traffic rather
than a real external attacker.

## Future Work

Future development can incorporate adversarial attack simulation,
machine-learning-based detection, evasion testing, automated
defense mechanisms and more advanced behavioral analysis.

## Project Status

Completed — experimental IDS implementation and validation.
