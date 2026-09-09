# AI-Powered Intrusion Detection System

A real-time network Intrusion Detection System (IDS) designed to monitor network traffic, identify suspicious activity, classify threats, profile attackers, and generate security and forensic reports.

The system combines packet-level inspection, adaptive traffic baseline analysis, rule-based threat detection, risk scoring, attacker profiling, automated IP blacklisting, persistent logging, and a real-time graphical dashboard.

## Project Overview

This project was developed as the first stage of a broader cybersecurity research project focused on improving network intrusion detection and evaluating its robustness against adversarial and evasive traffic.

The IDS operates on live network traffic and performs continuous analysis to identify abnormal traffic patterns and potential attacks.

## Core Objectives

- Monitor network traffic in real time
- Detect suspicious and malicious traffic patterns
- Classify detected attack types
- Calculate risk and threat scores
- Build attacker profiles
- Automatically blacklist high-risk sources
- Maintain incident and forensic records
- Provide real-time security monitoring through a graphical dashboard

## System Architecture

```text
Network Traffic
       |
       v
Packet Capture
       |
       v
Packet Inspection
       |
       v
Traffic / Feature Analysis
       |
       v
Adaptive Baseline Comparison
       |
       v
Threat Detection
       |
       v
Attack Classification
       |
       +--------------------+
       |                    |
       v                    v
Risk & Threat Scoring   Attacker Profiling
       |                    |
       +---------+----------+
                 |
                 v
        Alert / Blacklisting
                 |
        +--------+--------+
        |                 |
        v                 v
   SQLite / CSV      Incident & Forensic
       Logging           Reporting
                 |
                 v
        Real-Time Dashboard


Main Features

Network Monitoring
Real-time packet capture using Scapy
TCP/IP packet inspection
Continuous traffic monitoring
Traffic statistics and baseline analysis


Threat Detection
DDoS detection
SYN flood detection
Port scan detection
ICMP-based suspicious traffic detection
Adaptive traffic threshold analysis
Rule-based threat classification


Threat Intelligence
Attacker profiling
Risk scoring
Threat scoring
Confidence assessment
Activity tracking
Automatic IP blacklisting


Security Response
High-risk source blocking
Persistent blacklist management
Incident tracking
Security alert generation


Logging & Forensics
SQLite database logging
CSV event logging
Incident report generation
Forensic summary generation
Attack timeline generation


Performance Monitoring
Packet processing time
Memory usage monitoring
Traffic processing statistics
Real-time graphical monitoring

Technologies Used

| Technology  | Purpose                             |
| ----------- | ----------------------------------- |
| Python      | Core implementation                 |
| Scapy       | Network packet capture and analysis |
| Tkinter     | Graphical dashboard                 |
| Matplotlib  | Traffic visualization               |
| SQLite      | Persistent security event storage   |
| CSV         | Event and alert logging             |
| Tracemalloc | Memory usage analysis               |


Attack Types Detected
DDoS
SYN Flood
Port Scan
ICMP-based suspicious traffic


Real-Time Dashboard
The system provides a graphical dashboard for real-time security monitoring.

The dashboard displays:

Threat alerts
Safe traffic
System status
Real-time packet activity
Traffic analysis
Threat percentage


Dashboard

Threat Analysis
The IDS generates detailed attacker profiles containing:
Source IP address
Packet count
Attack count
Risk score
Threat score
Confidence
Behaviour classification
Priority
Persistence
First-seen / last-seen timestamps
Attack type
Threat level


Forensic Analysis
The system maintains an attack timeline and generates forensic summaries containing:

Incident ID
Total attackers
Blacklisted IPs
Most dangerous source
Highest attack count
Highest priority
Most common attack type
Timeline events


Testing & Validation
The system was evaluated using generated network traffic and packet-capture data.

Testing demonstrated the ability to:

Capture network traffic
Detect high-volume malicious traffic
Classify suspicious activity
Generate attacker profiles
Calculate risk and threat scores
Maintain security logs
Generate incident and forensic reports
Display activity through the real-time dashboard


Example Outputs
The repository contains generated security outputs including:

ids_logs.csv
ids_logs.db
incident_reports.txt
forensic_summary.txt


Project Structure
AI-Powered-Intrusion-Detection-System/
│
├── main.py
├── packet_sniffer.py
├── live_ids.py
├── requirements.txt
│
├── ids_logs.csv
├── ids_logs.db
├── incident_reports.txt
├── forensic_summary.txt
│
├── screenshots/
│   ├── README.md
│   └── dashboard.png
│
├── .gitignore
└── README.md


Limitations

The current implementation primarily uses:
Adaptive baseline analysis
Packet-level inspection
Rule-based detection

It does not currently use a trained machine-learning classifier.

Local testing may generate traffic from addresses such as 127.0.0.1. These addresses represent locally generated test traffic rather than a real external attacker.

Research Extension

This IDS forms the baseline system for a subsequent adversarial-security study.

The second stage evaluates how the detection system responds to controlled attack variations, including:

High-rate traffic
Low-rate traffic
Timing variation
Threshold manipulation
Controlled SYN-based attacks
Adaptive defensive responses

The objective is to evaluate detection robustness and identify weaknesses that may not be visible during normal testing.

Future Work
Machine-learning-based traffic classification
Advanced behavioural anomaly detection
Adversarial attack simulation
Evasion-resistant detection
Automated adaptive defence mechanisms
Expanded attack datasets
Multi-model detection
Real-world network validation


Project Status
Completed — experimental IDS implementation and validation.

This project serves as the baseline intrusion detection system for the accompanying adversarial attack and defense research.

Disclaimer

This project is intended for cybersecurity research, education, and controlled laboratory environments.

Only test systems and networks for which you have explicit authorization should be monitored or subjected to security testing.
