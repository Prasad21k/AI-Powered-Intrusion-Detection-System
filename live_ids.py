from scapy.all import *
from scapy.all import IP, TCP, ICMP
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import sqlite3
import time
import csv
import tracemalloc
from datetime import datetime

# =========================
# DATABASE SETUP
# =========================

conn = sqlite3.connect(
    "ids_logs.db",
    check_same_thread=False
)

cursor = conn.cursor()
csv_file = open("ids_logs.csv", "a", newline="")
incident_file = open("incident_reports.txt", "a")
forensic_file = open("forensic_summary.txt", "w")
csv_writer = csv.writer(csv_file)

csv_writer.writerow([
    "Timestamp",
    "Alert_Type",
    "Severity",
    "Message"
])

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    alert_type TEXT,
    message TEXT
)
""")

conn.commit()

# =========================
# COUNTERS
# =========================

attack_count = 0
safe_count = 0
ddos_attacks = 0
packet_count = 0
port_stats = {}
attacker_ips = {}
blacklisted_ips = set()
high_alerts = 0
medium_alerts = 0
low_alerts = 0
start_time = time.time()
syn_flood_attacks = 0
port_scan_attacks = 0
icmp_attacks = 0
syn_count = 0
icmp_count = 0
most_dangerous_ip = "None"
highest_attack_count = 0
incident_id = 1
attack_timeline = []
processing_times = []
max_processing_time = 0
min_processing_time = float("inf")
average_processing_time = 0

tracemalloc.start()

attack_type_count = {
    "DDoS": 0,
    "SYN Flood": 0,
    "Port Scan": 0,
    "ICMP": 0
}

average_pps = 0
baseline_pps = 0
baseline_samples = 0
learning_mode = True
TESTING_MODE = True
SYN_THRESHOLD = 3
ICMP_THRESHOLD = 5
PORTSCAN_THRESHOLD = 8

# =========================
# GUI WINDOW
# =========================

root = tk.Tk()

root.title("AI Intrusion Detection System")

root.geometry("1600x900")

root.configure(bg="#06133d")

# =========================
# TITLE
# =========================

title = tk.Label(
    root,
    text="AI-Powered Intrusion Detection Dashboard",
    font=("Arial", 32, "bold"),
    fg="#38bdf8",
    bg="#06133d"
)

title.pack(pady=20)

# =========================
# STATUS LABELS
# =========================

top_frame = tk.Frame(
    root,
    bg="#06133d"
)

top_frame.pack()

attack_label = tk.Label(
    top_frame,
    text="Threat Alerts: 0",
    font=("Arial", 22, "bold"),
    fg="red",
    bg="#06133d"
)

attack_label.grid(
    row=0,
    column=0,
    padx=40
)

safe_label = tk.Label(
    top_frame,
    text="Safe Traffic: 0",
    font=("Arial", 22, "bold"),
    fg="lime",
    bg="#06133d"
)

safe_label.grid(
    row=0,
    column=1,
    padx=40
)

status_label = tk.Label(
    top_frame,
    text="System Status: ACTIVE",
    font=("Arial", 22, "bold"),
    fg="#38bdf8",
    bg="#06133d"
)

status_label.grid(
    row=0,
    column=2,
    padx=40
)

# =========================
# MAIN FRAME
# =========================

main_frame = tk.Frame(
    root,
    bg="#06133d"
)

main_frame.pack(pady=20)

# =========================
# OUTPUT BOX
# =========================

output_box = ScrolledText(
    main_frame,
    width=80,
    height=35,
    bg="#020817",
    fg="white",
    font=("Consolas", 12)
)

output_box.grid(
    row=0,
    column=0,
    padx=20
)

# =========================
# GRAPH
# =========================

fig, ax = plt.subplots(figsize=(5, 5))

canvas = FigureCanvasTkAgg(
    fig,
    master=main_frame
)

canvas.get_tk_widget().grid(
    row=0,
    column=1
)

# =========================
# UPDATE GRAPH
# =========================

def update_graph():

    ax.clear()

    total = attack_count + safe_count

    if total == 0:
        threat_percent = 0
    else:
        threat_percent = (attack_count / total) * 100

    labels = ["Threats", "Safe"]

    values = [attack_count, safe_count]

    colors = ["red", "lime"]

    if attack_count == 0 and safe_count == 0:
        values = [1, 1]

    ax.pie(
        values,
        labels=labels,
        autopct='%1.1f%%',
        colors=colors
    )

    ax.set_title("Traffic Analysis")

    canvas.draw()

# =========================
# UPDATE DASHBOARD
# =========================

def update_dashboard():

    attack_label.config(
        text=f"Threat Alerts: {attack_count}"
    )

    safe_label.config(
        text=f"Safe Traffic: {safe_count}"
    )

    update_graph()
# =========================
# SAVE ALERTS TO DATABASE
# =========================

def save_alert(alert_type, severity, message):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        """
        INSERT INTO alerts (
            timestamp,
            alert_type,
            message
        )
        VALUES (?, ?, ?)
        """,
        (
            timestamp,
            alert_type,
            message
        )
    )

    conn.commit()

    csv_writer.writerow([
        timestamp,
        alert_type,
        severity,
        message
    ])

    csv_file.flush()

# =========================
# PROCESS PACKETS
# =========================
def calculate_threat_score(info, blacklisted):
    score = 0
    # Attack frequency (30 points)
    score += min(info["attacks"] * 3, 30)

    # Packet volume (20 points)
    score += min(info["packets"] // 20, 20)

    # Attack type (25 points)
    attack_weights = {
        "DDoS": 25,
        "SYN Flood": 20,
        "Port Scan": 15,
        "ICMP": 10,
        "Unknown": 0
    }

    score += attack_weights.get(info["attack_type"], 0)

    # Blacklisted attacker (25 points)
    if blacklisted:
        score += 25

    return min(score, 100)

def calculate_confidence_score(info):

    confidence = 50

    if info["attacks"] > 50:
        confidence += 20

    if info["packets"] > 100:
        confidence += 15

    if info["attack_type"] == "DDoS":
        confidence += 15

    return min(confidence, 100)

def calculate_threat_priority(info):

    priority = (
        info["threat_score"] * 0.4 +
        info["confidence"] * 0.3 +
        info["risk_score"] * 0.3
    )

    return round(priority)

def process_packet(packet):

    try:
        packet_start = time.perf_counter()
        global incident_id
        global attack_count
        global safe_count
        global packet_count
        global start_time
        global average_pps
        global baseline_pps
        global baseline_samples
        global learning_mode
        global ddos_attacks
        global syn_flood_attacks
        global port_scan_attacks
        global icmp_attacks
        global attacker_ips
        global blacklisted_ips
        global most_dangerous_ip
        global highest_attack_count
        global attack_type_count
        global high_alerts
        global medium_alerts
        global low_alerts
        global syn_count
        global icmp_count
        global max_processing_time
        global min_processing_time
        global average_processing_time
        global current_memory
        global peak_memory

        alert_message = ""

        packet_count += 1

        current_timestamp = time.time()
        current_datetime = time.strftime("%Y-%m-%d %H:%M:%S")
        current_time = current_datetime

        elapsed_time = current_timestamp - start_time
        if elapsed_time <= 0:
            elapsed_time = 1

        # REAL-TIME PPS CALCULATION

        if not hasattr(process_packet, "last_time"):
            process_packet.last_time = current_timestamp
            process_packet.last_packet_count = packet_count
            current_pps = 0
        else:
            time_difference = current_timestamp - process_packet.last_time

            if time_difference >= 1:
                current_pps = packet_count - process_packet.last_packet_count

                process_packet.last_packet_count = packet_count
                process_packet.last_time = current_timestamp
            else:
                current_pps = 0

        packets_per_second = current_pps

        # LEARNING MODE
        if learning_mode:

            baseline_samples += 1

            baseline_pps = (
                baseline_pps * (baseline_samples - 1)
                + current_pps
            ) / baseline_samples

            if baseline_samples > 50:
                learning_mode = False

        average_pps = (
            average_pps + current_pps
        ) / 2

        severity = "LOW"

        # GET SOURCE IP
        if packet.haslayer(IP):

            src_ip = packet[IP].src

        else:

            src_ip = "Unknown"

        if src_ip not in attacker_ips:
            attacker_ips[src_ip] = {
                "attacks": 0,
                "packets": 0,
                "risk_score": 0,
                "threat_score": 0,
                "confidence": 0,
                "behavior": "Normal",
                "attack_type": "Unknown",
                "threat_level": "LOW",
                "first_seen": None,
                "last_seen": None,
                "activity_count": 0,
                "threat_priority": 0,
                "persistence": "Low"
            }

        current_attacker = attacker_ips[src_ip]

        current_attacker["packets"] += 1
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")

        current_time = time.strftime("%Y-%m-%d %H:%M:%S")

        if current_attacker["first_seen"] is None:
            current_attacker["first_seen"] = current_time

        current_attacker["last_seen"] = current_time
        current_attacker["activity_count"] += 1

        # DDOS DETECTION
        if TESTING_MODE:
            ddos_detected = current_pps > 5
        else:
            ddos_detected = current_pps > baseline_pps * 2.5

        # DDOS ATTACK
        if ddos_detected:

            ddos_attacks += 1
            attack_type_count["DDoS"] += 1
            attack_count += 1

            severity = "HIGH"
            high_alerts += 1

            current_attacker["attacks"] += 1
            packets = current_attacker["packets"]
            activity = current_attacker["activity_count"]

            current_attacker["attack_type"] = "DDoS"
            current_attacker["risk_score"] = calculate_threat_score(
                current_attacker,
                src_ip in blacklisted_ips
            )

            current_attacker["threat_score"] = current_attacker["risk_score"]
            current_attacker["confidence"] = calculate_confidence_score(current_attacker)

            if packets > 500:
                current_attacker["behavior"] = "Anomalous"
            else:
                current_attacker["behavior"] = "Normal"
            
            current_attacker["threat_priority"] = calculate_threat_priority(current_attacker)

            if activity >= 500:
                persistence = "Persistent"
            elif activity >= 100:
                persistence = "Moderate"
            else:
                persistence = "Low"

            current_attacker["persistence"] = persistence
            incident_report = f"""
            ================ INCIDENT REPORT ================

            Incident ID   : {incident_id}
            Timestamp     : {current_time}
            Source IP     : {src_ip}
            Attack Type   : {current_attacker["attack_type"]}
            Threat Level  : {current_attacker["threat_level"]}
            Threat Score  : {current_attacker["threat_score"]}
            Confidence    : {current_attacker["confidence"]}
            Priority      : {current_attacker["threat_priority"]}
            Packets       : {current_attacker["packets"]}
            Status        : {"Blacklisted" if src_ip in blacklisted_ips else "Monitoring"}

            =================================================
            """

            print(incident_report)
            incident_file.write(incident_report)
            incident_file.write("\n")
            incident_file.flush()

            incident_id += 1

            risk = attacker_ips[src_ip]["risk_score"]

            if risk >= 90:
                threat_level = "CRITICAL"
            elif risk >= 70:
                threat_level = "HIGH"
            elif risk >= 40:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"

            attacker_ips[src_ip]["threat_level"] = threat_level
            attacker_ips[src_ip]["threat_level"] = threat_level

            attack_timeline.append(
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} | "
                f"IP: {src_ip} | "
                f"Attack: {attacker_ips[src_ip]['attack_type']} | "
                f"Level: {attacker_ips[src_ip]['threat_level']} | "
                f"Priority: {attacker_ips[src_ip]['threat_priority']}"
            )

# AUTO BLACKLIST

            # AUTO BLACKLIST
            if attacker_ips[src_ip]["attacks"] >= 10:
                blacklisted_ips.add(src_ip)

            # MOST DANGEROUS IP
            if attacker_ips[src_ip]["attacks"] > highest_attack_count:
                highest_attack_count = attacker_ips[src_ip]["attacks"]
                most_dangerous_ip = src_ip

            alert_message = (
                f"[ALERT] Heavy Traffic Detected | Confidence: 95% "
                f"| PPS: {int(packets_per_second)}"
            )

        # TCP DETECTION
        elif packet.haslayer(TCP):

            dst_port = packet[TCP].dport

            if dst_port not in port_stats:
                port_stats[dst_port] = 0

            port_stats[dst_port] += 1

            flags = packet[TCP].flags

            suspicious_ports = [
                21,
                22,
                23,
                445,
                3389
            ]

            # PORT SCAN DETECTION
            if dst_port in suspicious_ports:

                port_scan_attacks += 1
                attack_type_count["Port Scan"] += 1

                if port_scan_attacks >= PORTSCAN_THRESHOLD:

                    attack_count += 1

                    severity = "CRITICAL"
                    high_alerts += 1

                    alert_message = (
                        f"[ALERT] Suspicious Port Access | Confidence: 88% "
                        f"| Port: {dst_port}"
                    )

                else:

                    severity = "LOW"
                    safe_count += 1

                    alert_message = (
                        f"[SAFE] TCP Packet | Port: {dst_port}"
                    )

            # SYN FLOOD DETECTION
            elif flags == "S":

                syn_count += 1

                if syn_count >= SYN_THRESHOLD:

                    attack_count += 1
                    syn_flood_attacks += 1
                    attack_type_count["SYN Flood"] += 1

                    severity = "HIGH"
                    high_alerts += 1

                    alert_message = (
                        f"[ALERT] Possible SYN Flood | Confidence: 92% "
                        f"| Port: {dst_port}"
                    )

                else:

                    severity = "LOW"
                    safe_count += 1

                    alert_message = (
                        f"[SAFE] TCP Packet | Port: {dst_port}"
                    )

            # NORMAL TCP TRAFFIC
            else:

                severity = "LOW"

                safe_count += 1

                alert_message = (
                    f"[SAFE] TCP Packet | Port: {dst_port}"
                )

        # ICMP DETECTION
        elif packet.haslayer(ICMP):

            icmp_count += 1

            if icmp_count >= ICMP_THRESHOLD: 

                attack_count += 1
                icmp_attacks += 1
                attack_type_count["ICMP"] += 1

                severity = "MEDIUM"
                medium_alerts += 1

                alert_message = (
                    "[ALERT] ICMP Packet Detected | Confidence: 70%"
                )

            else:

                severity = "LOW"
                safe_count += 1

                alert_message = "[SAFE] ICMP Traffic"

        # NORMAL TRAFFIC
        else:

            severity = "LOW"

            safe_count += 1

            alert_message = "[SAFE] Normal Traffic"

        # UPDATE LABELS
        threat_percentage = 0

        if packet_count > 0:
            threat_percentage = (attack_count / packet_count) * 100

        print("\n========== AI-POWERED IDS ANALYTICS ==========")

        print(f"Total Packets: {packet_count}")
        print(f"Threat Alerts: {attack_count}")
        print(f"Safe Traffic: {safe_count}")
        print(f"Threat Percentage: {threat_percentage:.2f} %")

        print("\nHigh Alerts:", high_alerts)
        print("Medium Alerts:", medium_alerts)
        print("Low Alerts:", low_alerts)

        print("\nThreat Breakdown:")
        print(f"DDoS Attacks: {ddos_attacks}")
        print(f"SYN Flood Attacks: {syn_flood_attacks}")
        print(f"Port Scan Attacks: {port_scan_attacks}")
        print(f"ICMP Attacks: {icmp_attacks}")

        print("\nTop Ports:")

        top_ports = sorted(
            port_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        for port, count in top_ports:
            print(f"Port {port}: {count} packets")

        print("\n===== PERFORMANCE METRICS =====")

        if len(processing_times) > 0:

            fastest = min(processing_times)
            slowest = max(processing_times)
            average = sum(processing_times) / len(processing_times)

            current_memory, peak_memory = tracemalloc.get_traced_memory()

            print(f"Fastest Packet Processing : {fastest*1000:.3f} ms")
            print(f"Slowest Packet Processing : {slowest*1000:.3f} ms")
            print(f"Average Processing Time   : {average*1000:.3f} ms")
            print(f"Packets Processed         : {len(processing_times)}")
            print(f"Current Memory Usage      : {current_memory/1024:.2f} KB")
            print(f"Peak Memory Usage         : {peak_memory/1024:.2f} KB")

        else:

            print("Collecting performance metrics...")

        print("\n===== ATTACKER INTELLIGENCE =====")

        print("Blacklisted IPs:", len(blacklisted_ips))
        print("Most Dangerous IP:", most_dangerous_ip)
        print("Highest Attack Count:", highest_attack_count)

        print("\n===== ATTACKER PROFILES =====")

        for ip, info in attacker_ips.items():
            print(f"\nIP Address   : {ip}")
            print(f"Packets      : {info['packets']}")
            print(f"Attacks      : {info['attacks']}")
            print(f"Risk Score   : {info['risk_score']}%")
            print(f"Threat Score : {info['threat_score']}%")
            print(f"Confidence   : {info['confidence']}%")
            print(f"Behavior     : {info['behavior']}")
            print(f"Priority     : {info['threat_priority']}/100")
            print(f"Persistence  : {info['persistence']}")
            print(f"First Seen   : {info['first_seen']}")
            print(f"Last Seen    : {info['last_seen']}")
            print(f"Activity Cnt : {info['activity_count']}")
            print(f"Threat Level : {info['threat_level']}")
            print(f"Attack Type  : {info['attack_type']}")

        print("\n===== TOP ATTACKERS =====")

        sorted_attackers = sorted(
            attacker_ips.items(),
            key=lambda x: x[1]["attacks"],
            reverse=True
        )
        for rank, (ip, info) in enumerate(sorted_attackers[:5], start=1):
            print(f"\n#{rank}")
            print(f"IP           : {ip}")
            print(f"Attacks      : {info['attacks']}")
            print(f"Risk Score   : {info['risk_score']}%")
            print(f"Threat Score : {info['threat_score']}%")
            print(f"Threat Level : {info['threat_level']}")

        print("\n===== ATTACK TYPE STATISTICS =====")

        for attack, count in attack_type_count.items():
            print(f"{attack:<12}: {count}")

        print("\n===== THREAT SUMMARY =====")

        print(f"Total Attackers     : {len(attacker_ips)}")
        print(f"Blacklisted IPs     : {len(blacklisted_ips)}")
        print(f"Most Dangerous IP   : {most_dangerous_ip}")
        print(f"Highest Attack Count: {highest_attack_count}")

        if attacker_ips:
            avg_risk = sum(info["risk_score"] for info in attacker_ips.values()) / len(attacker_ips)
            print(f"Average Risk Score  : {avg_risk:.2f}%")
        
        print("\n===== ATTACK TIMELINE =====")

        for event in attack_timeline[-10:]:
            print(event)

        print("====================================")

        print("\n============= FORENSIC SUMMARY =============")
        print(f"Incident ID           : {incident_id-1}")
        print(f"Total Attackers       : {len(attacker_ips)}")
        print(f"Blacklisted IPs       : {len(blacklisted_ips)}")
        print(f"Most Dangerous IP     : {most_dangerous_ip}")
        print(f"Highest Attack Count  : {highest_attack_count}")

        highest_priority = max(
            info["threat_priority"]
            for info in attacker_ips.values()
        )

        print(f"Highest Priority      : {highest_priority}")

        most_common_attack = max(
            attack_type_count,
            key=attack_type_count.get
        )

        print(f"Most Common Attack    : {most_common_attack}")
        print(f"Timeline Events       : {len(attack_timeline)}")

        print("============================================")
        forensic_summary = f"""
        ============= FORENSIC SUMMARY =============

        Incident ID          : {incident_id-1}
        Total Attackers      : {len(attacker_ips)}
        Blacklisted IPs      : {len(blacklisted_ips)}
        Most Dangerous IP    : {most_dangerous_ip}
        Highest Attack Count : {highest_attack_count}
        Highest Priority     : {highest_priority}
        Most Common Attack   : {most_common_attack}
        Timeline Events      : {len(attack_timeline)}

        ============================================
        """
        forensic_file.seek(0)
        forensic_file.write(forensic_summary)
        forensic_file.truncate()
        forensic_file.flush()
        # OUTPUT BOX
        output_box.insert(
            tk.END,
            f"[{severity}] {alert_message}\n"
        )

        # ALERT COLOR
        if "[ALERT]" in alert_message:

            save_alert(
                "THREAT",
                severity,
                alert_message
            )

            output_box.tag_add(
                "alert",
                "end-2l",
                "end-1l"
            )

            output_box.tag_config(
                "alert",
                foreground="red"
            )

        # SAFE COLOR
        else:

            output_box.tag_add(
                "safe",
                "end-2l",
                "end-1l"
            )

            output_box.tag_config(
                "safe",
                foreground="lime"
            )

        output_box.see(tk.END)

        # UPDATE DASHBOARD — update every 10 packets
        if packet_count % 10 == 0:
            root.after(0, update_dashboard)

        packet_end = time.perf_counter()
        processing_times.append(packet_end - packet_start)

        if processing_times:
            max_processing_time = max(processing_times)
            min_processing_time = min(processing_times)
            average_processing_time = (
                sum(processing_times) / len(processing_times)
            )
        current_memory, peak_memory = tracemalloc.get_traced_memory()

    except Exception as e:

        print("ERROR:", e)
# =========================
# START SNIFFING
# =========================

def start_sniffing():

    sniff(
        iface="\\Device\\NPF_Loopback",
        prn=process_packet,
        store=False
    )

# =========================
# THREADING
# =========================

sniff_thread = threading.Thread(
    target=start_sniffing
)

sniff_thread.daemon = True

sniff_thread.start()

# =========================
# RUN GUI
# =========================

root.mainloop()