import pandas as pd
import numpy as np
import threading
import time

from tkinter import *
from tkinter.scrolledtext import ScrolledText

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# ==========================================
# LOAD DATASET
# ==========================================

data = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

# Convert labels
data[' Label'] = data[' Label'].map({
    'BENIGN': 0,
    'DDoS': 1
})

# Clean dataset
data.replace([np.inf, -np.inf], np.nan, inplace=True)

data.dropna(inplace=True)

# Features and labels
X = data.drop(' Label', axis=1)

y = data[' Label']

# Normalize
scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled,
    y,
    test_size=0.2,
    random_state=42
)

# ==========================================
# TRAIN MODEL
# ==========================================

print("Training IDS Model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

print("Model Ready!")

# ==========================================
# CREATE GUI
# ==========================================

root = Tk()

root.title("AI Intrusion Detection System")

root.geometry("1400x850")

root.configure(bg="#0f172a")

# ==========================================
# TITLE
# ==========================================

title_label = Label(
    root,
    text="AI-Based Intrusion Detection Dashboard",
    font=("Arial", 28, "bold"),
    fg="#38bdf8",
    bg="#0f172a"
)

title_label.pack(pady=15)

# ==========================================
# STATUS FRAME
# ==========================================

status_frame = Frame(root, bg="#0f172a")

status_frame.pack(pady=10)

attack_count = 0
safe_count = 0

attack_label = Label(
    status_frame,
    text="Attacks: 0",
    font=("Arial", 16, "bold"),
    fg="red",
    bg="#0f172a"
)

attack_label.grid(row=0, column=0, padx=40)

safe_label = Label(
    status_frame,
    text="Safe Traffic: 0",
    font=("Arial", 16, "bold"),
    fg="lime",
    bg="#0f172a"
)

safe_label.grid(row=0, column=1, padx=40)

system_label = Label(
    status_frame,
    text="System Status: ACTIVE",
    font=("Arial", 16, "bold"),
    fg="#38bdf8",
    bg="#0f172a"
)

system_label.grid(row=0, column=2, padx=40)

# ==========================================
# MAIN FRAME
# ==========================================

main_frame = Frame(root, bg="#0f172a")

main_frame.pack(fill=BOTH, expand=True)

# ==========================================
# LEFT SIDE — LOGS
# ==========================================

log_area = ScrolledText(
    main_frame,
    width=70,
    height=35,
    bg="#111827",
    fg="white",
    font=("Consolas", 11)
)

log_area.pack(side=LEFT, padx=15, pady=15)

log_area.tag_config("alert", foreground="red")

log_area.tag_config("safe", foreground="lime")

# ==========================================
# RIGHT SIDE — GRAPH
# ==========================================

graph_frame = Frame(main_frame, bg="#0f172a")

graph_frame.pack(side=RIGHT, fill=BOTH, expand=True)

fig = Figure(figsize=(7, 5), dpi=100)

ax = fig.add_subplot(111)

ax.set_title("Live Threat Monitoring")

ax.set_xlabel("Packets")

ax.set_ylabel("Count")

canvas = FigureCanvasTkAgg(fig, master=graph_frame)

canvas.get_tk_widget().pack(fill=BOTH, expand=True)

# Data for graph
x_data = []

attack_data = []

safe_data = []

# ==========================================
# MONITOR FUNCTION
# ==========================================

def monitor_traffic():

    global attack_count
    global safe_count

    for i in range(100):

        packet = X_test[i].reshape(1, -1)

        prediction = model.predict(packet)

        # ATTACK
        if prediction[0] == 1:

            attack_count += 1

            attack_label.config(
                text=f"Attacks: {attack_count}"
            )

            message = f"[ALERT] DDoS Attack at Packet {i}\n"

            log_area.insert(END, message, "alert")

        # SAFE
        else:

            safe_count += 1

            safe_label.config(
                text=f"Safe Traffic: {safe_count}"
            )

            message = f"[SAFE] Normal Packet {i}\n"

            log_area.insert(END, message, "safe")

        # Auto-scroll
        log_area.see(END)

        # ==================================
        # UPDATE GRAPH
        # ==================================

        x_data.append(i)

        attack_data.append(attack_count)

        safe_data.append(safe_count)

        ax.clear()

        ax.plot(
            x_data,
            attack_data,
            label="Attacks",
            color="red",
            linewidth=2
        )

        ax.plot(
            x_data,
            safe_data,
            label="Safe",
            color="lime",
            linewidth=2
        )

        ax.set_title("Live Threat Monitoring")

        ax.set_xlabel("Packets")

        ax.set_ylabel("Count")

        ax.legend()

        ax.grid(True)

        canvas.draw()

        # Delay
        time.sleep(0.5)

    log_area.insert(
        END,
        "\nMonitoring Finished.\n",
        "safe"
    )

# ==========================================
# START THREAD
# ==========================================

thread = threading.Thread(
    target=monitor_traffic
)

thread.start()

# ==========================================
# RUN GUI
# ==========================================

root.mainloop()