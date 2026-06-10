import pandas as pd
import numpy as np
import joblib
import seaborn as sns
import matplotlib.pyplot as plt

from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import f1_score
from sklearn.metrics import confusion_matrix

from device import Device
from server import Server

# Attack imports
from attacks.replay_attack import run_replay_attack
from attacks.stale_attack import run_stale_attack
from attacks.tampering_attack import run_tampering_attack
from attacks.noise_attack import run_noise_attack
from attacks.software_mimic_attack import run_mimic_attack
from attacks.hardware_mimic_attack import run_hardware_mimic_attack

import os

# ------------------------------
# RESULTS DIRECTORY
# ------------------------------

os.makedirs("results", exist_ok=True)

# ------------------------------
# LOAD MODEL
# ------------------------------

model = joblib.load("model.pkl")
scaler = joblib.load("scaler.pkl")
centroids = joblib.load("centroids.pkl")

server = Server(model, scaler, centroids)

# ------------------------------
# CREATE DEVICES
# ------------------------------

devices = [Device(i) for i in range(1, 7)]

# ------------------------------
# RESULTS STORAGE
# ------------------------------

results = []

# ------------------------------
# NORMAL AUTH TESTS
# ------------------------------

for _ in range(1000):
    d = np.random.choice(devices)
    request = d.send_request()
    success, _ = server.verify(request, d)
    results.append({
        "expected": 1,
        "predicted": int(success),
        "type": "normal"
    })

# ------------------------------
# NOISE ATTACKS
# ------------------------------

for _ in range(300):
    d = np.random.choice(devices)
    success, _ = run_noise_attack(d, server)
    results.append({
        "expected": 0,
        "predicted": int(success),
        "type": "noise"
    })

# ------------------------------
# REPLAY ATTACKS
# ------------------------------

for _ in range(300):
    d = np.random.choice(devices)
    success, _ = run_replay_attack(d, server)
    results.append({
        "expected": 0,
        "predicted": int(success),
        "type": "replay"
    })

# ------------------------------
# STALE ATTACKS
# ------------------------------

for _ in range(300):
    d = np.random.choice(devices)
    success, _ = run_stale_attack(d, server)
    results.append({
        "expected": 0,
        "predicted": int(success),
        "type": "stale"
    })

# ------------------------------
# TAMPERING ATTACKS
# ------------------------------

for _ in range(300):
    d = np.random.choice(devices)
    success, _ = run_tampering_attack(d, server)
    results.append({
        "expected": 0,
        "predicted": int(success),
        "type": "tampering"
    })

# ------------------------------
# SOFTWARE MIMIC ATTACKS
# ------------------------------

for _ in range(300):
    d = np.random.choice(devices)
    success, _ = run_mimic_attack(d, server)
    results.append({
        "expected": 0,
        "predicted": int(success),
        "type": "software_mimic"
    })

# ------------------------------
# HARDWARE MIMIC ATTACKS
# ------------------------------

for _ in range(300):
    legit = np.random.choice(devices)
    attacker = np.random.choice(devices)
    while attacker.device_id == legit.device_id:
        attacker = np.random.choice(devices)
    success, _ = run_hardware_mimic_attack(
        legit,
        attacker,
        server
    )
    results.append({
        "expected": 0,
        "predicted": int(success),
        "type": "hardware_mimic"
    })

# ------------------------------
# SAVE RESULTS
# ------------------------------

results_df = pd.DataFrame(results)
results_df.to_csv("results/experiment_results.csv", index=False)

# ------------------------------
# OVERALL METRICS
# ------------------------------

accuracy = accuracy_score(results_df["expected"], results_df["predicted"])
precision = precision_score(results_df["expected"], results_df["predicted"], zero_division=0)
recall = recall_score(results_df["expected"], results_df["predicted"], zero_division=0)
f1 = f1_score(results_df["expected"], results_df["predicted"], zero_division=0)

# Overall FAR / FRR
cm = confusion_matrix(results_df["expected"], results_df["predicted"], labels=[0,1])
TN, FP, FN, TP = cm.ravel()
FAR_overall = FP / (FP + TN) if (FP+TN) > 0 else 0
FRR_overall = FN / (FN + TP) if (FN+TP) > 0 else 0

print("\n===== OVERALL METRICS =====")
print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"FAR (False Acceptance Rate) : {FAR_overall:.4f} (lower is better, ideally 0)")
print(f"FRR (False Rejection Rate) : {FRR_overall:.4f} (lower is better, ideally 0)")

# ------------------------------
# CONFUSION MATRIX
# ------------------------------

cm = confusion_matrix(results_df["expected"], results_df["predicted"])
plt.figure(figsize=(6,5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
plt.title("Overall Confusion Matrix\nNote: Values on diagonal are good, off-diagonal are errors")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.text(0.5, -0.15, "Higher diagonal values indicate good classification", color='red', ha='center', va='center', transform=plt.gca().transAxes)
plt.tight_layout()
plt.savefig("results/confusion_matrix.png")
plt.show()

# ------------------------------
# METRICS BY ATTACK TYPE
# ------------------------------

attack_types = results_df["type"].unique()
metrics_list = []

for attack in attack_types:
    subset = results_df[results_df["type"] == attack]
    acc = accuracy_score(subset["expected"], subset["predicted"])
    prec = precision_score(subset["expected"], subset["predicted"], zero_division=0)
    rec = recall_score(subset["expected"], subset["predicted"], zero_division=0)
    f1s = f1_score(subset["expected"], subset["predicted"], zero_division=0)
    cm_sub = confusion_matrix(subset["expected"], subset["predicted"], labels=[0,1])

    if cm_sub.size == 1:
        cm_sub = np.array([[cm_sub[0,0],0],[0,0]])
    elif cm_sub.shape != (2,2):
        cm_sub = np.pad(cm_sub, ((0,2-cm_sub.shape[0]), (0,2-cm_sub.shape[1])), 'constant')

    TN, FP, FN, TP = cm_sub.ravel()
    FAR = FP / (FP + TN) if (FP+TN) > 0 else 0
    FRR = FN / (FN + TP) if (FN+TP) > 0 else 0
    metrics_list.append({
        "Attack": attack,
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1": f1s,
        "FAR": FAR,
        "FRR": FRR
    })

metrics_df = pd.DataFrame(metrics_list)
metrics_df.to_csv("results/metrics_by_attack.csv", index=False)

print("\n===== METRICS BY ATTACK TYPE =====")
print(metrics_df)

# ------------------------------
# BAR PLOT OF METRICS BY ATTACK
# ------------------------------

metrics_df_melted = metrics_df.melt(id_vars="Attack", var_name="Metric", value_name="Value")
plt.figure(figsize=(10,6))
sns.barplot(x="Attack", y="Value", hue="Metric", data=metrics_df_melted)
plt.title("Metrics by Attack Type")
plt.ylim(0,1)
plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("results/metrics_by_attack.png")
plt.show()