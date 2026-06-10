# IoT Device Fingerprint Authentication

This project demonstrates an IoT device authentication framework that combines:

- Machine Learning–based device fingerprinting
- HMAC request authentication
- Replay attack protection
- Timestamp validation
- Mutual authentication
- Mimic attack detection

The goal is to verify the identity of IoT devices using both cryptographic authentication and hardware-derived fingerprint features.

---

# Project Overview

Each device has a unique fingerprint generated from hardware measurements.

A Random Forest classifier is trained to recognize legitimate devices based on these fingerprint characteristics.

During authentication, the server verifies:

1. Request freshness using timestamps
2. Request authenticity using HMAC signatures
3. Device identity using machine learning classification
4. Fingerprint similarity using centroid distance checks
5. Server authenticity through mutual authentication

---

# Dataset

The dataset contains fingerprint measurements collected from multiple devices.

Features include:

- Mean25
- Std25
- Mean26
- Std26
- Mean27
- Std27
- Corr2526
- Corr2527
- Corr2627
- TempC

The target label is:

- BoardID

Only devices 1–6 are used in the experiments.

---

# Training the Model

Train the device classifier:

```bash
python train.py
```

This creates:

```text
model.pkl
scaler.pkl
centroids.pkl
```

---

# Running Experiments

Run all authentication and attack simulations:

```bash
python experiment_runner.py
```

Generated outputs are saved in:

```text
results/
```

Including:

- Experiment results CSV
- Metrics by attack type
- Confusion matrix visualization

---

# Simulated Attacks

The framework evaluates several attack scenarios:

### Replay Attack

A previously accepted request is retransmitted.

### Stale Request Attack

An old timestamp is used to bypass freshness checks.

### Tampering Attack

Fingerprint data is modified during transmission.

### Noise Attack

Random measurement noise is added to the fingerprint.

### Software Mimic Attack

An attacker attempts to imitate a legitimate device using forged data.

### Hardware Mimic Attack

One physical device attempts to impersonate another device.

---

# Authentication Pipeline

1. A device generates a fingerprint sample from its hardware-derived characteristics.
2. The device creates an HMAC-SHA256 signature over the request contents.
3. The server validates the request timestamp to ensure freshness.
4. The server verifies the HMAC signature to confirm request authenticity.
5. The server checks the nonce history to detect replay attacks.
6. The nonce-dependent fingerprint offset is removed.
7. Fingerprint features are standardized using the trained scaler.
8. A Random Forest classifier predicts the device identity.
9. The fingerprint is compared against the enrolled device centroid to detect mimic attacks.
10. The server optionally performs mutual authentication by proving its own identity to the device.
11. If all checks succeed, a session token is issued.

---

# Technologies Used

- Python
- NumPy
- Pandas
- Scikit-learn
- Matplotlib
- Seaborn
- Joblib

---

# Results

The system evaluates:

- Accuracy
- Precision
- Recall
- F1 Score
- False Acceptance Rate (FAR)
- False Rejection Rate (FRR)

These metrics help assess authentication reliability and resistance to attacks.
