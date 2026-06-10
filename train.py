import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

FEATURE_COLUMNS = [
    "Mean25", "Std25",
    "Mean26", "Std26",
    "Mean27", "Std27",
    "Corr2526", "Corr2527", "Corr2627",
    "TempC"
]

# ------------------------------
# LOAD AND PREPARE TRAINING DATA
# ------------------------------

df = pd.read_csv("datasets/fingerprints_additional.csv")

# 6 devices
df = df[df["BoardID"].isin([1,2,3,4,5,6])]

# ------------------------------
# FEATURES + LABELS
# ------------------------------

X = df[FEATURE_COLUMNS]
y = df["BoardID"]

# ------------------------------
# TRAIN TEST SPLIT
# ------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ------------------------------
# LOAD AND PREPARE TRAINING DATA
# ------------------------------

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ------------------------------
# TRAIN THE RANDOM FOREST CLASSIFIER
# ------------------------------

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X_train_scaled, y_train)

# ------------------------------
# EVALUATE MODEL PERFORMANCE
# ------------------------------

predictions = model.predict(X_test_scaled)

print(classification_report(y_test, predictions))

# ------------------------------
# COMPUTE DEVICE CENTROIDS
# ------------------------------

centroids = {}

for device_id in sorted(df["BoardID"].unique()):
    device_samples = df[df["BoardID"] == device_id][FEATURE_COLUMNS]
    scaled_samples = scaler.transform(device_samples)
    centroid = np.mean(scaled_samples, axis=0)
    centroids[device_id] = centroid

# ------------------------------
# SAVE
# ------------------------------

joblib.dump(model, "model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(centroids, "centroids.pkl")

print("Training complete.")