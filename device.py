import pandas as pd
import numpy as np
import time
import hmac
import hashlib

FEATURE_COLUMNS = [
    "Mean25", "Std25",
    "Mean26", "Std26",
    "Mean27", "Std27",
    "Corr2526", "Corr2527", "Corr2627",
    "TempC"
]

# ------------------------------
# LOAD DEVICE DATA
# ------------------------------

df = pd.read_csv("datasets/fingerprints_additional.csv")
df = df[df["BoardID"].isin([1,2,3,4,5,6])]

# ------------------------------
# DEVICE SIMULATION
# ------------------------------

class Device:

    def __init__(self, device_id):
        self.device_id = device_id
        self.secret = f"secret_device_{device_id}"

        # Shared secret used to verify server authenticity
        self.server_secret = "trusted_server_secret"
        self.sequence = 0

        # Extract fingerprint samples associated with this device
        self.device_data = df[df["BoardID"] == device_id]

        # Ensure fingerprint data exists for the selected device
        if self.device_data.empty:
            raise ValueError(f"No data found for device {device_id} in the dataset!")

    # ------------------------------
    # GENERATE DEVICE FINGERPRINT
    # ------------------------------

    def generate_fingerprint(self, nonce):
        # Ensure fingerprint data exists for the selected device
        sample = self.device_data.sample(1)

        # Keep as DataFrame to preserve column names
        vector = sample[FEATURE_COLUMNS].astype(float)

        # Dynamic nonce binding
        vector = vector + (nonce % 10) * 0.01
        return vector  # shape (1, num_features)

    # ------------------------------
    # DEVICE REQUEST SIGNATURE
    # ------------------------------

    def _sign_request(self, device_id, timestamp, nonce, fingerprint):
        # Convert DataFrame to 1D list
        fingerprint_array = fingerprint.values.flatten()
        message = f"{device_id}|{timestamp}|{nonce}|{fingerprint_array.tolist()}"
        return hmac.new(
            self.secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
    
    # ------------------------------
    # VERIFY SERVER AUTHENTICITY
    # ------------------------------

    def verify_server(self, server_timestamp, server_nonce, server_signature):
        # Create same message used by server
        message = f"{self.device_id}|{server_timestamp}|{server_nonce}"
        expected_signature = hmac.new(
            self.server_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(
            expected_signature,
            server_signature
        )

    # ------------------------------
    # SEND REQUEST
    # ------------------------------

    def send_request(self, add_noise=False):
        timestamp = int(time.time())
        nonce = self.sequence
        self.sequence += 1

        fingerprint = self.generate_fingerprint(nonce)

        if add_noise:
            # Add Gaussian noise
            fingerprint += np.random.normal(0, 0.05, fingerprint.shape)

        signature = self._sign_request(
            self.device_id,
            timestamp,
            nonce,
            fingerprint
        )

        return {
            "device_id": self.device_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "fingerprint": fingerprint,
            "signature": signature
        }