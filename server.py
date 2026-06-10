import time
import uuid
import numpy as np
import hmac
import hashlib
import pandas as pd
from device import FEATURE_COLUMNS

class Server:

    def __init__(self, model, scaler, centroids):
        self.model = model
        self.scaler = scaler
        self.centroids = centroids

        self.device_nonce_history = {}
        self.allowed_time_window = 10
        self.distance_threshold = 2.5

        # ------------------------------
        # REGISTER DEVICE SHARED SECRETS
        # ------------------------------

        self.device_secrets = {}

        for i in range(1, 51):
            self.device_secrets[i] = f"secret_device_{i}"

        # ------------------------------
        # SERVER AUTHENTICATION SECRET
        # ------------------------------

        self.server_secret = "trusted_server_secret"

    # ------------------------------
    # SAME message mapping as device
    # ------------------------------
    
    def _derive_message_shift(self, nonce):
        dynamic_factor = nonce % 50
        jitter_shift = dynamic_factor * 0.01
        sram_shift = dynamic_factor
        return jitter_shift, sram_shift
    
    # ------------------------------
    # VERIFY DEVICE SIGNATURE
    # ------------------------------

    def _verify_signature(self, request):
        device_id = request["device_id"]
        if device_id not in self.device_secrets:
            return False
        secret = self.device_secrets[device_id]

        # Convert DataFrame to 1D array if needed
        fingerprint = request["fingerprint"]
        if isinstance(fingerprint, pd.DataFrame):
            fingerprint_array = fingerprint.values.flatten()
        else:
            fingerprint_array = fingerprint

        message = f"{device_id}|{request['timestamp']}|{request['nonce']}|{fingerprint_array.tolist()}"

        expected_signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected_signature, request["signature"])
    
    # ------------------------------
    # SERVER AUTHENTICATION PROOF
    # ------------------------------

    def _generate_server_proof(self, device_id):
        server_timestamp = int(time.time())
        server_nonce = str(uuid.uuid4())
        message = f"{device_id}|{server_timestamp}|{server_nonce}"
        signature = hmac.new(
            self.server_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return {
            "server_timestamp": server_timestamp,
            "server_nonce": server_nonce,
            "server_signature": signature
        }

    # ------------------------------
    # PROCESS AND VERIFY DEVICE REQUESTS
    # ------------------------------

    def verify(self, request, device_object=None):
        device_id = request["device_id"]
        timestamp = request["timestamp"]
        nonce = request["nonce"]
        fingerprint = request["fingerprint"]

        # ------------------------------
        # TIMESTAMP
        # ------------------------------

        if abs(int(time.time()) - timestamp) > self.allowed_time_window:
            return False, "Timestamp Invalid"

        # ------------------------------
        # SIGNATURE
        # ------------------------------

        if not self._verify_signature(request):
            return False, "Signature Invalid"

        # ------------------------------
        # REPLAY DETECTION
        # ------------------------------

        if device_id not in self.device_nonce_history:
            self.device_nonce_history[device_id] = set()

        if nonce in self.device_nonce_history[device_id]:
            return False, "Replay Attack"

        self.device_nonce_history[device_id].add(nonce)

        # ------------------------------
        # REMOVE MESSAGE SHIFT
        # ------------------------------

        shift = (nonce % 10) * 0.01

        corrected_fp = fingerprint - shift

        # ------------------------------
        # SCALE
        # ------------------------------

        fp_df = pd.DataFrame(corrected_fp, columns=FEATURE_COLUMNS)
        scaled = self.scaler.transform(fp_df)

        # ------------------------------
        # CLASSIFICATION
        # ------------------------------

        prediction = self.model.predict(scaled)[0]

        if prediction != device_id:
            return False, "Identity Mismatch"
        
        # ------------------------------
        # DISTANCE CHECK
        # ------------------------------

        centroid = self.centroids[device_id]

        distance = np.linalg.norm(
            scaled[0] - centroid
        )

        if distance > self.distance_threshold:
            return False, "Mimic Attack Detected"
        
        # ------------------------------
        # SERVER AUTHENTICATION
        # ------------------------------

        if device_object is not None:
            proof = self._generate_server_proof(
                device_id
            )

            verified = device_object.verify_server(
                proof["server_timestamp"],
                proof["server_nonce"],
                proof["server_signature"]
            )

            if not verified:
                return False, "Server Authentication Failed"

        # ------------------------------
        # SUCCESS (SESSION TOKEN)
        # ------------------------------

        token = str(uuid.uuid4())
        return True, token